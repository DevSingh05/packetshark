//! Packet sources that grow while packetshark is running: a live capture via
//! `dumpcap`, or a capture stream piped to stdin. Both are spooled to a
//! temporary file that the app reloads as it grows.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tempfile::TempDir;

use crate::sharkd::client::find_on_path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub description: String,
}

/// Find a Wireshark tool: next to sharkd first (so all tools are the same
/// version), then on `$PATH`.
pub fn locate_tool(name: &str, sharkd: &Path) -> Option<PathBuf> {
    if let Some(sibling) = sharkd
        .parent()
        .map(|d| d.join(name))
        .filter(|p| p.is_file())
    {
        return Some(sibling);
    }
    find_on_path(name)
}

/// Parse `dumpcap -D` output: `1. en0 (Wi-Fi)`.
pub fn parse_interfaces(output: &str) -> Vec<Interface> {
    output
        .lines()
        .filter_map(|line| {
            let (index, rest) = line.trim().split_once(". ")?;
            index.parse::<u32>().ok()?;
            let (name, description) = match rest.split_once(" (") {
                Some((n, d)) => (n, d.trim_end_matches(')')),
                None => (rest, ""),
            };
            Some(Interface {
                name: name.trim().to_string(),
                description: description.to_string(),
            })
        })
        .collect()
}

pub fn list_interfaces(dumpcap: &Path) -> Result<Vec<Interface>, String> {
    let out = Command::new(dumpcap)
        .arg("-D")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {}: {e}", dumpcap.display()))?;
    // dumpcap prints the list on stdout or stderr depending on version.
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let interfaces = parse_interfaces(&text);
    if interfaces.is_empty() {
        let reason = text
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no interfaces found");
        return Err(format!(
            "no capture interfaces available ({}). You may need capture permissions: \
             on macOS install ChmodBPF, on Linux join the `wireshark` group.",
            reason.trim()
        ));
    }
    Ok(interfaces)
}

enum Producer {
    Dumpcap {
        child: Child,
        log: PathBuf,
    },
    Stdin {
        done: Arc<AtomicBool>,
        /// Tells the spool thread to stop writing.
        stop: Arc<AtomicBool>,
        error: Arc<std::sync::Mutex<Option<String>>>,
    },
}

/// A capture in progress. Dropping it stops the producer and deletes the
/// spool file.
pub struct Capture {
    producer: Producer,
    path: PathBuf,
    stopped: bool,
    // Deleted on drop; declared last so the producer is stopped first.
    _dir: TempDir,
}

impl Capture {
    /// Start `dumpcap` on the given interfaces.
    pub fn live(
        dumpcap: &Path,
        interfaces: &[String],
        capture_filter: Option<&str>,
    ) -> Result<Capture, String> {
        let dir = spool_dir()?;
        let path = dir.path().join("capture.pcapng");
        let log = dir.path().join("dumpcap.log");
        let log_file = File::create(&log).map_err(|e| format!("could not create log: {e}"))?;
        let mut cmd = Command::new(dumpcap);
        cmd.args(dumpcap_args(interfaces, capture_filter, &path));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", dumpcap.display()))?;
        Ok(Capture {
            producer: Producer::Dumpcap { child, log },
            path,
            stopped: false,
            _dir: dir,
        })
    }

    /// Spool a capture stream from `input` (normally stdin).
    pub fn from_reader(mut input: impl Read + Send + 'static) -> Result<Capture, String> {
        let dir = spool_dir()?;
        let path = dir.path().join("stdin.pcap");
        let mut file =
            File::create(&path).map_err(|e| format!("could not create spool file: {e}"))?;
        let done = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let error = Arc::new(std::sync::Mutex::new(None));
        let (done2, stop2, error2) = (done.clone(), stop.clone(), error.clone());
        std::thread::Builder::new()
            .name("spool".into())
            .spawn(move || {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match input.read(&mut buf) {
                        Ok(0) => break,
                        // Stopped: what arrives from now on is discarded.
                        Ok(_) if stop2.load(Ordering::SeqCst) => break,
                        Ok(n) => {
                            if let Err(e) = file.write_all(&buf[..n]).and_then(|_| file.flush()) {
                                *error2.lock().unwrap() = Some(format!("spool write failed: {e}"));
                                break;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => {
                            *error2.lock().unwrap() = Some(format!("reading input failed: {e}"));
                            break;
                        }
                    }
                }
                done2.store(true, Ordering::SeqCst);
            })
            .map_err(|e| format!("could not start spool thread: {e}"))?;
        Ok(Capture {
            producer: Producer::Stdin { done, stop, error },
            path,
            stopped: false,
            _dir: dir,
        })
    }

    /// The file being written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether packets may still arrive.
    pub fn running(&mut self) -> bool {
        if self.stopped {
            return false;
        }
        match &mut self.producer {
            Producer::Dumpcap { child, .. } => matches!(child.try_wait(), Ok(None)),
            Producer::Stdin { done, .. } => !done.load(Ordering::SeqCst),
        }
    }

    /// If the producer failed, why.
    pub fn failure(&mut self) -> Option<String> {
        match &mut self.producer {
            Producer::Dumpcap { child, log } => match child.try_wait() {
                Ok(Some(status)) if !status.success() && !self.stopped => {
                    let text = fs::read_to_string(log).unwrap_or_default();
                    Some(dumpcap_failure(&text))
                }
                _ => None,
            },
            Producer::Stdin { error, .. } => error.lock().unwrap().clone(),
        }
    }

    /// Stop capturing. The packets captured so far stay available.
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        match &mut self.producer {
            Producer::Stdin { stop, .. } => stop.store(true, Ordering::SeqCst),
            Producer::Dumpcap { child, .. } => {
                // Only signal a child that is still running. Once `try_wait`
                // has reaped it, its pid may belong to another process.
                if !matches!(child.try_wait(), Ok(None)) {
                    return;
                }
                // SIGINT lets dumpcap flush and close the file cleanly.
                #[cfg(unix)]
                // SAFETY: `kill` has no memory-safety preconditions. The
                // check above showed the child has not been reaped, and
                // nothing else can reap it before this call, so the pid is
                // still ours.
                unsafe {
                    libc::kill(child.id() as libc::pid_t, libc::SIGINT);
                }
                #[cfg(not(unix))]
                let _ = child.kill();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) | Err(_) => break,
                        Ok(None) if std::time::Instant::now() > deadline => {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
                    }
                }
            }
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Turn dumpcap's stderr into one sentence, with a hint when the problem is
/// capture permissions (by far the most common one).
fn dumpcap_failure(stderr: &str) -> String {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    // dumpcap prefixes its own diagnosis; other lines are progress or advice
    // written for the GUI.
    let reason = lines
        .iter()
        .find_map(|l| l.strip_prefix("dumpcap: "))
        .or(lines.last().copied())
        .unwrap_or("dumpcap exited with an error")
        .to_string();
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("permission") {
        let hint = if cfg!(target_os = "macos") {
            "Install ChmodBPF to capture without root: brew install --cask wireshark-chmodbpf"
        } else {
            "To capture without root, add yourself to the `wireshark` group \
             (sudo usermod -aG wireshark $USER) and log in again"
        };
        return format!("{reason} {hint}.");
    }
    reason
}

fn spool_dir() -> Result<TempDir, String> {
    tempfile::Builder::new()
        .prefix("packetshark-")
        .tempdir()
        .map_err(|e| format!("could not create a temporary directory: {e}"))
}

fn dumpcap_args(interfaces: &[String], capture_filter: Option<&str>, path: &Path) -> Vec<String> {
    let mut args = Vec::new();
    for iface in interfaces {
        args.push("-i".to_string());
        args.push(iface.clone());
        // A capture filter applies to the interface it follows.
        if let Some(f) = capture_filter.filter(|f| !f.trim().is_empty()) {
            args.push("-f".to_string());
            args.push(f.to_string());
        }
    }
    args.push("-w".to_string());
    args.push(path.to_string_lossy().into_owned());
    // Quiet: no packet counter on stderr.
    args.push("-q".to_string());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_interface_list() {
        let out = "1. en0 (Wi-Fi)\n2. lo0 (Loopback)\n3. utun3\n\ngarbage line\n";
        assert_eq!(
            parse_interfaces(out),
            vec![
                Interface {
                    name: "en0".into(),
                    description: "Wi-Fi".into()
                },
                Interface {
                    name: "lo0".into(),
                    description: "Loopback".into()
                },
                Interface {
                    name: "utun3".into(),
                    description: String::new()
                },
            ]
        );
    }

    #[test]
    fn dumpcap_errors_are_reduced_to_the_reason() {
        let macos = "Capturing on 'Loopback: lo0'\n\
            dumpcap: You do not have permission to capture on device \"lo0\".\n\
            ((cannot open BPF device) /dev/bpf0: Permission denied)\n\
            Please check to make sure you have sufficient permissions.\n\n\
            If you installed Wireshark using the package from wireshark.org, close this dialog.\n";
        let message = dumpcap_failure(macos);
        assert!(
            message.starts_with("You do not have permission to capture on device \"lo0\". "),
            "{message}"
        );
        assert!(message.contains("without root"), "{message}");
        assert!(!message.contains("close this dialog"), "{message}");

        assert_eq!(
            dumpcap_failure("dumpcap: There is no device named \"en9\".\n"),
            "There is no device named \"en9\"."
        );
        assert_eq!(dumpcap_failure("something odd\nlast words\n"), "last words");
        assert_eq!(dumpcap_failure(""), "dumpcap exited with an error");
    }

    #[test]
    fn dumpcap_arguments() {
        let args = dumpcap_args(
            &["en0".into(), "lo0".into()],
            Some("port 53"),
            Path::new("/tmp/x.pcapng"),
        );
        assert_eq!(
            args,
            [
                "-i",
                "en0",
                "-f",
                "port 53",
                "-i",
                "lo0",
                "-f",
                "port 53",
                "-w",
                "/tmp/x.pcapng",
                "-q"
            ]
        );
        let args = dumpcap_args(&["en0".into()], Some("  "), Path::new("o"));
        assert_eq!(args, ["-i", "en0", "-w", "o", "-q"]);
    }

    /// A reader fed through a channel, like a pipe that stays open.
    struct Piped(std::sync::mpsc::Receiver<Vec<u8>>);
    impl Read for Piped {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.recv() {
                Ok(chunk) => {
                    buf[..chunk.len()].copy_from_slice(&chunk);
                    Ok(chunk.len())
                }
                Err(_) => Ok(0),
            }
        }
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !done() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn stopping_a_piped_capture_stops_the_spooling() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut cap = Capture::from_reader(Piped(rx)).unwrap();
        tx.send(b"first".to_vec()).unwrap();
        wait_until("the first chunk", || {
            fs::read(cap.path()).unwrap() == b"first"
        });
        assert!(cap.running());

        cap.stop();
        assert!(!cap.running());
        // The pipe is still open and still delivering; none of it is kept.
        tx.send(b"second".to_vec()).unwrap();
        tx.send(b"third".to_vec()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(fs::read(cap.path()).unwrap(), b"first");
        assert!(cap.failure().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn stopping_a_capture_whose_dumpcap_already_exited_signals_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("dumpcap");
        fs::write(
            &script,
            "#!/bin/sh\necho 'dumpcap: no such device' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut cap = Capture::live(&script, &["nope0".into()], None).unwrap();
        wait_until("dumpcap to exit", || !cap.running());
        assert_eq!(cap.failure().as_deref(), Some("no such device"));
        // The child has been reaped; stop must return at once without
        // signalling its old pid.
        let started = std::time::Instant::now();
        cap.stop();
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert!(!cap.running());
    }

    #[test]
    fn spools_a_reader_to_a_file() {
        let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let mut cap = Capture::from_reader(io::Cursor::new(data.clone())).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while cap.running() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!cap.running());
        assert_eq!(fs::read(cap.path()).unwrap(), data);
        assert!(cap.failure().is_none());
        let path = cap.path().to_path_buf();
        drop(cap);
        assert!(!path.exists(), "spool file is removed on drop");
    }
}
