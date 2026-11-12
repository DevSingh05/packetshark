//! A blocking JSON-RPC client for one `sharkd` process.
//!
//! `sharkd -` reads one request per line on stdin and writes one reply per
//! line on stdout. Replies can be very large (a statistics table for a big
//! capture runs to hundreds of megabytes), so a reply is parsed straight off
//! the pipe into its final type and never held in memory as text.

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

#[derive(Debug)]
pub enum Error {
    /// sharkd answered with a JSON-RPC error.
    Rpc { code: i64, message: String },
    /// The pipe to sharkd failed.
    Io(io::Error),
    /// sharkd closed its end; it has exited or crashed.
    Exited,
    /// sharkd sent something that is not a valid reply.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rpc { message, .. } => write!(f, "{message}"),
            Error::Io(e) => write!(f, "lost connection to sharkd: {e}"),
            Error::Exited => write!(f, "sharkd exited unexpectedly"),
            Error::Protocol(m) => write!(f, "unexpected reply from sharkd: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// True when the sharkd process is gone and must be restarted.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Error::Io(_) | Error::Exited)
    }
}

#[derive(Deserialize)]
#[serde(bound = "T: DeserializeOwned")]
struct Reply<T> {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default = "none")]
    result: Option<T>,
    #[serde(default)]
    error: Option<RpcError>,
}

fn none<T>() -> Option<T> {
    None
}

#[derive(Deserialize)]
struct RpcError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// How to start sharkd.
#[derive(Debug, Clone)]
pub struct Launch {
    pub program: PathBuf,
    /// Wireshark configuration profile (`sharkd -C`).
    pub profile: Option<String>,
    /// A configuration directory to use in place of the user's own
    /// (`WIRESHARK_CONFIG_DIR`).
    pub config_dir: Option<PathBuf>,
}

impl Launch {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Launch {
            program: program.into(),
            profile: None,
            config_dir: None,
        }
    }
}

pub struct Client {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Client {
    pub fn spawn(launch: &Launch) -> io::Result<Client> {
        let mut cmd = Command::new(&launch.program);
        // sharkd talks on its console either when told to with `-` or when
        // given no socket to listen on. The two cannot be combined: with a
        // profile, `-` after it is refused and `-` before it makes sharkd
        // ignore the profile. So it is one or the other.
        match &launch.profile {
            Some(profile) => {
                cmd.arg("-C").arg(profile);
            }
            None => {
                cmd.arg("-");
            }
        }
        if let Some(dir) = &launch.config_dir {
            cmd.env("WIRESHARK_CONFIG_DIR", dir);
        }
        // sharkd logs progress to stderr; it would corrupt the screen.
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Keep sharkd out of the terminal's foreground process group so a
        // Ctrl-C meant for the UI does not kill it mid-request.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(Client {
            child,
            stdin,
            stdout: BufReader::with_capacity(256 * 1024, stdout),
            next_id: 1,
        })
    }

    /// Write one request and return the id its reply will carry.
    fn send(&mut self, method: &str, params: Value) -> Result<u64, Error> {
        let id = self.next_id;
        self.next_id += 1;
        let mut request = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if !params.is_null() {
            request["params"] = params;
        }
        // serde_json never emits raw newlines, so the request is one line.
        let mut text = request.to_string();
        text.push('\n');
        self.stdin.write_all(text.as_bytes()).map_err(Error::Io)?;
        self.stdin.flush().map_err(Error::Io)?;
        Ok(id)
    }

    /// Read the next reply, whichever request it answers.
    fn read_reply<T: DeserializeOwned>(&mut self, method: &str) -> Result<Reply<T>, Error> {
        loop {
            let mut line = OneLine::new(&mut self.stdout);
            let parsed = {
                let mut de = serde_json::Deserializer::from_reader(Utf8Lossy::new(&mut line));
                Reply::<T>::deserialize(&mut de)
            };
            // Whatever happened, leave the pipe at the start of the next line.
            let (seen, blank, ended) = (line.bytes, line.blank, line.ended);
            line.finish().map_err(Error::Io)?;
            match parsed {
                Ok(reply) => return Ok(reply),
                // The stream ended, before or part-way through a reply:
                // sharkd is gone.
                Err(_) if seen == 0 || ended => return Err(Error::Exited),
                // An empty line between replies.
                Err(_) if blank => {}
                Err(e) if e.is_io() => return Err(Error::Io(e.into())),
                Err(e) => return Err(Error::Protocol(format!("{method}: {e}"))),
            }
        }
    }

    /// The result a reply carries, or the error it reports.
    fn unwrap_reply<T: DeserializeOwned>(reply: Reply<T>, method: &str) -> Result<T, Error> {
        if let Some(err) = reply.error {
            return Err(Error::Rpc {
                code: err.code,
                message: err.message,
            });
        }
        match reply.result {
            Some(result) => Ok(result),
            // No result member: acceptable only for callers that ignore it.
            None => serde_json::from_value(Value::Null)
                .map_err(|_| Error::Protocol(format!("{method}: reply has no result"))),
        }
    }

    /// Send one request and parse its result as `T`.
    pub fn call<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T, Error> {
        let id = self.send(method, params)?;
        let reply = self.read_reply::<T>(method)?;
        if reply.id.is_some_and(|got| got != id) {
            return Err(Error::Protocol(format!(
                "{method}: reply is for another request"
            )));
        }
        Self::unwrap_reply(reply, method)
    }

    /// Load a capture and read back its status.
    ///
    /// The two requests are sent together because Wireshark before 4.2 sends
    /// no reply at all to a `load` that reads some packets and then hits the
    /// end of a file cut short mid-packet, which is what a capture still
    /// being written looks like. The status reply arriving first is how that
    /// is noticed; `None` for the load result means exactly that.
    pub fn load<L, S>(&mut self, file: &Path) -> Result<(Option<L>, S), Error>
    where
        L: DeserializeOwned,
        S: DeserializeOwned,
    {
        let load_id = self.send("load", json!({ "file": file }))?;
        let status_id = self.send("status", Value::Null)?;
        let first = self.read_reply::<Value>("load")?;
        fn parse<T: DeserializeOwned>(value: Value, method: &str) -> Result<T, Error> {
            serde_json::from_value(value).map_err(|e| Error::Protocol(format!("{method}: {e}")))
        }
        if first.id == Some(status_id) {
            let status = Self::unwrap_reply(first, "status")?;
            return Ok((None, parse(status, "status")?));
        }
        if first.id.is_some_and(|got| got != load_id) {
            return Err(Error::Protocol("load: reply is for another request".into()));
        }
        // The status reply is read even if the load failed, to leave the
        // pipe in step with the requests.
        let status = self.read_reply::<Value>("status")?;
        let loaded = Self::unwrap_reply(first, "load")?;
        let status = Self::unwrap_reply(status, "status")?;
        Ok((Some(parse(loaded, "load")?), parse(status, "status")?))
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A reader that yields exactly one line of the underlying stream, then
/// reports end of input. Parsing through it can never run past the reply
/// being read, and `finish` discards whatever part of the line is left.
struct OneLine<'a, R: BufRead> {
    inner: &'a mut R,
    done: bool,
    /// Bytes handed out so far.
    bytes: u64,
    /// Nothing but whitespace has been handed out.
    blank: bool,
    /// The underlying stream ended before the line did.
    ended: bool,
}

impl<'a, R: BufRead> OneLine<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        OneLine {
            inner,
            done: false,
            bytes: 0,
            blank: true,
            ended: false,
        }
    }

    /// Skip to the end of the line without buffering it.
    fn finish(mut self) -> io::Result<()> {
        while !self.done {
            let available = match self.inner.fill_buf() {
                Ok(buf) => buf,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if available.is_empty() {
                break;
            }
            if let Some(i) = available.iter().position(|b| *b == b'\n') {
                self.inner.consume(i + 1);
                self.done = true;
            } else {
                let n = available.len();
                self.inner.consume(n);
            }
        }
        Ok(())
    }
}

impl<R: BufRead> Read for OneLine<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        let available = self.inner.fill_buf()?;
        if available.is_empty() {
            self.done = true;
            self.ended = true;
            return Ok(0);
        }
        let limit = out.len().min(available.len());
        let n = match available[..limit].iter().position(|b| *b == b'\n') {
            Some(i) => {
                self.done = true;
                i + 1
            }
            None => limit,
        };
        out[..n].copy_from_slice(&available[..n]);
        if self.blank && !out[..n].iter().all(u8::is_ascii_whitespace) {
            self.blank = false;
        }
        self.inner.consume(n);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// A reader that passes UTF-8 through and replaces anything else with
/// U+FFFD, as it streams.
///
/// JSON has to be UTF-8, but sharkd before 4.2 copies some bytes of a
/// malformed packet into its reply as they are. One such byte made the
/// whole reply unreadable, so that packet could not be shown at all.
struct Utf8Lossy<R: Read> {
    inner: R,
    /// The start of a character whose remaining bytes have not arrived.
    carry: Vec<u8>,
    /// Cleaned bytes not yet handed out.
    ready: Vec<u8>,
    ready_at: usize,
    ended: bool,
}

const REPLACEMENT: &[u8] = "\u{fffd}".as_bytes();

impl<R: Read> Utf8Lossy<R> {
    fn new(inner: R) -> Self {
        Utf8Lossy {
            inner,
            carry: Vec::new(),
            ready: Vec::new(),
            ready_at: 0,
            ended: false,
        }
    }

    /// Move `data` into `ready`, replacing what is not UTF-8 and keeping
    /// back a character that is cut off at the end.
    fn clean(&mut self, mut data: &[u8]) {
        loop {
            match std::str::from_utf8(data) {
                Ok(_) => {
                    self.ready.extend_from_slice(data);
                    return;
                }
                Err(e) => {
                    let (valid, rest) = data.split_at(e.valid_up_to());
                    self.ready.extend_from_slice(valid);
                    let Some(bad) = e.error_len() else {
                        // Cut off, not wrong: wait for the rest of it.
                        self.carry.extend_from_slice(rest);
                        return;
                    };
                    self.ready.extend_from_slice(REPLACEMENT);
                    data = &rest[bad..];
                }
            }
        }
    }
}

impl<R: Read> Read for Utf8Lossy<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.ready_at < self.ready.len() {
                let n = out.len().min(self.ready.len() - self.ready_at);
                out[..n].copy_from_slice(&self.ready[self.ready_at..self.ready_at + n]);
                self.ready_at += n;
                return Ok(n);
            }
            self.ready.clear();
            self.ready_at = 0;
            if self.ended {
                return Ok(0);
            }
            let n = self.inner.read(out)?;
            if n == 0 {
                self.ended = true;
                // A character that never finished.
                if !self.carry.is_empty() {
                    self.carry.clear();
                    self.ready.extend_from_slice(REPLACEMENT);
                }
                continue;
            }
            // The usual case: all of it is fine and can stay where it is.
            if self.carry.is_empty() && std::str::from_utf8(&out[..n]).is_ok() {
                return Ok(n);
            }
            let mut data = std::mem::take(&mut self.carry);
            data.extend_from_slice(&out[..n]);
            self.clean(&data);
        }
    }
}

/// The Wireshark version of the sharkd at `program`, as (major, minor).
///
/// This asks `sharkd -v` rather than using the `version` in sharkd's `info`
/// reply, which is a git description that often holds no version at all.
pub fn version(program: &Path) -> Option<(u32, u32)> {
    let output = Command::new(program)
        .arg("-v")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    parse_version(&String::from_utf8_lossy(&output.stdout))
}

/// Pick the version out of `Sharkd (Wireshark) 4.6.9 (Git commit ...)`.
fn parse_version(banner: &str) -> Option<(u32, u32)> {
    let rest = banner.split("(Wireshark)").nth(1)?.trim_start();
    let mut parts = rest.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Find the sharkd binary: an explicit path, `$PACKETSHARK_SHARKD`, `$PATH`, or
/// the places Wireshark installs it that are often not on `$PATH`.
pub fn locate(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return if p.is_file() {
            Ok(p.to_path_buf())
        } else {
            Err(format!("sharkd not found at {}", p.display()))
        };
    }
    if let Some(p) = std::env::var_os("PACKETSHARK_SHARKD") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!(
            "PACKETSHARK_SHARKD points to {}, which does not exist",
            p.display()
        ));
    }
    if let Some(p) = find_on_path("sharkd") {
        return Ok(p);
    }
    const EXTRA: &[&str] = &[
        "/opt/homebrew/bin/sharkd",
        "/usr/local/bin/sharkd",
        "/usr/bin/sharkd",
        "/usr/sbin/sharkd",
        "/Applications/Wireshark.app/Contents/MacOS/sharkd",
    ];
    for p in EXTRA {
        if Path::new(p).is_file() {
            return Ok(PathBuf::from(p));
        }
    }
    Err(
        "sharkd was not found. It ships with Wireshark's command-line tools \
         (Homebrew: `brew install wireshark`; Debian/Ubuntu: `apt install tshark`; \
         Fedora: `dnf install wireshark-cli`; Arch: `pacman -S wireshark-cli`). \
         Use --sharkd PATH if it is installed somewhere unusual."
            .to_string(),
    )
}

/// Search `$PATH` for an executable.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out its data a few bytes at a time, to split characters.
    struct Dribble<'a>(&'a [u8], usize);

    impl Read for Dribble<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.1.min(out.len()).min(self.0.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn lossy(data: &[u8], step: usize) -> String {
        let mut out = Vec::new();
        Utf8Lossy::new(Dribble(data, step))
            .read_to_end(&mut out)
            .unwrap();
        String::from_utf8(out).expect("the output is always UTF-8")
    }

    #[test]
    fn bytes_that_are_not_utf8_are_replaced() {
        for step in 1..8 {
            assert_eq!(lossy(b"plain ascii", step), "plain ascii");
            assert_eq!(
                lossy("caf\u{e9} \u{4e2d}\u{6587} \u{1f988}".as_bytes(), step),
                "caf\u{e9} \u{4e2d}\u{6587} \u{1f988}"
            );
            assert_eq!(lossy(b"filesys: \xaa)", step), "filesys: \u{fffd})");
            assert_eq!(
                lossy(b"\xff\xfe ok \xc3", step),
                "\u{fffd}\u{fffd} ok \u{fffd}"
            );
            // A lead byte followed by something that is not a continuation.
            assert_eq!(lossy(b"a\xe4\xb8z", step), "a\u{fffd}z");
        }
    }

    #[test]
    fn a_reply_holding_a_raw_byte_still_parses() {
        let line = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"l\":\"Unknown filesys: \xaa\"}}\n";
        let mut de = serde_json::Deserializer::from_reader(Utf8Lossy::new(&line[..]));
        let reply = Reply::<Value>::deserialize(&mut de).unwrap();
        assert_eq!(reply.result.unwrap()["l"], "Unknown filesys: \u{fffd}");
    }

    #[test]
    fn the_version_is_read_from_the_banner() {
        let v = parse_version;
        assert_eq!(
            v("Sharkd (Wireshark) 4.6.9 (Git commit 2d548b197c75).\n\nCopyright"),
            Some((4, 6))
        );
        assert_eq!(
            v("Sharkd (Wireshark) 3.6.2 (Git v3.6.2 packaged as 3.6.2-2)"),
            Some((3, 6))
        );
        assert_eq!(
            v("Running as user \"root\".\nSharkd (Wireshark) 4.10.1."),
            Some((4, 10))
        );
        assert_eq!(v("Git commit 2d548b197c75"), None);
        assert_eq!(v(""), None);
    }
    use std::io::Cursor;

    #[test]
    fn one_line_stops_at_the_newline() {
        let mut stream = Cursor::new(b"first line\nsecond\n".to_vec());
        let mut line = OneLine::new(&mut stream);
        let mut text = String::new();
        line.read_to_string(&mut text).unwrap();
        assert_eq!(text, "first line\n");
        line.finish().unwrap();
        let mut rest = String::new();
        stream.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "second\n");
    }

    #[test]
    fn finish_discards_an_unread_remainder() {
        let mut stream = Cursor::new(b"abcdefgh\nnext\n".to_vec());
        let mut line = OneLine::new(&mut stream);
        let mut two = [0u8; 2];
        line.read_exact(&mut two).unwrap();
        assert_eq!(&two, b"ab");
        line.finish().unwrap();
        let mut rest = String::new();
        stream.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "next\n");
    }

    #[test]
    fn a_line_cut_short_by_end_of_stream_is_flagged() {
        let mut stream = Cursor::new(b"{\"partial\":".to_vec());
        let mut line = OneLine::new(&mut stream);
        let mut text = String::new();
        line.read_to_string(&mut text).unwrap();
        assert_eq!(text, "{\"partial\":");
        assert!(line.ended, "no newline before the stream ended");

        let mut stream = Cursor::new(b"whole\n".to_vec());
        let mut line = OneLine::new(&mut stream);
        let mut text = String::new();
        line.read_to_string(&mut text).unwrap();
        assert!(!line.ended);
    }

    #[test]
    fn end_of_stream_is_seen_as_no_bytes() {
        let mut stream = Cursor::new(Vec::new());
        let mut line = OneLine::new(&mut stream);
        let mut buf = [0u8; 8];
        assert_eq!(line.read(&mut buf).unwrap(), 0);
        assert_eq!(line.bytes, 0);
        assert!(line.ended);
        line.finish().unwrap();
    }
}
