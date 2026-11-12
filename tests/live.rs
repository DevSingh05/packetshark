//! Live capture, with a scripted stand-in for dumpcap so the tests need no
//! capture privileges.

#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::{Harness, pcap};
use crossterm::event::KeyCode;
use packetshark::app::{Event, LoadState, Options};
use packetshark::capture::Capture;

fn script(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("fake-dumpcap");
    std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn wait_for(h: &mut Harness, what: &str, mut done: impl FnMut(&mut Harness) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        h.app.handle(Event::Tick);
        h.settle();
        if done(h) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}:\n{}",
            h.screen()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Start the app on a capture produced by `dumpcap`.
fn start(dumpcap: &Path, dir: tempfile::TempDir) -> Option<Harness> {
    let capture = Capture::live(dumpcap, &["en0".to_string()], Some("port 53")).unwrap();
    let options = Options {
        tail: true,
        ..Default::default()
    };
    let mut h = Harness::start(dir, capture.path().to_path_buf(), 100, 30, options)?;
    h.app.title = "en0 (live)".into();
    h.app.attach_capture(capture);
    Some(h)
}

#[test]
fn a_live_capture_fills_in_and_can_be_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pcap");
    pcap::many(30).write(&source);
    let args_seen = dir.path().join("args");
    // Writes a third of the capture, then the rest, then idles like a quiet
    // interface until interrupted.
    let dumpcap = script(
        dir.path(),
        &format!(
            r#"echo "$@" > '{args}'
while [ $# -gt 0 ]; do
  if [ "$1" = "-w" ]; then out="$2"; fi
  shift
done
trap 'exit 0' INT TERM
head -c 800 '{src}' > "$out"
sleep 0.4
cat '{src}' > "$out"
while :; do sleep 0.05; done
"#,
            args = args_seen.display(),
            src = source.display()
        ),
    );
    let Some(mut h) = start(&dumpcap, dir) else {
        return;
    };
    h.settle();
    assert!(h.app.capturing());

    wait_for(&mut h, "the first packets", |h| h.app.frames() > 0);
    assert!(
        h.app.frames() < 30,
        "partial capture shown first, got {}",
        h.app.frames()
    );
    h.app.message = None;
    h.assert_screen_contains("● capturing");
    h.assert_screen_contains("en0 (live)");

    wait_for(&mut h, "all packets", |h| h.app.frames() == 30);
    assert_eq!(
        h.app.list.selected_num(),
        Some(30),
        "the newest packet is selected"
    );

    let args = std::fs::read_to_string(h.dir.path().join("args")).unwrap();
    assert!(args.starts_with("-i en0 -f port 53 -w "), "{args}");
    assert!(args.trim_end().ends_with(".pcapng -q"), "{args}");

    // Ctrl-C stops the capture but keeps the packets; a second one quits.
    h.ctrl('c');
    assert!(!h.app.capturing());
    assert!(!h.app.quit);
    assert!(h.message().contains("Capture stopped"), "{}", h.message());
    h.app.message = None;
    h.assert_screen_contains("capture stopped");
    h.keys("gj");
    assert_eq!(h.app.list.selected_num(), Some(2));
    h.assert_screen_contains("Frame 2:");
    h.keys(":stop\n");
    assert!(h.message().contains("No capture is running"));
    h.ctrl('c');
    assert!(h.app.quit);

    // Dropping the app removes the spool file.
    let spool = h.app.source.clone();
    assert!(spool.exists());
    drop(h);
    assert!(!spool.exists(), "spool file left behind");
}

#[test]
fn a_capture_that_cannot_start_reports_dumpcaps_reason() {
    let dir = tempfile::tempdir().unwrap();
    let dumpcap = script(
        dir.path(),
        "echo 'dumpcap: The capture session could not be initiated on interface en0 (You do not have permission to capture on that device).' >&2\nexit 1\n",
    );
    let Some(mut h) = start(&dumpcap, dir) else {
        return;
    };
    wait_for(&mut h, "the failure", |h| {
        matches!(h.app.load, LoadState::Failed(_))
    });
    match &h.app.load {
        LoadState::Failed(reason) => {
            assert!(reason.starts_with("Capture failed:"), "{reason}");
            assert!(reason.contains("You do not have permission"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    assert!(!h.app.capturing());
    // The reason is long, so it is wrapped over several lines rather than cut.
    let screen: String = h.screen().split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        screen.contains("(You do not have permission to capture on that device)."),
        "{screen}"
    );
    assert!(
        screen.contains("without root"),
        "a hint on fixing permissions: {screen}"
    );
}

#[test]
fn a_capture_that_dies_midway_keeps_its_packets() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.pcap");
    pcap::web().write(&source);
    let dumpcap = script(
        dir.path(),
        &format!(
            r#"while [ $# -gt 0 ]; do
  if [ "$1" = "-w" ]; then out="$2"; fi
  shift
done
cat '{src}' > "$out"
sleep 0.5
echo 'dumpcap: the interface went down' >&2
exit 2
"#,
            src = source.display()
        ),
    );
    let Some(mut h) = start(&dumpcap, dir) else {
        return;
    };
    wait_for(&mut h, "packets", |h| h.app.frames() == 21);
    wait_for(&mut h, "the failure notice", |h| {
        h.message().contains("Capture stopped")
    });
    assert!(
        h.message().contains("the interface went down"),
        "{}",
        h.message()
    );
    assert_eq!(
        h.app.load,
        LoadState::Ready,
        "what was captured is still usable"
    );
    h.key(KeyCode::Char('g'));
    h.assert_screen_contains("Standard query 0x1234 A example.com");
}
