//! The JSON-RPC client, against the real sharkd and against a scripted fake
//! that misbehaves in the ways a crashing or buggy sharkd could.

mod common;

use std::fmt::Write as _;

use common::{pcap, sharkd_path};
use packetshark::sharkd::types::*;
use packetshark::sharkd::{Client, Error, Launch};
use serde_json::{Value, json};

#[test]
fn talks_to_the_real_sharkd() {
    let Some(sharkd) = sharkd_path() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.pcap");
    pcap::web().write(&path);
    let mut c = Client::spawn(&Launch::new(sharkd)).unwrap();

    let info: Info = c.call("info", Value::Null).unwrap();
    assert!(
        info.columns.iter().any(|col| col.format == "%i"),
        "knows the Info column"
    );
    assert!(info.convs.iter().any(|t| t.tap == "conv:TCP"));

    let loaded: LoadResult = c.call("load", json!({ "file": path })).unwrap();
    assert_eq!((loaded.status.as_str(), loaded.err), ("OK", 0));
    let status: Status = c.call("status", Value::Null).unwrap();
    assert_eq!(status.frames, 21);
    assert!(status.column_info.iter().any(|col| col.title == "Info"));

    let rows: Vec<FrameRow> = c
        .call("frames", json!({ "filter": "http", "limit": 2 }))
        .unwrap();
    assert_eq!(rows.iter().map(|r| r.num).collect::<Vec<_>>(), [6, 8]);
    assert!(rows[0].bg.is_some(), "colouring rules are applied");

    let frame: FrameDetail = c
        .call("frame", json!({ "frame": 6, "proto": true, "bytes": true }))
        .unwrap();
    let tcp = frame
        .tree
        .iter()
        .find(|n| n.field.as_deref() == Some("tcp"))
        .unwrap();
    assert_eq!(tcp.range, Some((34, 20)));
    assert!(
        tcp.children
            .iter()
            .any(|n| n.field.as_deref() == Some("tcp.srcport"))
    );
    assert_eq!(
        frame
            .fol
            .iter()
            .map(|(p, _)| p.as_str())
            .collect::<Vec<_>>(),
        ["HTTP", "TCP"]
    );

    // sharkd's own errors come back as errors, and the connection stays usable.
    match c.call::<Value>("check", json!({ "filter": "tcp.prt" })) {
        Err(Error::Rpc { message, .. }) => assert!(message.contains("tcp.prt"), "{message}"),
        other => panic!("expected an RPC error, got {other:?}"),
    }
    assert!(matches!(
        c.call::<Value>("no-such-method", Value::Null),
        Err(Error::Rpc { .. })
    ));
    let again: Status = c.call("status", Value::Null).unwrap();
    assert_eq!(again.frames, 21);
}

/// A stand-in for sharkd that answers each request line with the next canned
/// reply, then exits.
#[cfg(unix)]
fn fake_sharkd(dir: &std::path::Path, replies: &[&str]) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let mut script =
        String::from("#!/bin/sh\ni=0\nwhile IFS= read -r line; do\n  i=$((i+1))\n  case $i in\n");
    for (n, reply) in replies.iter().enumerate() {
        let file = dir.join(format!("reply{n}"));
        std::fs::write(&file, reply).unwrap();
        let _ = writeln!(script, "    {}) cat '{}' ;;", n + 1, file.display());
    }
    script.push_str("    *) exit 0 ;;\n  esac\ndone\n");
    let path = dir.join("fake-sharkd");
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn survives_a_misbehaving_sharkd() {
    let dir = tempfile::tempdir().unwrap();
    let huge_item = "x".repeat(1000);
    let huge = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":[{}]}}\n",
        vec![format!("\"{huge_item}\""); 5000].join(",")
    );
    let program = fake_sharkd(
        dir.path(),
        &[
            "this is not json at all\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"status\":\"OK\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"error\":{\"code\":-5001,\"message\":\"Filter invalid - nope\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":[1,2\n",
            "{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":6,\"result\":{\"frames\":\"many\"}}\n",
            &huge,
            "\n\n{\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{\"status\":\"OK\"}}\n",
        ],
    );
    let mut c = Client::spawn(&Launch::new(program)).unwrap();

    assert!(
        matches!(c.call::<Value>("a", Value::Null), Err(Error::Protocol(_))),
        "garbage"
    );
    // The bad line was discarded; the next reply is read from its start.
    let ok: LoadResult = c.call("b", Value::Null).unwrap();
    assert_eq!(ok.status, "OK");
    match c.call::<Value>("c", Value::Null) {
        Err(Error::Rpc { code, message }) => {
            assert_eq!(code, -5001);
            assert_eq!(message, "Filter invalid - nope");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        matches!(
            c.call::<Vec<u32>>("d", Value::Null),
            Err(Error::Protocol(_))
        ),
        "truncated"
    );
    assert!(
        matches!(c.call::<Value>("e", Value::Null), Err(Error::Protocol(_))),
        "wrong id"
    );
    assert!(
        matches!(c.call::<Status>("f", Value::Null), Err(Error::Protocol(_))),
        "wrong shape"
    );
    // A 5 MB reply spanning many pipe reads parses, and nothing is left over.
    let big: Vec<String> = c.call("g", Value::Null).unwrap();
    assert_eq!(big.len(), 5000);
    assert!(big.iter().all(|s| s.len() == 1000));
    // Blank lines before a reply are skipped.
    let ok: LoadResult = c.call("h", Value::Null).unwrap();
    assert_eq!(ok.status, "OK");
    // The fake exits on the ninth request.
    let gone = c.call::<Value>("i", Value::Null).unwrap_err();
    assert!(gone.is_fatal(), "{gone:?}");
    let gone = c.call::<Value>("j", Value::Null).unwrap_err();
    assert!(gone.is_fatal(), "{gone:?}");
}

#[cfg(unix)]
#[test]
fn a_reply_cut_off_by_a_crash_counts_as_sharkd_exiting() {
    let dir = tempfile::tempdir().unwrap();
    // The second reply stops mid-way, with no newline, and the fake exits.
    let program = fake_sharkd(
        dir.path(),
        &[
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"OK\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":[{\"c\":[\"1\"],\"num\":1},{\"c\":[\"2",
        ],
    );
    // Make the fake exit right after its second reply.
    let script = std::fs::read_to_string(&program)
        .unwrap()
        .replace("    2) cat", "    2) trap 'exit 0' EXIT; cat");
    let script = script.replace("reply1' ;;", "reply1'; exit 0 ;;");
    std::fs::write(&program, script).unwrap();
    let mut c = Client::spawn(&Launch::new(program)).unwrap();
    let ok: LoadResult = c.call("a", Value::Null).unwrap();
    assert_eq!(ok.status, "OK");
    let err = c.call::<Vec<FrameRow>>("b", Value::Null).unwrap_err();
    assert!(
        matches!(err, Error::Exited),
        "a truncated reply means sharkd died: {err:?}"
    );
    assert!(err.is_fatal());
}

#[cfg(unix)]
#[test]
fn dropping_the_worker_does_not_wait_for_a_slow_request() {
    use packetshark::sharkd::{Request, Worker};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("slow-sharkd");
    // Never answers: like sharkd half-way through loading a huge capture.
    std::fs::write(&program, "#!/bin/sh\nread -r line\nexec sleep 60\n").unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
    let worker = Worker::start(Launch::new(program), |_reply| {}).unwrap();
    worker.send(Request::Load {
        path: "/tmp/big.pcap".into(),
    });
    worker.send(Request::Info);
    worker.send(Request::Info);
    std::thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    drop(worker);
    let took = started.elapsed();
    assert!(took < Duration::from_secs(3), "quitting took {took:?}");
}

#[test]
fn a_missing_binary_is_an_error_not_a_panic() {
    assert!(Client::spawn(&Launch::new("/definitely/not/sharkd")).is_err());
}
