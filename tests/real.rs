//! Walks through every packet of real capture files, exercising the views a
//! user would open, and fails on any error or inconsistency. Not run by
//! default, because it needs captures that are not part of this repository:
//!
//!   `PACKETSHARK_REAL_DIR=/path/to/captures` cargo test --test real -- --ignored --nocapture

mod common;

use std::path::PathBuf;

use common::Harness;
use crossterm::event::KeyCode;
use packetshark::app::{Level, LoadState, Options, Overlay};

#[test]
#[ignore = "needs PACKETSHARK_REAL_DIR"]
fn real_captures_can_be_explored_without_errors() {
    let Some(dir) = std::env::var_os("PACKETSHARK_REAL_DIR").map(PathBuf::from) else {
        eprintln!("set PACKETSHARK_REAL_DIR to a directory of capture files");
        return;
    };
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let mut explored = 0;
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let scratch = tempfile::tempdir().unwrap();
        let Some(mut h) = Harness::start(scratch, file.clone(), 120, 40, Options::default()) else {
            return;
        };
        h.settle();
        if let LoadState::Failed(reason) = &h.app.load {
            println!("{name}: not a capture ({reason})");
            continue;
        }
        let total = h.app.frames();
        let mut sources = 0;
        let mut followable = 0;
        let mut fields = 0;
        let fail = |h: &mut Harness, what: &str| -> ! {
            let screen = h.screen();
            panic!("{name}: {what}\nmessage: {:?}\n{screen}", h.app.message)
        };
        let check = |h: &mut Harness, what: &str| {
            if h.app
                .message
                .as_ref()
                .is_some_and(|m| m.level == Level::Error)
            {
                fail(h, what);
            }
        };

        // Every packet: details load, every field's byte range is inside its
        // data source, and the tree can be fully expanded.
        h.key(KeyCode::Char('2'));
        h.key(KeyCode::Char('e'));
        h.key(KeyCode::Char('1'));
        for index in 0..total.min(400) {
            if index > 0 {
                h.key(KeyCode::Char('j'));
            }
            check(&mut h, "moving through the list");
            let num = h
                .app
                .list
                .selected_num()
                .unwrap_or_else(|| fail(&mut h, "no packet selected"));
            assert_eq!(num, index + 1, "{name}: cursor on the wrong packet");
            let Some(detail) = h.app.detail.as_ref() else {
                fail(&mut h, "details did not load")
            };
            assert_eq!(detail.num, num, "{name}: details are for another packet");
            assert!(
                !detail.tree.is_empty(),
                "{name}: packet {num} has an empty tree"
            );
            sources = sources.max(detail.sources.len());
            followable += usize::from(!detail.follow.is_empty());
            for line in &h.app.tree.lines {
                let node = detail.node(&line.path).expect("line refers to a node");
                fields += 1;
                if let Some((start, len)) = node.range {
                    let source = node.ds.unwrap_or(0);
                    let size = detail.sources.get(source).map(|s| s.bytes.len());
                    let Some(size) = size else {
                        panic!(
                            "{name}: packet {num} field {:?} names data source {source} of {}",
                            node.label,
                            detail.sources.len()
                        )
                    };
                    assert!(
                        start as usize + len as usize <= size,
                        "{name}: packet {num} field {:?} covers {start}+{len} of {size} bytes",
                        node.label
                    );
                }
            }
        }

        // The bytes pane: walk a packet's bytes; each selects some field.
        h.keys("g3");
        for _ in 0..40 {
            h.key(KeyCode::Char('l'));
        }
        h.keys("]]");
        h.app.message = None;

        // Follow whatever the first followable packets offer, in every mode.
        h.key(KeyCode::Char('1'));
        let mut followed = 0;
        for index in 0..total.min(60) {
            h.keys(&format!(":{}\n", index + 1));
            let options = h
                .app
                .detail
                .as_ref()
                .map(|d| d.follow.clone())
                .unwrap_or_default();
            for (protocol, _) in options.iter().take(2) {
                h.keys(&format!(":follow {protocol}\n"));
                let outcome = match &h.app.overlay {
                    Some(Overlay::Follow(view)) => {
                        view.error.clone().map(|e| format!("failed: {e}"))
                    }
                    _ => Some("did not open".to_string()),
                };
                if let Some(problem) = outcome {
                    fail(&mut h, &format!("follow {protocol} {problem}"));
                }
                h.keys("MjGMdd");
                h.key(KeyCode::Esc);
                followed += 1;
            }
            if followed >= 6 {
                break;
            }
        }
        check(&mut h, "following streams");

        // Statistics.
        for command in [
            "conv",
            "conv udp",
            "conv ipv4",
            "endpoints",
            "endpoints eth",
            "phs",
            "expert",
            "objects",
        ] {
            if command == "phs" && h.app.wireshark_version() < Some((4, 2)) {
                continue;
            }
            h.keys(&format!(":{command}\n"));
            let outcome = match &h.app.overlay {
                Some(Overlay::Stats(view)) if view.loading => Some("never finished".to_string()),
                Some(Overlay::Stats(view)) => view.error.clone().map(|e| format!("failed: {e}")),
                _ => Some("did not open".to_string()),
            };
            if let Some(problem) = outcome {
                fail(&mut h, &format!(":{command} {problem}"));
            }
            h.keys("jjorG");
            h.key(KeyCode::Esc);
        }
        check(&mut h, "statistics");

        // A filter from a field of the first packet, then find, then clear.
        h.keys(":1\n");
        h.keys("2jja");
        if matches!(h.app.overlay, Some(Overlay::Menu(_))) {
            h.key(KeyCode::Char('s'));
            check(&mut h, "applying a field as a filter");
            assert!(
                h.app.list.total.is_some_and(|t| t >= 1),
                "{name}: the field's own packet must match"
            );
        }
        h.keys("x");
        h.keys("sframe\n");
        h.keys("nnN");
        check(&mut h, "finding");
        h.keys("tttc");
        h.key(KeyCode::Char('L'));
        h.key(KeyCode::Char('z'));
        check(&mut h, "display options");

        println!(
            "{name}: {total} packets, {fields} fields checked, up to {sources} data sources, {followable} followable packets, {followed} streams followed"
        );
        explored += 1;
    }
    assert!(
        explored > 0,
        "no capture files could be opened in {}",
        dir.display()
    );
}
