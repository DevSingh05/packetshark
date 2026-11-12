//! Timings on a large capture. Not run by default:
//!
//!   `PACKETSHARK_PERF_PCAP=/path/to/big.pcap` cargo test --release --test perf -- --ignored --nocapture

mod common;

use std::path::PathBuf;
use std::time::Instant;

use common::Harness;
use crossterm::event::KeyCode;
use packetshark::app::Options;

fn rss_mb(pid: u32) -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .unwrap_or(0)
        / 1024
}

fn memory(label: &str, h: &Harness) {
    println!(
        "  memory {label}: packetshark {} MB, sharkd {} MB",
        rss_mb(std::process::id()),
        rss_mb(h.app.sharkd_pid())
    );
}

fn timed(label: &str, f: impl FnOnce()) {
    let start = Instant::now();
    f();
    println!(
        "{label:<44} {:>9.1} ms",
        start.elapsed().as_secs_f64() * 1000.0
    );
}

#[test]
#[ignore = "needs PACKETSHARK_PERF_PCAP"]
fn large_capture_timings() {
    let Some(path) = std::env::var_os("PACKETSHARK_PERF_PCAP").map(PathBuf::from) else {
        eprintln!("set PACKETSHARK_PERF_PCAP to a capture file");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let start = Instant::now();
    let Some(mut h) = Harness::start(dir, path, 160, 50, Options::default()) else {
        return;
    };
    h.settle();
    println!(
        "{:<44} {:>9.1} ms",
        "open (load + first screen)",
        start.elapsed().as_secs_f64() * 1000.0
    );
    let total = h.app.frames();
    println!("packets: {total}");
    memory("after open", &h);

    timed("j (next packet, with details)", || {
        h.key(KeyCode::Char('j'));
    });
    timed("PageDown x20", || {
        for _ in 0..20 {
            h.key(KeyCode::PageDown);
        }
    });
    timed("G (jump to the last packet)", || {
        h.key(KeyCode::Char('G'));
    });
    assert_eq!(h.app.list.selected_num(), Some(total));
    timed(":<middle> (go to a packet)", || {
        h.keys(&format!(":{}\n", total / 2));
    });
    timed("filter: udp.srcport == 30500 (first time)", || {
        h.keys("/udp.srcport == 30500\n");
    });
    println!("  displayed: {:?}", h.app.list.total);
    timed("G in the filtered list", || {
        h.key(KeyCode::Char('G'));
    });
    timed("x (clear filter, keep position)", || {
        h.key(KeyCode::Char('x'));
    });
    timed("filter again (cached by sharkd)", || {
        h.keys("/udp.srcport == 30500\n");
    });
    timed("find text in filtered list (s packet-9995)", || {
        h.keys("spacket-9995\n");
    });
    println!("  found: {:?}", h.app.list.selected_num());
    timed("n (next match)", || {
        h.keys("n");
    });
    memory("after browsing, filtering and searching", &h);
    timed("x then :phs (protocol hierarchy)", || {
        h.keys("x");
        h.keys(":phs\n");
    });
    memory("after protocol hierarchy", &h);
    timed(":conv udp", || {
        h.keys(":conv udp\n");
    });
    if let Some(packetshark::app::Overlay::Stats(view)) = &h.app.overlay {
        println!("  conversations: {}", view.rows.len());
    }
    memory("with the conversation list open", &h);
    h.key(KeyCode::Esc);
    memory("after closing it", &h);
}
