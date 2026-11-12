//! End-to-end tests: the real app, a real sharkd, and an in-memory terminal.
//! They are skipped (with a note) when Wireshark is not installed.

mod common;

use std::time::{Duration, Instant};

use common::{Harness, pcap};
use crossterm::event::{KeyCode, MouseEventKind};
use packetshark::app::filter::Validity;
use packetshark::app::{Event, Focus, LayoutKind, Level, LoadState, Options, Overlay};
use packetshark::theme::RowColors;
use ratatui::style::Color;

/// Screen row of the first packet in the list.
const FIRST_ROW: u16 = 3;

fn selected_packet(h: &Harness) -> u32 {
    h.app.list.selected_num().expect("a packet is selected")
}

fn selected_label(h: &Harness) -> String {
    h.app
        .selected_node()
        .expect("a field is selected")
        .label
        .clone()
}

/// Select the first tree line whose label contains `needle`, expanding everything first.
fn select_field(h: &mut Harness, needle: &str) {
    h.key(KeyCode::Char('2'));
    if !h.app.tree.expand_all {
        h.key(KeyCode::Char('e'));
    }
    let detail = h.app.detail.as_ref().expect("detail loaded");
    let index = h
        .app
        .tree
        .lines
        .iter()
        .position(|l| {
            detail
                .node(&l.path)
                .is_some_and(|n| n.label.contains(needle))
        })
        .unwrap_or_else(|| panic!("no field containing {needle:?}"));
    let tree = detail.tree.clone();
    h.app.tree.select(index, &tree);
    // Any key press re-syncs the other panes; `j` then `k` returns to the field.
    h.keys("jk");
    assert!(
        selected_label(h).contains(needle),
        "selected {:?}",
        selected_label(h)
    );
}

/// Keep processing events until `done`, for work that finishes outside sharkd.
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

// ---- loading and layout ----------------------------------------------------

#[test]
fn opens_a_capture_and_shows_all_three_panes() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    assert_eq!(h.app.load, LoadState::Ready);
    assert_eq!(h.app.frames(), 21);
    assert!(h.line(1).contains("21 packets"), "{}", h.line(1));
    assert!(h.line(2).contains("No.") && h.line(2).contains("Info"));
    let first = h.line(FIRST_ROW);
    assert!(
        first.contains("10.0.0.2") && first.contains("DNS"),
        "{first}"
    );
    assert!(
        first.contains("Standard query 0x1234 A example.com"),
        "{first}"
    );
    h.assert_screen_contains("Domain Name System (query)");
    h.assert_screen_contains("0000  aa bb cc dd ee 02");
    h.assert_screen_contains("test.pcap");
}

#[test]
fn a_file_that_is_not_a_capture_fails_with_a_reason() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pcap");
    std::fs::write(&path, b"this is not a capture file at all\n").unwrap();
    let Some(mut h) = Harness::start(dir, path, 100, 30, Options::default()) else {
        return;
    };
    h.settle();
    match &h.app.load {
        LoadState::Failed(reason) => assert!(reason.contains("test.pcap"), "{reason}"),
        other => panic!("expected a failure, got {other:?}"),
    }
    h.assert_screen_contains("test.pcap:");
    assert!(h.app.status.is_none());
}

#[test]
fn an_empty_capture_says_so() {
    let Some(mut h) = Harness::open(&pcap::Pcap::new()) else {
        return;
    };
    h.assert_screen_contains("This capture has no packets.");
    // Nothing to act on, and nothing crashes.
    h.keys("jkGg\tjk3hjkl");
    h.keys("F");
    assert!(
        h.message().contains("Select a packet first"),
        "{}",
        h.message()
    );
}

#[test]
fn tiny_terminals_do_not_panic() {
    for (w, hgt) in [(20, 4), (30, 6), (40, 8), (50, 10), (200, 60)] {
        let Some(mut h) = Harness::open_with(&pcap::web(), w, hgt, Options::default()) else {
            return;
        };
        h.keys("jj\tjl3llz/tcp\n:phs\n");
        h.keys("q?");
        let screen = h.screen();
        if w < 30 || hgt < 6 {
            assert!(screen.contains("Terminal too small"), "{screen}");
        }
    }
}

#[test]
fn side_layout_and_zoom() {
    let Some(mut h) = Harness::open_with(&pcap::web(), 140, 30, Options::default()) else {
        return;
    };
    h.key(KeyCode::Char('L'));
    assert_eq!(h.app.layout, LayoutKind::Side);
    let (y, line) = h.find_line("Details").unwrap();
    assert!(
        line.contains("Bytes"),
        "details and bytes share a row: {line}"
    );
    assert!(h.line(y + 1).contains('│'), "divider drawn");
    h.assert_screen_contains("0000  aa bb cc dd ee 02 aa bb  cc dd ee 01 08 00 45 00");

    h.keys("2z");
    assert!(h.app.zoom);
    h.assert_screen_lacks("Packets");
    h.assert_screen_contains("Details");
    assert_eq!(h.app.tree.height, 27, "the details pane fills the body");
    h.key(KeyCode::Esc);
    assert!(!h.app.zoom);
    h.assert_screen_contains("Packets");
}

#[test]
fn panes_can_be_resized() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    let before = h.app.list.height;
    h.keys("+++");
    assert!(
        h.app.list.height > before,
        "{} -> {}",
        before,
        h.app.list.height
    );
    h.keys("------");
    assert!(h.app.list.height < before);
}

#[test]
fn the_config_file_sets_the_starting_look() {
    let config = packetshark::config::Config::parse(
        "[ui]\nrow_colors = \"off\"\nlayout = \"side\"\nexpand_all = true\n",
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pcap");
    pcap::web().write(&path);
    let Some(mut h) = Harness::start_configured(dir, path, 140, 30, Options::default(), config)
    else {
        return;
    };
    h.settle();
    assert_eq!(h.app.layout, LayoutKind::Side);
    assert_eq!(h.app.theme.row_colors, RowColors::Off);
    assert_eq!(
        h.bg_at(10, FIRST_ROW + 1),
        Some(Color::Reset),
        "no row colours"
    );
    assert!(
        h.app.tree.lines.len() > 40,
        "the tree starts fully expanded"
    );
    h.assert_screen_contains("Encapsulation type: Ethernet (1)");
}

// ---- packet list -----------------------------------------------------------

#[test]
fn moving_the_cursor_updates_details_and_bytes() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.key(KeyCode::Char('j'));
    assert_eq!(selected_packet(&h), 2);
    h.assert_screen_contains("Domain Name System (response)");
    assert!(h.line(1).contains("21 packets"));
    h.assert_screen_contains("packet 2");
    h.key(KeyCode::Char('G'));
    assert_eq!(selected_packet(&h), 21);
    h.assert_screen_contains("Frame 21:");
    h.key(KeyCode::Char('g'));
    assert_eq!(selected_packet(&h), 1);
    h.key(KeyCode::PageDown);
    assert_eq!(selected_packet(&h), 1 + u32::from(h.app.list.height) - 1);
    h.key(KeyCode::Char('k'));
    h.ctrl('u');
    h.ctrl('u');
    h.ctrl('u');
    assert_eq!(selected_packet(&h), 1);
}

#[test]
fn large_captures_are_paged_not_loaded_whole() {
    let Some(mut h) = Harness::open(&pcap::many(5000)) else {
        return;
    };
    assert!(h.line(1).contains("5,000 packets"), "{}", h.line(1));
    assert!(h.app.list.row(0).is_some());
    assert!(
        h.app.list.row(4000).is_none(),
        "far rows are not fetched up front"
    );

    h.key(KeyCode::Char('G'));
    assert_eq!(selected_packet(&h), 5000);
    let (_, last) = h.find_line(" 5000 ").expect("last packet visible");
    assert!(last.contains("UDP"), "{last}");
    h.assert_screen_contains("Frame 5000:");
    assert!(h.app.list.row(4999).is_some());

    h.keys(":2500\n");
    assert_eq!(selected_packet(&h), 2500);
    h.assert_screen_contains(" 2500 ");
    h.assert_screen_contains("Frame 2500:");

    // Paging through: every visible row is loaded once things settle.
    for _ in 0..8 {
        h.key(KeyCode::PageDown);
        let (top, height) = (h.app.list.top, u32::from(h.app.list.height));
        assert!(
            (top..top + height).all(|i| h.app.list.fresh_row(i).is_some()),
            "rows from {top}"
        );
    }
    assert_eq!(
        selected_packet(&h),
        2500 + 8 * (u32::from(h.app.list.height) - 1)
    );
    h.key(KeyCode::Char('g'));
    assert_eq!(selected_packet(&h), 1);
}

#[test]
fn rows_use_wireshark_colours_until_turned_off() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    // Row 2 (not selected) is DNS: Wireshark's light blue.
    let y = FIRST_ROW + 1;
    assert_eq!(h.bg_at(10, y), Some(Color::Rgb(0xda, 0xee, 0xff)));
    assert_eq!(h.style_at(10, y).fg, Some(Color::Rgb(0x12, 0x27, 0x2e)));
    h.key(KeyCode::Char('c'));
    assert_eq!(h.app.theme.row_colors, RowColors::Tint);
    assert_eq!(
        h.bg_at(10, y),
        Some(Color::Reset),
        "the terminal's own background"
    );
    assert_eq!(h.style_at(10, y).fg, Some(Color::Rgb(0xda, 0xee, 0xff)));
    h.key(KeyCode::Char('c'));
    assert_eq!(h.app.theme.row_colors, RowColors::Off);
    assert_eq!(h.style_at(10, y).fg, Some(Color::Reset));
    h.keys(":colors wireshark\n");
    assert_eq!(h.bg_at(10, y), Some(Color::Rgb(0xda, 0xee, 0xff)));
}

#[test]
fn time_format_can_be_changed() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    assert!(h.line(FIRST_ROW + 1).contains("0.012300"));
    h.keys(":time utc-date\n");
    assert!(
        h.line(FIRST_ROW + 1).contains("2023-11-14 22:13:20.0246"),
        "{}",
        h.line(FIRST_ROW + 1)
    );
    h.keys(":time delta\n");
    assert!(
        h.line(FIRST_ROW + 4).contains("0.012300"),
        "{}",
        h.line(FIRST_ROW + 4)
    );
    h.keys(":time default\n");
    assert!(
        h.line(FIRST_ROW + 4).contains("0.049200"),
        "{}",
        h.line(FIRST_ROW + 4)
    );
    // `t` cycles, and says what it switched to.
    h.key(KeyCode::Char('t'));
    assert!(h.message().starts_with("Time:"), "{}", h.message());
    h.keys(":time nonsense\n");
    assert!(h.message().contains("Usage: :time"));
}

#[test]
fn a_time_reference_restarts_the_clock() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("jj");
    h.ctrl('t');
    if h.app.wireshark_version() < Some((4, 0)) {
        // sharkd ignores time references before 4.0, and the app says so.
        assert!(
            h.message().contains("need Wireshark 4.0"),
            "{}",
            h.message()
        );
        assert!(h.app.time_refs.is_empty());
        return;
    }
    assert!(h.app.time_refs.contains(&3));
    assert!(
        h.line(FIRST_ROW + 2).contains("*REF*"),
        "{}",
        h.line(FIRST_ROW + 2)
    );
    assert!(
        h.line(FIRST_ROW + 3).contains("0.012300"),
        "{}",
        h.line(FIRST_ROW + 3)
    );
    assert!(
        h.line(FIRST_ROW + 2).starts_with('@'),
        "reference marker in the gutter"
    );
    h.ctrl('t');
    assert!(h.app.time_refs.is_empty());
    assert!(h.line(FIRST_ROW + 3).contains("0.036900"));
}

#[test]
fn marks_can_be_listed_and_cleared() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":marked\n");
    assert!(h.message().contains("No packets are marked"));
    h.keys("MjM"); // marks 1 and 3 (marking moves down one)
    assert_eq!(h.app.marks.iter().copied().collect::<Vec<_>>(), [1, 3]);
    assert!(h.line(FIRST_ROW).starts_with('●'));
    h.app.message = None;
    h.assert_screen_contains("2 marked");
    h.keys(":marked\n");
    assert!(h.line(1).contains("2 of 21 packets"), "{}", h.line(1));
    h.keys(":unmark\n");
    assert!(h.app.marks.is_empty());
    assert!(h.message().contains("Removed 2 marks"));
    // Unmarking with m toggles.
    h.keys("xgmgm");
    assert!(h.app.marks.is_empty());
}

// ---- display filter --------------------------------------------------------

#[test]
fn applying_a_filter_narrows_the_list() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/dns\n");
    assert_eq!(h.app.filter.applied, "dns");
    assert_eq!(h.app.focus, Focus::List);
    assert!(
        h.line(1).contains("2 of 21 packets (9.5%)"),
        "{}",
        h.line(1)
    );
    assert!(h.line(FIRST_ROW + 1).contains("Standard query response"));
    assert!(h.line(FIRST_ROW + 2).trim().is_empty(), "only two rows");
    h.key(KeyCode::Char('x'));
    assert_eq!(h.app.filter.applied, "");
    assert!(h.line(1).contains("21 packets"));
}

#[test]
fn the_selected_packet_survives_a_filter_change() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":8\n");
    assert_eq!(selected_packet(&h), 8);
    h.keys("/http\n");
    assert_eq!(
        selected_packet(&h),
        8,
        "packet 8 is HTTP, so it stays selected"
    );
    assert_eq!(h.app.list.selected, 1, "it is the second HTTP packet");
    // Packet 8 is not in the next filter; the nearest later match is taken.
    h.keys("/tcp.port == 40001\n");
    assert_eq!(selected_packet(&h), 13);
    h.keys("x");
    assert_eq!(selected_packet(&h), 13);
    assert_eq!(h.app.list.selected, 12);
}

#[test]
fn an_invalid_filter_is_refused_with_the_reason() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/tcp.prt == 1");
    assert!(matches!(h.app.filter.validity, Validity::Invalid(_)));
    // The wording is Wireshark's and differs between versions; what matters
    // is that its reason is on screen.
    let Validity::Invalid(reason) = h.app.filter.validity.clone() else {
        unreachable!();
    };
    assert!(reason.len() > 10, "a real reason: {reason:?}");
    let shown: String = reason.chars().take(24).collect();
    h.assert_screen_contains(&shown);
    h.key(KeyCode::Enter);
    assert_eq!(h.app.filter.applied, "", "nothing was applied");
    assert_eq!(h.app.focus, Focus::Filter, "still editing");
    assert!(h.message().contains("Invalid filter"));
    assert!(h.line(1).contains("21 packets"));
    // Escape abandons the edit.
    h.key(KeyCode::Esc);
    assert_eq!(h.app.focus, Focus::List);
    assert!(h.app.filter.input.is_empty());
    assert_eq!(h.app.filter.validity, Validity::Empty);
}

#[test]
fn a_filter_matching_nothing_explains_itself() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/tcp.port == 1\n");
    assert!(h.line(1).contains("0 of 21 packets"));
    h.assert_screen_contains("No packets match the filter. Press x to clear it.");
    assert!(h.app.detail.is_none());
    h.assert_screen_lacks("Frame 1:");
    h.keys("jkG");
    h.key(KeyCode::Char('x'));
    h.assert_screen_contains("Frame 1:");
}

#[test]
fn field_names_complete_in_the_filter_bar() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/tcp.srcpo");
    assert!(h.app.filter.has_completions());
    h.assert_screen_contains("tcp.srcport");
    h.assert_screen_contains("Source Port");
    h.key(KeyCode::Tab);
    assert_eq!(h.app.filter.input.text(), "tcp.srcport");
    assert!(!h.app.filter.has_completions());
    h.keys(" == 40000 && ip.ds");
    h.key(KeyCode::Down);
    h.key(KeyCode::Enter);
    assert_eq!(
        h.app.filter.input.text(),
        "tcp.srcport == 40000 && ip.dst",
        "shortest match first"
    );
    assert_eq!(
        h.app.focus,
        Focus::Filter,
        "Enter on a completion does not apply"
    );
    // Esc closes the popup first, then leaves.
    h.keys(".");
    if h.app.filter.has_completions() {
        h.key(KeyCode::Esc);
        assert_eq!(h.app.focus, Focus::Filter);
    }
    h.key(KeyCode::Esc);
    assert_eq!(h.app.focus, Focus::List);
}

#[test]
fn recent_filters_are_recalled_with_the_arrow_keys() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/dns\n/arp\n/");
    h.ctrl('u');
    h.key(KeyCode::Up);
    assert_eq!(h.app.filter.input.text(), "arp");
    h.key(KeyCode::Up);
    assert_eq!(h.app.filter.input.text(), "dns");
    h.key(KeyCode::Enter);
    assert_eq!(h.app.filter.applied, "dns");
}

#[test]
fn slash_starts_a_new_filter_but_arrows_edit_the_old_one() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/dns\n");
    // Typing after `/` replaces the old filter...
    h.keys("/arp\n");
    assert_eq!(h.app.filter.applied, "arp");
    // ...while moving the cursor first keeps it for editing.
    h.key(KeyCode::Char('/'));
    assert!(h.app.filter.select_all);
    h.key(KeyCode::End);
    assert!(!h.app.filter.select_all);
    h.keys(" || dns\n");
    assert_eq!(h.app.filter.applied, "arp || dns");
    assert!(h.line(1).contains("3 of 21 packets"));
    // Backspace on the selection clears it; Escape brings the applied filter back.
    h.key(KeyCode::Char('/'));
    h.key(KeyCode::Backspace);
    assert!(h.app.filter.input.is_empty());
    h.key(KeyCode::Esc);
    assert_eq!(h.app.filter.input.text(), "arp || dns");
    assert_eq!(h.app.filter.applied, "arp || dns");
}

#[test]
fn enter_pressed_before_validation_finishes_still_does_the_right_thing() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    // All keys arrive before sharkd has answered a single check.
    h.keys("/tcp.prt == 1\n");
    assert_eq!(
        h.app.filter.applied, "",
        "an invalid filter is never applied"
    );
    assert_eq!(h.app.focus, Focus::Filter);
    assert!(h.message().contains("Invalid filter"), "{}", h.message());
    assert!(h.app.list.error.is_none());
    assert!(h.line(1).contains("21 packets"));
    h.ctrl('u');
    h.keys("udp\n");
    assert_eq!(h.app.filter.applied, "udp");
    assert_eq!(h.app.focus, Focus::List);
    assert!(h.line(1).contains("2 of 21 packets"));
}

#[test]
fn a_filter_can_be_given_at_startup() {
    let options = Options {
        display_filter: "arp".into(),
        ..Default::default()
    };
    let Some(mut h) = Harness::open_with(&pcap::web(), 100, 30, options) else {
        return;
    };
    assert!(h.line(0).contains("arp"), "{}", h.line(0));
    assert!(h.line(1).contains("1 of 21 packets"), "{}", h.line(1));
    assert_eq!(selected_packet(&h), 12);
    h.assert_screen_contains("Address Resolution Protocol (request)");
}

// ---- find and go to --------------------------------------------------------

#[test]
fn find_accepts_filters_and_plain_text() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("sarp\n");
    assert_eq!(selected_packet(&h), 12, "a filter expression");
    h.keys("g");
    h.keys("sabout.html\n");
    assert_eq!(
        selected_packet(&h),
        16,
        "plain text falls back to a byte search"
    );
    // Only one packet contains it: the next search wraps back to it.
    h.keys("n");
    assert_eq!(selected_packet(&h), 16);
    assert!(h.message().contains("wrapped"), "{}", h.message());

    h.keys("shttp\n");
    assert_eq!(selected_packet(&h), 18);
    h.keys("n");
    assert_eq!(selected_packet(&h), 6, "wraps to the first HTTP packet");
    h.keys("N");
    assert_eq!(selected_packet(&h), 18, "and back again");
    h.keys("NN");
    assert_eq!(selected_packet(&h), 8);

    h.keys("szzz-not-there\n");
    assert!(h.message().contains("No packet matches"), "{}", h.message());
    assert_eq!(selected_packet(&h), 8, "the cursor stays put");
}

#[test]
fn find_only_visits_displayed_packets() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/tcp.port == 40001\n");
    h.keys("shttp\n");
    assert_eq!(selected_packet(&h), 16);
    h.keys("n");
    assert_eq!(selected_packet(&h), 18);
    h.keys("n");
    assert_eq!(selected_packet(&h), 16, "packets 6 and 8 are filtered out");
}

#[test]
fn n_without_a_search_says_what_to_do() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("n");
    assert!(h.message().contains("Press s to find"));
}

#[test]
fn go_to_packet_reports_what_it_cannot_do() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":8\n");
    assert_eq!(selected_packet(&h), 8);
    h.keys(":99\n");
    assert!(
        h.message().contains("There is no packet 99"),
        "{}",
        h.message()
    );
    assert_eq!(selected_packet(&h), 8);
    h.keys("/dns\n:8\n");
    assert!(
        h.message().contains("Packet 8 is hidden by the filter"),
        "{}",
        h.message()
    );
    assert_eq!(selected_packet(&h), 2);
}

// ---- details and bytes -----------------------------------------------------

#[test]
fn expanding_fields_and_highlighting_their_bytes() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("\tjj"); // details pane, IPv4 line
    assert!(selected_label(&h).starts_with("Internet Protocol Version 4"));
    assert_eq!(h.app.highlight(), Some((0, 14, 20)));
    let (hex_y, _) = h.find_line("0000  aa bb").unwrap();
    let highlight = h.app.theme.hex_highlight.bg;
    // Byte 14 (0x45) is the first IPv4 byte: row 0, column 14.
    let geometry = packetshark::ui::hex::Geometry::new(100, 71);
    assert_eq!(h.bg_at(geometry.hex_x(14), hex_y), highlight);
    assert_ne!(h.bg_at(geometry.hex_x(13), hex_y), highlight);
    assert_eq!(
        h.bg_at(geometry.ascii_x(14), hex_y),
        highlight,
        "ASCII column too"
    );
    assert_eq!(
        h.bg_at(geometry.hex_x(1), hex_y + 2),
        highlight,
        "byte 33, the last one"
    );
    assert_ne!(h.bg_at(geometry.hex_x(2), hex_y + 2), highlight);

    h.key(KeyCode::Char('l'));
    h.assert_screen_contains("0100 .... = Version: 4");
    h.key(KeyCode::Char('h'));
    h.assert_screen_lacks("0100 .... = Version: 4");

    // The open subtree stays open on the next packet.
    h.keys("l1j2");
    assert_eq!(selected_packet(&h), 2);
    h.assert_screen_contains("0100 .... = Version: 4");
    assert!(
        selected_label(&h).starts_with("Internet Protocol Version 4"),
        "same field selected"
    );
}

#[test]
fn expand_all_and_collapse_all() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.key(KeyCode::Char('2'));
    assert_eq!(h.app.tree.lines.len(), 5);
    h.key(KeyCode::Char('e'));
    assert!(
        h.app.tree.lines.len() > 40,
        "{} lines",
        h.app.tree.lines.len()
    );
    h.key(KeyCode::Char('G'));
    h.assert_screen_contains("Class: IN (0x0001)");
    h.key(KeyCode::Char('e'));
    assert_eq!(h.app.tree.lines.len(), 5);
    // `*` opens one subtree all the way down.
    h.keys("gjjjj*");
    let detail = h.app.detail.as_ref().unwrap();
    let labels: Vec<&str> = h
        .app
        .tree
        .lines
        .iter()
        .map(|l| detail.node(&l.path).unwrap().label.as_str())
        .collect();
    assert!(
        labels.contains(&"example.com: type A, class IN"),
        "{labels:?}"
    );
    assert!(labels.contains(&"Name: example.com"), "{labels:?}");
    assert!(
        !labels.iter().any(|l| l.starts_with("Source Port")),
        "only DNS was opened: {labels:?}"
    );
}

#[test]
fn packet_links_jump_to_the_referenced_packet() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":8\n");
    select_field(&mut h, "Request in frame: 6");
    h.key(KeyCode::Enter);
    assert_eq!(selected_packet(&h), 6);
    h.assert_screen_contains("GET /index.html HTTP/1.1");
}

#[test]
fn the_byte_cursor_selects_the_matching_field() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.key(KeyCode::Char('3'));
    assert_eq!(h.app.focus, Focus::Hex);
    // Byte 23 is the IPv4 protocol field.
    h.keys("jlllllll");
    assert_eq!(h.app.hex.cursor, 23);
    assert_eq!(selected_label(&h), "Protocol: UDP (17)");
    h.assert_screen_contains("offset 23 (0x0017)");
    h.assert_screen_contains("Protocol: UDP (17)");
    // The cursor stays where the user put it rather than snapping to the field start.
    h.keys("l");
    assert_eq!(h.app.hex.cursor, 24);
    assert!(
        selected_label(&h).starts_with("Header Checksum"),
        "{}",
        selected_label(&h)
    );
    h.key(KeyCode::Char('G'));
    assert_eq!(h.app.hex.cursor, 70);
    h.key(KeyCode::Char('g'));
    assert_eq!(h.app.hex.cursor, 0);
    h.keys("$");
    assert_eq!(h.app.hex.cursor, 15);
    h.keys("0");
    assert_eq!(h.app.hex.cursor, 0);
}

#[test]
fn reassembled_data_is_a_second_data_source() {
    let mut capture = pcap::Pcap::new();
    capture.http_split(40000, "example.com", "/big.txt", &"0123456789".repeat(8));
    let Some(mut h) = Harness::open(&capture) else {
        return;
    };
    h.keys(":6\n");
    let sources = h.app.detail.as_ref().unwrap().sources.len();
    assert_eq!(sources, 2, "frame plus reassembled TCP");
    h.assert_screen_contains("[1/2]");
    h.keys("3]");
    assert_eq!(h.app.hex.source, 1);
    h.assert_screen_contains("Reassembled TCP");
    h.assert_screen_contains("[2/2]");
    h.assert_screen_contains("0000  48 54 54 50 2f 31 2e 31"); // "HTTP/1.1"
    h.keys("]");
    assert_eq!(h.app.hex.source, 0);

    // Selecting a field that lives in the reassembled data switches to it.
    select_field(&mut h, "Content-Type: text/plain");
    assert_eq!(h.app.hex.source, 1);
    let (source, start, len) = h.app.highlight().unwrap();
    assert_eq!(source, 1);
    let bytes = &h.app.detail.as_ref().unwrap().sources[1].bytes[start..start + len];
    assert_eq!(bytes, b"Content-Type: text/plain\r\n");

    // A packet with one source says so.
    h.keys(":1\n");
    h.keys("3]");
    assert!(h.message().contains("only one data source"));
}

#[test]
fn a_field_can_be_applied_or_prepared_as_a_filter() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":6\n");
    select_field(&mut h, "Source Port: 40000");
    h.key(KeyCode::Char('a'));
    assert!(matches!(h.app.overlay, Some(Overlay::Menu(_))));
    h.assert_screen_contains("Apply as filter");
    h.assert_screen_contains("tcp.srcport == 40000");
    h.key(KeyCode::Char('s'));
    assert_eq!(h.app.filter.applied, "tcp.srcport == 40000");
    assert!(h.line(1).contains("5 of 21 packets"), "{}", h.line(1));
    assert_eq!(selected_packet(&h), 6);

    // With a filter in place there are and/or choices.
    select_field(&mut h, "Destination Port: 80");
    h.key(KeyCode::Char('a'));
    h.assert_screen_contains("… and not");
    h.key(KeyCode::Char('n'));
    assert_eq!(h.app.filter.applied, "!(tcp.dstport == 80)");

    // Prepare puts it in the bar without applying.
    h.keys("x:6\n");
    select_field(&mut h, "Source Port: 40000");
    h.keys("ps");
    assert_eq!(h.app.focus, Focus::Filter);
    assert_eq!(h.app.filter.input.text(), "tcp.srcport == 40000");
    assert_eq!(h.app.filter.applied, "");
    h.assert_screen_contains("Enter to apply");
    h.keys(" && http\n");
    assert_eq!(h.app.filter.applied, "tcp.srcport == 40000 && http");
    assert!(h.line(1).contains("1 of 21 packets"));
}

#[test]
fn fields_can_be_copied_to_the_clipboard() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":6\n");
    select_field(&mut h, "Source Port: 40000");
    h.keys("y");
    h.assert_screen_contains("Copy");
    h.keys("v");
    assert_eq!(h.app.clipboard, ["40000"]);
    assert!(h.message().contains("Copied value"));
    h.keys("yf");
    assert_eq!(h.app.clipboard[1], "tcp.srcport == 40000");
    h.keys("yn");
    assert_eq!(h.app.clipboard[2], "tcp.srcport");
    h.keys("yb");
    assert_eq!(h.app.clipboard[3], "9c40");
    h.keys("ys");
    assert!(
        h.app.clipboard[4].contains("GET /index.html HTTP/1.1"),
        "{}",
        h.app.clipboard[4]
    );
    h.keys("yh");
    assert!(
        h.app.clipboard[5].starts_with("00000000  aa bb cc dd ee 02"),
        "{}",
        h.app.clipboard[5]
    );

    // A protocol line has no single value to copy.
    select_field(&mut h, "Transmission Control Protocol, Src Port");
    h.keys("y");
    h.assert_screen_lacks("Value ");
    h.assert_screen_contains("Description");
    h.assert_screen_contains("Field bytes   20 bytes as hex");
}

// ---- follow stream ---------------------------------------------------------

#[test]
fn following_a_stream_shows_the_conversation() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":6\n");
    h.keys("F");
    // An HTTP packet can be followed as HTTP or TCP.
    h.assert_screen_contains("HTTP stream");
    h.assert_screen_contains("TCP stream");
    h.key(KeyCode::Char('t'));
    h.assert_screen_contains("Follow TCP stream");
    h.assert_screen_contains("client 10.0.0.2:40000 sent 74 B");
    h.assert_screen_contains("server 93.184.216.34:80 sent 101 B");
    h.assert_screen_contains("GET /index.html HTTP/1.1");
    h.assert_screen_contains("<html><body>hello world</body></html>");
    // Client and server lines are coloured differently.
    let (get_y, _) = h.find_line("GET /index.html").unwrap();
    let (ok_y, _) = h.find_line("HTTP/1.1 200 OK").unwrap();
    assert_eq!(h.style_at(2, get_y).fg, h.app.theme.client.fg);
    assert_eq!(h.style_at(2, ok_y).fg, h.app.theme.server.fg);

    h.key(KeyCode::Char('m'));
    h.assert_screen_contains("hex dump");
    h.assert_screen_contains("00000000  47 45 54 20 2f 69 6e 64");
    h.key(KeyCode::Char('d'));
    h.assert_screen_contains("client only");
    h.assert_screen_lacks("48 54 54 50 2f 31 2e 31  20 32 30 30");
    h.keys("dm");
    h.assert_screen_contains("server only");
    h.assert_screen_contains("raw hex");
    h.assert_screen_contains("485454502f312e3120323030");

    h.key(KeyCode::Char('f'));
    assert!(h.app.overlay.is_none());
    assert_eq!(h.app.filter.applied, "tcp.stream eq 0");
    assert!(h.line(1).contains("9 of 21 packets"));
}

#[test]
fn a_stream_can_be_saved_copied_and_navigated_from() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":16\n");
    h.keys(":follow tcp\n");
    h.assert_screen_contains("GET /about.html HTTP/1.1");
    h.key(KeyCode::Char('y'));
    assert!(h.app.clipboard[0].contains("GET /about.html HTTP/1.1\nHost: example.com"));

    let out = h.dir.path().join("stream.bin");
    h.key(KeyCode::Char('w'));
    h.assert_screen_contains("Save stream to: stream-tcp.bin");
    h.ctrl('u');
    h.keys(&format!("{}\n", out.display()));
    assert!(h.message().starts_with("Saved"), "{}", h.message());
    let saved = std::fs::read(&out).unwrap();
    assert!(saved.starts_with(b"GET /about.html HTTP/1.1\r\n"));
    assert!(saved.ends_with(b"<html><body>about us</body></html>"));

    // Enter goes to the packet shown at the top of the view.
    h.keys("dd"); // server side only, so its first line is on top
    h.key(KeyCode::Enter);
    assert!(h.app.overlay.is_none());
    assert_eq!(selected_packet(&h), 18, "the response packet");
}

#[test]
fn follow_reports_packets_without_a_stream() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":12\n"); // ARP
    h.keys("F");
    assert!(h.app.overlay.is_none());
    assert!(
        h.message().contains("not part of a stream"),
        "{}",
        h.message()
    );
    h.keys(":1\n"); // DNS over UDP
    h.keys(":follow tcp\n");
    assert!(h.message().contains("no tcp stream"), "{}", h.message());
    h.keys(":follow udp\n");
    h.assert_screen_contains("Follow UDP stream");
}

// ---- statistics ------------------------------------------------------------

#[test]
fn conversations_can_be_browsed_sorted_and_used_as_filters() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":conv\n");
    h.assert_screen_contains("Conversations");
    h.assert_screen_contains("Address A");
    h.assert_screen_contains("Address B");
    h.assert_screen_contains("Duration");
    let (y, line) = h.find_line("40000").unwrap();
    assert!(
        line.contains("10.0.0.2") && line.contains("93.184.216.34") && line.contains("661 B"),
        "{line}"
    );
    assert!(h.line(y + 1).contains("40001"), "busiest first");
    h.assert_screen_contains("Bytes ▼");

    // Sort by the first column, then reverse.
    h.keys("oooooo");
    h.assert_screen_lacks("Bytes ▼");
    h.key(KeyCode::Char('r'));

    // Other protocols are a Tab away.
    h.key(KeyCode::Tab);
    h.assert_screen_contains("8.8.8.8");
    h.assert_screen_contains("5353");
    h.key(KeyCode::BackTab);
    h.key(KeyCode::BackTab);
    h.assert_screen_lacks("5353");

    h.keys(":conv tcp\n");
    h.key(KeyCode::Char('j'));
    h.key(KeyCode::Enter);
    assert!(h.app.overlay.is_none());
    assert!(
        h.app.filter.applied.contains("40001"),
        "{}",
        h.app.filter.applied
    );
    assert!(h.line(1).contains("9 of 21 packets"), "{}", h.line(1));
}

#[test]
fn statistics_can_be_limited_to_the_display_filter() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("/tcp.port == 40001\n:endpoints tcp\n");
    h.assert_screen_contains("all packets");
    h.assert_screen_contains("40000");
    h.key(KeyCode::Char('f'));
    h.assert_screen_contains("only packets matching: tcp.port == 40001");
    h.assert_screen_lacks("40000");
    h.assert_screen_contains("40001");
}

fn protocol_hierarchy(h: &mut Harness) {
    h.keys(":phs\n");
    h.assert_screen_contains("Protocol hierarchy");
    let (_, tcp) = h.find_line("tcp ").unwrap();
    assert!(tcp.contains("85.7") && tcp.contains("18"), "{tcp}");
    assert!(tcp.contains('█'), "share bar drawn: {tcp}");
    let (_, dns) = h.find_line("dns").unwrap();
    // Nested under udp, however many layers this Wireshark puts above it.
    let (_, udp) = h.find_line("udp ").unwrap();
    let indent = |line: &str| line.len() - line.trim_start().len();
    assert_eq!(indent(&dns), indent(&udp) + 2, "{udp:?} / {dns:?}");
    // Move down to the dns row, wherever this version puts it.
    let on_dns = |h: &Harness| match &h.app.overlay {
        Some(Overlay::Stats(view)) => {
            view.selected_row().and_then(|r| r.filter.as_deref()) == Some("dns")
        }
        _ => false,
    };
    for _ in 0..12 {
        if on_dns(h) {
            break;
        }
        h.keys("j");
    }
    assert!(on_dns(h), "no dns row:\n{}", h.screen());
    h.key(KeyCode::Enter);
    assert_eq!(h.app.filter.applied, "dns");
}

#[test]
fn protocol_hierarchy_and_expert_information() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    if h.app.wireshark_version() < Some((4, 2)) {
        // sharkd has no protocol hierarchy before 4.2, and the app says so.
        h.keys(":phs\n");
        assert!(
            h.message().contains("need Wireshark 4.2"),
            "{}",
            h.message()
        );
        assert!(h.app.overlay.is_none());
    } else {
        protocol_hierarchy(&mut h);
    }

    h.keys("x:expert\n");
    h.assert_screen_contains("Expert information");
    h.assert_screen_contains("Connection establish request (SYN): server port 80");
    h.assert_screen_contains("Sequence");
    let frame = match &h.app.overlay {
        Some(Overlay::Stats(view)) => view.selected_row().unwrap().frame.unwrap(),
        other => panic!("expected stats, got {other:?}"),
    };
    h.key(KeyCode::Enter);
    assert!(h.app.overlay.is_none());
    assert_eq!(selected_packet(&h), frame);
}

#[test]
fn protocol_statistics_trees() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":stat http\n");
    assert!(h.line(0).contains("HTTP / Packet Counter"), "{}", h.line(0));
    let (_, total) = h.find_line("Total HTTP Packets").unwrap();
    assert!(total.contains(" 4 "), "{total}");
    let (_, get) = h.find_line("GET").unwrap();
    assert!(
        get.starts_with("     GET"),
        "nested under requests: {get:?}"
    );
    h.assert_screen_contains("200 OK");
    h.assert_screen_lacks("5xx");
    h.assert_screen_lacks("Enter ");

    h.keys(":stat nope\n");
    assert!(
        h.message()
            .starts_with("No statistic matches `nope`. Available: "),
        "{}",
        h.message()
    );
    assert!(h.message().contains("http"), "{}", h.message());
    h.keys(":stat\n");
    assert!(
        h.message().starts_with("Usage: :stat <name>."),
        "{}",
        h.message()
    );
}

#[test]
fn objects_can_be_exported_without_trusting_their_names() {
    let mut capture = pcap::Pcap::new();
    capture.http(40000, "example.com", "/../../etc/passwd", "root:x:0:0");
    capture.http(40001, "example.com", "/index.html", "<html>hi</html>");
    let Some(mut h) = Harness::open(&capture) else {
        return;
    };
    h.app.download_dir = h.dir.path().join("out");
    std::fs::create_dir(&h.app.download_dir).unwrap();
    h.keys(":objects http\n");
    h.assert_screen_contains("Export objects");
    h.assert_screen_contains("text/html");
    h.assert_screen_contains("index.html");
    h.key(KeyCode::Enter);
    assert!(h.message().starts_with("Saved"), "{}", h.message());
    h.key(KeyCode::Char('j'));
    h.key(KeyCode::Enter);
    h.key(KeyCode::Enter); // same object again: a new name, not an overwrite

    let mut names: Vec<String> = std::fs::read_dir(&h.app.download_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["index-1.html", "index.html", "passwd"],
        "nothing escaped the directory"
    );
    assert_eq!(
        std::fs::read(h.app.download_dir.join("passwd")).unwrap(),
        b"root:x:0:0"
    );
    assert_eq!(
        std::fs::read(h.app.download_dir.join("index.html")).unwrap(),
        b"<html>hi</html>"
    );
}

#[test]
fn the_statistics_menu_opens_each_view() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    for (key, title) in [
        ('c', "Conversations"),
        ('e', "Endpoints"),
        ('h', "Protocol hierarchy"),
        ('x', "Expert information"),
        ('o', "Export objects"),
    ] {
        if key == 'h' && h.app.wireshark_version() < Some((4, 2)) {
            continue;
        }
        h.key(KeyCode::Char('S'));
        h.assert_screen_contains("Statistics");
        h.key(KeyCode::Char(key));
        assert!(h.line(0).contains(title), "{key}: {}", h.line(0));
        h.assert_screen_lacks("Computing…");
        h.key(KeyCode::Esc);
        assert!(h.app.overlay.is_none());
    }
    // Menus also work with the arrow keys and Enter.
    h.key(KeyCode::Char('S'));
    h.key(KeyCode::Down);
    h.key(KeyCode::Enter);
    assert!(h.line(0).contains("Endpoints"));
}

// ---- commands --------------------------------------------------------------

#[test]
fn displayed_packets_can_be_written_to_a_new_capture() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    let all = h.dir.path().join("all.pcap");
    h.keys(&format!(":write {}\n", all.display()));
    wait_for(&mut h, "unfiltered export", |h| {
        h.message().starts_with("Wrote")
    });
    assert_eq!(
        std::fs::read(&all).unwrap(),
        std::fs::read(&h.path).unwrap()
    );

    let dns = h.dir.path().join("dns.pcapng");
    h.keys("/dns\n");
    h.keys(&format!(":write {}\n", dns.display()));
    wait_for(&mut h, "filtered export", |h| {
        h.message().starts_with("Wrote") && h.message().contains("dns.pcapng")
    });
    assert!(h.message().contains("Wrote 2 packets"), "{}", h.message());

    // The written file is itself a capture with exactly the two DNS packets.
    h.keys(&format!("x:open {}\n", dns.display()));
    assert_eq!(h.app.frames(), 2);
    assert!(h.line(1).contains("2 packets"), "{}", h.line(1));
    h.assert_screen_contains("dns.pcapng");

    h.keys(&format!(":write {}\n", dns.display()));
    assert!(
        h.message()
            .contains("Cannot write over the capture that is open")
    );
}

#[test]
fn unknown_and_incomplete_commands_explain_themselves() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    for (command, expected) in [
        ("bogus", "Unknown command: bogus"),
        ("write", "Usage: :write <file>"),
        ("keylog", "Usage: :keylog <file>"),
        ("keylog /definitely/not/here", "is not a file"),
        ("open", "Usage: :open <file>"),
        ("open /definitely/not/here", "is not a file"),
        ("set", "Usage: :set"),
        ("layout diagonal", "Usage: :layout"),
        ("colors loud", "Usage: :colors"),
        ("stop", "No capture is running"),
    ] {
        h.keys(&format!(":{command}\n"));
        assert!(
            h.message().contains(expected),
            ":{command} said {:?}",
            h.message()
        );
        assert_eq!(h.app.load, LoadState::Ready);
    }
    // Escape and an emptied line both cancel the prompt.
    h.keys(":");
    assert!(h.app.prompt.is_some());
    h.key(KeyCode::Esc);
    assert!(h.app.prompt.is_none());
    h.keys(":a");
    h.key(KeyCode::Backspace);
    h.key(KeyCode::Backspace);
    assert!(h.app.prompt.is_none());
    h.keys(":quit\n");
    assert!(h.app.quit);
}

#[test]
fn a_preference_change_redissects_the_capture() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":3\n");
    assert!(
        h.line(FIRST_ROW + 2).contains("Seq=0"),
        "{}",
        h.line(FIRST_ROW + 2)
    );
    h.keys(":set tcp.relative_sequence_numbers FALSE\n");
    assert!(
        h.line(FIRST_ROW + 2).contains("Seq=1000"),
        "absolute numbers: {}",
        h.line(FIRST_ROW + 2)
    );
    assert_eq!(selected_packet(&h), 3, "the cursor stays where it was");
    h.keys(":set no.such.preference 1\n");
    assert!(
        h.message().contains("Could not set no.such.preference"),
        "{}",
        h.message()
    );
    assert_eq!(h.app.message.as_ref().unwrap().level, Level::Error);
}

#[test]
fn commands_work_from_inside_a_window() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":phs\n");
    h.keys(":conv udp\n");
    assert!(h.line(0).contains("Conversations"), "{}", h.line(0));
    h.assert_screen_contains("5353");
    h.keys(":8\n");
    assert!(
        h.app.overlay.is_none(),
        "going to a packet closes the window"
    );
    assert_eq!(selected_packet(&h), 8);
    h.keys("?");
    h.keys(":expert\n");
    assert!(h.line(0).contains("Expert information"));
}

#[test]
fn actions_on_a_packet_wait_for_it_to_load() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    // The cursor moves and F arrives before packet 6 has been dissected.
    h.keys(":6\nF");
    assert!(
        h.app.overlay.is_none(),
        "did not follow the previous packet's stream"
    );
    assert!(h.message().contains("still loading"), "{}", h.message());
    h.keys("F");
    h.assert_screen_contains("HTTP stream");
}

#[test]
fn help_lists_keys_and_scrolls() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.key(KeyCode::Char('?'));
    h.assert_screen_contains("Edit the display filter");
    h.assert_screen_lacks("Decrypt TLS with a key log file");
    h.key(KeyCode::Char('G'));
    h.assert_screen_contains(":keylog <file>");
    h.assert_screen_contains(":quit");
    h.key(KeyCode::Char('?'));
    assert!(h.app.overlay.is_none());
    h.keys(":help\n");
    assert!(matches!(h.app.overlay, Some(Overlay::Help { .. })));
}

// ---- mouse -----------------------------------------------------------------

#[test]
fn the_mouse_selects_scrolls_and_focuses() {
    let Some(mut h) = Harness::open(&pcap::many(300)) else {
        return;
    };
    h.click(20, FIRST_ROW + 4);
    assert_eq!(selected_packet(&h), 5);
    h.mouse(MouseEventKind::ScrollDown, 20, FIRST_ROW + 2);
    assert_eq!(h.app.list.top, 3);
    assert_eq!(
        selected_packet(&h),
        5,
        "still on screen, so it stays selected"
    );
    h.mouse(MouseEventKind::ScrollDown, 20, FIRST_ROW + 2);
    h.mouse(MouseEventKind::ScrollDown, 20, FIRST_ROW + 2);
    assert_eq!(h.app.list.top, 9);
    assert_eq!(selected_packet(&h), 10, "dragged along with the view");
    h.mouse(MouseEventKind::ScrollUp, 20, FIRST_ROW + 2);
    assert_eq!(h.app.list.top, 6);

    // Clicking a details line selects it; clicking it again expands it.
    let (tree_y, _) = h.find_line("User Datagram Protocol").unwrap();
    h.click(10, tree_y);
    assert_eq!(h.app.focus, Focus::Tree);
    assert!(selected_label(&h).starts_with("User Datagram Protocol"));
    h.click(10, tree_y);
    h.assert_screen_contains("Source Port:");

    // Clicking a byte puts the cursor there and selects its field.
    let (hex_y, _) = h.find_line("0000  aa bb").unwrap();
    let geometry = packetshark::ui::hex::Geometry::new(100, 60);
    h.click(geometry.hex_x(12), hex_y);
    assert_eq!(h.app.focus, Focus::Hex);
    assert_eq!(h.app.hex.cursor, 12);
    assert!(
        selected_label(&h).starts_with("Type: IPv4"),
        "{}",
        selected_label(&h)
    );
    h.click(geometry.ascii_x(3), hex_y);
    assert_eq!(h.app.hex.cursor, 3);

    h.click(30, 0);
    assert_eq!(h.app.focus, Focus::Filter);
    h.click(20, FIRST_ROW);
    assert_eq!(h.app.focus, Focus::List);
}

// ---- growing captures and recovery -----------------------------------------

#[test]
fn a_growing_capture_is_followed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pcap");
    std::fs::write(&path, b"").unwrap();
    let options = Options {
        tail: true,
        ..Default::default()
    };
    let Some(mut h) = Harness::start(dir, path.clone(), 100, 30, options) else {
        return;
    };
    h.settle();
    h.assert_screen_contains("Waiting for packets…");
    h.assert_screen_contains("following file");

    // The capture arrives in pieces, the last record cut in half at first.
    let full = pcap::many(40).bytes();
    let first_cut = 24 + 16 * 10 + 630; // header, ten whole records, part of the next
    std::fs::write(&path, &full[..first_cut]).unwrap();
    wait_for(&mut h, "first packets", |h| h.app.frames() >= 10);
    let seen = h.app.frames();
    assert!(
        (10..=12).contains(&seen),
        "only complete packets are shown, got {seen}"
    );
    assert_eq!(
        selected_packet(&h),
        seen,
        "the cursor follows the newest packet"
    );
    assert!(
        h.app.message.is_none(),
        "a truncated tail is not worth a warning: {}",
        h.message()
    );

    std::fs::write(&path, &full).unwrap();
    wait_for(&mut h, "all packets", |h| h.app.frames() == 40);
    assert_eq!(selected_packet(&h), 40);
    h.assert_screen_contains("Frame 40:");

    // Once the user scrolls up, new packets no longer move the cursor.
    h.keys("gjj");
    let mut more = pcap::many(40);
    more.dns("late.example", pcap::SERVER);
    std::fs::write(&path, more.bytes()).unwrap();
    wait_for(&mut h, "late packets", |h| h.app.frames() == 42);
    assert_eq!(selected_packet(&h), 3);
    assert!(h.line(1).contains("42 packets"));
    h.key(KeyCode::Char('G'));
    h.assert_screen_contains("late.example");
}

#[test]
fn a_filtered_view_keeps_up_with_a_growing_capture() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pcap");
    let mut capture = pcap::web();
    capture.write(&path);
    let options = Options {
        tail: true,
        display_filter: "dns".into(),
        ..Default::default()
    };
    let Some(mut h) = Harness::start(dir, path.clone(), 100, 30, options) else {
        return;
    };
    wait_for(&mut h, "initial load", |h| h.app.list.total == Some(2));
    capture.dns("second.example", pcap::SERVER);
    capture.write(&path);
    wait_for(&mut h, "new dns packets", |h| h.app.list.total == Some(4));
    assert!(h.line(1).contains("4 of 23 packets"), "{}", h.line(1));
    h.assert_screen_contains("second.example");
}

#[test]
fn a_followed_file_that_is_not_a_capture_waits_quietly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pcap");
    std::fs::write(&path, b"these are notes, not packets\n").unwrap();
    let options = Options {
        tail: true,
        ..Default::default()
    };
    let Some(mut h) = Harness::start(dir, path.clone(), 100, 30, options) else {
        return;
    };
    wait_for(&mut h, "the first attempt", |h| {
        h.app.tail.as_ref().is_some_and(|t| t.error.is_some())
    });
    // It is not retried until the file changes: many ticks later, sharkd has
    // nothing queued and the reason is on screen.
    for _ in 0..30 {
        h.app.handle(Event::Tick);
    }
    assert!(
        !h.app.busy(),
        "the unchanged file is being reloaded in a loop"
    );
    assert_eq!(h.app.load, LoadState::Loading);
    let screen: String = h.screen().split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        screen.contains("Waiting for packets… (not readable yet: Unable to open the file)"),
        "{screen}"
    );

    // When a real capture replaces it, it loads.
    pcap::web().write(&path);
    wait_for(&mut h, "the capture", |h| h.app.frames() == 21);
    assert!(h.app.tail.as_ref().unwrap().error.is_none());
}

#[test]
fn a_pipe_that_carried_no_capture_is_reported_when_it_ends() {
    let capture = packetshark::capture::Capture::from_reader(std::io::Cursor::new(
        b"hello, not a capture\n".to_vec(),
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let options = Options {
        tail: true,
        ..Default::default()
    };
    let Some(mut h) = Harness::start(dir, capture.path().to_path_buf(), 100, 30, options) else {
        return;
    };
    h.app.title = "stdin".into();
    h.app.attach_capture(capture);
    wait_for(&mut h, "the failure", |h| {
        matches!(h.app.load, LoadState::Failed(_))
    });
    assert_eq!(
        h.app.startup_failure(),
        Some("stdin: Unable to open the file")
    );
}

#[test]
fn a_refresh_during_a_slow_count_does_not_strand_the_list() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    // The filter's count is still running when the time format changes.
    h.keys("/udp\nt");
    let total = h.app.list.total;
    assert_eq!(
        total,
        Some(2),
        "stuck counting:
{}",
        h.screen()
    );
    assert!(h.line(1).contains("2 of 21 packets"), "{}", h.line(1));
    h.keys("x/tcp\n");
    h.app.handle(Event::Key(crossterm::event::KeyEvent::new(
        KeyCode::Char('t'),
        crossterm::event::KeyModifiers::CONTROL,
    )));
    h.settle();
    assert_eq!(h.app.list.total, Some(18));
}

#[test]
fn search_keeps_working_after_the_list_is_refreshed_mid_search() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys("shttp\n");
    assert_eq!(selected_packet(&h), 6);
    // `n` is in flight when `t` refreshes the list, so its answer is dropped.
    h.keys("nt");
    let after = selected_packet(&h);
    // The search is not left waiting for that answer.
    h.keys("n");
    let now = selected_packet(&h);
    assert_ne!(
        now,
        after,
        "search is dead:
{}",
        h.screen()
    );
    h.keys("n");
    h.keys("N");
    assert!([6, 8, 16, 18].contains(&selected_packet(&h)));
}

#[test]
fn a_failed_open_keeps_the_current_capture() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":8\n");
    h.keys("M");
    let notes = h.dir.path().join("notes.bin");
    std::fs::write(&notes, b"this is not a capture file at all\n").unwrap();
    h.keys(&format!(":open {}\n", notes.display()));
    assert!(
        h.message().starts_with("Could not open notes.bin:"),
        "{}",
        h.message()
    );
    assert_eq!(h.app.load, LoadState::Ready);
    assert!(
        h.app.startup_failure().is_none(),
        "the program must not exit"
    );
    assert_eq!(
        h.app.frames(),
        21,
        "the capture that was open is still open"
    );
    assert_eq!(selected_packet(&h), 9);
    assert_eq!(h.app.marks.len(), 1);
    h.keys("k");
    h.assert_screen_contains("Frame 8:");

    // A good file replaces it, and starts clean.
    let other = h.dir.path().join("other.pcap");
    pcap::many(7).write(&other);
    h.keys(&format!(":open {}\n", other.display()));
    assert_eq!(h.app.frames(), 7);
    assert!(h.app.marks.is_empty());
    assert_eq!(selected_packet(&h), 1);
    h.assert_screen_contains("other.pcap");
    h.assert_screen_contains("7 packets");
    // Reload now refers to the new file.
    h.ctrl('r');
    assert_eq!(h.app.frames(), 7);
}

#[test]
fn reload_picks_up_a_changed_file() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.keys(":8\n");
    let mut bigger = pcap::web();
    bigger.dns("more.example", pcap::SERVER);
    bigger.write(&h.path);
    h.ctrl('r');
    assert_eq!(h.app.frames(), 23);
    assert!(h.line(1).contains("23 packets"));
    assert_eq!(selected_packet(&h), 8, "the cursor stays on its packet");
    h.keys(":reload\n");
    assert_eq!(h.app.frames(), 23);
}

#[cfg(unix)]
#[test]
fn sharkd_is_restarted_if_it_dies() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    // Find our sharkd child and kill it, as a crash on a malformed packet would.
    let before = h.app.sharkd_pid();
    // SAFETY: signalling a process this test started.
    unsafe {
        libc::kill(before as libc::pid_t, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(100));

    h.keys("j");
    assert!(h.message().contains("was restarted"), "{}", h.message());
    // The capture was reloaded into the new sharkd and everything works again.
    h.keys("j");
    assert_eq!(selected_packet(&h), 3);
    h.assert_screen_contains("Frame 3:");
    h.keys("/dns\n");
    assert!(h.line(1).contains("2 of 21 packets"), "{}", h.line(1));
    assert_ne!(h.app.sharkd_pid(), before, "a new sharkd process is in use");
}

#[test]
fn keys_typed_before_the_capture_opens_are_not_lost() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pcap");
    pcap::web().write(&path);
    let Some(mut h) = Harness::start(dir, path, 100, 30, Options::default()) else {
        return;
    };
    // Typed at once, before sharkd has answered anything: filter, go to the
    // last match, open its details and expand the DNS layer.
    h.keys("/dns\nG\njjjjl");
    assert!(h.line(1).contains("2 of"), "{}", h.line(1));
    assert_eq!(h.app.list.selected_num(), Some(2));
    assert_eq!(h.app.focus, Focus::Tree);
    h.assert_screen_contains("Transaction ID");
}

#[test]
fn q_quits_while_the_capture_is_still_opening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pcap");
    pcap::web().write(&path);
    let Some(mut h) = Harness::start(dir, path, 100, 30, Options::default()) else {
        return;
    };
    h.app.handle(Event::Key(crossterm::event::KeyEvent::new(
        KeyCode::Char('q'),
        crossterm::event::KeyModifiers::NONE,
    )));
    assert!(h.app.quit);
}

#[test]
fn a_window_hides_the_colours_of_the_rows_beneath_it() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    // The packet rows are coloured by Wireshark's rules.
    let coloured = (2..12).any(|y| h.bg_at(10, y) != Some(Color::Reset));
    assert!(coloured, "expected coloured packet rows:\n{}", h.screen());
    h.keys("jj");
    h.key(KeyCode::Char('F'));
    h.key(KeyCode::Char('t'));
    h.assert_screen_contains("Follow TCP stream");
    for y in 1..28 {
        for x in 0..100 {
            assert_eq!(
                h.bg_at(x, y),
                Some(Color::Reset),
                "background showing through at {x},{y}:\n{}",
                h.screen()
            );
        }
    }
}

#[test]
fn ascii_mode_draws_nothing_outside_ascii() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    h.app.theme.ascii = true;
    h.key(KeyCode::Enter);
    h.keys("jjl");
    h.key(KeyCode::Char('S'));
    let screen = h.screen();
    assert!(screen.is_ascii(), "non-ASCII on screen:\n{screen}");
    // The shapes are still there in their plain form.
    assert!(screen.contains("- Packets -"), "{screen}");
    assert!(screen.contains("+- Statistics -"), "{screen}");
    assert!(screen.contains("> Frame 1"), "{screen}");
}

#[test]
fn columns_can_be_added_and_removed() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    assert!(!h.line(2).contains("Stream"), "{}", h.line(2));
    assert!(!h.app.columns_customised());
    h.keys(":column tcp.stream Stream\n");
    assert!(
        h.message().contains("Added column Stream"),
        "{}",
        h.message()
    );
    let header = h.line(2);
    assert!(
        header.find("Stream").unwrap() < header.find("Info").unwrap(),
        "the new column goes before Info: {header}"
    );
    // The first TCP packet is in stream 0; the DNS packets have no value.
    let screen = h.screen();
    let Some((_, syn)) = h.find_line("40000 → 80") else {
        panic!("no TCP row:\n{screen}");
    };
    assert!(syn.contains(" 0 "), "{syn}");
    // It survives a reload and a filter change.
    h.ctrl('r');
    h.keys("/tcp\n");
    assert!(h.line(2).contains("Stream"), "{}", h.line(2));

    // A second one, from the selected field in the details pane.
    h.key(KeyCode::Enter);
    h.keys("jjl");
    h.keys("zjjjjjjjj");
    let screen = h.screen();
    let Some((y, _)) = h.find_line("Time to Live") else {
        panic!("no TTL line:\n{screen}");
    };
    h.click(5, y);
    h.keys("z");
    h.key(KeyCode::Char('C'));
    assert!(
        h.message().contains("Added column ip.ttl"),
        "{}",
        h.message()
    );
    assert!(h.line(2).contains("ip.ttl"), "{}", h.line(2));

    // Adding it twice, or adding nonsense, changes nothing.
    let before = h.app.column_list().len();
    h.keys(":column ip.ttl\n");
    assert!(h.message().contains("already"), "{}", h.message());
    h.keys(":column no.such.field\n");
    assert!(h.message().contains("No column added"), "{}", h.message());
    assert_eq!(h.app.column_list().len(), before);

    // Any column can be removed, the profile's own included.
    h.keys(":column remove Stream\n");
    assert!(!h.line(2).contains("Stream"), "{}", h.line(2));
    assert!(h.line(2).contains("ip.ttl"), "{}", h.line(2));
    h.keys(":column remove Length\n");
    assert!(!h.line(2).contains("Length"), "{}", h.line(2));
    h.keys(":column remove Nonsense\n");
    assert!(
        h.message().contains("no column called Nonsense"),
        "{}",
        h.message()
    );
    // ... and one command puts the Wireshark profile's columns back.
    h.keys(":column reset\n");
    assert!(!h.app.columns_customised());
    assert!(
        h.line(2).contains("Length") && !h.line(2).contains("ip.ttl"),
        "{}",
        h.line(2)
    );
    h.assert_screen_contains("40000 → 80");
}

#[test]
fn the_column_editor_arranges_columns_and_remembers_them() {
    use packetshark::config::Store;
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::at(scratch.path().join("state.toml"));
    let options = || Options {
        store: store.clone(),
        ..Default::default()
    };
    let Some(mut h) = Harness::open_with(&pcap::web(), 110, 30, options()) else {
        return;
    };
    let titles = |h: &Harness| -> Vec<String> {
        h.app
            .column_list()
            .iter()
            .filter(|c| c.visible)
            .map(|c| c.title.clone())
            .collect()
    };
    assert_eq!(
        titles(&h),
        [
            "No.",
            "Time",
            "Source",
            "Destination",
            "Protocol",
            "Length",
            "Info"
        ]
    );

    h.keys(":columns\n");
    h.assert_screen_contains("Columns (from the Wireshark profile)");
    h.assert_screen_contains("[x] Protocol");
    // Hide Time (the second row).
    h.keys("j ");
    h.assert_screen_contains("[ ] Time");
    assert!(!h.line(2).contains("Time"), "hidden at once: {}", h.line(2));
    // Move Source below Destination.
    h.keys("jJ");
    // Rename Protocol, the row after the one that just moved.
    h.keys("j");
    h.key(KeyCode::Char('r'));
    h.ctrl('u');
    h.keys("Proto\n");
    // Add a field, with a title, and a built-in type from the list.
    h.key(KeyCode::Char('a'));
    h.keys("ip.ttl TTL\n");
    h.assert_screen_contains("[x] TTL");
    h.key(KeyCode::Char('b'));
    h.assert_screen_contains("Delta time");
    h.keys("c");
    h.assert_screen_contains("[x] Delta time");
    // Delete Length.
    h.keys("g");
    for _ in 0..12 {
        let on_length = match &h.app.overlay {
            Some(Overlay::Columns(e)) => h.app.column_list()[e.selected].title == "Length",
            _ => panic!("the editor closed:\n{}", h.screen()),
        };
        if on_length {
            break;
        }
        h.keys("j");
    }
    h.keys("d");
    h.key(KeyCode::Esc);
    assert!(h.app.overlay.is_none());

    let wanted = [
        "No.",
        "Destination",
        "Source",
        "Proto",
        "TTL",
        "Delta time",
        "Info",
    ];
    assert_eq!(titles(&h), wanted);
    let header = h.line(2);
    let mut last = 0;
    for title in wanted {
        let at = header[last..]
            .find(title)
            .unwrap_or_else(|| panic!("{title} in {header}"));
        last += at;
    }
    // The rows follow the new order: destination first, then source.
    let (_, row) = h.find_line("40000 → 80").unwrap();
    assert!(
        row.find("93.184.216.34").unwrap() < row.find("10.0.0.2").unwrap(),
        "{row}"
    );

    // The last visible column cannot be hidden or deleted.
    h.keys(":columns\n");
    for _ in 0..8 {
        h.keys("gd");
    }
    assert_eq!(titles(&h).len(), 1, "{}", h.screen());
    assert!(
        h.message().contains("At least one column"),
        "{}",
        h.message()
    );
    h.keys(" ");
    assert_eq!(titles(&h).len(), 1);
    // Put the arrangement back for the restart check below.
    h.keys("R");
    h.assert_screen_contains("Columns (from the Wireshark profile)");
    h.keys("j ");
    h.key(KeyCode::Esc);
    drop(h);

    // A new run starts with the arrangement.
    let Some(mut h) = Harness::open_with(&pcap::web(), 110, 30, options()) else {
        return;
    };
    assert!(h.app.columns_customised());
    assert_eq!(
        titles(&h),
        ["No.", "Source", "Destination", "Protocol", "Length", "Info"]
    );
    assert!(!h.line(2).contains("Time"), "{}", h.line(2));
    h.assert_screen_contains("40000 → 80");
}

#[test]
fn expert_information_groups_messages_and_leads_to_their_packets() {
    // One connection: one SYN, and a FIN from each side.
    let mut capture = pcap::Pcap::new();
    capture.http(40000, "example.com", "/index.html", "hello world");
    let Some(mut h) = Harness::open(&capture) else {
        return;
    };
    let total = h.app.frames();
    h.keys(":expert\n");
    h.assert_screen_contains("Expert information");
    let (_, header) = h.find_line("Severity").unwrap();
    assert!(
        header.contains("Count") && header.contains("First"),
        "{header}"
    );
    // The two FINs of the connection are one line with a count of two.
    let screen = h.screen();
    assert_eq!(
        screen.matches("Connection finish (FIN)").count(),
        1,
        "{screen}"
    );
    let select = |h: &mut Harness, message: &str| {
        for _ in 0..12 {
            let on_it = match &h.app.overlay {
                Some(Overlay::Stats(view)) => view
                    .selected_row()
                    .is_some_and(|r| r.cells.last().is_some_and(|c| c == message)),
                _ => false,
            };
            if on_it {
                return;
            }
            h.keys("j");
        }
        panic!("no row for {message}:\n{}", h.screen());
    };

    // Enter on a message seen several times lists the packets that carry it.
    select(&mut h, "Connection finish (FIN)");
    let count: u32 = match &h.app.overlay {
        Some(Overlay::Stats(view)) => view.selected_row().unwrap().cells[3].parse().unwrap(),
        _ => unreachable!(),
    };
    assert_eq!(count, 2, "a FIN from each side");
    h.key(KeyCode::Enter);
    assert_eq!(
        h.app.filter.applied,
        r#"_ws.expert.message == "Connection finish (FIN)""#
    );
    let wanted = format!("{count} of {total} packets");
    assert!(h.line(1).contains(&wanted), "{}", h.line(1));

    // Enter on one seen once goes straight to its packet.
    h.keys("x:expert\n");
    select(&mut h, "Connection establish request (SYN): server port 80");
    let first = match &h.app.overlay {
        Some(Overlay::Stats(view)) => view.selected_row().unwrap().frame.unwrap(),
        _ => unreachable!(),
    };
    h.key(KeyCode::Enter);
    assert!(h.app.overlay.is_none());
    assert_eq!(h.app.filter.applied, "");
    assert_eq!(h.app.list.selected_num(), Some(first));
}

#[test]
fn a_theme_can_be_chosen_and_is_remembered() {
    use packetshark::config::Store;
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::at(scratch.path().join("state.toml"));
    let themes = scratch.path().join("themes");
    std::fs::create_dir_all(&themes).unwrap();
    std::fs::write(
        themes.join("mine.toml"),
        "[styles]\ntext = { fg = \"#102030\", bg = \"#f0e0d0\" }\n",
    )
    .unwrap();
    let options = || Options {
        store: store.clone(),
        themes_dir: Some(themes.clone()),
        ..Default::default()
    };
    let Some(mut h) = Harness::open_with(&pcap::web(), 100, 30, options()) else {
        return;
    };
    assert_eq!(h.app.theme_name(), "default");
    // An empty corner of the screen is in the terminal's own colours.
    assert_eq!(h.bg_at(99, 0), Some(Color::Reset));

    // A built-in theme paints the whole screen, corners included.
    h.keys(":theme dracula\n");
    assert_eq!(h.app.theme_name(), "dracula");
    let background = Color::Rgb(0x28, 0x2a, 0x36);
    assert_eq!(h.bg_at(99, 0), Some(background));
    assert_eq!(
        h.bg_at(50, 29),
        Some(Color::Rgb(0x34, 0x37, 0x46)),
        "status bar"
    );
    // ... and so do windows drawn over it.
    h.keys(":expert\n");
    assert_eq!(h.bg_at(99, 10), Some(background));
    h.key(KeyCode::Esc);

    // The chooser lists built-in and user themes, and marks the one in use.
    h.keys(":theme\n");
    h.assert_screen_contains("dracula  (in use)");
    h.assert_screen_contains("solarized-light");
    h.assert_screen_contains("mine");
    h.key(KeyCode::Esc);
    h.keys(":theme mine\n");
    assert_eq!(h.bg_at(99, 0), Some(Color::Rgb(0xf0, 0xe0, 0xd0)));

    // A mistake changes nothing and says why.
    h.keys(":theme nope\n");
    assert!(
        h.message().contains("no theme called nope"),
        "{}",
        h.message()
    );
    assert_eq!(h.app.theme_name(), "mine");

    // The next run starts with the theme that was chosen.
    drop(h);
    let Some(mut h) = Harness::open_with(&pcap::web(), 100, 30, options()) else {
        return;
    };
    assert_eq!(h.app.theme_name(), "mine");
    h.keys(":no-theme\n");
    assert_eq!(h.bg_at(99, 0), Some(Color::Reset));
    drop(h);
    let Some(h) = Harness::open_with(&pcap::web(), 100, 30, options()) else {
        return;
    };
    assert_eq!(h.app.theme_name(), "default");
}

#[test]
fn the_command_line_completes_commands_arguments_and_paths() {
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    let typed = |h: &Harness| {
        h.app
            .prompt
            .as_ref()
            .map(|p| p.input.text())
            .unwrap_or_default()
    };

    // Nothing is offered until asked; Tab on an empty line lists everything.
    h.keys(":");
    h.assert_screen_lacks("Arrange the columns");
    h.key(KeyCode::Tab);
    h.assert_screen_contains("Clear the display filter");
    h.assert_screen_contains("Packet row colours");
    assert_eq!(typed(&h), "clear", "the first candidate is taken");
    h.key(KeyCode::Tab);
    assert_eq!(typed(&h), "colors", "and Tab steps on to the next");
    h.key(KeyCode::BackTab);
    assert_eq!(typed(&h), "clear");
    h.key(KeyCode::Esc);

    // Typing narrows the list; a single match is completed with its space.
    h.keys(":th");
    h.assert_screen_contains("Choose a colour theme");
    h.assert_screen_lacks("Clear the display filter");
    h.key(KeyCode::Tab);
    assert_eq!(typed(&h), "theme ");
    // ... and then its arguments are offered.
    h.assert_screen_contains("solarized-light");
    h.keys("no");
    h.key(KeyCode::Tab);
    assert_eq!(typed(&h), "theme nord ");
    h.key(KeyCode::Enter);
    assert_eq!(h.app.theme_name(), "nord");

    // Arguments that depend on what is open.
    h.keys(":column remove Pro");
    h.key(KeyCode::Tab);
    assert_eq!(typed(&h), "column remove Protocol ");
    h.key(KeyCode::Esc);
    h.keys(":layout s");
    h.assert_screen_contains("stacked");
    h.assert_screen_contains("side");
    h.key(KeyCode::Esc);

    // File names, and into a directory.
    let dir = h.dir.path().to_path_buf();
    std::fs::create_dir(dir.join("captures")).unwrap();
    std::fs::write(dir.join("captures").join("other.pcap"), pcap::web().bytes()).unwrap();
    h.keys(&format!(":open {}/cap", dir.display()));
    h.key(KeyCode::Tab);
    assert_eq!(typed(&h), format!("open {}/captures/", dir.display()));
    h.key(KeyCode::Tab);
    assert_eq!(
        typed(&h),
        format!("open {}/captures/other.pcap ", dir.display())
    );
    h.key(KeyCode::Enter);
    assert_eq!(h.app.title, "other.pcap");
}

#[test]
fn every_listed_command_is_one_the_program_knows() {
    use packetshark::app::cmdline::COMMANDS;
    let Some(mut h) = Harness::open(&pcap::web()) else {
        return;
    };
    for command in COMMANDS {
        h.keys(&format!(":{}\n", command.name));
        assert!(
            !h.message().contains("Unknown command"),
            ":{} is listed but not handled",
            command.name
        );
        // Leave whatever it opened, and undo a quit.
        h.key(KeyCode::Esc);
        h.key(KeyCode::Esc);
        h.app.quit = false;
    }
    // And the other way round: the help mentions no command that is not listed.
    for section in packetshark::app::help::SECTIONS {
        for (keys, _) in section.keys {
            let Some(rest) = keys.strip_prefix(':') else {
                continue;
            };
            let name = rest.split_whitespace().next().unwrap_or("");
            if name.is_empty() || name.starts_with('<') || name.chars().all(|c| c.is_ascii_digit())
            {
                continue;
            }
            assert!(
                COMMANDS.iter().any(|c| c.name == name),
                "the help lists :{name}, which completion does not know"
            );
        }
    }
}

#[test]
fn marks_counts_and_the_way_back() {
    use packetshark::config::Store;
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::at(scratch.path().join("state.toml"));
    let options = Options {
        store: store.clone(),
        ..Default::default()
    };
    // The capture lives in a directory that outlasts this run of the app,
    // for the mark that is used from a later one.
    let capture = scratch.path().join("first.pcap");
    pcap::web().write(&capture);
    let Some(mut h) = Harness::start(tempfile::tempdir().unwrap(), capture, 100, 30, options)
    else {
        return;
    };
    h.settle();
    let at = |h: &Harness| h.app.list.selected_num().unwrap();

    // A count names the row to go to.
    h.keys("12G");
    assert_eq!(at(&h), 12);
    assert_eq!(
        h.app.focus,
        Focus::List,
        "the 1 of 12 did not leave the list"
    );
    h.keys("k");
    assert_eq!(at(&h), 11);
    h.keys("5gg");
    assert_eq!(at(&h), 5);
    h.keys("gg");
    assert_eq!(at(&h), 1);
    h.keys("999G");
    assert_eq!(at(&h), 21, "a count past the end stops at the end");
    // A digit on its own, or before anything but G, is still a pane key.
    h.keys("2");
    assert_eq!(h.app.focus, Focus::Tree);
    h.keys("1j");
    assert_eq!(h.app.focus, Focus::List);
    assert_eq!(at(&h), 21, "j at the last row stays there");
    // In the details pane a count is a line of the tree. The 2 pressed to
    // get there is long past by the time the count is typed.
    h.keys("2");
    std::thread::sleep(Duration::from_millis(1100));
    h.keys("3G");
    assert_eq!(h.app.focus, Focus::Tree);
    h.keys("1");

    // Marks, and the way back.
    h.keys(":4\n");
    h.keys("ma");
    assert!(
        h.message().contains("Mark a is packet 4"),
        "{}",
        h.message()
    );
    h.keys(":15\n");
    h.keys("mb");
    h.keys("'a");
    assert_eq!(at(&h), 4);
    h.keys("''");
    assert_eq!(at(&h), 15, "back to where the jump started");
    h.keys("''");
    assert_eq!(at(&h), 4, "and '' again swaps the two");
    h.keys("'q");
    assert!(h.message().contains("Mark q is not set"), "{}", h.message());
    // A mark also works under a filter that still shows its packet.
    h.keys("/tcp\n");
    h.keys("'b");
    assert_eq!(at(&h), 15);
    h.keys("x");

    // The list of marks, and choosing from it.
    h.keys(":marks\n");
    h.assert_screen_contains("packet 4");
    h.assert_screen_contains("packet 15");
    h.keys("a");
    assert_eq!(at(&h), 4);

    // An upper-case mark remembers its file.
    h.keys(":8\n");
    h.keys("mQ");
    assert!(
        h.message().contains("Mark Q is packet 8 of test.pcap"),
        "{}",
        h.message()
    );
    let first = std::fs::canonicalize(&h.app.source).unwrap();
    let other = h.dir.path().join("other.pcap");
    pcap::many(50).write(&other);
    h.keys(&format!(":open {}\n", other.display()));
    assert_eq!(h.app.title, "other.pcap");
    assert!(
        h.app.local_marks.is_empty(),
        "lower-case marks stay with their capture"
    );
    h.keys("'a");
    assert!(h.message().contains("Mark a is not set"), "{}", h.message());
    h.keys("'Q");
    assert_eq!(h.app.source, first, "the mark's capture was opened again");
    assert_eq!(at(&h), 8);

    // Ctrl-w and ZZ.
    h.ctrl('w');
    h.keys("w");
    assert_eq!(h.app.focus, Focus::Tree);
    h.keys("+++");
    h.ctrl('w');
    h.keys("=");
    assert!(h.message().contains("Panes reset"), "{}", h.message());
    h.keys("Zj");
    assert!(!h.app.quit, "Z then another key is nothing");
    h.keys("ZZ");
    assert!(h.app.quit);
    drop(h);

    // The upper-case mark is still there in a new run, from another capture.
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere.pcap");
    pcap::many(30).write(&elsewhere);
    let options = Options {
        store,
        ..Default::default()
    };
    let Some(mut h) = Harness::start(dir, elsewhere, 100, 30, options) else {
        return;
    };
    h.settle();
    h.keys("'Q");
    assert_eq!(h.app.source, first);
    assert_eq!(at(&h), 8);
}

#[test]
fn keys_can_be_mapped_to_sequences_and_are_remembered() {
    use packetshark::config::Store;
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::at(scratch.path().join("state.toml"));
    let options = || Options {
        store: store.clone(),
        ..Default::default()
    };
    let Some(mut h) = Harness::open_with(&pcap::web(), 100, 30, options()) else {
        return;
    };
    let press = |h: &mut Harness, code: KeyCode| {
        h.key(code);
    };

    h.keys(":map <f5> :conv<enter>\n");
    assert!(
        h.message().contains("<f5> now types :conv<enter>"),
        "{}",
        h.message()
    );
    press(&mut h, KeyCode::F(5));
    h.assert_screen_contains("Conversations");
    h.key(KeyCode::Esc);

    // A mapping can move around and act: down three, then filter on tcp.
    h.keys(":map T jjj/tcp<enter>\n");
    h.keys("T");
    assert_eq!(h.app.filter.applied, "tcp");
    // ... but while typing text, a mapped key is just its character.
    h.keys("/http || frame.len > T");
    assert_eq!(h.app.filter.input.text(), "http || frame.len > T");
    h.key(KeyCode::Esc);
    h.keys(":filter udp || T\n");
    assert!(
        h.message().contains("Invalid") || h.app.filter.applied != "tcp",
        "typed as text"
    );

    // A mapping is not applied to the keys of a mapping, so this cannot loop.
    h.keys(":map j jj\n");
    h.keys("x");
    h.keys("gg");
    h.keys("j");
    assert_eq!(
        h.app.list.selected_num(),
        Some(3),
        "j now moves two, not forever"
    );

    // Mistakes are refused with a reason.
    h.keys(":map <f99> x\n");
    assert!(
        h.message().contains("<f99> is not a key"),
        "{}",
        h.message()
    );
    h.keys(":map ab cd\n");
    assert!(h.message().contains("Only a single key"), "{}", h.message());
    h.keys(":unmap <f9>\n");
    assert!(
        h.message().contains("<f9> is not mapped"),
        "{}",
        h.message()
    );

    // The list, and removing one.
    h.keys(":map\n");
    h.assert_screen_contains("Key mappings");
    h.assert_screen_contains(":conv<enter>");
    h.key(KeyCode::Esc);
    h.keys(":unmap j\n");
    h.keys("ggj");
    assert_eq!(h.app.list.selected_num(), Some(2));
    drop(h);

    // Mappings are there in the next run.
    let Some(mut h) = Harness::open_with(&pcap::web(), 100, 30, options()) else {
        return;
    };
    press(&mut h, KeyCode::F(5));
    h.assert_screen_contains("Conversations");
}

#[test]
fn searching_bytes_details_and_the_summary() {
    use packetshark::app::search::{Kind, Target};
    use packetshark::config::Store;
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::at(scratch.path().join("state.toml"));
    let options = || Options {
        store: store.clone(),
        ..Default::default()
    };
    let Some(mut h) = Harness::open_with(&pcap::web(), 120, 34, options()) else {
        return;
    };
    let at = |h: &Harness| h.app.list.selected_num().unwrap();
    let find = |h: &mut Harness, text: &str| {
        h.keys("gg");
        h.keys(&format!("s{text}\n"));
    };

    // As it comes: a filter if the text is one, else text in the bytes,
    // in any case.
    assert_eq!(h.app.find_options(), (Target::Bytes, Kind::Auto, false));
    h.keys("s");
    h.assert_screen_contains("Find in bytes as filter or text, any case:");
    h.assert_screen_contains("Tab: where to look");
    h.key(KeyCode::Esc);
    find(&mut h, "http.response");
    assert_eq!(at(&h), 8, "read as a filter");
    find(&mut h, "HELLO WORLD");
    assert_eq!(at(&h), 8, "read as text, in any case");
    // The match is pointed out: the cursor is on its first byte, and the
    // field that holds it is selected.
    let detail = h.app.detail.as_ref().unwrap();
    let bytes = &detail.sources[h.app.hex.source].bytes;
    assert!(
        bytes[h.app.hex.cursor..].starts_with(b"hello world"),
        "cursor at {}",
        h.app.hex.cursor
    );
    // ... and the field that holds those bytes is selected, not the frame.
    assert!(
        !selected_label(&h).starts_with("Frame "),
        "{}",
        selected_label(&h)
    );

    // Exact case: Ctrl-o in the prompt.
    h.keys("s");
    h.ctrl('o');
    h.assert_screen_contains("exact case:");
    h.keys("HELLO WORLD\n");
    assert!(h.message().contains("No packet matches"), "{}", h.message());
    find(&mut h, "hello world");
    assert_eq!(at(&h), 8);

    // Shift-Tab changes how the text is read: text, regex, hex, filter.
    h.keys("gg");
    h.keys("s");
    h.key(KeyCode::BackTab);
    h.assert_screen_contains("Find in bytes as text, exact case:");
    h.key(KeyCode::BackTab);
    h.assert_screen_contains("Find in bytes as regex, exact case:");
    h.keys("GET /[a-z]+\\.html\n");
    assert_eq!(at(&h), 6);
    find(&mut h, "GET /[0-9]+\\.html");
    assert!(h.message().contains("No packet matches"), "{}", h.message());
    find(&mut h, "GET /(");
    assert!(
        h.message().contains("Not a regular expression"),
        "{}",
        h.message()
    );

    h.keys("gg");
    h.keys("s");
    h.key(KeyCode::BackTab);
    h.assert_screen_contains("Find in bytes as hex:");
    // "GET " as bytes.
    h.keys("47 45 54 20\n");
    assert_eq!(at(&h), 6);
    assert!(bytes_at_cursor(&h).starts_with(b"GET "));
    find(&mut h, "4745zz");
    assert!(h.message().contains("pairs of digits"), "{}", h.message());

    // Tab changes where to look. The details: text that is in no packet's
    // bytes, only in what Wireshark says about them.
    h.keys("gg");
    h.keys("s");
    h.key(KeyCode::BackTab);
    h.key(KeyCode::BackTab);
    h.key(KeyCode::BackTab);
    h.assert_screen_contains("as text");
    h.key(KeyCode::Tab);
    h.ctrl('o');
    h.assert_screen_contains("Find in details as text, any case:");
    h.keys("status code description\n");
    assert_eq!(at(&h), 8);
    assert!(
        selected_label(&h)
            .to_lowercase()
            .contains("status code description"),
        "the matching line is selected: {}",
        selected_label(&h)
    );
    // n and N go on from there, and wrap.
    h.keys("n");
    assert_eq!(at(&h), 18, "the second response has one too");
    h.keys("n");
    assert_eq!(
        at(&h),
        8,
        "and after the last, the search wraps to the first"
    );
    assert!(h.message().contains("wrapped"), "{}", h.message());

    // The summary column, where the Wireshark in use can filter on it.
    h.keys("gg");
    h.keys("s");
    h.key(KeyCode::Tab);
    h.assert_screen_contains("Find in summary as text, any case:");
    h.keys("syn, ack\n");
    assert_eq!(at(&h), 4);
    drop(h);

    // The choices are remembered.
    let Some(h) = Harness::open_with(&pcap::web(), 120, 34, options()) else {
        return;
    };
    assert_eq!(h.app.find_options(), (Target::Summary, Kind::Text, false));
}

fn bytes_at_cursor(h: &Harness) -> Vec<u8> {
    let detail = h.app.detail.as_ref().unwrap();
    detail.sources[h.app.hex.source].bytes[h.app.hex.cursor..].to_vec()
}

#[test]
fn a_details_search_reads_on_through_a_long_capture_and_can_be_stopped() {
    use packetshark::config::{FindPrefs, State, Store};
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::at(scratch.path().join("state.toml"));
    store.save(&State {
        find: FindPrefs {
            target: "details".into(),
            kind: "string".into(),
            case_sensitive: true,
        },
        ..State::default()
    });
    let options = Options {
        store,
        ..Default::default()
    };
    // The port is unique to one packet, far beyond one step of the search.
    let Some(mut h) = Harness::open_with(&pcap::many(700), 100, 30, options) else {
        return;
    };
    h.keys("sSource Port: 30650\n");
    assert_eq!(h.app.list.selected_num(), Some(651));
    assert!(selected_label(&h).contains("Source Port: 30650"));
    // Backwards from there, to the same packet by the long way round.
    h.keys("N");
    assert_eq!(h.app.list.selected_num(), Some(651));
    assert!(h.message().contains("wrapped"), "{}", h.message());
    // Under a filter only the displayed packets are read.
    h.keys("/udp.srcport < 30100\n");
    h.keys("sSource Port: 30650\n");
    assert!(h.message().contains("No packet matches"), "{}", h.message());
    h.keys("sSource Port: 30050\n");
    assert_eq!(h.app.list.selected_num(), Some(51));

    // Esc calls a running search off.
    h.keys("x");
    h.keys("gg");
    h.app.handle(Event::Key(crossterm::event::KeyEvent::new(
        KeyCode::Char('s'),
        crossterm::event::KeyModifiers::NONE,
    )));
    for c in "nothing like this anywhere".chars() {
        h.app.handle(Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Char(c),
            crossterm::event::KeyModifiers::NONE,
        )));
    }
    h.app.handle(Event::Key(crossterm::event::KeyEvent::new(
        KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    )));
    assert!(h.app.searching());
    h.app.handle(Event::Key(crossterm::event::KeyEvent::new(
        KeyCode::Esc,
        crossterm::event::KeyModifiers::NONE,
    )));
    assert!(!h.app.searching());
    h.settle();
    assert!(h.message().contains("Search stopped"), "{}", h.message());
    assert_eq!(h.app.list.selected_num(), Some(1), "nothing moved");
}

#[test]
fn a_followed_stream_can_be_searched() {
    use packetshark::app::follow::Mode;
    use packetshark::config::Store;
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::at(scratch.path().join("state.toml"));
    // A response long enough to need scrolling.
    let body: String = (0..300)
        .map(|i| format!("row {i:03} of the report\n"))
        .collect();
    let mut capture = pcap::Pcap::new();
    capture.http(40000, "example.com", "/report", &body);
    let options = || Options {
        store: store.clone(),
        ..Default::default()
    };
    let Some(mut h) = Harness::open_with(&capture, 100, 30, options()) else {
        return;
    };
    let top_line = |h: &mut Harness| h.line(2);
    h.keys("jjj");
    h.key(KeyCode::Char('F'));
    h.key(KeyCode::Char('t'));
    h.assert_screen_contains("Follow TCP stream");
    // How the conversation went: one request, the reply in several packets.
    assert!(h.line(0).contains("packets · 1 turn"), "{}", h.line(0));

    // Text in any case; the match comes to the top and is picked out.
    h.keys("/ROW 150\n");
    assert!(
        top_line(&mut h).contains("row 150 of the report"),
        "{}",
        top_line(&mut h)
    );
    let x = top_line(&mut h).find("row 150").unwrap() as u16;
    assert_eq!(
        h.bg_at(x, 2),
        h.app.theme.hex_highlight.bg,
        "the match is highlighted"
    );
    assert_ne!(
        h.bg_at(x + 9, 2),
        h.app.theme.hex_highlight.bg,
        "and only the match"
    );

    // A regular expression between slashes; n and N step through, and wrap.
    h.keys("//row 2[0-9]5/\n");
    assert!(top_line(&mut h).contains("row 205"), "{}", top_line(&mut h));
    h.keys("n");
    assert!(top_line(&mut h).contains("row 215"), "{}", top_line(&mut h));
    h.keys("N");
    assert!(top_line(&mut h).contains("row 205"), "{}", top_line(&mut h));
    h.keys("N");
    assert!(h.message().contains("wrapped"), "{}", h.message());
    h.assert_screen_contains("row 295");

    // Nothing found, and a mistake in the expression.
    h.keys("/no such text\n");
    assert!(h.message().contains("does not contain"), "{}", h.message());
    h.keys("//row (/\n");
    assert!(
        h.message().contains("Not a regular expression"),
        "{}",
        h.message()
    );

    // The way of showing the data is remembered for the next stream.
    h.key(KeyCode::Char('m'));
    h.assert_screen_contains("hex dump");
    h.key(KeyCode::Esc);
    drop(h);
    let Some(mut h) = Harness::open_with(&capture, 100, 30, options()) else {
        return;
    };
    h.keys("jjj");
    h.key(KeyCode::Char('F'));
    h.key(KeyCode::Char('t'));
    match &h.app.overlay {
        Some(Overlay::Follow(view)) => assert_eq!(view.mode, Mode::HexDump),
        _ => panic!("no stream:\n{}", h.screen()),
    }
}
