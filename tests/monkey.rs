//! Random input. Keys, mouse events, pastes and resizes are thrown at the
//! real app, which must neither panic nor stop responding.
//!
//! The default run is short. `PACKETSHARK_MONKEY_EVENTS=20000 cargo test
//! --test monkey` runs for as long as you like, and `PACKETSHARK_MONKEY_SEED`
//! replays one seed.

mod common;

use std::collections::BTreeSet;

use common::{Harness, pcap};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use packetshark::app::{App, Event, Focus, Options, Overlay};

/// xorshift64*: small, seedable, good enough to pick keys.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

/// Characters that mean something somewhere in the app, plus enough others
/// to type filters and commands. `~` is left out so that no path typed by
/// chance can point into the home directory.
const CHARS: &[u8] = b"jkhlgGnNsSFfmtcCaAypPzLxeEoOrdwq/:?*+-123 0456789.=!&|()\"abcdefinoprstuvw_";

const SPECIAL: &[KeyCode] = &[
    KeyCode::Enter,
    KeyCode::Enter,
    KeyCode::Esc,
    KeyCode::Esc,
    KeyCode::Tab,
    KeyCode::BackTab,
    KeyCode::Up,
    KeyCode::Down,
    KeyCode::Left,
    KeyCode::Right,
    KeyCode::PageUp,
    KeyCode::PageDown,
    KeyCode::Home,
    KeyCode::End,
    KeyCode::Backspace,
    KeyCode::Delete,
];

/// Things a user might really type, so that filters, commands and windows
/// are reached far more often than chance alone would manage.
const PHRASES: &[&str] = &[
    "/tcp\n",
    "/dns\n",
    "/http || udp\n",
    "/tcp.port == \n",
    "/frame.number > 5\n",
    "x",
    ":conv\n",
    ":endpoints tcp\n",
    ":phs\n",
    ":expert\n",
    ":follow\n",
    ":follow tcp\n",
    ":column tcp.stream\n",
    ":column ip.ttl TTL\n",
    ":column reset\n",
    ":column remove Length\n",
    ":columns\n",
    ":columns\nj jJrx\nd",
    ":columns\nbc",
    ":columns\nR",
    ":theme\n",
    ":theme nord\n",
    ":theme default\n",
    ":marked\n",
    ":marks\n",
    ":info\n",
    ":profile\n",
    ":profile default\n",
    ":decode udp.port 9999 dns\n",
    ":decode clear\n",
    ":decode\n",
    ":graph\n",
    ":graph\nll+-b\n",
    ":flow\n",
    ":flow tcp\n\n",
    "Sf",
    ":recent\n",
    ":map <f5> :conv<enter>\n",
    ":map j jj\n",
    ":map T jjj/tcp<enter>\n",
    ":unmap j\n",
    ":map\n",
    "T",
    "ma",
    "mQ",
    "'a",
    "'Q",
    "''",
    "12G",
    "5gg",
    "ZZ",
    ":th\t\t\n",
    ":\t\t\t",
    ":open /tm\t",
    ":unmark\n",
    ":reload\n",
    ":layout side\n",
    ":layout stacked\n",
    ":colors tint\n",
    ":3\n",
    ":999999\n",
    "Ft",
    "Ft/get\nnN",
    "Ft//h.st/\n",
    "Fh",
    "Sc",
    "Sca>",
    "Scp<",
    "Seas",
    "Se",
    "Sh",
    "Sx",
    "So",
    "sGET\n",
    "s\t\tsource port\n",
    "s\tsyn\n",
    "sn",
    "nnN",
    "stcp\n",
    "\nel*",
    "3vllljy",
    "3vjjyx",
    "3v",
    "?",
];

fn key(code: KeyCode, modifiers: KeyModifiers) -> Event {
    Event::Key(KeyEvent::new(code, modifiers))
}

fn random_events(rng: &mut Rng, out: &mut Vec<Event>, size: &mut Option<(u16, u16)>) {
    match rng.below(100) {
        0..=54 => {
            let c = rng.pick(CHARS) as char;
            out.push(key(KeyCode::Char(c), KeyModifiers::NONE));
        }
        55..=69 => out.push(key(rng.pick(SPECIAL), KeyModifiers::NONE)),
        70..=74 => {
            // Ctrl-c is left out: it quits, which is right and ends the fun.
            let c = rng.pick(b"durtwae") as char;
            out.push(key(KeyCode::Char(c), KeyModifiers::CONTROL));
        }
        75..=84 => {
            for c in rng.pick(PHRASES).chars() {
                let code = match c {
                    '\n' => KeyCode::Enter,
                    '\t' => KeyCode::Tab,
                    c => KeyCode::Char(c),
                };
                out.push(key(code, KeyModifiers::NONE));
            }
        }
        85..=92 => {
            let kind = match rng.below(5) {
                0 => MouseEventKind::ScrollUp,
                1 => MouseEventKind::ScrollDown,
                2 => MouseEventKind::Drag(MouseButton::Left),
                3 => MouseEventKind::Up(MouseButton::Left),
                _ => MouseEventKind::Down(MouseButton::Left),
            };
            out.push(Event::Mouse(MouseEvent {
                kind,
                column: rng.below(210) as u16,
                row: rng.below(70) as u16,
                modifiers: KeyModifiers::NONE,
            }));
        }
        93..=95 => {
            let text: String = (0..rng.below(40))
                .map(|_| rng.pick(b"tcp.port == 80 && \n\t\x1b[31m\xc3\xa9") as char)
                .collect();
            out.push(Event::Paste(text));
        }
        96..=98 => {
            // Mostly ordinary sizes, sometimes absurd ones.
            let (w, h) = if rng.below(4) == 0 {
                (1 + rng.below(12) as u16, 1 + rng.below(6) as u16)
            } else {
                (20 + rng.below(180) as u16, 5 + rng.below(55) as u16)
            };
            *size = Some((w, h));
            out.push(Event::Resize);
        }
        _ => out.push(Event::Tick),
    }
}

/// Where the app is, for checking that the random input gets around.
fn place(app: &App) -> &'static str {
    if app.prompt.is_some() {
        return "prompt";
    }
    match &app.overlay {
        Some(Overlay::Help { .. }) => "help",
        Some(Overlay::Menu(_)) => "menu",
        Some(Overlay::Follow(_)) => "follow stream",
        Some(Overlay::Stats(_)) => "statistics",
        Some(Overlay::Columns(_)) => "column editor",
        Some(Overlay::Text { .. }) => "text window",
        Some(Overlay::Graph(_)) => "graph",
        None => match app.focus {
            Focus::Filter => "filter bar",
            Focus::List => "packet list",
            Focus::Tree => "details",
            Focus::Hex => "bytes",
        },
    }
}

fn run(seed: u64, events: usize, capture: &pcap::Pcap, visited: &mut BTreeSet<&'static str>) {
    let Some(mut h) = Harness::open_with(capture, 100, 30, Options::default()) else {
        return;
    };
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut done = 0;
    let mut batch = Vec::new();
    while done < events {
        batch.clear();
        let mut size = None;
        random_events(&mut rng, &mut batch, &mut size);
        if let Some((w, height)) = size {
            h.terminal.backend_mut().resize(w, height);
        }
        for event in batch.drain(..) {
            h.app.handle(event);
            done += 1;
            // Whatever sharkd has answered so far, without waiting for it:
            // the next key should often land while work is in flight.
            while let Ok(reply) = h.rx.try_recv() {
                h.app.handle(reply);
            }
            h.draw();
            visited.insert(place(&h.app));
            // Quitting is allowed; carry on as if the user had not meant it.
            h.app.quit = false;
        }
        if done % 97 == 0 {
            h.settle();
        }
    }

    // It must still be usable: leave whatever it is in, clear the filter and
    // go to a packet.
    h.terminal.backend_mut().resize(100, 30);
    for _ in 0..4 {
        h.key(KeyCode::Esc);
    }
    h.app.quit = false;
    h.keys(":clear\n");
    h.keys(":2\n");
    assert_eq!(
        h.app.list.selected_num(),
        Some(2),
        "seed {seed}: the app stopped responding:\n{}",
        h.screen()
    );
}

#[test]
fn random_input_never_breaks_the_app() {
    // Files the app saves by chance (stream payloads, exported objects) go
    // into a directory of their own.
    let scratch = tempfile::tempdir().unwrap();
    std::env::set_current_dir(scratch.path()).unwrap();

    let events = std::env::var("PACKETSHARK_MONKEY_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500);
    let seeds: Vec<u64> = match std::env::var("PACKETSHARK_MONKEY_SEED") {
        Ok(seed) => vec![seed.parse().expect("a number")],
        Err(_) => (1..=4).collect(),
    };
    let mut visited = BTreeSet::new();
    for &seed in &seeds {
        eprintln!("seed {seed}, {events} events");
        let capture = if seed % 2 == 0 {
            pcap::many(3000)
        } else {
            pcap::web()
        };
        run(seed, events, &capture, &mut visited);
    }
    eprintln!("visited: {visited:?}");
    // A run that never left the packet list would prove nothing.
    if seeds.len() > 1 {
        for place in [
            "packet list",
            "details",
            "bytes",
            "filter bar",
            "prompt",
            "menu",
            "help",
            "follow stream",
            "statistics",
            "column editor",
            "graph",
        ] {
            assert!(
                visited.contains(place),
                "the input never reached the {place}"
            );
        }
    }
}
