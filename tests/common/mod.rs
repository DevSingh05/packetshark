//! Test harness: runs the real app against a real sharkd and renders it to an
//! in-memory terminal.

#![allow(dead_code)]

pub mod pcap;

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use packetshark::app::{App, Event, Options};
use packetshark::config::{Config, History};
use packetshark::sharkd::{self, Launch};
use packetshark::theme::Theme;
use packetshark::ui;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Style};
use tempfile::TempDir;

/// Path to sharkd, or `None` (with a note) when Wireshark is not installed.
/// Tests return early in that case rather than fail.
pub fn sharkd_path() -> Option<PathBuf> {
    if let Ok(p) = sharkd::locate(None) {
        Some(p)
    } else {
        eprintln!("skipping: sharkd is not installed");
        None
    }
}

/// Run `start`, which executes a script the test has just written, again
/// if the system says the file is busy. On Linux a script cannot be run
/// while any process holds it open for writing, and for a moment a child
/// that another test's thread has just forked still does.
pub fn retry_while_busy<T, E: std::fmt::Display>(mut start: impl FnMut() -> Result<T, E>) -> T {
    let mut tries = 0;
    loop {
        match start() {
            Ok(value) => return value,
            Err(e) if tries < 200 && e.to_string().contains("ext file busy") => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("could not start the helper script: {e}"),
        }
    }
}

pub struct Harness {
    pub app: App,
    pub rx: Receiver<Event>,
    pub tx: Sender<Event>,
    pub terminal: Terminal<TestBackend>,
    pub dir: TempDir,
    pub path: PathBuf,
}

impl Harness {
    /// Open `capture` in an 100x30 terminal and wait for it to load.
    pub fn open(capture: &pcap::Pcap) -> Option<Harness> {
        Self::open_with(capture, 100, 30, Options::default())
    }

    pub fn open_with(
        capture: &pcap::Pcap,
        width: u16,
        height: u16,
        options: Options,
    ) -> Option<Harness> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pcap");
        capture.write(&path);
        let mut h = Self::start(dir, path, width, height, options)?;
        h.settle();
        Some(h)
    }

    /// Start the app on `path` without waiting for anything.
    pub fn start(
        dir: TempDir,
        path: PathBuf,
        width: u16,
        height: u16,
        options: Options,
    ) -> Option<Harness> {
        Self::start_configured(dir, path, width, height, options, Config::default())
    }

    /// Like `start`, with a user configuration.
    pub fn start_configured(
        dir: TempDir,
        path: PathBuf,
        width: u16,
        height: u16,
        options: Options,
        config: Config,
    ) -> Option<Harness> {
        let sharkd = sharkd_path()?;
        let (tx, rx) = mpsc::channel();
        let options = Options {
            source: path.clone(),
            title: "test.pcap".into(),
            ..options
        };
        // Isolate from the developer's Wireshark profile and packetshark config.
        let launch = Launch {
            program: sharkd,
            profile: None,
            config_dir: None,
        };
        let app = App::new(
            launch,
            config,
            Theme::new(true, true),
            options,
            tx.clone(),
            History::disabled(),
        )
        .expect("sharkd starts");
        let terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        Some(Harness {
            app,
            rx,
            tx,
            terminal,
            dir,
            path,
        })
    }

    pub fn draw(&mut self) {
        let app = &mut self.app;
        self.terminal.draw(|frame| ui::draw(app, frame)).unwrap();
    }

    /// Process events until sharkd has answered everything and the screen has
    /// stopped changing.
    pub fn settle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            self.draw();
            // Drawing sets pane heights; this lets the app react to them.
            self.app.handle(Event::Resize);
            let mut progressed = false;
            let wait = if self.app.busy() {
                Duration::from_secs(10)
            } else {
                Duration::from_millis(20)
            };
            while let Ok(event) = self.rx.recv_timeout(if progressed {
                Duration::from_millis(20)
            } else {
                wait
            }) {
                if std::env::var_os("PF_TRACE").is_some() {
                    let text = format!("{event:?}");
                    eprintln!("event: {}", &text[..text.len().min(160)]);
                }
                self.app.handle(event);
                progressed = true;
                if !self.app.busy() {
                    break;
                }
            }
            if !self.app.busy() && !progressed {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "app did not settle:\n{}",
                self.screen()
            );
        }
        self.draw();
    }

    pub fn key(&mut self, code: KeyCode) -> &mut Self {
        self.app
            .handle(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
        self.settle();
        self
    }

    pub fn ctrl(&mut self, c: char) -> &mut Self {
        self.app.handle(Event::Key(KeyEvent::new(
            KeyCode::Char(c),
            KeyModifiers::CONTROL,
        )));
        self.settle();
        self
    }

    /// Press each character of `keys` in turn.
    pub fn keys(&mut self, keys: &str) -> &mut Self {
        for c in keys.chars() {
            let code = match c {
                '\n' => KeyCode::Enter,
                '\t' => KeyCode::Tab,
                c => KeyCode::Char(c),
            };
            self.app
                .handle(Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
        }
        self.settle();
        self
    }

    pub fn click(&mut self, x: u16, y: u16) -> &mut Self {
        self.mouse(MouseEventKind::Down(MouseButton::Left), x, y)
    }

    pub fn mouse(&mut self, kind: MouseEventKind, x: u16, y: u16) -> &mut Self {
        self.app.handle(Event::Mouse(MouseEvent {
            kind,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        }));
        self.settle();
        self
    }

    /// The screen as text, one line per row, trailing spaces removed.
    pub fn screen(&mut self) -> String {
        self.draw();
        let buffer = self.terminal.backend().buffer();
        let area = buffer.area;
        let mut out = String::new();
        for y in 0..area.height {
            let mut line = String::new();
            for x in 0..area.width {
                line.push_str(buffer[(x, y)].symbol());
            }
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    pub fn line(&mut self, y: u16) -> String {
        self.screen()
            .lines()
            .nth(y as usize)
            .unwrap_or("")
            .to_string()
    }

    /// The first row containing `needle`.
    pub fn find_line(&mut self, needle: &str) -> Option<(u16, String)> {
        self.screen()
            .lines()
            .enumerate()
            .find(|(_, l)| l.contains(needle))
            .map(|(y, l)| (y as u16, l.to_string()))
    }

    pub fn style_at(&mut self, x: u16, y: u16) -> Style {
        self.draw();
        self.terminal.backend().buffer()[(x, y)].style()
    }

    pub fn bg_at(&mut self, x: u16, y: u16) -> Option<Color> {
        self.style_at(x, y).bg
    }

    /// The status-bar message, if one is showing.
    pub fn message(&self) -> String {
        self.app
            .message
            .as_ref()
            .map(|m| m.text.clone())
            .unwrap_or_default()
    }

    #[track_caller]
    pub fn assert_screen_contains(&mut self, needle: &str) {
        let screen = self.screen();
        assert!(
            screen.contains(needle),
            "expected to see {needle:?} on screen:\n{screen}"
        );
    }

    #[track_caller]
    pub fn assert_screen_lacks(&mut self, needle: &str) {
        let screen = self.screen();
        assert!(
            !screen.contains(needle),
            "did not expect {needle:?} on screen:\n{screen}"
        );
    }
}

pub fn write_bytes(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
}
