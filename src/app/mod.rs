//! Application state and behaviour. Nothing here touches the terminal: the
//! app consumes `Event`s and is drawn by `crate::ui`, so the whole thing can
//! be driven from tests.

pub mod columns;
pub mod detail;
pub mod filter;
pub mod follow;
pub mod help;
pub mod list;
pub mod stats;

mod commands;
mod keys;
mod replies;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent};
use ratatui::layout::Rect;

use crate::capture::Capture;
use crate::config::{Config, History};
use crate::sharkd::types::{Info, Status};
use crate::sharkd::{Launch, Purpose, Reply, Request, Seek, Worker};
use crate::text_input::TextInput;
use crate::theme::{RowColors, Theme};
use crate::util::filter_quote;

use columns::{Columns, TimeFormat};
use detail::{Detail, HexState, TreeState};
use filter::FilterBar;
use follow::FollowView;
use list::{PAGE, PacketList};
use stats::StatsView;

/// Everything that can happen to the app.
#[derive(Debug)]
pub enum Event {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Paste(String),
    Resize,
    /// Fires a few times a second; drives the spinner and live reloads.
    Tick,
    Reply(Reply),
    /// A background job (such as an export) finished.
    Job {
        ok: bool,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    List,
    Tree,
    Hex,
    Filter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutKind {
    /// List, details and bytes on top of each other.
    Stacked,
    /// List on top; details and bytes next to each other.
    Side,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub text: String,
    pub level: Level,
    pub at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadState {
    Loading,
    Ready,
    Failed(String),
}

/// Something a menu entry does.
#[derive(Debug, Clone)]
pub enum Action {
    ApplyFilter(String),
    PrepareFilter(String),
    Copy { what: &'static str, text: String },
    Follow { protocol: String, filter: String },
    Stats(stats::Kind),
}

#[derive(Debug, Clone)]
pub struct MenuItem {
    pub key: char,
    pub label: String,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct Menu {
    pub title: String,
    pub items: Vec<MenuItem>,
    pub selected: usize,
}

#[derive(Debug)]
pub enum Overlay {
    Help { top: usize },
    Menu(Menu),
    Follow(Box<FollowView>),
    Stats(Box<StatsView>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    Command,
    Find,
    SaveStream,
}

#[derive(Debug)]
pub struct Prompt {
    pub kind: PromptKind,
    pub input: TextInput,
}

impl Prompt {
    pub fn label(&self) -> &'static str {
        match self.kind {
            PromptKind::Command => ":",
            PromptKind::Find => "Find: ",
            PromptKind::SaveStream => "Save stream to: ",
        }
    }
}

/// Where things were drawn, for mouse hit-testing.
#[derive(Debug, Default, Clone, Copy)]
pub struct Areas {
    pub filter: Rect,
    /// Packet rows (without the column header).
    pub list: Rect,
    pub tree: Rect,
    pub hex: Rect,
    /// Scrollable body of the open overlay.
    pub overlay: Rect,
}

/// State for a capture file that is still growing.
#[derive(Debug)]
pub struct Tail {
    /// File size at the last load attempt; a reload happens when it changes.
    size: u64,
    loading: bool,
    started: Instant,
    cost: Duration,
    /// Why the last attempt failed, if it did.
    pub error: Option<String>,
}

struct Find {
    /// List generation of the search request in flight, if any. A reply for
    /// an older generation never arrives, so it does not count as busy.
    busy: Option<u64>,
    /// Steps asked for while one was in flight.
    queued: std::collections::VecDeque<Seek>,
    filter: String,
    /// The text as typed, kept while it might still be meant as plain text
    /// rather than a filter expression.
    plain: Option<String>,
    wrapped: bool,
}

/// What to open and how.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub source: PathBuf,
    /// Name shown in the status bar.
    pub title: String,
    pub display_filter: String,
    /// Keep reloading as the file grows.
    pub tail: bool,
    /// Wireshark preferences to set before loading (`name`, `value`).
    pub prefs: Vec<(String, String)>,
}

pub struct App {
    worker: Worker,
    events: Sender<Event>,
    launch: Launch,
    /// Requests sent and not yet answered.
    inflight: usize,
    /// Keys typed while a filter was waiting to be validated; replayed once
    /// it is applied, so type-ahead lands where the user meant it.
    held_keys: Vec<KeyEvent>,
    /// Keys typed before the capture had opened; see `holds_for_opening`.
    typed_ahead: std::collections::VecDeque<KeyEvent>,
    /// Columns added on top of the profile's, as (title, field).
    pub extra_columns: Vec<(String, String)>,
    history: History,
    command_history: Vec<String>,

    pub config: Config,
    pub theme: Theme,
    pub source: PathBuf,
    pub title: String,
    pub info: Option<Info>,
    pub status: Option<Status>,
    pub load: LoadState,
    pub columns: Columns,
    pub time_format: TimeFormat,
    pub filter: FilterBar,
    pub list: PacketList,
    pub detail: Option<Detail>,
    /// Frame whose detail was last asked for.
    detail_requested: Option<u32>,
    pub tree: TreeState,
    pub hex: HexState,
    pub focus: Focus,
    /// Pane that had focus before the filter bar took it.
    focus_before_filter: Focus,
    pub zoom: bool,
    pub layout: LayoutKind,
    /// Relative heights of list, details and bytes.
    pub split: [u16; 3],
    pub overlay: Option<Overlay>,
    pub prompt: Option<Prompt>,
    pub message: Option<Message>,
    pub marks: BTreeSet<u32>,
    pub time_refs: BTreeSet<u32>,
    find: Option<Find>,
    /// Frame a pending "go to" asked for, to report if the filter hides it.
    goto_exact: Option<u32>,
    pub tail: Option<Tail>,
    /// A file `:open` asked for that sharkd has not finished loading.
    pending_open: Option<PathBuf>,
    /// Whether any capture has loaded; until then a failure is fatal.
    loaded_once: bool,
    pub capture: Option<Capture>,
    capture_failure_reported: bool,
    tap_seq: u64,
    pub quit: bool,
    /// Where exported objects are saved.
    pub download_dir: PathBuf,
    /// Text waiting to be sent to the terminal's clipboard.
    pub clipboard: Vec<String>,
    pub areas: Areas,
    pub ticks: u64,
}

impl App {
    pub fn new(
        launch: Launch,
        config: Config,
        mut theme: Theme,
        options: Options,
        events: Sender<Event>,
        history: History,
    ) -> std::io::Result<App> {
        let tx = events.clone();
        let worker = Worker::start(launch.clone(), move |reply| {
            let _ = tx.send(Event::Reply(reply));
        })?;

        if let Some(mode) = RowColors::parse(&config.ui.row_colors) {
            theme.row_colors = mode;
        }
        let layout = match config.ui.layout.as_str() {
            "side" => LayoutKind::Side,
            _ => LayoutKind::Stacked,
        };
        let mut filter = FilterBar::default();
        filter.input.set_history(history.load());
        let display_filter = options.display_filter.trim().to_string();
        filter.input.set(&display_filter);
        filter.applied = display_filter;

        let mut app = App {
            worker,
            events,
            launch,
            inflight: 0,
            held_keys: Vec::new(),
            typed_ahead: std::collections::VecDeque::new(),
            extra_columns: Vec::new(),
            history,
            command_history: Vec::new(),
            tree: TreeState::with_expand_all(config.ui.expand_all),
            config,
            theme,
            source: options.source.clone(),
            title: options.title,
            info: None,
            status: None,
            load: LoadState::Loading,
            columns: Columns::default(),
            time_format: TimeFormat::default(),
            filter,
            list: PacketList::default(),
            detail: None,
            detail_requested: None,
            hex: HexState::default(),
            focus: Focus::List,
            focus_before_filter: Focus::List,
            zoom: false,
            layout,
            split: [40, 35, 25],
            overlay: None,
            prompt: None,
            message: None,
            marks: BTreeSet::new(),
            time_refs: BTreeSet::new(),
            find: None,
            goto_exact: None,
            tail: None,
            pending_open: None,
            loaded_once: false,
            capture: None,
            capture_failure_reported: false,
            tap_seq: 0,
            quit: false,
            download_dir: PathBuf::from("."),
            clipboard: Vec::new(),
            areas: Areas::default(),
            ticks: 0,
        };

        app.send(Request::Info);
        for (name, value) in options.prefs {
            app.send(Request::SetConf { name, value });
        }
        if !app.filter.applied.is_empty()
            && let Some((seq, text)) = app.filter.check_request()
        {
            app.send(Request::Check { seq, filter: text });
        }
        if options.tail {
            // The first load happens once the file has something in it.
            app.tail = Some(Tail {
                size: 0,
                loading: false,
                started: Instant::now(),
                cost: Duration::ZERO,
                error: None,
            });
        } else {
            app.send(Request::Load {
                path: options.source,
            });
        }
        Ok(app)
    }

    /// The reason, if the capture given at startup could not be opened at
    /// all. The program then has nothing to show and should exit.
    pub fn startup_failure(&self) -> Option<&str> {
        match &self.load {
            LoadState::Failed(reason) if !self.loaded_once => Some(reason),
            _ => None,
        }
    }

    /// Hand the app the process that is producing the capture file.
    pub fn attach_capture(&mut self, capture: Capture) {
        self.capture = Some(capture);
    }

    fn send(&mut self, request: Request) {
        self.inflight += 1;
        self.worker.send(request);
    }

    /// True while sharkd is working on something for us.
    pub fn busy(&self) -> bool {
        self.inflight > 0
    }

    pub fn capturing(&mut self) -> bool {
        self.capture.as_mut().is_some_and(Capture::running)
    }

    pub fn say(&mut self, level: Level, text: impl Into<String>) {
        self.message = Some(Message {
            text: text.into(),
            level,
            at: Instant::now(),
        });
    }

    fn info(&mut self, text: impl Into<String>) {
        self.say(Level::Info, text);
    }

    fn error(&mut self, text: impl Into<String>) {
        self.say(Level::Error, text);
    }

    // ---- events -----------------------------------------------------------

    pub fn handle(&mut self, event: Event) {
        match event {
            Event::Key(key) => {
                if key.kind == KeyEventKind::Release {
                } else if self.holds_for_opening(&key) {
                    self.typed_ahead.push_back(key);
                } else {
                    self.on_key(key);
                }
            }
            Event::Mouse(mouse) => self.on_mouse(mouse),
            Event::Paste(text) => self.on_paste(&text),
            Event::Resize => {}
            Event::Tick => self.on_tick(),
            Event::Reply(reply) => self.on_reply(reply),
            Event::Job { ok, message } => {
                self.say(if ok { Level::Info } else { Level::Error }, message);
            }
        }
        self.request_pages();
        self.sync_detail();
        self.replay_typed_ahead();
    }

    /// Whether a capture file is being opened for the first time, with
    /// nothing on screen yet for a key to act on.
    fn opening(&self) -> bool {
        self.load == LoadState::Loading
            && self.status.is_none()
            && self.tail.is_none()
            && self.capture.is_none()
    }

    /// Keys typed while a capture is still opening are kept and played back
    /// once there are packets to act on, instead of being lost: `packetshark
    /// big.pcap` followed at once by `G` should end on the last packet.
    fn holds_for_opening(&self, key: &KeyEvent) -> bool {
        if !self.opening() && self.typed_ahead.is_empty() {
            return false;
        }
        if self.typed_ahead.len() >= 256 {
            return false;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return false;
        }
        // `q` quits at once, unless it is part of something being typed.
        let typing_text = self
            .typed_ahead
            .iter()
            .any(|k| matches!(k.code, KeyCode::Char('/' | ':' | 's')));
        !(key.code == KeyCode::Char('q') && !typing_text)
    }

    /// Play back held keys, each one only after the previous has settled, so
    /// they see the same screen they would have if typed slowly.
    fn replay_typed_ahead(&mut self) {
        if matches!(self.load, LoadState::Failed(_)) {
            self.typed_ahead.clear();
        }
        while !self.opening() && !self.busy() {
            let Some(key) = self.typed_ahead.pop_front() else {
                break;
            };
            self.on_key(key);
            self.request_pages();
            self.sync_detail();
        }
    }

    fn on_tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
        if let Some(m) = &self.message {
            let ttl = match m.level {
                Level::Info => Duration::from_secs(4),
                Level::Warn => Duration::from_secs(6),
                Level::Error => Duration::from_secs(10),
            };
            if m.at.elapsed() > ttl {
                self.message = None;
            }
        }
        self.poll_tail();
        self.check_capture_ended_empty();
        if !self.capture_failure_reported
            && let Some(reason) = self.capture.as_mut().and_then(Capture::failure)
        {
            self.capture_failure_reported = true;
            if self.status.is_none() {
                self.load = LoadState::Failed(format!("Capture failed: {reason}"));
            } else {
                self.error(format!("Capture stopped: {reason}"));
            }
        }
    }

    /// A capture source that has finished without giving sharkd anything it
    /// could read (an empty pipe, or one that carried something other than a
    /// capture) will never show packets; say so instead of waiting forever.
    fn check_capture_ended_empty(&mut self) {
        if self.status.is_some() || self.load != LoadState::Loading {
            return;
        }
        if self.tail.as_ref().is_some_and(|t| t.loading) {
            return;
        }
        let Some(capture) = &mut self.capture else {
            return;
        };
        if capture.running() || capture.failure().is_some() {
            return;
        }
        let size = std::fs::metadata(&self.source).map_or(0, |m| m.len());
        let attempted = self.tail.as_ref().map_or(0, |t| t.size);
        if size == 0 {
            self.load = LoadState::Failed(format!("{}: no capture data arrived", self.title));
        } else if size == attempted
            && let Some(reason) = self.tail.as_ref().and_then(|t| t.error.clone())
        {
            // Everything that was going to arrive has been tried.
            self.load = LoadState::Failed(format!("{}: {reason}", self.title));
        }
    }

    /// Reload a growing file when it has grown, no more often than sharkd can
    /// keep up with.
    pub fn poll_tail(&mut self) {
        let Some(tail) = &mut self.tail else { return };
        if tail.loading {
            return;
        }
        let size = std::fs::metadata(&self.source).map_or(0, |m| m.len());
        if size == tail.size || size == 0 {
            return;
        }
        let wait = (tail.cost * 3).max(Duration::from_millis(300));
        if tail.size != 0 && tail.started.elapsed() < wait {
            return;
        }
        tail.size = size;
        tail.loading = true;
        tail.started = Instant::now();
        let path = self.source.clone();
        self.send(Request::Load { path });
    }

    // ---- packet list ------------------------------------------------------

    fn request_pages(&mut self) {
        if self.load != LoadState::Ready {
            return;
        }
        for page in self.list.pages_needed() {
            let request = Request::Frames {
                generation: self.list.generation,
                filter: self.filter.applied.clone(),
                skip: page * PAGE,
                limit: PAGE,
                columns: self.columns.specs(self.time_format),
                refs: self.time_refs.iter().copied().collect(),
            };
            self.send(request);
        }
    }

    /// Make sure the detail panes show (or are fetching) the selected packet.
    fn sync_detail(&mut self) {
        if self.load != LoadState::Ready {
            return;
        }
        if self.list.total == Some(0) {
            self.detail = None;
            self.detail_requested = None;
            return;
        }
        let Some(num) = self.list.selected_num() else {
            return;
        };
        if self.detail_requested == Some(num) {
            return;
        }
        self.detail_requested = Some(num);
        let prev = self
            .list
            .selected
            .checked_sub(1)
            .and_then(|i| self.list.row(i))
            .map(|r| r.num);
        let reference = self.time_refs.range(..=num).next_back().copied();
        self.send(Request::Frame {
            num,
            prev,
            reference,
        });
    }

    /// Total packets in the file.
    pub fn frames(&self) -> u32 {
        self.status.as_ref().map_or(0, |s| s.frames)
    }

    /// Apply a new total, keeping the cursor on the newest packet if it was
    /// there (live captures scroll with the traffic).
    fn set_total(&mut self, total: u32) {
        let at_end = self.list.is_empty() || self.list.selected + 1 == self.list.len();
        self.list.set_total(total);
        if self.tail.is_some() && at_end && total > 0 {
            self.list.select(total - 1);
        }
    }

    fn count_displayed(&mut self) {
        if self.filter.applied.is_empty() {
            let frames = self.frames();
            self.set_total(frames);
        } else {
            let request = Request::Count {
                generation: self.list.generation,
                filter: self.filter.applied.clone(),
            };
            self.send(request);
        }
    }

    /// Show a different set of packets.
    pub fn apply_filter(&mut self, text: &str) {
        let text = text.trim().to_string();
        self.filter.input.set(&text);
        self.filter.close_completions();
        if let Some((seq, filter)) = self.filter.check_request() {
            self.send(Request::Check { seq, filter });
        }
        if !text.is_empty() {
            self.filter.input.remember(&text);
            self.history.save(self.filter.input.history());
        }
        if text == self.filter.applied {
            return;
        }
        let keep = self.list.selected_num();
        self.filter.applied = text;
        self.list.reset();
        self.detail = None;
        self.detail_requested = None;
        if self.load != LoadState::Ready {
            return;
        }
        self.count_displayed();
        if let Some(num) = keep {
            self.goto_exact = None;
            self.locate(num, Seek::Nearest, Purpose::Select);
        }
    }

    fn locate(&mut self, frame: u32, seek: Seek, purpose: Purpose) {
        if self.filter.applied.is_empty() && purpose == Purpose::Select {
            // No filter: packet N is row N-1.
            if frame >= 1 && self.list.total.is_some() {
                self.list.select(frame - 1);
                self.list.center();
            }
            return;
        }
        let request = Request::Locate {
            generation: self.list.generation,
            filter: self.filter.applied.clone(),
            frame,
            seek,
            purpose,
        };
        self.send(request);
    }

    /// Move the cursor to packet `num`.
    pub fn goto_frame(&mut self, num: u32) {
        if num == 0 || num > self.frames() {
            self.error(format!(
                "There is no packet {num} (the capture has {}).",
                self.frames()
            ));
            return;
        }
        self.goto_exact = Some(num);
        self.locate(num, Seek::Nearest, Purpose::Select);
        if self.filter.applied.is_empty() {
            self.goto_exact = None;
        }
    }

    /// Fetch the list again without changing what it contains.
    fn refresh_list(&mut self) {
        self.list.refresh();
        self.detail_requested = None;
        // A count that was still running belongs to the old generation and
        // its reply will be ignored; ask again.
        if self.list.total.is_none() && self.load == LoadState::Ready {
            self.count_displayed();
        }
    }

    pub fn reload(&mut self) {
        let path = self.source.clone();
        self.send(Request::Load { path });
    }

    /// Open another capture. The current one stays on screen until the new
    /// one has loaded, so a file that turns out not to be a capture costs
    /// nothing.
    fn open(&mut self, path: PathBuf) {
        if !path.is_file() {
            self.error(format!("{} is not a file.", path.display()));
            return;
        }
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        self.info(format!("Opening {}…", path.display()));
        self.pending_open = Some(path.clone());
        self.send(Request::Load { path });
    }

    /// Switch the app over to a capture that sharkd has just loaded.
    pub(super) fn adopt_opened(&mut self, path: PathBuf) {
        self.capture = None;
        self.tail = None;
        self.title = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.source = path;
        self.status = None;
        self.list.reset();
        self.detail = None;
        self.detail_requested = None;
        self.marks.clear();
        self.time_refs.clear();
        self.find = None;
        self.overlay = None;
        self.message = None;
    }

    // ---- find -------------------------------------------------------------

    fn start_find(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        // A leading quote forces a text search.
        let find = match text.strip_prefix('"') {
            Some(quoted) => Find {
                busy: None,
                queued: Default::default(),
                filter: contains(quoted.strip_suffix('"').unwrap_or(quoted)),
                plain: None,
                wrapped: false,
            },
            None => Find {
                busy: None,
                queued: Default::default(),
                filter: text.to_string(),
                plain: Some(text.to_string()),
                wrapped: false,
            },
        };
        self.find = Some(find);
        self.find_step(Seek::Next);
    }

    fn find_step(&mut self, seek: Seek) {
        let Some(find) = &mut self.find else {
            self.info("Nothing to search for yet. Press s to find a packet.");
            return;
        };
        // One search at a time: the next step starts where this one lands.
        if find.busy == Some(self.list.generation) {
            find.queued.push_back(seek);
            return;
        }
        find.wrapped = false;
        let from = self.list.selected_num().unwrap_or(0);
        self.send_find(from, seek);
    }

    fn send_find(&mut self, from: u32, seek: Seek) {
        let Some(find) = &mut self.find else { return };
        find.busy = Some(self.list.generation);
        let filter = if self.filter.applied.is_empty() {
            find.filter.clone()
        } else {
            format!("({}) && ({})", self.filter.applied, find.filter)
        };
        let request = Request::Locate {
            generation: self.list.generation,
            filter,
            frame: from,
            seek,
            purpose: Purpose::Find,
        };
        self.send(request);
    }

    // ---- detail panes -----------------------------------------------------

    /// Whether the detail panes show the packet under the cursor (they lag
    /// behind by one sharkd round trip after the cursor moves).
    fn detail_ready(&mut self) -> bool {
        let shown = self.detail.as_ref().map(|d| d.num);
        if shown.is_some() && shown == self.list.selected_num() {
            return true;
        }
        if self.list.is_empty() {
            self.info("Select a packet first.");
        } else {
            self.info("The packet is still loading; try again in a moment.");
        }
        false
    }

    /// The byte range of the selected field: `(source, start, length)`.
    pub fn highlight(&self) -> Option<(usize, usize, usize)> {
        let detail = self.detail.as_ref()?;
        let node = detail.node(self.tree.selected_path()?)?;
        let (start, len) = node.range?;
        Some((node.ds.unwrap_or(0), start as usize, len as usize))
    }

    /// Scroll the bytes pane to the selected field.
    fn sync_hex_to_tree(&mut self) {
        if let Some((source, start, len)) = self.highlight() {
            self.hex.show_range(source, start, len);
        }
    }

    /// Select the field under the byte cursor.
    fn sync_tree_to_hex(&mut self) {
        let Some(detail) = &self.detail else { return };
        if let Some(path) = detail::deepest_at(&detail.tree, self.hex.source, self.hex.cursor) {
            self.tree.reveal(&detail.tree, &path);
        }
    }

    /// Bytes of the data source shown in the bytes pane.
    pub fn hex_bytes(&self) -> &[u8] {
        self.detail
            .as_ref()
            .and_then(|d| d.sources.get(self.hex.source))
            .map_or(&[], |s| s.bytes.as_slice())
    }

    // ---- windows ----------------------------------------------------------

    fn open_follow(&mut self, protocol: &str, filter: &str) {
        self.overlay = Some(Overlay::Follow(Box::new(FollowView::new(protocol, filter))));
        self.send(Request::Follow {
            protocol: protocol.to_string(),
            filter: filter.to_string(),
        });
    }

    /// Follow the selected packet's stream, asking which protocol if there is
    /// a choice. `wanted` picks one by name.
    fn follow_selected(&mut self, wanted: Option<&str>) {
        if !self.detail_ready() {
            return;
        }
        let Some(detail) = &self.detail else { return };
        let options = detail.follow.clone();
        if options.is_empty() {
            self.info("This packet is not part of a stream that can be followed.");
            return;
        }
        if let Some(name) = wanted {
            if let Some((p, f)) = options.iter().find(|(p, _)| p.eq_ignore_ascii_case(name)) {
                self.open_follow(&p.clone(), &f.clone());
            } else {
                let names: Vec<&str> = options.iter().map(|(p, _)| p.as_str()).collect();
                self.error(format!(
                    "This packet has no {name} stream. Available: {}.",
                    names.join(", ")
                ));
            }
            return;
        }
        if options.len() == 1 {
            let (p, f) = &options[0];
            self.open_follow(&p.clone(), &f.clone());
            return;
        }
        let mut items: Vec<MenuItem> = Vec::new();
        for (protocol, filter) in &options {
            let taken: Vec<char> = items.iter().map(|i| i.key).collect();
            items.push(MenuItem {
                key: menu_key(protocol, &taken),
                label: format!("{protocol} stream"),
                action: Action::Follow {
                    protocol: protocol.clone(),
                    filter: filter.clone(),
                },
            });
        }
        self.overlay = Some(Overlay::Menu(Menu {
            title: "Follow".into(),
            items,
            selected: 0,
        }));
    }

    fn open_stats(&mut self, kind: stats::Kind, wanted: Option<&str>) {
        let mut tabs: Vec<String> = match kind {
            stats::Kind::Conversations | stats::Kind::Endpoints => {
                let prefix = if kind == stats::Kind::Conversations {
                    "conv:"
                } else {
                    "endpt:"
                };
                let common = ["Ethernet", "IPv4", "IPv6", "TCP", "UDP"];
                match &self.info {
                    Some(info) => common
                        .iter()
                        .filter(|p| info.convs.iter().any(|t| t.tap == format!("{prefix}{p}")))
                        .map(ToString::to_string)
                        .collect(),
                    None => common.iter().map(ToString::to_string).collect(),
                }
            }
            stats::Kind::Objects => match &self.info {
                Some(info) if !info.eo.is_empty() => info
                    .eo
                    .iter()
                    .filter_map(|t| t.tap.strip_prefix("eo:"))
                    .map(str::to_ascii_uppercase)
                    .collect(),
                _ => ["HTTP", "SMB", "TFTP", "IMF", "DICOM"]
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            },
            _ => Vec::new(),
        };
        let mut tab = match kind {
            stats::Kind::Conversations | stats::Kind::Endpoints => {
                tabs.iter().position(|t| t == "TCP").unwrap_or(0)
            }
            stats::Kind::Objects => tabs.iter().position(|t| t == "HTTP").unwrap_or(0),
            _ => 0,
        };
        if let Some(name) = wanted.filter(|_| kind.has_tabs()) {
            let name = match name.to_ascii_lowercase().as_str() {
                "eth" | "ethernet" => "Ethernet".to_string(),
                "ip" | "ipv4" => "IPv4".to_string(),
                "ip6" | "ipv6" => "IPv6".to_string(),
                other => other.to_ascii_uppercase(),
            };
            tab = if let Some(i) = tabs.iter().position(|t| t.eq_ignore_ascii_case(&name)) {
                i
            } else {
                // Not one of the usual tabs; trust the user and ask sharkd.
                tabs.push(name);
                tabs.len() - 1
            };
        }
        self.overlay = Some(Overlay::Stats(Box::new(StatsView::new(kind, tabs, tab))));
        self.request_stats();
    }

    /// Open one of sharkd's per-protocol statistics trees by (part of) its name.
    fn open_stat_tree(&mut self, wanted: &str) {
        let Some(info) = &self.info else {
            return self.error("sharkd has not reported its statistics yet.");
        };
        let short = |tap: &str| tap.strip_prefix("stat:").unwrap_or(tap).to_string();
        let wanted_lower = wanted.to_ascii_lowercase();
        let found = info
            .stats
            .iter()
            .find(|t| short(&t.tap).eq_ignore_ascii_case(wanted))
            .or_else(|| {
                info.stats.iter().find(|t| {
                    !wanted.is_empty() && t.name.to_ascii_lowercase().contains(&wanted_lower)
                })
            })
            .cloned();
        match found {
            Some(tap) if !wanted.is_empty() => {
                let name = tap
                    .name
                    .replace("//", " / ")
                    .replace('/', " / ")
                    .replace("  ", " ");
                self.overlay = Some(Overlay::Stats(Box::new(StatsView::tree(&tap.tap, &name))));
                self.request_stats();
            }
            _ => {
                let mut names: Vec<String> = info.stats.iter().map(|t| short(&t.tap)).collect();
                names.sort();
                let lead = if wanted.is_empty() {
                    "Usage: :stat <name>.".to_string()
                } else {
                    format!("No statistic matches `{wanted}`.")
                };
                self.error(format!("{lead} Available: {}.", names.join(", ")));
            }
        }
    }

    fn request_stats(&mut self) {
        self.tap_seq += 1;
        let id = self.tap_seq;
        let applied = self.filter.applied.clone();
        let Some(Overlay::Stats(view)) = &mut self.overlay else {
            return;
        };
        view.set_loading(id);
        let filter = if view.limit_to_filter {
            applied
        } else {
            String::new()
        };
        let taps = vec![view.tap()];
        self.send(Request::Tap { id, taps, filter });
    }

    fn open_menu(&mut self, title: &str, items: Vec<MenuItem>) {
        if items.is_empty() {
            return;
        }
        self.overlay = Some(Overlay::Menu(Menu {
            title: title.to_string(),
            items,
            selected: 0,
        }));
    }

    /// The "apply as filter" / "prepare filter" choices for the selected field.
    fn filter_menu(&mut self, prepare: bool) {
        if !self.detail_ready() {
            return;
        }
        let Some(filter) = self.selected_node().and_then(|n| n.filter.clone()) else {
            self.info("This field cannot be used as a filter.");
            return;
        };
        let current = self.filter.applied.clone();
        let make = |expr: String| {
            if prepare {
                Action::PrepareFilter(expr)
            } else {
                Action::ApplyFilter(expr)
            }
        };
        let mut items = vec![
            MenuItem {
                key: 's',
                label: format!("Selected        {filter}"),
                action: make(filter.clone()),
            },
            MenuItem {
                key: 'n',
                label: format!("Not selected    !({filter})"),
                action: make(format!("!({filter})")),
            },
        ];
        if !current.is_empty() {
            let combos = [
                ('a', "… and selected ", format!("({current}) && ({filter})")),
                ('o', "… or selected  ", format!("({current}) || ({filter})")),
                (
                    'A',
                    "… and not      ",
                    format!("({current}) && !({filter})"),
                ),
                (
                    'O',
                    "… or not       ",
                    format!("({current}) || !({filter})"),
                ),
            ];
            for (key, name, expr) in combos {
                items.push(MenuItem {
                    key,
                    label: format!("{name} {expr}"),
                    action: make(expr),
                });
            }
        }
        self.open_menu(
            if prepare {
                "Prepare filter"
            } else {
                "Apply as filter"
            },
            items,
        );
    }

    fn copy_menu(&mut self) {
        if !self.detail_ready() {
            return;
        }
        let mut items = Vec::new();
        if let Some(node) = self.selected_node() {
            let label = node.label.clone();
            // A protocol's summary line ("TCP, Src Port: 1, Dst Port: 2") is
            // not a name and a value.
            let is_protocol = node.kind.as_deref() == Some("proto");
            if let Some((_, value)) = label.split_once(": ").filter(|_| !is_protocol) {
                items.push(MenuItem {
                    key: 'v',
                    label: format!("Value         {value}"),
                    action: Action::Copy {
                        what: "value",
                        text: value.to_string(),
                    },
                });
            }
            items.push(MenuItem {
                key: 'd',
                label: format!("Description   {label}"),
                action: Action::Copy {
                    what: "description",
                    text: label,
                },
            });
            if let Some(field) = node.field.clone() {
                items.push(MenuItem {
                    key: 'n',
                    label: format!("Field name    {field}"),
                    action: Action::Copy {
                        what: "field name",
                        text: field,
                    },
                });
            }
            if let Some(filter) = node.filter.clone() {
                items.push(MenuItem {
                    key: 'f',
                    label: format!("As filter     {filter}"),
                    action: Action::Copy {
                        what: "filter",
                        text: filter,
                    },
                });
            }
        }
        if let Some((source, start, len)) = self.highlight()
            && let Some(bytes) = self
                .detail
                .as_ref()
                .and_then(|d| d.sources.get(source))
                .and_then(|s| s.bytes.get(start..start + len))
        {
            items.push(MenuItem {
                key: 'b',
                label: format!("Field bytes   {len} bytes as hex"),
                action: Action::Copy {
                    what: "field bytes",
                    text: crate::util::hex_string(bytes),
                },
            });
        }
        let bytes = self.hex_bytes();
        if !bytes.is_empty() {
            items.push(MenuItem {
                key: 'h',
                label: format!("Hex dump      {} bytes", bytes.len()),
                action: Action::Copy {
                    what: "hex dump",
                    text: crate::util::hexdump(bytes),
                },
            });
        }
        if let Some(row) = self.list.selected_row() {
            let summary = row.cols.join("  ");
            items.push(MenuItem {
                key: 's',
                label: "Summary line  the packet list row".to_string(),
                action: Action::Copy {
                    what: "summary line",
                    text: summary,
                },
            });
        }
        if items.is_empty() {
            self.info("Nothing to copy yet.");
        } else {
            self.open_menu("Copy", items);
        }
    }

    fn stats_menu(&mut self) {
        use stats::Kind::*;
        let entry = |key, label: &str, kind| MenuItem {
            key,
            label: label.to_string(),
            action: Action::Stats(kind),
        };
        self.open_menu(
            "Statistics",
            vec![
                entry('c', "Conversations", Conversations),
                entry('e', "Endpoints", Endpoints),
                entry('h', "Protocol hierarchy", Hierarchy),
                entry('x', "Expert information", Expert),
                entry('o', "Export objects", Objects),
            ],
        );
    }

    fn run_action(&mut self, action: Action) {
        match action {
            Action::ApplyFilter(expr) => self.apply_filter(&expr),
            Action::PrepareFilter(expr) => {
                self.filter.input.set(&expr);
                if let Some((seq, filter)) = self.filter.check_request() {
                    self.send(Request::Check { seq, filter });
                }
                self.focus_filter();
                // The point of preparing is to edit before applying.
                self.filter.select_all = false;
            }
            Action::Copy { what, text } => self.copy(what, text),
            Action::Follow { protocol, filter } => self.open_follow(&protocol, &filter),
            Action::Stats(kind) => self.open_stats(kind, None),
        }
    }

    fn copy(&mut self, what: &str, text: String) {
        // Terminals cap clipboard escapes; stay well under common limits.
        const LIMIT: usize = 512 * 1024;
        if text.len() > LIMIT {
            self.error(format!(
                "Too large to copy ({} bytes). Save it to a file instead.",
                text.len()
            ));
            return;
        }
        self.clipboard.push(text);
        self.info(format!("Copied {what} to the clipboard."));
    }

    // ---- columns ----------------------------------------------------------

    /// The profile's columns plus the ones added here.
    pub(super) fn build_columns(&mut self) {
        let Some(status) = &self.status else { return };
        let mut columns = Columns::new(status, self.info.as_ref());
        if columns.can_customize() {
            for (title, field) in &self.extra_columns {
                columns.add_custom(title, field);
            }
        }
        self.columns = columns;
    }

    /// Start adding a column for `field`; it appears once sharkd has
    /// confirmed the field exists.
    pub(super) fn add_column(&mut self, field: &str, title: Option<&str>) {
        let field = field.trim();
        if field.is_empty() || field.contains(char::is_whitespace) || field.contains(':') {
            self.error("A column shows one field, e.g. :column tcp.stream");
            return;
        }
        if self.extra_columns.iter().any(|(_, f)| f == field) {
            self.info(format!("There is already a column for {field}."));
            return;
        }
        let title = title.map_or(field, str::trim).to_string();
        self.send(Request::CheckField {
            title,
            field: field.to_string(),
        });
    }

    pub(super) fn on_field_checked(
        &mut self,
        title: String,
        field: String,
        result: Result<(), String>,
    ) {
        if let Err(reason) = result {
            self.error(format!("No column added: {reason}"));
            return;
        }
        if !self.columns.can_customize() && self.status.is_some() {
            self.error("This version of sharkd cannot show extra columns.");
            return;
        }
        if self.extra_columns.iter().any(|(_, f)| *f == field) {
            return;
        }
        self.info(format!("Added column {title}."));
        self.extra_columns.push((title, field));
        self.columns_changed();
    }

    /// Remove an added column by its title or field, or all of them.
    pub(super) fn remove_column(&mut self, which: &str) {
        let before = self.extra_columns.len();
        if which.is_empty() {
            self.extra_columns.clear();
        } else {
            self.extra_columns
                .retain(|(title, field)| title != which && field != which);
        }
        match before - self.extra_columns.len() {
            0 if which.is_empty() => self.info("No columns have been added."),
            0 => self.error(format!(
                "No added column is called {which}. Columns from the Wireshark profile are changed in Wireshark."
            )),
            1 => self.info("Removed 1 column."),
            n => self.info(format!("Removed {n} columns.")),
        }
        if before != self.extra_columns.len() {
            self.columns_changed();
        }
    }

    fn columns_changed(&mut self) {
        if self.status.is_some() {
            self.build_columns();
            // Widths were measured for the old set of columns.
            self.list.widths.clear();
            self.refresh_list();
        }
    }

    /// Add the field selected in the details pane as a column.
    pub(super) fn column_from_selected(&mut self) {
        if !self.detail_ready() {
            return;
        }
        match self.selected_node().and_then(|n| n.field.clone()) {
            Some(field) => self.add_column(&field, None),
            None => self.info("This line is not a field, so it cannot be a column."),
        }
    }

    pub fn selected_node(&self) -> Option<&crate::sharkd::types::Node> {
        self.detail.as_ref()?.node(self.tree.selected_path()?)
    }

    fn focus_filter(&mut self) {
        if self.focus != Focus::Filter {
            self.focus_before_filter = self.focus;
        }
        self.focus = Focus::Filter;
        self.overlay = None;
        self.filter.select_all = !self.filter.input.is_empty();
        self.filter.apply_when_checked = false;
    }

    fn leave_filter(&mut self) {
        self.filter.close_completions();
        self.filter.select_all = false;
        self.filter.apply_when_checked = false;
        self.focus = self.focus_before_filter;
    }

    fn sharkd_path(&self) -> &Path {
        &self.launch.program
    }

    /// Process id of the sharkd in use.
    pub fn sharkd_pid(&self) -> u32 {
        self.worker.pid()
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // Stop the capture before the worker is torn down, so dumpcap never
        // outlives us even if shutting sharkd down is interrupted.
        self.capture.take();
    }
}

fn contains(text: &str) -> String {
    format!("frame contains {}", filter_quote(text))
}

/// A hotkey for a menu entry: the first letter of its label that no earlier
/// entry uses, else the first free digit.
fn menu_key(label: &str, taken: &[char]) -> char {
    label
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(char::is_ascii_alphanumeric)
        .chain('1'..='9')
        .find(|c| !taken.contains(c))
        .unwrap_or('0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_keys_are_unique() {
        let mut taken = Vec::new();
        for label in ["HTTP", "HTTP2", "TCP", "TLS"] {
            let key = menu_key(label, &taken);
            assert!(!taken.contains(&key));
            taken.push(key);
        }
        assert_eq!(taken, ['h', 't', 'c', 'l']);
    }

    #[test]
    fn text_search_is_quoted_as_a_filter() {
        assert_eq!(contains("hello"), r#"frame contains "hello""#);
        assert_eq!(contains(r#"say "hi""#), r#"frame contains "say \"hi\"""#);
    }
}
