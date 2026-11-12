//! Application state and behaviour. Nothing here touches the terminal: the
//! app consumes `Event`s and is drawn by `crate::ui`, so the whole thing can
//! be driven from tests.

pub mod cmdline;
pub mod columns;
pub mod detail;
pub mod filter;
pub mod follow;
pub mod graph;
pub mod help;
pub mod keymap;
pub mod list;
pub mod search;
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
use crate::config::{Config, History, SavedColumn, State, Store};
use crate::sharkd::types::{Info, Status};
use crate::sharkd::{Launch, Purpose, Reply, Request, Seek, Worker};
use crate::text_input::TextInput;
use crate::theme::{RowColors, Theme};

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
    /// A background job produced text to read, such as the capture file's
    /// properties.
    Report {
        title: String,
        text: Result<String, String>,
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
    Copy {
        what: &'static str,
        text: String,
    },
    Follow {
        protocol: String,
        filter: String,
    },
    Stats(stats::Kind),
    /// Run a command line, as if typed after `:`.
    Command(String),
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
    Help {
        top: usize,
    },
    Menu(Menu),
    Follow(Box<FollowView>),
    Stats(Box<StatsView>),
    Columns(ColumnEditor),
    /// Packets over time.
    Graph(Box<graph::IoGraph>),
    /// Plain text to read and scroll.
    Text {
        title: String,
        lines: Vec<String>,
        top: usize,
    },
}

/// The share of the screen each pane starts with: list, details, bytes.
pub const DEFAULT_SPLIT: [u16; 3] = [40, 35, 25];

/// A key that is waiting for the key after it, as in vim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Pending {
    #[default]
    None,
    /// `m`: a letter names the mark to set.
    Mark,
    /// `'`: a letter names the mark to go to; another `'` goes back.
    Jump,
    /// `Z`: a second `Z` quits.
    Z,
    /// `Ctrl-w`: a window command.
    Window,
}

/// The column editor: a cursor over [`App::column_list`].
#[derive(Debug, Clone, Copy)]
pub struct ColumnEditor {
    pub selected: usize,
}

/// A change made in the column editor to the column under the cursor.
#[derive(Debug, Clone)]
pub enum ColumnEdit {
    Toggle,
    Delete,
    Move(i64),
    Rename(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    Command,
    Find,
    SaveStream,
    /// Text to look for in the stream being followed.
    FollowSearch,
    /// A field, and optionally a title, for a new column.
    AddColumn,
    RenameColumn,
}

#[derive(Debug)]
pub struct Prompt {
    pub kind: PromptKind,
    /// What is shown before the text being typed.
    pub label: String,
    pub input: TextInput,
    /// Completions on offer, for the command line.
    pub candidates: cmdline::Candidates,
}

impl PromptKind {
    /// What a prompt of this kind says before the text, unless it is told
    /// something more exact.
    fn label(self) -> &'static str {
        match self {
            PromptKind::Command => ":",
            PromptKind::Find => "Find: ",
            PromptKind::SaveStream => "Save stream to: ",
            PromptKind::FollowSearch => "Search the stream (text, or /regex/): ",
            PromptKind::AddColumn => "Field for the new column, then a title if you like: ",
            PromptKind::RenameColumn => "New title: ",
        }
    }
}

impl Prompt {
    pub fn label(&self) -> &str {
        &self.label
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
    query: search::Query,
    plan: search::Plan,
    wrapped: bool,
}

/// Something to point out in a packet once its details have arrived: the
/// place a search matched.
struct Reveal {
    frame: u32,
    target: search::Target,
    pattern: String,
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
    /// How packet times are shown to begin with.
    pub time_format: TimeFormat,
    /// Where choices made while running are remembered.
    pub store: Store,
    /// Where the user's own themes are.
    pub themes_dir: Option<PathBuf>,
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
    history: History,
    command_history: Vec<String>,

    pub config: Config,
    pub theme: Theme,
    pub source: PathBuf,
    pub title: String,
    pub info: Option<Info>,
    wireshark: Option<(u32, u32)>,
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
    reveal: Option<Reveal>,
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
    /// Ctrl-z was pressed: the program should stop and give the terminal
    /// back until it is continued.
    pub suspend: bool,
    /// A key waiting for the one after it.
    pub pending: Pending,
    /// A count typed before a motion, as in `25G`.
    count: Option<u32>,
    /// Where the focus was before the count's first digit, which is also a
    /// pane key, moved it.
    count_focus: Option<Focus>,
    /// When the count's last digit was typed.
    count_at: Option<Instant>,
    /// A count and a `g` have just gone to a row; a second `g` is nothing.
    after_count_g: bool,
    /// Marks `a` to `z`: packet numbers in this capture.
    pub local_marks: std::collections::BTreeMap<char, u32>,
    /// Where the cursor was before the last jump, for `''`.
    jump_back: Option<u32>,
    /// A packet to go to once the capture being opened has loaded.
    after_open_goto: Option<u32>,
    /// Key mappings, read from the remembered ones: a key and what it
    /// stands for.
    maps: Vec<(KeyEvent, Vec<KeyEvent>)>,
    /// Keys being played back from a mapping are not themselves mapped.
    replaying: bool,
    /// Choices remembered between runs.
    pub state: State,
    store: Store,
    /// The look that follows the terminal's colours, kept to go back to.
    base_theme: Theme,
    theme_name: String,
    themes_dir: Option<PathBuf>,
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
        let wireshark = crate::sharkd::version(&launch.program);
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
        let base_theme = theme.clone();
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
            history,
            command_history: Vec::new(),
            tree: TreeState::with_expand_all(config.ui.expand_all),
            config,
            theme,
            source: options.source.clone(),
            title: options.title,
            info: None,
            wireshark,
            status: None,
            load: LoadState::Loading,
            columns: Columns::default(),
            time_format: options.time_format,
            filter,
            list: PacketList::default(),
            detail: None,
            detail_requested: None,
            hex: HexState::default(),
            focus: Focus::List,
            focus_before_filter: Focus::List,
            zoom: false,
            layout,
            split: DEFAULT_SPLIT,
            overlay: None,
            prompt: None,
            message: None,
            marks: BTreeSet::new(),
            time_refs: BTreeSet::new(),
            find: None,
            reveal: None,
            goto_exact: None,
            tail: None,
            pending_open: None,
            loaded_once: false,
            capture: None,
            capture_failure_reported: false,
            tap_seq: 0,
            quit: false,
            suspend: false,
            pending: Pending::None,
            count: None,
            count_focus: None,
            count_at: None,
            after_count_g: false,
            local_marks: std::collections::BTreeMap::new(),
            jump_back: None,
            after_open_goto: None,
            maps: Vec::new(),
            replaying: false,
            state: options.store.load(),
            store: options.store,
            base_theme,
            theme_name: "default".to_string(),
            themes_dir: options.themes_dir,
            download_dir: PathBuf::from("."),
            clipboard: Vec::new(),
            areas: Areas::default(),
            ticks: 0,
        };

        app.load_maps();
        // The theme last chosen with `:theme`, else the one in the config.
        if let Some(name) = app
            .state
            .theme
            .clone()
            .or_else(|| app.config.ui.theme.clone())
            && let Err(e) = app.set_theme(&name)
        {
            app.say(Level::Warn, format!("Theme {name} not used: {e}"));
        }

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
                } else if key.code == KeyCode::Char('z')
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    self.suspend = true;
                } else if let Some(keys) = self.mapped(key) {
                    self.replaying = true;
                    for key in keys {
                        self.type_key(key);
                    }
                    self.replaying = false;
                } else {
                    self.type_key(key);
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
            Event::Report { title, text } => match text {
                Ok(text) => {
                    self.message = None;
                    self.overlay = Some(Overlay::Text {
                        title,
                        lines: text
                            .lines()
                            .map(|l| crate::util::sanitize(l).into_owned())
                            .collect(),
                        top: 0,
                    });
                }
                Err(e) => self.error(e),
            },
        }
        self.request_pages();
        self.sync_detail();
        self.replay_typed_ahead();
    }

    fn type_key(&mut self, key: KeyEvent) {
        if self.holds_for_opening(&key) {
            self.typed_ahead.push_back(key);
        } else {
            self.on_key(key);
        }
    }

    // ---- key mappings -----------------------------------------------------

    /// What `key` stands for, if it is mapped and typed where mappings
    /// apply: not while text is being entered, where a key is its character.
    fn mapped(&self, key: KeyEvent) -> Option<Vec<KeyEvent>> {
        if self.replaying || self.prompt.is_some() || self.focus == Focus::Filter {
            return None;
        }
        let wanted = keymap::normalize(key);
        self.maps
            .iter()
            .find(|(from, _)| keymap::normalize(*from) == wanted)
            .map(|(_, to)| to.clone())
    }

    /// Read the remembered mappings. One that no longer parses is skipped.
    fn load_maps(&mut self) {
        self.maps = self
            .state
            .maps
            .iter()
            .filter_map(|map| {
                let from = keymap::parse(&map.key).ok()?;
                let to = keymap::parse(&map.keys).ok()?;
                (from.len() == 1).then(|| (from[0], to))
            })
            .collect();
    }

    /// `:map <key> <keys>`: make one key stand for a sequence of keys.
    pub(super) fn map_key(&mut self, arg: &str) {
        let (key, keys) = match arg.split_once(char::is_whitespace) {
            Some((k, rest)) => (k, rest.trim()),
            None => (arg, ""),
        };
        if key.is_empty() {
            return self.maps_menu();
        }
        if keys.is_empty() {
            return self.error("Usage: :map <key> <keys>, e.g. :map <f5> :conv<enter>");
        }
        let parsed = match (keymap::parse(key), keymap::parse(keys)) {
            (Ok(from), Ok(to)) if from.len() == 1 => (from[0], to),
            (Ok(_), Ok(_)) => return self.error("Only a single key can be mapped."),
            (Err(e), _) | (_, Err(e)) => return self.error(e),
        };
        let name = keymap::describe(parsed.0);
        self.state.maps.retain(|m| m.key != name);
        self.state.maps.push(crate::config::KeyMap {
            key: name.clone(),
            keys: keys.to_string(),
        });
        self.save_state();
        self.load_maps();
        self.info(format!("{name} now types {keys}"));
    }

    /// `:unmap <key>`.
    pub(super) fn unmap_key(&mut self, arg: &str) {
        let name = match keymap::parse(arg.trim()) {
            Ok(keys) if keys.len() == 1 => keymap::describe(keys[0]),
            Ok(_) => return self.error("Usage: :unmap <key>"),
            Err(e) => return self.error(e),
        };
        let before = self.state.maps.len();
        self.state.maps.retain(|m| m.key != name);
        if self.state.maps.len() == before {
            return self.error(format!("{name} is not mapped."));
        }
        self.save_state();
        self.load_maps();
        self.info(format!("{name} is no longer mapped."));
    }

    fn maps_menu(&mut self) {
        if self.state.maps.is_empty() {
            return self.info("No keys are mapped. Example: :map <f5> :conv<enter>");
        }
        let keys = "abcdefghijklmnopqrstuvwxyz";
        let items = self
            .state
            .maps
            .iter()
            .zip(keys.chars())
            .map(|(map, key)| MenuItem {
                key,
                label: format!("{:<10} {}", map.key, map.keys),
                // Choosing one puts it on the command line, ready to change.
                action: Action::Command(format!("edit-map {}", map.key)),
            })
            .collect();
        self.open_menu("Key mappings (Enter to change one)", items);
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
        self.note_jump();
        self.goto_exact = Some(num);
        self.locate(num, Seek::Nearest, Purpose::Select);
        if self.filter.applied.is_empty() {
            self.goto_exact = None;
        }
    }

    /// Remember where the cursor is, so that `''` can come back to it.
    pub(super) fn note_jump(&mut self) {
        if let Some(num) = self.list.selected_num() {
            self.jump_back = Some(num);
        }
    }

    // ---- marks ------------------------------------------------------------

    /// Set mark `letter` on the selected packet. A lower-case mark belongs
    /// to this capture; an upper-case one remembers the file as well and is
    /// kept between runs.
    pub(super) fn set_mark(&mut self, letter: char) {
        let Some(num) = self.list.selected_num() else {
            return self.info("Select a packet first.");
        };
        if letter.is_ascii_lowercase() {
            self.local_marks.insert(letter, num);
            return self.info(format!("Mark {letter} is packet {num}."));
        }
        if self.capture.is_some() || self.tail.is_some() {
            return self.error(
                "A mark that remembers its file needs a capture that is not still being written.",
            );
        }
        let summary = self
            .list
            .selected_row()
            .and_then(|row| row.cols.last().cloned())
            .unwrap_or_default();
        self.state.marks.insert(
            letter.to_string(),
            crate::config::FileMark {
                // One spelling of the path, so that the mark is recognised
                // however the capture is opened next time.
                file: std::fs::canonicalize(&self.source).unwrap_or_else(|_| self.source.clone()),
                packet: num,
                summary,
            },
        );
        self.save_state();
        self.info(format!("Mark {letter} is packet {num} of {}.", self.title));
    }

    /// Go to mark `letter`, opening its capture if it is in another one.
    pub(super) fn jump_to_mark(&mut self, letter: char) {
        if letter.is_ascii_lowercase() {
            return match self.local_marks.get(&letter).copied() {
                Some(num) => self.goto_frame(num),
                None => self.error(format!("Mark {letter} is not set. Set it with m{letter}.")),
            };
        }
        let Some(mark) = self.state.marks.get(&letter.to_string()).cloned() else {
            return self.error(format!("Mark {letter} is not set. Set it with m{letter}."));
        };
        let same = |a: &Path, b: &Path| match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
            (Ok(a), Ok(b)) => a == b,
            _ => a == b,
        };
        if same(&mark.file, &self.source) {
            self.goto_frame(mark.packet);
        } else {
            self.after_open_goto = Some(mark.packet);
            self.open(mark.file);
            if self.pending_open.is_none() {
                // The file is gone; nothing will load.
                self.after_open_goto = None;
            }
        }
    }

    /// `''`: go back to where the cursor was before the last jump.
    pub(super) fn jump_back(&mut self) {
        match self.jump_back {
            Some(num) => self.goto_frame(num),
            None => self.info("There is no earlier position to go back to."),
        }
    }

    pub(super) fn marks_menu(&mut self) {
        let mut items: Vec<MenuItem> = self
            .local_marks
            .iter()
            .map(|(letter, num)| MenuItem {
                key: *letter,
                label: format!("packet {num}"),
                action: Action::Command(format!("jump {letter}")),
            })
            .collect();
        for (letter, mark) in &self.state.marks {
            let Some(key) = letter.chars().next() else {
                continue;
            };
            let file = mark
                .file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            items.push(MenuItem {
                key,
                label: format!(
                    "packet {} of {file}  {}",
                    mark.packet,
                    crate::util::truncate(&mark.summary, 50)
                ),
                action: Action::Command(format!("jump {letter}")),
            });
        }
        if items.is_empty() {
            return self.info("No marks are set. ma marks a packet; 'a comes back to it.");
        }
        self.open_menu("Marks", items);
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

    /// What the find prompt would search with the choices as they stand.
    pub fn find_options(&self) -> (search::Target, search::Kind, bool) {
        let prefs = &self.state.find;
        (
            search::Target::parse(&prefs.target),
            search::Kind::parse(&prefs.kind),
            prefs.case_sensitive,
        )
    }

    /// Change where, how or with what case the find prompt searches, and
    /// remember it.
    pub(super) fn set_find_options(
        &mut self,
        target: search::Target,
        kind: search::Kind,
        case: bool,
    ) {
        self.state.find = crate::config::FindPrefs {
            target: target.name().to_string(),
            kind: kind.key().to_string(),
            case_sensitive: case,
        };
        self.save_state();
        if let Some(prompt) = &mut self.prompt
            && prompt.kind == PromptKind::Find
        {
            prompt.label = search::Query::describe(target, kind, case);
        }
    }

    fn start_find(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        let (target, mut kind, case_sensitive) = self.find_options();
        let mut text = text;
        // A leading quote means "this is text", when it could be either.
        if kind == search::Kind::Auto
            && let Some(quoted) = text.strip_prefix('"')
        {
            text = quoted.strip_suffix('"').unwrap_or(quoted);
            kind = search::Kind::Text;
        }
        let query = search::Query {
            target,
            kind,
            case_sensitive,
            text: text.to_string(),
        };
        let plan = match query.plan() {
            Ok(plan) => plan,
            Err(e) => return self.error(e),
        };
        self.find = Some(Find {
            busy: None,
            queued: Default::default(),
            query,
            plan,
            wrapped: false,
        });
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
        let generation = self.list.generation;
        let request = match &find.plan {
            search::Plan::Filter(filter) => Request::Locate {
                generation,
                filter: if self.filter.applied.is_empty() {
                    filter.clone()
                } else {
                    format!("({}) && ({filter})", self.filter.applied)
                },
                frame: from,
                seek,
                purpose: Purpose::Find,
            },
            search::Plan::Details(pattern) => Request::SearchDetails {
                generation,
                filter: self.filter.applied.clone(),
                from,
                seek,
                pattern: pattern.clone(),
                summary: None,
            },
            search::Plan::Summary(pattern) => Request::SearchDetails {
                generation,
                filter: self.filter.applied.clone(),
                from,
                seek,
                pattern: pattern.clone(),
                summary: Some(self.columns.specs(self.time_format)),
            },
        };
        self.send(request);
    }

    /// Whether a search is under way.
    pub fn searching(&self) -> bool {
        self.find
            .as_ref()
            .is_some_and(|f| f.busy == Some(self.list.generation))
    }

    /// Call off a search that is under way.
    pub(super) fn stop_find(&mut self) {
        if let Some(find) = &mut self.find {
            find.busy = None;
            find.queued.clear();
        }
        self.info("Search stopped.");
    }

    /// Point out where the search matched in the packet now shown.
    pub(super) fn reveal_match(&mut self) {
        let Some(reveal) = &self.reveal else { return };
        let Some(detail) = &self.detail else { return };
        if detail.num != reveal.frame {
            return;
        }
        let Some(reveal) = self.reveal.take() else {
            return;
        };
        let Ok(regex) = search::compile(&reveal.pattern) else {
            return;
        };
        let Some(detail) = &self.detail else { return };
        match reveal.target {
            search::Target::Details => {
                if let Some(path) = search::find_node(&detail.tree, &regex) {
                    self.tree.reveal(&detail.tree, &path);
                    self.sync_hex_to_tree();
                }
            }
            search::Target::Bytes => {
                // The frame's own bytes first, then reassembled or decrypted data.
                let hit = detail.sources.iter().enumerate().find_map(|(i, source)| {
                    regex.find(&source.bytes).map(|m| (i, m.start(), m.len()))
                });
                if let Some((source, start, len)) = hit {
                    if let Some(path) = detail::deepest_at(&detail.tree, source, start) {
                        self.tree.reveal(&detail.tree, &path);
                    }
                    self.hex.show_range(source, start, len.max(1));
                }
            }
            search::Target::Summary => {}
        }
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
        let mut view = FollowView::new(protocol, filter);
        // Shown the way it was last looked at.
        if let Some(mode) = &self.state.follow_mode {
            view.mode = follow::Mode::parse(mode);
        }
        self.overlay = Some(Overlay::Follow(Box::new(view)));
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

    /// The Wireshark version of the sharkd in use, as (major, minor).
    pub fn wireshark_version(&self) -> Option<(u32, u32)> {
        self.wireshark
    }

    /// Whether `feature` is missing because Wireshark is older than `needs`,
    /// telling the user if so. An unknown version is given the benefit of
    /// the doubt.
    pub(super) fn lacks(&mut self, feature: &str, needs: (u32, u32)) -> bool {
        match self.wireshark_version() {
            Some(have) if have < needs => {
                self.error(format!(
                    "{feature} need Wireshark {}.{} or newer; this is {}.{}.",
                    needs.0, needs.1, have.0, have.1
                ));
                true
            }
            _ => false,
        }
    }

    fn open_stats(&mut self, kind: stats::Kind, wanted: Option<&str>) {
        if kind == stats::Kind::Hierarchy && self.lacks("Protocol hierarchy statistics", (4, 2)) {
            return;
        }
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
            stats::Kind::Flow => match &self.info {
                Some(info) if !info.seqa.is_empty() => info
                    .seqa
                    .iter()
                    .filter_map(|t| t.tap.strip_prefix("seqa:"))
                    .map(|name| match name {
                        "any" => "All".to_string(),
                        other => other.to_ascii_uppercase(),
                    })
                    .collect(),
                _ => vec!["All".to_string(), "TCP".to_string()],
            },
            _ => Vec::new(),
        };
        let mut tab = match kind {
            stats::Kind::Conversations | stats::Kind::Endpoints => {
                tabs.iter().position(|t| t == "TCP").unwrap_or(0)
            }
            stats::Kind::Objects => tabs.iter().position(|t| t == "HTTP").unwrap_or(0),
            stats::Kind::Flow => tabs.iter().position(|t| t == "All").unwrap_or(0),
            _ => 0,
        };
        if let Some(name) = wanted.filter(|_| kind.has_tabs()) {
            let name = match name.to_ascii_lowercase().as_str() {
                "eth" | "ethernet" => "Ethernet".to_string(),
                "ip" | "ipv4" => "IPv4".to_string(),
                "ip6" | "ipv6" => "IPv6".to_string(),
                "any" | "all" => "All".to_string(),
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
                entry('f', "Flow sequence", Flow),
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
            Action::Command(line) => self.run_command(&line),
        }
    }

    // ---- packets over time -----------------------------------------------

    /// Open the graph of packets over time, or redraw it with buckets of
    /// `interval_ms`.
    pub(super) fn open_graph(&mut self, interval_ms: Option<u64>) {
        let Some(status) = &self.status else {
            return self.info("Open a capture first.");
        };
        // Enough buckets for a wide terminal; a narrow one merges them.
        let interval_ms = interval_ms.unwrap_or_else(|| graph::interval_for(status.duration, 240));
        self.tap_seq += 1;
        let request = self.tap_seq;
        let previous = match self.overlay.take() {
            Some(Overlay::Graph(graph)) => Some(graph),
            _ => None,
        };
        let filter = self.filter.applied.clone();
        self.overlay = Some(Overlay::Graph(Box::new(graph::IoGraph {
            request,
            loading: true,
            interval_ms,
            filter: filter.clone(),
            bytes: previous.as_ref().is_some_and(|g| g.bytes),
            columns: previous.as_ref().map_or(0, |g| g.columns),
            ..Default::default()
        })));
        self.send(Request::Intervals {
            id: request,
            interval_ms,
            filter,
        });
    }

    // ---- the capture file ------------------------------------------------

    /// Show what the capture file is: its format, size, time span and so
    /// on, as `capinfos` reports them.
    pub(super) fn capture_properties(&mut self) {
        let Some(status) = &self.status else {
            return self.info("Open a capture first.");
        };
        // What is known without help, shown if capinfos is not installed.
        let ours = format!(
            "File:      {}\nPackets:   {}\nDuration:  {}\nSize:      {}\n\nInstall Wireshark's capinfos for the full properties.",
            self.source.display(),
            crate::util::thousands(u64::from(status.frames)),
            crate::util::human_duration(status.duration),
            status
                .filesize
                .map_or_else(|| "unknown".to_string(), crate::util::human_bytes),
        );
        let title = format!("Capture file properties: {}", self.title);
        let Some(capinfos) = crate::capture::locate_tool("capinfos", self.sharkd_path()) else {
            self.overlay = Some(Overlay::Text {
                title,
                lines: ours.lines().map(str::to_string).collect(),
                top: 0,
            });
            return;
        };
        let source = self.source.clone();
        let events = self.events.clone();
        self.info("Reading the capture file's properties…");
        std::thread::spawn(move || {
            let text = std::process::Command::new(&capinfos)
                .arg(&source)
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|e| format!("could not run {}: {e}", capinfos.display()))
                .and_then(|out| {
                    let text = String::from_utf8_lossy(&out.stdout).into_owned();
                    if text.trim().is_empty() {
                        let why = String::from_utf8_lossy(&out.stderr);
                        Err(format!(
                            "capinfos could not read the file: {}",
                            why.lines().next().unwrap_or("no reason given").trim()
                        ))
                    } else {
                        Ok(text)
                    }
                });
            let _ = events.send(Event::Report { title, text });
        });
    }

    /// What to tell the user about the captured packets as the program
    /// leaves: where they were kept, or that they were not.
    pub fn capture_farewell(&self) -> Option<String> {
        let capture = self.capture.as_ref()?;
        let packets = self.frames();
        if capture.kept() {
            Some(format!(
                "{} packets were saved in {}",
                crate::util::thousands(u64::from(packets)),
                capture.path().display()
            ))
        } else if packets > 0 {
            Some(format!(
                "{} captured packets were not kept. To keep them next time, start with -w FILE, or use :write FILE before quitting.",
                crate::util::thousands(u64::from(packets))
            ))
        } else {
            None
        }
    }

    /// Note that `path` was opened, for the list of recent captures.
    pub(super) fn remember_capture(&mut self, path: &Path) {
        const KEEP: usize = 20;
        let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        self.state.recent_files.retain(|p| *p != path);
        self.state.recent_files.insert(0, path);
        self.state.recent_files.truncate(KEEP);
        self.save_state();
    }

    /// The captures opened lately, to pick one from.
    pub(super) fn recent_menu(&mut self) {
        let here = std::fs::canonicalize(&self.source).ok();
        let keys = "abcdefghijklmnopqrstuvwxyz";
        let items: Vec<MenuItem> = self
            .state
            .recent_files
            .iter()
            .filter(|p| Some(*p) != here.as_ref())
            .zip(keys.chars())
            .map(|(path, key)| MenuItem {
                key,
                label: path.display().to_string(),
                action: Action::Command(format!("open {}", path.display())),
            })
            .collect();
        if items.is_empty() {
            return self.info("No other captures have been opened yet.");
        }
        self.open_menu("Recent captures", items);
    }

    // ---- remembered choices and themes -----------------------------------

    /// Write the remembered choices to disk.
    pub(super) fn save_state(&self) {
        self.store.save(&self.state);
    }

    /// Switch to the theme called `name`; `default` goes back to the look
    /// that follows the terminal's own colours.
    pub fn set_theme(&mut self, name: &str) -> Result<(), String> {
        if self.base_theme.monochrome_in_use() {
            return Err("NO_COLOR is set, so themes are switched off.".into());
        }
        let mut theme = if name == "default" {
            self.base_theme.clone()
        } else {
            let spec = crate::theme::find_theme(name, self.themes_dir.as_deref())?;
            Theme::themed(&spec, self.base_theme.truecolor)?
        };
        theme.ascii = self.theme.ascii;
        theme.row_colors = self.theme.row_colors;
        self.theme = theme;
        self.theme_name = name.to_string();
        Ok(())
    }

    /// The theme in use, by name.
    pub fn theme_name(&self) -> &str {
        &self.theme_name
    }

    pub(super) fn choose_theme(&mut self, name: &str) {
        match self.set_theme(name) {
            Ok(()) => {
                self.state.theme = (name != "default").then(|| name.to_string());
                self.save_state();
                self.info(format!("Theme: {name}."));
            }
            Err(e) => self.error(e),
        }
    }

    pub(super) fn theme_menu(&mut self) {
        let names = crate::theme::theme_names(self.themes_dir.as_deref());
        let keys = "abcdefghijklmnopqrstuvwxyz0123456789";
        let items = names
            .iter()
            .zip(keys.chars())
            .map(|(name, key)| MenuItem {
                key,
                label: if *name == self.theme_name {
                    format!("{name}  (in use)")
                } else {
                    name.clone()
                },
                action: Action::Command(format!("theme {name}")),
            })
            .collect();
        self.open_menu("Theme", items);
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
        let Some((program, args)) = self.config.ui.copy_command.split_first() else {
            // The terminal sets the clipboard (OSC 52), which also works
            // over SSH.
            self.clipboard.push(text);
            return self.info(format!("Copied {what} to the clipboard."));
        };
        // The user's own command gets the text on its standard input. It
        // runs apart from the interface, which must not wait on it.
        let (program, args) = (program.clone(), args.to_vec());
        let events = self.events.clone();
        let what = what.to_string();
        std::thread::spawn(move || {
            use std::io::Write as _;
            use std::process::{Command, Stdio};
            let outcome = Command::new(&program)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("Could not run the copy command {program}: {e}"))
                .and_then(|mut child| {
                    if let Some(mut stdin) = child.stdin.take() {
                        // A command that does not read its input closes the
                        // pipe; its exit status says whether that mattered.
                        let _ = stdin.write_all(text.as_bytes());
                    }
                    let output = child
                        .wait_with_output()
                        .map_err(|e| format!("The copy command {program} failed: {e}"))?;
                    if output.status.success() {
                        Ok(())
                    } else {
                        let why = String::from_utf8_lossy(&output.stderr);
                        let why = why.lines().next().unwrap_or("").trim().to_string();
                        Err(if why.is_empty() {
                            format!("The copy command {program} failed.")
                        } else {
                            format!("The copy command {program} failed: {why}")
                        })
                    }
                });
            let (ok, message) = match outcome {
                Ok(()) => (true, format!("Copied {what} with {program}.")),
                Err(e) => (false, e),
            };
            let _ = events.send(Event::Job { ok, message });
        });
    }

    // ---- columns ----------------------------------------------------------

    /// Every column there is, shown or hidden: the set arranged in the
    /// column editor if there is one, else the Wireshark profile's.
    pub fn column_list(&self) -> Vec<SavedColumn> {
        match (&self.state.columns, &self.status) {
            (Some(list), _) => list.clone(),
            (None, Some(status)) => Columns::profile_list(status),
            (None, None) => Vec::new(),
        }
    }

    /// Whether the columns are the user's own arrangement.
    pub fn columns_customised(&self) -> bool {
        self.state.columns.is_some()
    }

    pub(super) fn build_columns(&mut self) {
        if self.status.is_none() {
            return;
        }
        let mut columns = Columns::from_list(&self.column_list(), self.info.as_ref());
        if self.state.columns.is_some() && !columns.can_customize() {
            // sharkd has not said how it numbers its columns (yet, or ever):
            // an arrangement cannot be described to it, so show its own.
            if let Some(status) = &self.status {
                columns = Columns::new(status, self.info.as_ref());
            }
        }
        self.columns = columns;
    }

    /// Replace the arrangement, remember it and redraw the list with it.
    /// `None` goes back to the Wireshark profile's columns.
    pub(super) fn set_column_list(&mut self, list: Option<Vec<SavedColumn>>) {
        self.state.columns = list;
        self.save_state();
        if self.status.is_some() {
            self.build_columns();
            // Widths were measured for the old set of columns.
            self.list.widths.clear();
            self.refresh_list();
        }
    }

    fn can_arrange_columns(&mut self) -> bool {
        if self.info.is_some() && !Columns::from_list(&[], self.info.as_ref()).can_customize() {
            self.error("This version of sharkd cannot show a changed set of columns.");
            return false;
        }
        true
    }

    /// Start adding a column for `field`; it appears once sharkd has
    /// confirmed the field exists.
    pub(super) fn add_column(&mut self, field: &str, title: Option<&str>) {
        let field = field.trim();
        if field.is_empty() || field.contains(char::is_whitespace) || field.contains(':') {
            self.error("A column shows one field, e.g. :column tcp.stream");
            return;
        }
        if !self.can_arrange_columns() {
            return;
        }
        let format = format!("%Cus:{field}:0");
        if self.column_list().iter().any(|c| c.format == format) {
            self.info(format!("There is already a column for {field}."));
            return;
        }
        let title = title
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .unwrap_or(field);
        self.send(Request::CheckField {
            title: title.to_string(),
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
        let format = format!("%Cus:{field}:0");
        if self.column_list().iter().any(|c| c.format == format) {
            return;
        }
        self.info(format!("Added column {title}."));
        self.insert_column(SavedColumn {
            title,
            format,
            visible: true,
        });
    }

    /// Add a column just before Info, which is where a new one is wanted:
    /// next to the summary it adds to.
    pub(super) fn insert_column(&mut self, column: SavedColumn) {
        let mut list = self.column_list();
        let at = list
            .iter()
            .position(|c| c.format == "%i")
            .unwrap_or(list.len());
        list.insert(at, column);
        self.set_column_list(Some(list));
        if let Some(Overlay::Columns(editor)) = &mut self.overlay {
            editor.selected = at;
        }
    }

    /// Add one of the built-in column types by its format code.
    pub(super) fn add_built_in_column(&mut self, format: &str, title: &str) {
        if !self.can_arrange_columns() {
            return;
        }
        let known = columns::BUILT_IN.iter().find(|(_, code)| *code == format);
        let Some((default_title, _)) = known else {
            self.error(format!("{format} is not a column type."));
            return;
        };
        let title = if title.trim().is_empty() {
            default_title
        } else {
            title.trim()
        };
        self.info(format!("Added column {title}."));
        self.insert_column(SavedColumn {
            title: title.to_string(),
            format: format.to_string(),
            visible: true,
        });
    }

    /// Remove a column by its title or field, or go back to the Wireshark
    /// profile's columns.
    pub(super) fn remove_column(&mut self, which: &str) {
        if which.is_empty() {
            if self.state.columns.is_none() {
                self.info("The columns are already the Wireshark profile's.");
            } else {
                self.set_column_list(None);
                self.info("Columns reset to the Wireshark profile's.");
            }
            return;
        }
        let mut list = self.column_list();
        let custom = format!("%Cus:{which}:0");
        let before = list.len();
        list.retain(|c| c.title != which && c.format != custom);
        if list.len() == before {
            self.error(format!("There is no column called {which}."));
        } else if !list.iter().any(|c| c.visible) {
            self.error("That would leave no columns.");
        } else {
            self.set_column_list(Some(list));
            self.info(format!("Removed column {which}."));
        }
    }

    // ---- column editor ----------------------------------------------------

    pub(super) fn open_column_editor(&mut self) {
        if self.status.is_none() {
            self.info("Open a capture first.");
            return;
        }
        if !self.can_arrange_columns() {
            return;
        }
        self.overlay = Some(Overlay::Columns(ColumnEditor { selected: 0 }));
    }

    /// Apply `change` to the column list from the editor, keeping the cursor
    /// on a sensible row.
    pub(super) fn edit_columns(&mut self, change: ColumnEdit) {
        let Some(Overlay::Columns(editor)) = &self.overlay else {
            return;
        };
        let mut at = editor.selected;
        let mut list = self.column_list();
        if list.is_empty() {
            return;
        }
        at = at.min(list.len() - 1);
        match change {
            ColumnEdit::Toggle => {
                let shown = list.iter().filter(|c| c.visible).count();
                if list[at].visible && shown == 1 {
                    self.error("At least one column has to stay visible.");
                    return;
                }
                list[at].visible = !list[at].visible;
            }
            ColumnEdit::Delete => {
                if list.len() == 1
                    || (list[at].visible && list.iter().filter(|c| c.visible).count() == 1)
                {
                    self.error("At least one column has to stay visible.");
                    return;
                }
                list.remove(at);
                at = at.min(list.len() - 1);
            }
            ColumnEdit::Move(by) => {
                let to = at as i64 + by;
                if to < 0 || to >= list.len() as i64 {
                    return;
                }
                list.swap(at, to as usize);
                at = to as usize;
            }
            ColumnEdit::Rename(title) => {
                let title = title.trim();
                if title.is_empty() {
                    return;
                }
                list[at].title = title.to_string();
            }
        }
        self.set_column_list(Some(list));
        if let Some(Overlay::Columns(editor)) = &mut self.overlay {
            editor.selected = at;
        }
    }

    pub(super) fn built_in_column_menu(&mut self) {
        let keys = "abcdefghijklmnopqrstuvwxyz";
        let items = columns::BUILT_IN
            .iter()
            .zip(keys.chars())
            .map(|((title, format), key)| MenuItem {
                key,
                label: (*title).to_string(),
                action: Action::Command(format!("column type {format}")),
            })
            .collect();
        self.open_menu("Add a column", items);
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
}
