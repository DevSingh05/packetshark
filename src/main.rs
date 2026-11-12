//! packetshark: a terminal UI for Wireshark.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use clap::Parser;
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use packetshark::app::{App, Event, Options};
use packetshark::capture::{self, Capture};
use packetshark::config::{Config, History};
use packetshark::sharkd::{self, Launch};
use packetshark::theme::{RowColors, Theme};
use packetshark::{ui, util};

/// A terminal UI for Wireshark: packet list, protocol details and bytes,
/// with display filters, stream following and statistics. Dissection is done
/// by Wireshark's own engine (sharkd), so every protocol Wireshark knows is
/// supported.
#[derive(Parser, Debug)]
#[command(name = "packetshark", version, max_term_width = 100)]
struct Cli {
    /// Capture file to open (pcap, pcapng, or anything Wireshark reads).
    /// Use `-` to read a capture from stdin, e.g.
    /// `ssh host tcpdump -U -w - | packetshark -`
    file: Option<PathBuf>,

    /// Capture live from this interface (repeat for several). Needs dumpcap
    /// and capture permissions
    #[arg(short = 'i', long = "interface", value_name = "IFACE")]
    interfaces: Vec<String>,

    /// Capture filter (BPF syntax) for live capture, e.g. "port 53"
    #[arg(short = 'f', long, value_name = "BPF")]
    capture_filter: Option<String>,

    /// Display filter to apply at startup, e.g. "http && ip.addr == 10.0.0.1"
    #[arg(short = 'Y', long, value_name = "FILTER")]
    display_filter: Option<String>,

    /// List capture interfaces and exit
    #[arg(short = 'D', long)]
    list_interfaces: bool,

    /// Keep reading the file as it grows (for a capture another program is
    /// still writing)
    #[arg(long)]
    tail: bool,

    /// TLS key log file (SSLKEYLOGFILE format) used to decrypt TLS
    #[arg(long, value_name = "FILE")]
    keylog: Option<PathBuf>,

    /// Set a Wireshark preference, e.g. -o `tcp.relative_sequence_numbers:FALSE`
    #[arg(short = 'o', value_name = "NAME:VALUE")]
    prefs: Vec<String>,

    /// Wireshark configuration profile to use
    #[arg(short = 'C', long, value_name = "NAME")]
    profile: Option<String>,

    /// Path to the sharkd binary (default: search $PATH and common locations)
    #[arg(long, value_name = "PATH")]
    sharkd: Option<PathBuf>,

    /// Packet row colouring: wireshark, tint or off
    #[arg(long, value_name = "MODE")]
    colors: Option<String>,

    /// Do not capture the mouse (lets the terminal select text)
    #[arg(long)]
    no_mouse: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("packetshark: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let mut config = Config::load()?;
    if let Some(profile) = cli.profile.clone() {
        config.profile = Some(profile);
    }
    let sharkd_path = sharkd::locate(cli.sharkd.as_deref().or(config.sharkd.as_deref()))?;

    if cli.list_interfaces {
        let dumpcap = dumpcap(&sharkd_path)?;
        for iface in capture::list_interfaces(&dumpcap)? {
            if iface.description.is_empty() {
                println!("{}", iface.name);
            } else {
                println!("{}  ({})", iface.name, iface.description);
            }
        }
        return Ok(());
    }

    let mut prefs = Vec::new();
    for pref in &cli.prefs {
        let (name, value) = pref
            .split_once(':')
            .ok_or_else(|| format!("-o expects NAME:VALUE, got `{pref}`"))?;
        prefs.push((name.trim().to_string(), value.trim().to_string()));
    }
    if let Some(keylog) = &cli.keylog {
        if !keylog.is_file() {
            return Err(format!("key log file {} does not exist", keylog.display()));
        }
        let absolute = std::fs::canonicalize(keylog).unwrap_or_else(|_| keylog.clone());
        prefs.push((
            "tls.keylog_file".into(),
            absolute.to_string_lossy().into_owned(),
        ));
    }

    let mut theme = Theme::detect();
    match config.ui.background.as_str() {
        "dark" => theme.dark = true,
        "light" => theme.dark = false,
        "auto" | "" => {}
        other => {
            return Err(format!(
                "config: ui.background must be dark, light or auto, not `{other}`"
            ));
        }
    }
    if RowColors::parse(&config.ui.row_colors).is_none() {
        return Err(format!(
            "config: ui.row_colors must be wireshark, tint or off, not `{}`",
            config.ui.row_colors
        ));
    }
    if let Some(mode) = &cli.colors {
        RowColors::parse(mode)
            .ok_or_else(|| format!("--colors must be wireshark, tint or off, not `{mode}`"))?;
        config.ui.row_colors = mode.clone();
    }
    if cli.no_mouse {
        config.ui.mouse = false;
    }

    // Work out where the packets come from.
    let stdin_piped = !io::stdin().is_terminal();
    let from_stdin = cli.file.as_deref().is_some_and(|f| f.as_os_str() == "-")
        || (cli.file.is_none() && cli.interfaces.is_empty() && stdin_piped);
    let (source, title, tail, capture) = if !cli.interfaces.is_empty() {
        if cli.file.is_some() {
            return Err("give either a file or -i <interface>, not both".into());
        }
        let dumpcap = dumpcap(&sharkd_path)?;
        let capture = Capture::live(&dumpcap, &cli.interfaces, cli.capture_filter.as_deref())?;
        let title = format!("{} (live)", cli.interfaces.join(", "));
        (capture.path().to_path_buf(), title, true, Some(capture))
    } else if from_stdin {
        if !stdin_piped {
            return Err("`-` reads a capture from stdin, but stdin is a terminal".into());
        }
        let capture = Capture::from_reader(io::stdin())?;
        (
            capture.path().to_path_buf(),
            "stdin".to_string(),
            true,
            Some(capture),
        )
    } else if let Some(file) = &cli.file {
        if !file.exists() {
            return Err(format!("{} does not exist", file.display()));
        }
        if !file.is_file() {
            return Err(format!("{} is not a file", file.display()));
        }
        // sharkd runs in its own directory context; give it an absolute path.
        let path = std::fs::canonicalize(file).unwrap_or_else(|_| file.clone());
        let title = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        (path, title, cli.tail, None)
    } else {
        return Err("nothing to open.\n\n  \
                    packetshark capture.pcapng        open a capture file\n  \
                    packetshark -i en0                capture live\n  \
                    tcpdump -U -w - | packetshark -   read a capture from a pipe\n  \
                    packetshark -D                    list capture interfaces\n\n\
                    See packetshark --help for all options."
            .into());
    };

    if !io::stdout().is_terminal() {
        return Err("packetshark is an interactive program and needs a terminal on stdout".into());
    }

    let launch = Launch {
        program: sharkd_path,
        profile: config.profile.clone(),
    };
    let mouse = config.ui.mouse;
    let (tx, rx) = mpsc::channel();
    let options = Options {
        source,
        title,
        display_filter: cli.display_filter.unwrap_or_default(),
        tail,
        prefs,
    };
    let mut app = App::new(
        launch,
        config,
        theme,
        options,
        tx.clone(),
        History::filters(),
    )
    .map_err(|e| format!("could not start sharkd: {e}"))?;
    if let Some(capture) = capture {
        app.attach_capture(capture);
    }

    // Keyboard and mouse.
    let input = tx.clone();
    std::thread::Builder::new()
        .name("input".into())
        .spawn(move || {
            while let Ok(event) = event::read() {
                let event = match event {
                    event::Event::Key(k) => Event::Key(k),
                    event::Event::Mouse(m) => Event::Mouse(m),
                    event::Event::Paste(s) => Event::Paste(s),
                    event::Event::Resize(..) => Event::Resize,
                    _ => continue,
                };
                if input.send(event).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| format!("could not start input thread: {e}"))?;

    signals::install();
    let mut terminal = enter(mouse).map_err(|e| format!("could not set up the terminal: {e}"))?;
    let result = event_loop(&mut app, &mut terminal, &rx);
    leave(mouse);
    // Stop sharkd and any capture before reporting.
    let startup_failure = app.startup_failure().map(str::to_string);
    drop(app);
    result.map_err(|e| format!("terminal error: {e}"))?;
    match startup_failure {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

type Tui = Terminal<CrosstermBackend<io::Stdout>>;

fn event_loop(app: &mut App, terminal: &mut Tui, rx: &mpsc::Receiver<Event>) -> io::Result<()> {
    const TICK: Duration = Duration::from_millis(100);
    let mut last_tick = std::time::Instant::now();
    loop {
        terminal.draw(|frame| ui::draw(app, frame))?;
        flush_clipboard(app)?;

        // Wait for something to happen, then take everything that is queued
        // so a burst of key repeats or replies costs one redraw.
        let wait = TICK.saturating_sub(last_tick.elapsed());
        match rx.recv_timeout(wait) {
            Ok(event) => app.handle(event),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        for _ in 0..256 {
            match rx.try_recv() {
                Ok(event) => app.handle(event),
                Err(_) => break,
            }
        }
        if last_tick.elapsed() >= TICK {
            app.handle(Event::Tick);
            last_tick = std::time::Instant::now();
        }
        if app.quit {
            return Ok(());
        }
        // A capture file that cannot be opened at startup is an error to
        // report on exit, not a screen to sit on.
        if app.startup_failure().is_some() {
            return Ok(());
        }
        // Asked to stop from outside (terminal closed, `kill`): leave the
        // normal way so the terminal is restored and any capture is stopped.
        if signals::received() {
            return Ok(());
        }
    }
}

/// Send copied text to the terminal's clipboard with OSC 52.
fn flush_clipboard(app: &mut App) -> io::Result<()> {
    if app.clipboard.is_empty() {
        return Ok(());
    }
    let mut out = io::stdout().lock();
    for text in app.clipboard.drain(..) {
        write!(
            out,
            "\x1b]52;c;{}\x07",
            util::encode_base64(text.as_bytes())
        )?;
    }
    out.flush()
}

fn enter(mouse: bool) -> io::Result<Tui> {
    enable_raw_mode()?;
    // Put the terminal back even if we panic, so the shell stays usable.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        leave(mouse);
        default_hook(info);
    }));
    let setup = || -> io::Result<Tui> {
        let mut out = io::stdout();
        execute!(out, EnterAlternateScreen, EnableBracketedPaste)?;
        if mouse {
            execute!(out, EnableMouseCapture)?;
        }
        Terminal::new(CrosstermBackend::new(out))
    };
    // A half-finished setup must not leave raw mode on.
    setup().inspect_err(|_| leave(mouse))
}

fn leave(mouse: bool) {
    let mut out = io::stdout();
    if mouse {
        let _ = execute!(out, DisableMouseCapture);
    }
    let _ = execute!(
        out,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        cursor::Show
    );
    let _ = disable_raw_mode();
}

fn dumpcap(sharkd: &std::path::Path) -> Result<PathBuf, String> {
    capture::locate_tool("dumpcap", sharkd).ok_or_else(|| {
        "dumpcap was not found. It ships with Wireshark's command-line tools.".to_string()
    })
}

/// Termination signals. The handler only sets a flag; the event loop notices
/// it within one tick and shuts down in the ordinary way.
mod signals {
    use std::sync::atomic::{AtomicBool, Ordering};

    static RECEIVED: AtomicBool = AtomicBool::new(false);

    pub fn received() -> bool {
        RECEIVED.load(Ordering::Relaxed)
    }

    #[cfg(unix)]
    pub fn install() {
        extern "C" fn on_signal(_: libc::c_int) {
            // Storing to an atomic is async-signal-safe.
            RECEIVED.store(true, Ordering::Relaxed);
        }
        let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
            // SAFETY: `on_signal` is a valid handler for the lifetime of the
            // program and does nothing that is unsafe in a signal context.
            unsafe {
                libc::signal(signal, handler);
            }
        }
    }

    #[cfg(not(unix))]
    pub fn install() {}
}
