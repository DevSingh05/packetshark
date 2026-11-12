//! User configuration (`config.toml`) and persisted filter history.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Contents of `~/.config/packetshark/config.toml`. Every key is optional.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Path to the sharkd binary.
    pub sharkd: Option<PathBuf>,
    /// Wireshark configuration profile to use.
    pub profile: Option<String>,
    pub ui: Ui,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ui {
    /// `wireshark`, `tint` or `off`.
    pub row_colors: String,
    /// `stacked` or `side`.
    pub layout: String,
    /// `dark`, `light` or `auto`.
    pub background: String,
    pub mouse: bool,
    /// Expand the whole dissection tree by default.
    pub expand_all: bool,
    /// Draw with ASCII characters only.
    pub ascii: bool,
    /// Colour theme to start with, unless one was chosen with `:theme`.
    pub theme: Option<String>,
    /// A program to hand copied text to on its standard input, with its
    /// arguments, instead of asking the terminal to set the clipboard.
    pub copy_command: Vec<String>,
}

impl Default for Ui {
    fn default() -> Self {
        Ui {
            row_colors: "wireshark".into(),
            layout: "stacked".into(),
            background: "auto".into(),
            mouse: true,
            expand_all: false,
            ascii: false,
            theme: None,
            copy_command: Vec::new(),
        }
    }
}

impl Config {
    pub fn path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("PACKETSHARK_CONFIG") {
            return Some(PathBuf::from(p));
        }
        config_dir().map(|d| d.join("config.toml"))
    }

    /// Load the config file. A missing file is not an error; a malformed one is.
    pub fn load() -> Result<Config, String> {
        let Some(path) = Self::path() else {
            return Ok(Config::default());
        };
        match fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }
}

/// Where user-made themes live: `themes/NAME.toml` next to the config file.
pub fn themes_dir() -> Option<PathBuf> {
    Config::path()
        .and_then(|p| p.parent().map(|d| d.join("themes")))
        .or_else(|| config_dir().map(|d| d.join("themes")))
}

/// `$XDG_CONFIG_HOME/packetshark`, or `~/.config/packetshark` on every Unix
/// (including macOS, where terminal tools conventionally live there too).
fn config_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(x).join("packetshark"));
    }
    if cfg!(unix) {
        dirs::home_dir().map(|h| h.join(".config").join("packetshark"))
    } else {
        dirs::config_dir().map(|d| d.join("packetshark"))
    }
}

fn state_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(x).join("packetshark"));
    }
    if cfg!(unix) {
        dirs::home_dir().map(|h| h.join(".local").join("state").join("packetshark"))
    } else {
        dirs::data_local_dir().map(|d| d.join("packetshark"))
    }
}

/// Recently used display filters, oldest first.
pub struct History {
    path: Option<PathBuf>,
}

impl History {
    pub fn filters() -> History {
        History {
            path: state_dir().map(|d| d.join("filters")),
        }
    }

    /// A history that is never read or written; used by tests.
    pub fn disabled() -> History {
        History { path: None }
    }

    pub fn at(path: PathBuf) -> History {
        History { path: Some(path) }
    }

    pub fn load(&self) -> Vec<String> {
        let Some(path) = &self.path else {
            return Vec::new();
        };
        fs::read_to_string(path)
            .map(|t| {
                t.lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Best effort: history is a convenience, so failures are ignored.
    pub fn save(&self, entries: &[String]) {
        let Some(path) = &self.path else { return };
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::write(path, entries.join("\n") + "\n");
    }
}

/// What the program remembers between runs that the user did not write by
/// hand: choices made with commands, recent files, marks. It lives apart from
/// `config.toml`, which is the user's and is never rewritten.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Theme chosen with `:theme`.
    pub theme: Option<String>,
    /// The column set arranged with `:columns`; `None` means the Wireshark
    /// profile's columns.
    pub columns: Option<Vec<SavedColumn>>,
    /// Key mappings made with `:map`.
    pub maps: Vec<KeyMap>,
    /// Marks `A` to `Z`, which remember their capture file.
    pub marks: std::collections::BTreeMap<String, FileMark>,
    /// Captures opened recently, newest first.
    pub recent_files: Vec<PathBuf>,
    pub find: FindPrefs,
    /// How Follow Stream shows data: `ascii`, `hex` or `raw`.
    pub follow_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SavedColumn {
    pub title: String,
    /// A Wireshark format code (`%m`, `%s`, ...) or `%Cus:<field>:0`.
    pub format: String,
    #[serde(default = "yes")]
    pub visible: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyMap {
    pub key: String,
    pub keys: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileMark {
    pub file: PathBuf,
    pub packet: u32,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FindPrefs {
    /// `list`, `details` or `bytes`.
    pub target: String,
    /// `auto` (a filter if it is one, else text), `string`, `regex`, `hex`
    /// or `filter`.
    pub kind: String,
    pub case_sensitive: bool,
}

impl Default for FindPrefs {
    fn default() -> Self {
        FindPrefs {
            target: "bytes".into(),
            kind: "auto".into(),
            case_sensitive: false,
        }
    }
}

/// Where [`State`] is kept.
#[derive(Debug, Clone)]
pub struct Store {
    path: Option<PathBuf>,
}

impl Default for Store {
    fn default() -> Self {
        Store::disabled()
    }
}

impl Store {
    /// `~/.local/state/packetshark/state.toml`.
    pub fn standard() -> Store {
        Store {
            path: state_dir().map(|d| d.join("state.toml")),
        }
    }

    /// Never read or written; used by tests.
    pub fn disabled() -> Store {
        Store { path: None }
    }

    pub fn at(path: PathBuf) -> Store {
        Store { path: Some(path) }
    }

    /// A missing or unreadable file gives the defaults: losing remembered
    /// choices is better than refusing to start.
    pub fn load(&self) -> State {
        self.path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Best effort, written to a temporary file first so that a crash or a
    /// second instance cannot leave half a file behind.
    pub fn save(&self, state: &State) {
        let Some(path) = &self.path else { return };
        let Ok(text) = toml::to_string(state) else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let tmp = path.with_extension(format!("toml.{}", std::process::id()));
        if fs::write(&tmp, text).is_ok() && fs::rename(&tmp, path).is_err() {
            let _ = fs::remove_file(&tmp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_and_survives_a_damaged_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::at(dir.path().join("deep").join("state.toml"));
        assert_eq!(store.load(), State::default(), "nothing saved yet");

        let mut state = State {
            theme: Some("dracula".into()),
            ..State::default()
        };
        state.columns = Some(vec![SavedColumn {
            title: "Stream".into(),
            format: "%Cus:tcp.stream:0".into(),
            visible: false,
        }]);
        state.maps.push(KeyMap {
            key: "<f5>".into(),
            keys: ":conv<enter>".into(),
        });
        state.marks.insert(
            "A".into(),
            FileMark {
                file: "/tmp/x.pcap".into(),
                packet: 7,
                summary: "GET /".into(),
            },
        );
        state.recent_files.push("/tmp/x.pcap".into());
        store.save(&state);
        assert_eq!(store.load(), state);

        // Garbage on disk is ignored rather than fatal.
        fs::write(dir.path().join("deep").join("state.toml"), "not [toml").unwrap();
        assert_eq!(store.load(), State::default());
        // A store that is switched off does nothing at all.
        Store::disabled().save(&state);
        assert_eq!(Store::disabled().load(), State::default());
    }

    #[test]
    fn empty_config_uses_defaults() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.ui.row_colors, "wireshark");
        assert!(c.ui.mouse);
        assert!(c.sharkd.is_none());
    }

    #[test]
    fn partial_config_overrides_only_what_is_set() {
        let c = Config::parse("profile = \"work\"\n[ui]\nrow_colors = \"tint\"\nmouse = false\n")
            .unwrap();
        assert_eq!(c.profile.as_deref(), Some("work"));
        assert_eq!(c.ui.row_colors, "tint");
        assert!(!c.ui.mouse);
        assert_eq!(c.ui.layout, "stacked");
    }

    #[test]
    fn unknown_keys_are_reported() {
        let err = Config::parse("[ui]\ncolour = \"red\"\n").unwrap_err();
        assert!(err.contains("colour"), "{err}");
    }

    #[test]
    fn history_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let h = History::at(dir.path().join("nested").join("filters"));
        assert!(h.load().is_empty());
        h.save(&["dns".into(), "tcp.port == 80".into()]);
        assert_eq!(h.load(), ["dns", "tcp.port == 80"]);
    }
}
