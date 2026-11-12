//! User configuration (`config.toml`) and persisted filter history.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

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

#[cfg(test)]
mod tests {
    use super::*;

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
