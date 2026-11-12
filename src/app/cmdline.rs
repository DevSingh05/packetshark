//! The command line's vocabulary, and completion for it.
//!
//! [`COMMANDS`] is the one list of what can be typed after `:`. Completion
//! reads it, and a test runs every entry to make sure the list and the
//! dispatcher in `commands.rs` have not drifted apart.

use std::path::Path;

use super::App;

pub struct Command {
    pub name: &'static str,
    /// What follows the name, for display.
    pub args: &'static str,
    pub about: &'static str,
}

const fn cmd(name: &'static str, args: &'static str, about: &'static str) -> Command {
    Command { name, args, about }
}

pub const COMMANDS: &[Command] = &[
    cmd("clear", "", "Clear the display filter"),
    cmd(
        "colors",
        "<mode>",
        "Packet row colours: wireshark, tint, off",
    ),
    cmd("column", "<field> [title]", "Add a column showing a field"),
    cmd("columns", "", "Arrange the columns"),
    cmd("conv", "[proto]", "Conversations"),
    cmd("endpoints", "[proto]", "Endpoints"),
    cmd("expert", "", "Expert information"),
    cmd("filter", "<expr>", "Apply a display filter"),
    cmd("follow", "[proto]", "Follow the selected packet's stream"),
    cmd("help", "", "Show the keys and commands"),
    cmd("keylog", "<file>", "Decrypt TLS with a key log file"),
    cmd("layout", "<name>", "stacked, side"),
    cmd("marked", "", "Show only marked packets"),
    cmd("marks", "", "List the marks, and go to one"),
    cmd("no-theme", "", "Go back to the terminal's own colours"),
    cmd("objects", "[proto]", "Export objects"),
    cmd("open", "<file>", "Open another capture"),
    cmd("phs", "", "Protocol hierarchy"),
    cmd("quit", "", "Quit"),
    cmd("reload", "", "Reload the capture"),
    cmd("set", "<pref> <value>", "Set a Wireshark preference"),
    cmd("stat", "<name>", "A statistics tree"),
    cmd("stop", "", "Stop a live capture"),
    cmd("theme", "[name]", "Choose a colour theme"),
    cmd("time", "<format>", "Change the time format"),
    cmd("unmark", "", "Remove all marks"),
    cmd("write", "<file>", "Save the displayed packets"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// What the word being completed becomes.
    pub text: String,
    pub about: String,
}

impl Candidate {
    fn plain(text: impl Into<String>) -> Candidate {
        Candidate {
            text: text.into(),
            about: String::new(),
        }
    }
}

/// The completions on offer for a command line.
#[derive(Debug, Clone, Default)]
pub struct Candidates {
    pub items: Vec<Candidate>,
    pub selected: Option<usize>,
    /// Where the word being completed starts, in characters.
    pub start: usize,
}

impl Candidates {
    /// Move to the next (or previous) candidate, wrapping round. Returns the
    /// one now selected.
    pub fn step(&mut self, by: i64) -> Option<&Candidate> {
        let n = self.items.len() as i64;
        if n == 0 {
            return None;
        }
        let next = match self.selected {
            None if by > 0 => 0,
            None => n - 1,
            Some(i) => (i as i64 + by).rem_euclid(n),
        };
        self.selected = Some(next as usize);
        self.items.get(next as usize)
    }
}

/// Most candidates worth listing; a directory can hold thousands of files.
const MAX: usize = 200;

impl App {
    /// What could complete the word that ends `before`, the command line up
    /// to the cursor.
    pub(super) fn command_candidates(&self, before: &str) -> Candidates {
        let word_at = before
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map_or(0, |(i, c)| i + c.len_utf8());
        let word = &before[word_at..];
        let earlier: Vec<&str> = before[..word_at].split_whitespace().collect();
        let fixed = |choices: &[&str]| -> Vec<Candidate> {
            choices.iter().map(|c| Candidate::plain(*c)).collect()
        };
        let mut items: Vec<Candidate> = match earlier.as_slice() {
            [] => COMMANDS
                .iter()
                .map(|c| Candidate {
                    text: c.name.to_string(),
                    about: if c.args.is_empty() {
                        c.about.to_string()
                    } else {
                        format!("{}  {}", c.args, c.about)
                    },
                })
                .collect(),
            ["theme" | "themes"] => crate::theme::theme_names(self.themes_dir.as_deref())
                .into_iter()
                .map(Candidate::plain)
                .collect(),
            ["colors" | "colours"] => fixed(&["wireshark", "tint", "off"]),
            ["layout"] => fixed(&["stacked", "side"]),
            ["time"] => fixed(&[
                "default",
                "relative",
                "delta",
                "delta-displayed",
                "absolute",
                "date",
                "utc",
                "utc-date",
            ]),
            ["conv" | "conversations" | "endpoints" | "endpt" | "hosts"] => {
                fixed(&["eth", "ipv4", "ipv6", "tcp", "udp"])
            }
            ["objects" | "export-objects"] => self.tap_names(|i| &i.eo, "eo:"),
            ["stat" | "stats"] => self.tap_names(|i| &i.stats, "stat:"),
            ["follow"] => self
                .detail
                .as_ref()
                .map(|d| {
                    d.follow
                        .iter()
                        .map(|(protocol, _)| Candidate::plain(protocol.to_ascii_lowercase()))
                        .collect()
                })
                .unwrap_or_default(),
            ["column" | "col" | "columns"] => fixed(&["remove", "reset"]),
            [
                "column" | "col" | "columns",
                "remove" | "rm" | "del" | "delete",
            ] => self
                .column_list()
                .into_iter()
                .map(|c| Candidate::plain(c.title))
                .collect(),
            ["open" | "o" | "e" | "write" | "w" | "save" | "export" | "keylog"] => {
                return Candidates {
                    items: complete_path(word),
                    selected: None,
                    start: before[..word_at].chars().count(),
                };
            }
            _ => Vec::new(),
        };
        let wanted = word.to_ascii_lowercase();
        items.retain(|c| c.text.to_ascii_lowercase().starts_with(&wanted));
        items.truncate(MAX);
        Candidates {
            items,
            selected: None,
            start: before[..word_at].chars().count(),
        }
    }

    fn tap_names(
        &self,
        list: impl Fn(&crate::sharkd::types::Info) -> &Vec<crate::sharkd::types::NamedTap>,
        prefix: &str,
    ) -> Vec<Candidate> {
        let Some(info) = &self.info else {
            return Vec::new();
        };
        list(info)
            .iter()
            .filter_map(|tap| {
                tap.tap.strip_prefix(prefix).map(|name| Candidate {
                    text: name.to_ascii_lowercase(),
                    about: tap.name.clone(),
                })
            })
            .collect()
    }
}

/// Files and directories that `word` could be the start of. A directory
/// keeps its trailing slash, so that completing again goes inside it.
pub fn complete_path(word: &str) -> Vec<Candidate> {
    let (typed_dir, prefix) = match word.rfind('/') {
        Some(i) => (&word[..=i], &word[i + 1..]),
        None => ("", word),
    };
    let dir = super::commands::expand_path(if typed_dir.is_empty() {
        "./"
    } else {
        typed_dir
    });
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, bool)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Hidden files only when asked for.
            if !name.starts_with(prefix) || (name.starts_with('.') && !prefix.starts_with('.')) {
                return None;
            }
            Some((name, is_dir(&entry.path())))
        })
        .collect();
    found.sort();
    found.truncate(MAX);
    found
        .into_iter()
        .map(|(name, dir)| Candidate {
            text: format!("{typed_dir}{name}{}", if dir { "/" } else { "" }),
            about: if dir {
                "directory".into()
            } else {
                String::new()
            },
        })
        .collect()
}

/// Whether `path` is a directory, following a symbolic link to one.
fn is_dir(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_listed_once_and_in_order() {
        let names: Vec<&str> = COMMANDS.iter().map(|c| c.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted, "COMMANDS is sorted and has no duplicates");
        assert!(COMMANDS.iter().all(|c| !c.about.is_empty()));
    }

    #[test]
    fn paths_complete_with_directories_marked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        std::fs::write(dir.path().join("alpha.pcap"), b"").unwrap();
        std::fs::write(dir.path().join("alps.pcapng"), b"").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"").unwrap();
        std::fs::create_dir(dir.path().join("album")).unwrap();
        std::fs::write(dir.path().join("album").join("inner.pcap"), b"").unwrap();

        let texts = |word: String| -> Vec<String> {
            complete_path(&word).into_iter().map(|c| c.text).collect()
        };
        assert_eq!(
            texts(format!("{root}/al")),
            [
                format!("{root}/album/"),
                format!("{root}/alpha.pcap"),
                format!("{root}/alps.pcapng")
            ]
        );
        assert_eq!(
            texts(format!("{root}/alph")),
            [format!("{root}/alpha.pcap")]
        );
        // Inside a directory, and hidden files only on request.
        assert_eq!(
            texts(format!("{root}/album/")),
            [format!("{root}/album/inner.pcap")]
        );
        assert!(
            texts(format!("{root}/"))
                .iter()
                .all(|t| !t.contains(".hidden"))
        );
        assert_eq!(texts(format!("{root}/.h")), [format!("{root}/.hidden")]);
        assert!(texts(format!("{root}/nothing-here")).is_empty());
        assert!(texts("/no/such/directory/x".to_string()).is_empty());
    }

    #[test]
    fn stepping_through_candidates_wraps() {
        let mut c = Candidates {
            items: vec![Candidate::plain("a"), Candidate::plain("b")],
            selected: None,
            start: 0,
        };
        assert_eq!(c.step(1).unwrap().text, "a");
        assert_eq!(c.step(1).unwrap().text, "b");
        assert_eq!(c.step(1).unwrap().text, "a");
        assert_eq!(c.step(-1).unwrap().text, "b");
        let mut none = Candidates::default();
        assert!(none.step(1).is_none());
        let mut back = Candidates {
            items: vec![Candidate::plain("a"), Candidate::plain("b")],
            selected: None,
            start: 0,
        };
        assert_eq!(back.step(-1).unwrap().text, "b");
    }
}
