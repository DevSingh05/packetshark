//! The `:` command line.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::columns::TimeFormat;
use super::{App, Event, LayoutKind, Level, Overlay, stats};
use crate::capture::locate_tool;
use crate::sharkd::Request;
use crate::theme::RowColors;

impl App {
    pub(super) fn run_command(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        // A command typed over a window acts on the main view.
        self.overlay = None;
        if let Ok(num) = line.parse::<u32>() {
            return self.goto_frame(num);
        }
        let (name, arg) = match line.split_once(char::is_whitespace) {
            Some((n, a)) => (n, a.trim()),
            None => (line, ""),
        };
        let some = |s: &str| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        };
        match name {
            "q" | "quit" | "exit" => self.quit = true,
            "h" | "help" => self.overlay = Some(Overlay::Help { top: 0 }),
            "filter" | "f" => self.apply_filter(arg),
            "clear" | "nofilter" => self.apply_filter(""),
            "conv" | "conversations" => {
                self.open_stats(stats::Kind::Conversations, some(arg).as_deref());
            }
            "endpoints" | "endpt" | "hosts" => {
                self.open_stats(stats::Kind::Endpoints, some(arg).as_deref());
            }
            "phs" | "hierarchy" | "protocols" => self.open_stats(stats::Kind::Hierarchy, None),
            "expert" => self.open_stats(stats::Kind::Expert, None),
            "objects" | "export-objects" => {
                self.open_stats(stats::Kind::Objects, some(arg).as_deref());
            }
            "stat" | "stats" => self.open_stat_tree(arg),
            "follow" => self.follow_selected(some(arg).as_deref()),
            "w" | "write" | "export" | "save" => self.export(arg),
            "marked" => self.show_marked(),
            "marks" => self.marks_menu(),
            "recent" | "recents" => self.recent_menu(),
            "info" | "capinfo" | "properties" => self.capture_properties(),
            "map" => self.map_key(arg),
            "unmap" => {
                if arg.is_empty() {
                    self.error("Usage: :unmap <key>");
                } else {
                    self.unmap_key(arg);
                }
            }
            // What an entry of the mappings list does.
            "edit-map" => {
                let line = self
                    .state
                    .maps
                    .iter()
                    .find(|m| m.key == arg)
                    .map(|m| format!("map {} {}", m.key, m.keys));
                if let Some(line) = line {
                    self.open_prompt(super::PromptKind::Command, &line);
                }
            }
            // What an entry of the marks list does.
            "jump" => match arg.chars().next() {
                Some(letter) if letter.is_ascii_alphabetic() => self.jump_to_mark(letter),
                _ => self.error("Usage: :jump <mark letter>"),
            },
            "column" | "columns" | "col" => {
                let (verb, rest) = match arg.split_once(char::is_whitespace) {
                    Some((v, r)) => (v, r.trim()),
                    None => (arg, ""),
                };
                match verb {
                    "" | "edit" => self.open_column_editor(),
                    "remove" | "rm" | "del" | "delete" if rest.is_empty() => {
                        self.error("Usage: :column remove <title or field>, or :column reset");
                    }
                    "remove" | "rm" | "del" | "delete" => self.remove_column(rest),
                    "reset" | "clear" => self.remove_column(""),
                    // From the column editor's list of built-in types.
                    "type" => {
                        let (format, title) = match rest.split_once(char::is_whitespace) {
                            Some((f, t)) => (f, t),
                            None => (rest, ""),
                        };
                        self.add_built_in_column(format, title);
                        self.open_column_editor();
                        if let Some(Overlay::Columns(editor)) = &mut self.overlay {
                            let wanted = self.state.columns.as_ref().and_then(|list| {
                                list.iter().position(|c| c.format == format)
                            });
                            editor.selected = wanted.unwrap_or(0);
                        }
                    }
                    "add" => {
                        let (field, title) = match rest.split_once(char::is_whitespace) {
                            Some((f, t)) => (f, Some(t)),
                            None => (rest, None),
                        };
                        self.add_column(field, title);
                    }
                    field => self.add_column(field, some(rest).as_deref()),
                }
            }
            "unmark" => {
                let n = self.marks.len();
                self.marks.clear();
                self.info(format!("Removed {n} mark{}.", if n == 1 { "" } else { "s" }));
            }
            "keylog" => {
                if arg.is_empty() {
                    return self.error("Usage: :keylog <file>");
                }
                let path = expand_path(arg);
                if !path.is_file() {
                    return self.error(format!("{} is not a file.", path.display()));
                }
                self.send(Request::SetConf {
                    name: "tls.keylog_file".into(),
                    value: path.to_string_lossy().into_owned(),
                });
            }
            "set" => match arg.split_once(char::is_whitespace) {
                Some((pref, value)) => self.send(Request::SetConf {
                    name: pref.to_string(),
                    value: value.trim().to_string(),
                }),
                None => self.error("Usage: :set <preference> <value>, e.g. :set tcp.desegment_tcp_streams FALSE"),
            },
            "time" => match TimeFormat::parse(arg) {
                Some(format) if self.columns.can_change_time() => {
                    self.time_format = format;
                    self.list.widths.clear();
                    self.refresh_list();
                    self.info(format!("Time: {}.", format.name()));
                }
                Some(_) => self.error("The time format cannot be changed with this sharkd version."),
                None => self.error(
                    "Usage: :time relative | delta | delta-displayed | absolute | date | utc | utc-date | default",
                ),
            },
            "theme" | "themes" => {
                if arg.is_empty() {
                    self.theme_menu();
                } else {
                    self.choose_theme(arg);
                }
            }
            "no-theme" => self.choose_theme("default"),
            "colors" | "colours" => match RowColors::parse(arg) {
                Some(mode) => self.theme.row_colors = mode,
                None => self.error("Usage: :colors wireshark | tint | off"),
            },
            "layout" => match arg {
                "stacked" => self.layout = LayoutKind::Stacked,
                "side" => self.layout = LayoutKind::Side,
                _ => self.error("Usage: :layout stacked | side"),
            },
            "open" | "o" | "e" => {
                if arg.is_empty() {
                    self.error("Usage: :open <file>");
                } else {
                    self.open(expand_path(arg));
                }
            }
            "reload" => {
                self.info("Reloading.");
                self.reload();
            }
            "stop" => self.stop_capture(),
            other => self.error(format!("Unknown command: {other}. Press ? for the list.")),
        }
    }

    fn show_marked(&mut self) {
        if self.marks.is_empty() {
            return self.info("No packets are marked. Press M on a packet to mark it.");
        }
        let terms: Vec<String> = self
            .marks
            .iter()
            .map(|n| format!("frame.number == {n}"))
            .collect();
        let filter = terms.join(" || ");
        self.apply_filter(&filter);
    }

    /// Write the displayed packets to a new capture file, in the background.
    fn export(&mut self, arg: &str) {
        if arg.is_empty() {
            return self.error("Usage: :write <file>");
        }
        let dest = expand_path(arg);
        // Compare the files themselves: the same capture can be reached by
        // different spellings (a relative path, a symlinked directory).
        let same_file = match (
            std::fs::canonicalize(&dest),
            std::fs::canonicalize(&self.source),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => dest == self.source,
        };
        if same_file {
            return self.error("Cannot write over the capture that is open.");
        }
        let source = self.source.clone();
        let filter = self.filter.applied.clone();
        let tshark = locate_tool("tshark", self.sharkd_path());
        let events = self.events.clone();
        let shown = self.list.len();
        self.info(format!("Writing {}…", dest.display()));
        std::thread::spawn(move || {
            let result = write_packets(&source, &dest, &filter, tshark.as_deref());
            let (ok, message) = match result {
                Ok(()) => (
                    true,
                    format!("Wrote {shown} packets to {}.", dest.display()),
                ),
                Err(e) => (false, e),
            };
            let _ = events.send(Event::Job { ok, message });
        });
    }

    #[allow(dead_code)]
    pub(super) fn warn(&mut self, text: impl Into<String>) {
        self.say(Level::Warn, text);
    }
}

fn write_packets(
    source: &Path,
    dest: &Path,
    filter: &str,
    tshark: Option<&Path>,
) -> Result<(), String> {
    if filter.is_empty() {
        return std::fs::copy(source, dest)
            .map(|_| ())
            .map_err(|e| format!("Could not write {}: {e}", dest.display()));
    }
    let tshark = tshark.ok_or("Saving filtered packets needs tshark, which was not found.")?;
    let out = Command::new(tshark)
        .arg("-r")
        .arg(source)
        .arg("-Y")
        .arg(filter)
        .arg("-w")
        .arg(dest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Could not run {}: {e}", tshark.display()))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let reason = stderr
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("tshark failed");
    Err(format!(
        "Could not write {}: {}",
        dest.display(),
        reason.trim()
    ))
}

/// Expand a leading `~/`.
pub fn expand_path(text: &str) -> PathBuf {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(text)
}

/// A file name that is safe to create in the current directory, whatever the
/// capture claimed the object was called.
pub fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    // Drop a query string: `logo.png?v=3`.
    let base = base.split(['?', '#']).next().unwrap_or(base);
    let mut cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, ':' | '*' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    cleaned.truncate(
        cleaned
            .char_indices()
            .nth(120)
            .map_or(cleaned.len(), |(i, _)| i),
    );
    let cleaned = cleaned.trim().trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        "object.bin".to_string()
    } else {
        cleaned
    }
}

/// `name`, or `name-1`, `name-2`, ... if a file with that name already exists.
pub fn unique_path(name: &str) -> PathBuf {
    let path = PathBuf::from(name);
    if !path.exists() {
        return path;
    }
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    (1..)
        .map(|i| path.with_file_name(format!("{stem}-{i}{ext}")))
        .find(|p| !p.exists())
        .expect("an unused file name exists")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_cannot_escape_the_directory() {
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("/abs/path/logo.png?v=3"), "logo.png");
        assert_eq!(safe_file_name("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(safe_file_name(".bashrc"), "bashrc");
        assert_eq!(safe_file_name(""), "object.bin");
        assert_eq!(safe_file_name("/"), "object.bin");
        assert_eq!(safe_file_name("a:b*c"), "a_b_c");
        assert!(safe_file_name(&"x".repeat(500)).len() <= 120);
    }

    #[test]
    fn unique_path_avoids_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("index.html");
        let name = base.to_string_lossy().into_owned();
        assert_eq!(unique_path(&name), base);
        std::fs::write(&base, b"x").unwrap();
        assert_eq!(unique_path(&name), dir.path().join("index-1.html"));
        std::fs::write(dir.path().join("index-1.html"), b"x").unwrap();
        assert_eq!(unique_path(&name), dir.path().join("index-2.html"));
    }

    #[test]
    fn home_is_expanded() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_path("~/x.pcap"), home.join("x.pcap"));
        assert_eq!(expand_path(" /tmp/a "), PathBuf::from("/tmp/a"));
    }

    #[test]
    fn unfiltered_export_copies_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let (src, dst) = (dir.path().join("a.pcap"), dir.path().join("b.pcap"));
        std::fs::write(&src, b"pcap bytes").unwrap();
        write_packets(&src, &dst, "", None).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"pcap bytes");
        let err = write_packets(&src, &dst, "tcp", None).unwrap_err();
        assert!(err.contains("tshark"), "{err}");
    }
}
