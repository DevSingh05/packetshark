//! A single-line text editor with history, used for the filter bar and the
//! command line.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_width::UnicodeWidthChar;

#[derive(Debug, Default, Clone)]
pub struct TextInput {
    chars: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// Position while browsing history; `None` means editing a fresh line.
    browsing: Option<usize>,
    /// What was typed before history browsing began.
    stash: String,
}

/// What a key press did to the input.
#[derive(Debug, PartialEq, Eq)]
pub enum Edit {
    /// The text changed.
    Changed,
    /// Only the cursor moved.
    Moved,
    /// The key is not an editing key.
    Ignored,
}

impl TextInput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn text(&self) -> String {
        self.chars.iter().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn set(&mut self, text: &str) {
        self.chars = text.chars().collect();
        self.cursor = self.chars.len();
        self.browsing = None;
    }

    pub fn clear(&mut self) {
        self.set("");
    }

    pub fn insert_str(&mut self, s: &str) {
        for c in s.chars().filter(|c| !c.is_control()) {
            self.chars.insert(self.cursor, c);
            self.cursor += 1;
        }
    }

    pub fn set_history(&mut self, history: Vec<String>) {
        self.history = history;
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Record a submitted line; the most recent entry is last, without duplicates.
    pub fn remember(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        self.history.retain(|h| h != line);
        self.history.push(line.to_string());
        const KEEP: usize = 200;
        if self.history.len() > KEEP {
            let excess = self.history.len() - KEEP;
            self.history.drain(..excess);
        }
        self.browsing = None;
    }

    pub fn history_prev(&mut self) -> bool {
        if self.history.is_empty() {
            return false;
        }
        let next = match self.browsing {
            None => {
                self.stash = self.text();
                self.history.len() - 1
            }
            Some(0) => return false,
            Some(i) => i - 1,
        };
        self.browsing = Some(next);
        self.chars = self.history[next].chars().collect();
        self.cursor = self.chars.len();
        true
    }

    pub fn history_next(&mut self) -> bool {
        let Some(i) = self.browsing else { return false };
        if i + 1 < self.history.len() {
            self.browsing = Some(i + 1);
            self.chars = self.history[i + 1].chars().collect();
        } else {
            self.browsing = None;
            self.chars = self.stash.chars().collect();
        }
        self.cursor = self.chars.len();
        true
    }

    /// The run of field-name characters that ends at the cursor, with its
    /// start position. Used for completion.
    pub fn word_before_cursor(&self) -> (usize, String) {
        let mut start = self.cursor;
        while start > 0 && is_field_char(self.chars[start - 1]) {
            start -= 1;
        }
        (start, self.chars[start..self.cursor].iter().collect())
    }

    /// Replace `start..cursor` with `replacement`.
    pub fn replace_word(&mut self, start: usize, replacement: &str) {
        let start = start.min(self.cursor);
        self.chars.splice(start..self.cursor, replacement.chars());
        self.cursor = start + replacement.chars().count();
        self.browsing = None;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Edit {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        let before = self.chars.len();
        let moved_from = self.cursor;
        match key.code {
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.chars.len(),
            KeyCode::Char('b') if ctrl => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Char('f') if ctrl => self.cursor = (self.cursor + 1).min(self.chars.len()),
            KeyCode::Char('b') if alt => self.cursor = self.prev_word(),
            KeyCode::Char('f') if alt => self.cursor = self.next_word(),
            KeyCode::Char('u') if ctrl => {
                self.chars.drain(..self.cursor);
                self.cursor = 0;
            }
            KeyCode::Char('k') if ctrl => self.chars.truncate(self.cursor),
            KeyCode::Char('w') if ctrl => self.delete_prev_word(),
            KeyCode::Backspace if alt || ctrl => self.delete_prev_word(),
            KeyCode::Char('d') if ctrl => {
                if self.cursor < self.chars.len() {
                    self.chars.remove(self.cursor);
                }
            }
            KeyCode::Char(c) if !ctrl && !alt => {
                self.chars.insert(self.cursor, c);
                self.cursor += 1;
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.chars.remove(self.cursor);
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.chars.len() {
                    self.chars.remove(self.cursor);
                }
            }
            KeyCode::Left if ctrl || alt => self.cursor = self.prev_word(),
            KeyCode::Right if ctrl || alt => self.cursor = self.next_word(),
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.chars.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.chars.len(),
            _ => return Edit::Ignored,
        }
        if self.chars.len() != before {
            self.browsing = None;
            Edit::Changed
        } else if self.cursor != moved_from {
            Edit::Moved
        } else {
            // An editing key that had nothing to do (Backspace at the start).
            Edit::Moved
        }
    }

    fn prev_word(&self) -> usize {
        let mut i = self.cursor;
        while i > 0 && self.chars[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !self.chars[i - 1].is_whitespace() {
            i -= 1;
        }
        i
    }

    fn next_word(&self) -> usize {
        let mut i = self.cursor;
        while i < self.chars.len() && self.chars[i].is_whitespace() {
            i += 1;
        }
        while i < self.chars.len() && !self.chars[i].is_whitespace() {
            i += 1;
        }
        i
    }

    fn delete_prev_word(&mut self) {
        let start = self.prev_word();
        self.chars.drain(start..self.cursor);
        self.cursor = start;
    }

    /// The part of the text that fits in `width` columns while keeping the
    /// cursor visible, and the cursor's column within it.
    pub fn visible(&self, width: usize) -> (String, usize) {
        if width == 0 {
            return (String::new(), 0);
        }
        let widths: Vec<usize> = self.chars.iter().map(|c| c.width().unwrap_or(0)).collect();
        // Scroll so the cursor (which needs one cell itself) stays in view.
        let mut start = 0;
        let mut before: usize = widths[..self.cursor].iter().sum();
        while before + 1 > width && start < self.cursor {
            before -= widths[start];
            start += 1;
        }
        let mut out = String::new();
        let mut used = 0;
        for (c, w) in self.chars[start..].iter().zip(&widths[start..]) {
            if used + w > width {
                break;
            }
            out.push(*c);
            used += w;
        }
        (out, before)
    }
}

pub fn is_field_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn typing_and_editing() {
        let mut t = TextInput::new();
        for c in "tcp.port == 80".chars() {
            assert_eq!(t.handle_key(key(c)), Edit::Changed);
        }
        assert_eq!(t.text(), "tcp.port == 80");
        t.handle_key(ctrl('w'));
        assert_eq!(t.text(), "tcp.port == ");
        t.handle_key(ctrl('a'));
        t.handle_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(t.text(), "cp.port == ");
        t.handle_key(ctrl('k'));
        assert_eq!(t.text(), "");
    }

    #[test]
    fn word_before_cursor_stops_at_operators() {
        let mut t = TextInput::new();
        t.set("ip.addr == 1.2.3.4 && tcp.fl");
        assert_eq!(t.word_before_cursor(), (22, "tcp.fl".to_string()));
        t.replace_word(22, "tcp.flags");
        assert_eq!(t.text(), "ip.addr == 1.2.3.4 && tcp.flags");
    }

    #[test]
    fn history_round_trip_restores_draft() {
        let mut t = TextInput::new();
        t.remember("dns");
        t.remember("http");
        t.remember("dns");
        assert_eq!(t.history(), ["http", "dns"]);
        t.set("draft");
        assert!(t.history_prev());
        assert_eq!(t.text(), "dns");
        assert!(t.history_prev());
        assert_eq!(t.text(), "http");
        assert!(!t.history_prev());
        assert!(t.history_next());
        assert!(t.history_next());
        assert_eq!(t.text(), "draft");
    }

    #[test]
    fn visible_window_keeps_cursor_in_view() {
        let mut t = TextInput::new();
        t.set("abcdefghij");
        let (shown, col) = t.visible(5);
        assert_eq!(shown, "ghij");
        assert_eq!(col, 4);
        t.handle_key(ctrl('a'));
        let (shown, col) = t.visible(5);
        assert_eq!(shown, "abcde");
        assert_eq!(col, 0);
    }
}
