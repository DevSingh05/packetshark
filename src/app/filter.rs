//! The display filter bar: editing, live validation and completion.

use crate::sharkd::types::Completion;
use crate::text_input::TextInput;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Validity {
    #[default]
    Empty,
    /// Waiting for sharkd's verdict.
    Checking,
    Valid,
    Invalid(String),
}

/// Completion candidates shown under the filter bar.
#[derive(Debug, Default)]
pub struct Completions {
    pub items: Vec<Completion>,
    pub selected: Option<usize>,
    /// Where the word being completed starts in the input.
    pub start: usize,
}

#[derive(Debug, Default)]
pub struct FilterBar {
    pub input: TextInput,
    /// The filter the packet list currently shows.
    pub applied: String,
    pub validity: Validity,
    pub completions: Completions,
    /// The whole text is "selected": typing replaces it. Set when the bar is
    /// focused with a filter already in it, so `/` starts a new filter while
    /// the arrow keys still edit the old one.
    pub select_all: bool,
    /// Enter was pressed before sharkd had validated the text; apply as soon
    /// as it turns out valid.
    pub apply_when_checked: bool,
    check_seq: u64,
    complete_seq: u64,
}

/// Completion needs a prefix this long, so the candidate list stays short.
const MIN_PREFIX: usize = 2;
pub const MAX_COMPLETIONS: usize = 200;

impl FilterBar {
    /// True when the input differs from what is applied.
    pub fn dirty(&self) -> bool {
        self.input.text().trim() != self.applied
    }

    /// Call after the text changed. Returns the validation request to send
    /// (`seq`, `filter`), if any.
    pub fn check_request(&mut self) -> Option<(u64, String)> {
        let text = self.input.text();
        if text.trim().is_empty() {
            self.validity = Validity::Empty;
            self.check_seq += 1;
            return None;
        }
        self.validity = Validity::Checking;
        self.check_seq += 1;
        Some((self.check_seq, text))
    }

    pub fn on_check(&mut self, seq: u64, result: Result<(), String>) {
        if seq != self.check_seq {
            return;
        }
        self.validity = match result {
            Ok(()) => Validity::Valid,
            Err(e) => Validity::Invalid(clean_error(&e)),
        };
    }

    /// Call after the text or cursor changed. Returns the completion request
    /// to send (`seq`, `prefix`), if the word at the cursor is worth completing.
    pub fn complete_request(&mut self) -> Option<(u64, String)> {
        let (start, word) = self.input.word_before_cursor();
        self.complete_seq += 1;
        let looks_like_field = word.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        if word.len() < MIN_PREFIX || !looks_like_field {
            self.completions = Completions::default();
            return None;
        }
        self.completions.start = start;
        Some((self.complete_seq, word))
    }

    pub fn on_complete(&mut self, seq: u64, prefix: &str, mut items: Vec<Completion>) {
        if seq != self.complete_seq {
            return;
        }
        // A single candidate equal to what is typed is not worth a popup.
        if items.len() == 1 && items[0].field == prefix {
            items.clear();
        }
        // Shortest first puts `tcp.port` ahead of `tcp.port.something`.
        items.sort_by(|a, b| {
            a.field
                .len()
                .cmp(&b.field.len())
                .then(a.field.cmp(&b.field))
        });
        items.truncate(MAX_COMPLETIONS);
        self.completions.items = items;
        self.completions.selected = None;
    }

    pub fn has_completions(&self) -> bool {
        !self.completions.items.is_empty()
    }

    pub fn close_completions(&mut self) {
        self.completions = Completions::default();
        self.complete_seq += 1;
    }

    pub fn move_completion(&mut self, delta: i64) {
        let n = self.completions.items.len() as i64;
        if n == 0 {
            return;
        }
        let next = match self.completions.selected {
            None if delta > 0 => 0,
            None => n - 1,
            Some(i) => (i as i64 + delta).rem_euclid(n),
        };
        self.completions.selected = Some(next as usize);
    }

    /// Insert the selected candidate (or the first). Returns false if there
    /// was nothing to insert.
    pub fn accept_completion(&mut self) -> bool {
        let index = self.completions.selected.unwrap_or(0);
        let Some(item) = self.completions.items.get(index) else {
            return false;
        };
        let field = item.field.clone();
        self.input.replace_word(self.completions.start, &field);
        self.close_completions();
        true
    }
}

/// sharkd prefixes its messages; keep the part that helps the user.
fn clean_error(e: &str) -> String {
    e.strip_prefix("Filter invalid - ").unwrap_or(e).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completion(field: &str) -> Completion {
        Completion {
            field: field.into(),
            name: None,
        }
    }

    #[test]
    fn stale_check_replies_are_ignored() {
        let mut f = FilterBar::default();
        f.input.set("tcp.prt");
        let (first, _) = f.check_request().unwrap();
        f.input.set("tcp.port");
        let (second, _) = f.check_request().unwrap();
        f.on_check(
            first,
            Err("Filter invalid - \"tcp.prt\" is not a valid field.".into()),
        );
        assert_eq!(f.validity, Validity::Checking);
        f.on_check(second, Ok(()));
        assert_eq!(f.validity, Validity::Valid);
    }

    #[test]
    fn empty_filter_needs_no_check() {
        let mut f = FilterBar::default();
        f.input.set("   ");
        assert!(f.check_request().is_none());
        assert_eq!(f.validity, Validity::Empty);
    }

    #[test]
    fn error_prefix_is_removed() {
        let mut f = FilterBar::default();
        f.input.set("x");
        let (seq, _) = f.check_request().unwrap();
        f.on_check(
            seq,
            Err("Filter invalid - \"x\" is not a valid protocol.".into()),
        );
        assert_eq!(
            f.validity,
            Validity::Invalid("\"x\" is not a valid protocol.".into())
        );
    }

    #[test]
    fn completion_replaces_only_the_word_at_the_cursor() {
        let mut f = FilterBar::default();
        f.input.set("ip.addr == 10.0.0.1 && tcp.po");
        let (seq, prefix) = f.complete_request().unwrap();
        assert_eq!(prefix, "tcp.po");
        f.on_complete(
            seq,
            &prefix,
            vec![completion("tcp.port.extra"), completion("tcp.port")],
        );
        assert_eq!(f.completions.items[0].field, "tcp.port", "shortest first");
        f.move_completion(1);
        assert!(f.accept_completion());
        assert_eq!(f.input.text(), "ip.addr == 10.0.0.1 && tcp.port");
        assert!(!f.has_completions());
    }

    #[test]
    fn values_and_short_words_are_not_completed() {
        let mut f = FilterBar::default();
        f.input.set("tcp.port == 80");
        assert!(f.complete_request().is_none(), "a number is not a field");
        f.input.set("t");
        assert!(f.complete_request().is_none(), "too short");
    }

    #[test]
    fn exact_single_match_shows_no_popup() {
        let mut f = FilterBar::default();
        f.input.set("dns");
        let (seq, prefix) = f.complete_request().unwrap();
        f.on_complete(seq, &prefix, vec![completion("dns")]);
        assert!(!f.has_completions());
    }

    #[test]
    fn completion_selection_wraps() {
        let mut f = FilterBar::default();
        f.input.set("tc");
        let (seq, prefix) = f.complete_request().unwrap();
        f.on_complete(seq, &prefix, vec![completion("tcp"), completion("tcap")]);
        f.move_completion(-1);
        assert_eq!(f.completions.selected, Some(1));
        f.move_completion(1);
        assert_eq!(f.completions.selected, Some(0));
    }
}
