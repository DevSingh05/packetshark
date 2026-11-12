//! Keyboard and mouse handling.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::{Position, Rect};

use super::{
    App, ColumnEdit, DEFAULT_SPLIT, Focus, LayoutKind, Level, Overlay, Pending, Prompt, PromptKind,
};

/// How long typed digits wait for the G that makes them a count.
const COUNT_LIFETIME: Duration = Duration::from_millis(1000);

/// The furthest a count walks down the details or bytes, which are short.
const MAX_ROWS_BY_COUNT: u32 = 100_000;
use crate::sharkd::{Request, Seek};
use crate::text_input::{Edit, TextInput};

/// A cursor movement, shared by every scrollable thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Motion {
    Lines(i64),
    Pages(i64),
    HalfPages(i64),
    Home,
    End,
}

fn motion(key: KeyEvent) -> Option<Motion> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    Some(match key.code {
        KeyCode::Char('j') | KeyCode::Down if !ctrl => Motion::Lines(1),
        KeyCode::Char('k') | KeyCode::Up if !ctrl => Motion::Lines(-1),
        KeyCode::Char('n') if ctrl => Motion::Lines(1),
        KeyCode::Char('p') if ctrl => Motion::Lines(-1),
        KeyCode::PageDown => Motion::Pages(1),
        KeyCode::PageUp => Motion::Pages(-1),
        KeyCode::Char('f') if ctrl => Motion::Pages(1),
        KeyCode::Char('b') if ctrl => Motion::Pages(-1),
        KeyCode::Char('d') if ctrl => Motion::HalfPages(1),
        KeyCode::Char('u') if ctrl => Motion::HalfPages(-1),
        KeyCode::Char('g') | KeyCode::Home if !ctrl => Motion::Home,
        KeyCode::Char('G') | KeyCode::End if !ctrl => Motion::End,
        _ => return None,
    })
}

/// Turn a motion into a line delta for a view `height` lines tall.
fn delta(m: Motion, height: u16) -> i64 {
    let page = (i64::from(height) - 1).max(1);
    match m {
        Motion::Lines(n) => n,
        Motion::Pages(n) => n * page,
        Motion::HalfPages(n) => n * (page / 2).max(1),
        Motion::Home => i64::MIN / 4,
        Motion::End => i64::MAX / 4,
    }
}

fn contains(area: Rect, x: u16, y: u16) -> bool {
    area.contains(Position { x, y })
}

impl App {
    pub(super) fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            if self.capturing() {
                self.stop_capture();
            } else {
                self.quit = true;
            }
            return;
        }
        if self.filter.apply_when_checked {
            self.held_keys.push(key);
            return;
        }
        if self.prompt.is_some() {
            self.key_prompt(key);
        } else if self.overlay.is_some() {
            self.key_overlay(key);
        } else if self.focus == Focus::Filter {
            self.key_filter(key);
        } else {
            self.key_main(key);
        }
    }

    pub(super) fn stop_capture(&mut self) {
        if self.capturing() {
            if let Some(capture) = &mut self.capture {
                capture.stop();
            }
            self.info("Capture stopped. Press q to quit.");
        } else {
            self.info("No capture is running.");
        }
    }

    /// Throw away the packets captured so far and start the capture again.
    pub(super) fn restart_capture(&mut self) {
        let Some(capture) = &mut self.capture else {
            return self.error("Only a live capture can be started again.");
        };
        if let Err(e) = capture.restart() {
            return self.error(e);
        }
        // Everything about the old packets goes; what arrives from now on
        // loads as a capture's first packets do.
        self.status = None;
        self.load = super::LoadState::Loading;
        self.list.reset();
        self.detail = None;
        self.detail_requested = None;
        self.marks.clear();
        self.time_refs.clear();
        self.local_marks.clear();
        self.find = None;
        self.overlay = None;
        self.capture_failure_reported = false;
        self.sort = None;
        self.restart_tail();
        self.info("Capture started again; the earlier packets are gone.");
    }

    pub(super) fn on_paste(&mut self, text: &str) {
        if let Some(prompt) = &mut self.prompt {
            prompt.input.insert_str(text);
        } else if self.focus == Focus::Filter {
            if std::mem::take(&mut self.filter.select_all) {
                self.filter.input.clear();
            }
            self.filter.input.insert_str(text);
            self.filter_edited();
        }
    }

    pub(super) fn open_prompt(&mut self, kind: PromptKind, initial: &str) {
        let mut input = TextInput::new();
        if kind == PromptKind::Command {
            input.set_history(self.command_history.clone());
        }
        input.set(initial);
        let label = if kind == PromptKind::Find {
            let (target, how, case) = self.find_options();
            super::search::Query::describe(target, how, case)
        } else {
            kind.label().to_string()
        };
        self.prompt = Some(Prompt {
            kind,
            label,
            input,
            candidates: super::cmdline::Candidates::default(),
        });
    }

    /// Work out what could complete the command line as it now stands.
    /// Nothing is offered for an empty line: the list of every command is
    /// one Tab away, and should not appear unasked.
    fn refresh_candidates(&mut self, even_if_empty: bool) {
        let Some(prompt) = &self.prompt else { return };
        if prompt.kind != PromptKind::Command {
            return;
        }
        let before: String = prompt
            .input
            .text()
            .chars()
            .take(prompt.input.cursor())
            .collect();
        let candidates = if before.trim().is_empty() && !even_if_empty {
            super::cmdline::Candidates::default()
        } else {
            self.command_candidates(&before)
        };
        if let Some(prompt) = &mut self.prompt {
            prompt.candidates = candidates;
        }
    }

    /// Tab in the command line: take the only candidate, or step through
    /// several.
    fn complete_command(&mut self, by: i64) {
        if self
            .prompt
            .as_ref()
            .is_some_and(|p| p.candidates.items.is_empty())
        {
            self.refresh_candidates(true);
        }
        let Some(prompt) = &mut self.prompt else {
            return;
        };
        let start = prompt.candidates.start;
        let only = prompt.candidates.items.len() == 1;
        let Some(candidate) = prompt.candidates.step(by) else {
            return;
        };
        let mut text = candidate.text.clone();
        // A finished word gets its space, except a directory, which is
        // usually gone into next.
        if only && !text.ends_with('/') {
            text.push(' ');
        }
        prompt.input.replace_word(start, &text);
        if only {
            // Settled: offer what can follow it.
            self.refresh_candidates(false);
        }
    }

    fn key_prompt(&mut self, key: KeyEvent) {
        let Some(prompt) = &mut self.prompt else {
            return;
        };
        match key.code {
            KeyCode::Esc => self.prompt = None,
            KeyCode::Enter => {
                let Some(prompt) = self.prompt.take() else {
                    return;
                };
                let text = prompt.input.text();
                match prompt.kind {
                    PromptKind::Command => {
                        if !text.trim().is_empty() {
                            self.command_history.retain(|c| c != &text);
                            self.command_history.push(text.clone());
                        }
                        self.run_command(&text);
                    }
                    PromptKind::Find => self.start_find(&text),
                    PromptKind::SaveStream => self.save_stream(&text),
                    PromptKind::FollowSearch => self.search_stream(&text),
                    PromptKind::AddColumn => {
                        let text = text.trim();
                        let (field, title) = match text.split_once(char::is_whitespace) {
                            Some((f, t)) => (f, Some(t)),
                            None => (text, None),
                        };
                        if !field.is_empty() {
                            self.add_column(field, title);
                        }
                    }
                    PromptKind::RenameColumn => self.edit_columns(ColumnEdit::Rename(text)),
                }
            }
            KeyCode::Tab if prompt.kind == PromptKind::Command => self.complete_command(1),
            KeyCode::BackTab if prompt.kind == PromptKind::Command => self.complete_command(-1),
            // In the find prompt these choose where to look, how to read
            // the text, and whether case matters.
            KeyCode::Tab if prompt.kind == PromptKind::Find => {
                let (target, how, case) = self.find_options();
                self.set_find_options(target.next(), how, case);
            }
            KeyCode::BackTab if prompt.kind == PromptKind::Find => {
                let (target, how, case) = self.find_options();
                self.set_find_options(target, how.next(), case);
            }
            KeyCode::Char('o')
                if prompt.kind == PromptKind::Find
                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                let (target, how, case) = self.find_options();
                self.set_find_options(target, how, !case);
            }
            KeyCode::Up => {
                prompt.input.history_prev();
                self.refresh_candidates(false);
            }
            KeyCode::Down => {
                prompt.input.history_next();
                self.refresh_candidates(false);
            }
            KeyCode::Backspace if prompt.input.is_empty() => self.prompt = None,
            _ => {
                if prompt.input.handle_key(key) != Edit::Ignored {
                    self.refresh_candidates(false);
                }
            }
        }
    }

    // ---- filter bar -------------------------------------------------------

    /// Revalidate and recomplete after the filter text changed.
    fn filter_edited(&mut self) {
        if let Some((seq, filter)) = self.filter.check_request() {
            self.send(Request::Check { seq, filter });
        }
        self.filter_moved();
    }

    fn filter_moved(&mut self) {
        if let Some((seq, prefix)) = self.filter.complete_request() {
            self.send(Request::Complete { seq, prefix });
        }
    }

    fn key_filter(&mut self, key: KeyEvent) {
        self.filter.apply_when_checked = false;
        if std::mem::take(&mut self.filter.select_all) {
            // The text is "selected": typing replaces it, deleting removes it,
            // and anything else (arrows, Enter) just drops the selection.
            let plain = !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
            match key.code {
                KeyCode::Char(_) if plain => self.filter.input.clear(),
                KeyCode::Backspace | KeyCode::Delete => {
                    self.filter.input.clear();
                    self.filter_edited();
                    return;
                }
                _ => {}
            }
        }
        let popup = self.filter.has_completions();
        match key.code {
            KeyCode::Esc if popup => self.filter.close_completions(),
            KeyCode::Esc => {
                // Abandon the edit.
                let applied = self.filter.applied.clone();
                self.filter.input.set(&applied);
                self.filter_edited();
                self.filter.close_completions();
                self.leave_filter();
            }
            KeyCode::Enter => {
                if popup && self.filter.completions.selected.is_some() {
                    self.filter.accept_completion();
                    self.filter_edited();
                    return;
                }
                match &self.filter.validity {
                    super::filter::Validity::Invalid(reason) => {
                        let reason = reason.clone();
                        self.error(format!("Invalid filter: {reason}"));
                        return;
                    }
                    super::filter::Validity::Checking => {
                        // Typed faster than sharkd answers: apply once it has.
                        self.filter.apply_when_checked = true;
                        return;
                    }
                    _ => {}
                }
                let text = self.filter.input.text();
                self.apply_filter(&text);
                self.leave_filter();
            }
            KeyCode::Tab if popup => {
                self.filter.accept_completion();
                self.filter_edited();
            }
            KeyCode::Tab => {
                self.leave_filter();
                self.focus = Focus::List;
            }
            KeyCode::Down if popup => self.filter.move_completion(1),
            KeyCode::Up if popup => self.filter.move_completion(-1),
            KeyCode::Up => {
                if self.filter.input.history_prev() {
                    self.filter_edited();
                    self.filter.close_completions();
                }
            }
            KeyCode::Down => {
                if self.filter.input.history_next() {
                    self.filter_edited();
                    self.filter.close_completions();
                }
            }
            _ => match self.filter.input.handle_key(key) {
                Edit::Changed => self.filter_edited(),
                Edit::Moved => self.filter_moved(),
                Edit::Ignored => {}
            },
        }
    }

    // ---- main panes -------------------------------------------------------

    /// The second key of a two-key command. Returns whether the key was
    /// used up; an unrelated key cancels the command and is dropped, as in
    /// vim.
    fn key_pending(&mut self, key: KeyEvent) -> bool {
        let pending = std::mem::take(&mut self.pending);
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match (pending, key.code) {
            (Pending::None, _) => return false,
            (Pending::Mark, KeyCode::Char(c)) if c.is_ascii_alphabetic() && !ctrl => {
                self.set_mark(c);
            }
            (Pending::Jump, KeyCode::Char('\'' | '`')) => self.jump_back(),
            (Pending::Jump, KeyCode::Char(c)) if c.is_ascii_alphabetic() && !ctrl => {
                self.jump_to_mark(c);
            }
            (Pending::Z, KeyCode::Char('Z' | 'Q')) => self.quit = true,
            (Pending::Window, KeyCode::Char('w' | 'j' | 'l') | KeyCode::Down | KeyCode::Right) => {
                self.cycle_focus(1);
            }
            (
                Pending::Window,
                KeyCode::Char('W' | 'p' | 'k' | 'h') | KeyCode::Up | KeyCode::Left,
            ) => {
                self.cycle_focus(-1);
            }
            (Pending::Window, KeyCode::Char('=')) => {
                self.split = DEFAULT_SPLIT;
                self.info("Panes reset to their usual sizes.");
            }
            _ => {}
        }
        self.count = None;
        self.count_focus = None;
        true
    }

    /// Put the focus back where it was before a count's first digit, which
    /// doubles as a pane key, moved it.
    fn restore_count_focus(&mut self) {
        if let Some(focus) = self.count_focus.take() {
            self.focus = focus;
        }
    }

    /// Go to row `row` (counting from one) of the focused pane.
    fn go_to_row(&mut self, row: u32) {
        let index = row.saturating_sub(1);
        match self.focus {
            Focus::List | Focus::Filter => {
                self.note_jump();
                self.list
                    .select(index.min(self.list.len().saturating_sub(1)));
            }
            Focus::Tree | Focus::Hex => {
                let home = KeyEvent::new(KeyCode::Home, KeyModifiers::NONE);
                let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
                self.key_focused(home);
                for _ in 0..index.min(MAX_ROWS_BY_COUNT) {
                    self.key_focused(down);
                }
            }
        }
    }

    fn key_main(&mut self, key: KeyEvent) {
        if self.key_pending(key) {
            return;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // A count: `25G` goes to row 25. The digits 1 to 3 are also the pane
        // keys, so the first one still switches pane; a G that follows
        // undoes that.
        if !ctrl
            && let KeyCode::Char(c @ '0'..='9') = key.code
            && (c != '0' || self.count.is_some())
        {
            let digit = c as u32 - '0' as u32;
            // A digit pressed a while ago was a pane key and nothing more;
            // only digits typed in one go with the G are a count.
            if self
                .count_at
                .is_some_and(|at| at.elapsed() > COUNT_LIFETIME)
            {
                self.count = None;
            }
            self.count_at = Some(Instant::now());
            if self.count.is_none() {
                self.count_focus = Some(self.focus);
            }
            // Every 1, 2 or 3 acts as the pane key it is, so that `2` then
            // `1` ends in the list; a G after them puts the focus back.
            match c {
                '1' => self.focus = Focus::List,
                '2' => self.focus = Focus::Tree,
                '3' => self.focus = Focus::Hex,
                _ => {}
            }
            self.count = Some(
                self.count
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(digit),
            );
            return;
        }
        let fresh = self
            .count_at
            .take()
            .is_some_and(|at| at.elapsed() <= COUNT_LIFETIME);
        if let Some(count) = self.count.take().filter(|_| fresh) {
            // `25G`, `25g` and so `25gg`: row 25. Before any other key the
            // digits were pane keys, which is how they have already acted.
            if matches!(motion(key), Some(Motion::End | Motion::Home)) {
                self.restore_count_focus();
                self.after_count_g = key.code == KeyCode::Char('g');
                return self.go_to_row(count);
            }
        }
        self.count_focus = None;
        // The second g of `25gg`, which has nothing left to do.
        if std::mem::take(&mut self.after_count_g) && key.code == KeyCode::Char('g') && !ctrl {
            return;
        }
        if ctrl {
            match key.code {
                KeyCode::Char('w') => {
                    self.pending = Pending::Window;
                    return;
                }
                KeyCode::Char('r') => {
                    self.info("Reloading.");
                    self.reload();
                    return;
                }
                KeyCode::Char('t') => {
                    self.toggle_time_reference();
                    return;
                }
                _ => {}
            }
        } else {
            match key.code {
                KeyCode::Char('q') => {
                    self.quit = true;
                    return;
                }
                KeyCode::Char('?') | KeyCode::F(1) => {
                    self.overlay = Some(Overlay::Help { top: 0 });
                    return;
                }
                KeyCode::Tab => return self.cycle_focus(1),
                KeyCode::BackTab => return self.cycle_focus(-1),
                KeyCode::Char('m') => return self.pending = Pending::Mark,
                KeyCode::Char('\'' | '`') => return self.pending = Pending::Jump,
                KeyCode::Char('Z') => return self.pending = Pending::Z,
                KeyCode::Char('/') => return self.focus_filter(),
                KeyCode::Char('x') => {
                    if self.filter.applied.is_empty() && self.filter.input.is_empty() {
                        self.info("No filter is applied.");
                    } else {
                        self.apply_filter("");
                    }
                    return;
                }
                KeyCode::Char(':') => return self.open_prompt(PromptKind::Command, ""),
                KeyCode::Char('s') => return self.open_prompt(PromptKind::Find, ""),
                KeyCode::Char('n') => return self.find_step(Seek::Next),
                KeyCode::Char('N') => return self.find_step(Seek::Prev),
                KeyCode::Char('z') => return self.zoom = !self.zoom,
                KeyCode::Esc => {
                    if self.searching() {
                        self.stop_find();
                    } else if self.hex.anchor.take().is_some() {
                        // A selection of bytes was under way.
                    } else if self.zoom {
                        self.zoom = false;
                    }
                    return;
                }
                KeyCode::Char('L') => {
                    self.layout = match self.layout {
                        LayoutKind::Stacked => LayoutKind::Side,
                        LayoutKind::Side => LayoutKind::Stacked,
                    };
                    return;
                }
                KeyCode::Char('+' | '=') => return self.resize_pane(5),
                KeyCode::Char('-' | '_') => return self.resize_pane(-5),
                KeyCode::Char('t') => return self.cycle_time_format(),
                KeyCode::Char('c') => {
                    self.theme.row_colors = self.theme.row_colors.next();
                    let name = self.theme.row_colors.name();
                    self.info(format!("Row colours: {name}."));
                    return;
                }
                KeyCode::Char('F') => return self.follow_selected(None),
                KeyCode::Char('S') => return self.stats_menu(),
                KeyCode::Char('a') => return self.filter_menu(false),
                KeyCode::Char('p') => return self.filter_menu(true),
                KeyCode::Char('y') => return self.copy_menu(),
                KeyCode::Char('M') => return self.toggle_mark(),
                _ => {}
            }
        }
        if matches!(motion(key), Some(Motion::End | Motion::Home)) && self.focus == Focus::List {
            self.note_jump();
        }
        self.key_focused(key);
    }

    /// Hand a key to the pane that has the focus.
    fn key_focused(&mut self, key: KeyEvent) {
        match self.focus {
            Focus::List => self.key_list(key),
            Focus::Tree => self.key_tree(key),
            Focus::Hex => self.key_hex(key),
            Focus::Filter => {}
        }
    }

    fn cycle_focus(&mut self, step: i64) {
        const ORDER: [Focus; 3] = [Focus::List, Focus::Tree, Focus::Hex];
        let i = ORDER.iter().position(|f| *f == self.focus).unwrap_or(0) as i64;
        self.focus = ORDER[(i + step).rem_euclid(3) as usize];
    }

    fn resize_pane(&mut self, step: i16) {
        let i = match self.focus {
            Focus::List | Focus::Filter => 0,
            Focus::Tree => 1,
            Focus::Hex => 2,
        };
        self.split[i] = (self.split[i] as i16 + step).clamp(10, 200) as u16;
    }

    fn cycle_time_format(&mut self) {
        if !self.columns.can_change_time() {
            self.info("The time format cannot be changed with this sharkd version.");
            return;
        }
        self.time_format = self.time_format.next();
        self.list.widths.clear();
        self.refresh_list();
        let name = self.time_format.name();
        self.info(format!("Time: {name}."));
    }

    fn toggle_mark(&mut self) {
        let Some(num) = self.list.selected_num() else {
            return;
        };
        if !self.marks.remove(&num) {
            self.marks.insert(num);
        }
        self.list.move_by(1);
    }

    fn toggle_time_reference(&mut self) {
        let Some(num) = self.list.selected_num() else {
            return;
        };
        if self.lacks("Time references", (4, 0)) {
            return;
        }
        if self.time_refs.remove(&num) {
            self.info(format!("Packet {num} is no longer a time reference."));
        } else {
            self.time_refs.insert(num);
            self.info(format!("Packet {num} is now a time reference."));
        }
        self.refresh_list();
    }

    fn key_list(&mut self, key: KeyEvent) {
        if let Some(m) = motion(key) {
            match m {
                Motion::Home => self.list.select(0),
                Motion::End => self.list.select(u32::MAX),
                m => self.list.move_by(delta(m, self.list.height)),
            }
            return;
        }
        if let KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right = key.code {
            self.focus = Focus::Tree;
        }
    }

    fn key_tree(&mut self, key: KeyEvent) {
        let Some(detail) = &self.detail else { return };
        let tree = &detail.tree;
        if let Some(m) = motion(key) {
            match m {
                Motion::Home => self.tree.select(0, tree),
                Motion::End => self.tree.select(usize::MAX, tree),
                m => self.tree.move_by(delta(m, self.tree.height), tree),
            }
            self.sync_hex_to_tree();
            return;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => {
                // "Response in frame 8" style fields are links.
                if let Some(target) = self.selected_node().and_then(|n| n.fnum) {
                    self.goto_frame(target);
                    return;
                }
                self.tree.toggle(tree);
            }
            KeyCode::Char('l') | KeyCode::Right => self.tree.expand_or_descend(tree),
            KeyCode::Char('h') | KeyCode::Left => self.tree.collapse_or_ascend(tree),
            KeyCode::Char('*') => self.tree.expand_subtree(tree),
            KeyCode::Char('C') => return self.column_from_selected(),
            KeyCode::Char('e') => {
                let on = !self.tree.expand_all;
                self.tree.set_expand_all(tree, on);
            }
            _ => return,
        }
        self.sync_hex_to_tree();
    }

    fn key_hex(&mut self, key: KeyEvent) {
        let len = self.hex_bytes().len();
        let per_row = self.hex.per_row() as i64;
        let step = match key.code {
            KeyCode::Char('h') | KeyCode::Left => Some(-1),
            KeyCode::Char('l') | KeyCode::Right => Some(1),
            KeyCode::Char('j') | KeyCode::Down => Some(per_row),
            KeyCode::Char('k') | KeyCode::Up => Some(-per_row),
            KeyCode::Char('0') => Some(-((self.hex.cursor % per_row as usize) as i64)),
            KeyCode::Char('$') => Some(per_row - 1 - (self.hex.cursor % per_row as usize) as i64),
            // Start picking out bytes from here, or stop.
            KeyCode::Char('v') => {
                self.hex.anchor = match self.hex.anchor {
                    Some(_) => None,
                    None if len > 0 => {
                        self.info("Selecting bytes: move to extend, y to copy, v or Esc to stop.");
                        Some(self.hex.cursor)
                    }
                    None => None,
                };
                None
            }
            KeyCode::Char('[') => {
                self.switch_source(-1);
                None
            }
            KeyCode::Char(']') => {
                self.switch_source(1);
                None
            }
            _ => motion(key).map(|m| match m {
                Motion::Home => -(len as i64),
                Motion::End => len as i64,
                m => delta(m, self.hex.height) * per_row,
            }),
        };
        if let Some(step) = step {
            self.hex.move_cursor(step, len);
            self.sync_tree_to_hex();
        }
    }

    fn switch_source(&mut self, step: i64) {
        if !self.detail_ready() {
            return;
        }
        let Some(detail) = &self.detail else { return };
        let n = detail.sources.len() as i64;
        if n < 2 {
            self.info("This packet has only one data source.");
            return;
        }
        self.hex.source = (self.hex.source as i64 + step).rem_euclid(n) as usize;
        self.hex.anchor = None;
        self.hex.cursor = 0;
        self.hex.top = 0;
    }

    // ---- overlays ---------------------------------------------------------

    /// Start a search of the stream being followed.
    fn search_stream(&mut self, text: &str) {
        let Some(Overlay::Follow(view)) = &mut self.overlay else {
            return;
        };
        match view.set_search(text) {
            Err(e) => self.error(e),
            Ok(()) if !view.searching() => {}
            Ok(()) => match view.find(true, true) {
                Some(_) => {}
                None => self.info("The stream does not contain that."),
            },
        }
    }

    fn step_stream_search(&mut self, forward: bool) {
        let Some(Overlay::Follow(view)) = &mut self.overlay else {
            return;
        };
        if !view.searching() {
            return self.info("Nothing to search for yet. Press / to search the stream.");
        }
        match view.find(forward, false) {
            Some(true) => self.info("Search wrapped around."),
            Some(false) => {}
            None => self.info("The stream does not contain that."),
        }
    }

    fn key_column_editor(&mut self, key: KeyEvent, selected: usize, closes: bool) {
        let count = self.column_list().len();
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let select = |app: &mut App, to: usize| {
            if let Some(Overlay::Columns(editor)) = &mut app.overlay {
                editor.selected = to;
            }
        };
        match key.code {
            _ if closes => self.overlay = None,
            // Moving the column itself: the shifted or Ctrl-ed version of
            // moving the cursor.
            KeyCode::Char('J') => self.edit_columns(ColumnEdit::Move(1)),
            KeyCode::Char('K') => self.edit_columns(ColumnEdit::Move(-1)),
            KeyCode::Down if shift || ctrl => self.edit_columns(ColumnEdit::Move(1)),
            KeyCode::Up if shift || ctrl => self.edit_columns(ColumnEdit::Move(-1)),
            KeyCode::Down | KeyCode::Char('j') => {
                select(self, (selected + 1).min(count.saturating_sub(1)));
            }
            KeyCode::Up | KeyCode::Char('k') => select(self, selected.saturating_sub(1)),
            KeyCode::Home | KeyCode::Char('g') => select(self, 0),
            KeyCode::End | KeyCode::Char('G') => select(self, count.saturating_sub(1)),
            KeyCode::Char(' ') | KeyCode::Enter => self.edit_columns(ColumnEdit::Toggle),
            KeyCode::Char('d') | KeyCode::Delete => self.edit_columns(ColumnEdit::Delete),
            KeyCode::Char('a') => self.open_prompt(PromptKind::AddColumn, ""),
            KeyCode::Char('b') => self.built_in_column_menu(),
            KeyCode::Char('r') => {
                let title = self
                    .column_list()
                    .get(selected)
                    .map(|c| c.title.clone())
                    .unwrap_or_default();
                self.open_prompt(PromptKind::RenameColumn, &title);
            }
            KeyCode::Char('R') => {
                self.set_column_list(None);
                select(self, 0);
                self.info("Columns reset to the Wireshark profile's.");
            }
            _ => {}
        }
    }

    fn key_overlay(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Char(':') && !matches!(self.overlay, Some(Overlay::Menu(_))) {
            return self.open_prompt(PromptKind::Command, "");
        }
        let closes = matches!(key.code, KeyCode::Esc | KeyCode::Char('q'));
        if let Some(Overlay::Columns(editor)) = &self.overlay {
            let selected = editor.selected;
            return self.key_column_editor(key, selected, closes);
        }
        match &mut self.overlay {
            None => {}
            Some(Overlay::Help { top }) => {
                if closes || matches!(key.code, KeyCode::Char('?') | KeyCode::F(1)) {
                    self.overlay = None;
                } else if let Some(m) = motion(key) {
                    let height = self.areas.overlay.height;
                    *top = (*top as i64).saturating_add(delta(m, height)).max(0) as usize;
                }
            }
            Some(Overlay::Graph(graph)) => match key.code {
                _ if closes => self.overlay = None,
                KeyCode::Left | KeyCode::Char('h') => graph.move_cursor(-1),
                KeyCode::Right | KeyCode::Char('l') => graph.move_cursor(1),
                KeyCode::Home | KeyCode::Char('g' | '0') => graph.move_cursor(i64::MIN / 4),
                KeyCode::End | KeyCode::Char('G' | '$') => graph.move_cursor(i64::MAX / 4),
                KeyCode::Char('b') => graph.bytes = !graph.bytes,
                KeyCode::Char(c @ ('+' | '=' | '-' | '_')) => {
                    let finer = matches!(c, '+' | '=');
                    let interval = super::graph::step_interval(graph.interval_ms, finer);
                    let capture_ms = self.status.as_ref().map_or(0.0, |s| s.duration * 1000.0);
                    // Between one bar for the whole capture and more buckets
                    // than are worth counting. Judged by the capture's
                    // length, not by the bars on screen, so that the key
                    // can be pressed again before the last answer is in.
                    let sensible = if finer {
                        capture_ms / interval as f64 <= 100_000.0
                    } else {
                        (graph.interval_ms as f64) < capture_ms
                    };
                    if interval != graph.interval_ms && sensible {
                        self.open_graph(Some(interval));
                    }
                }
                KeyCode::Enter
                    if !graph.loading && graph.error.is_none() && !graph.all.is_empty() =>
                {
                    let range = graph.filter_at_cursor();
                    let filter = if graph.filter.is_empty() {
                        range
                    } else {
                        format!("({}) && {range}", graph.filter)
                    };
                    self.overlay = None;
                    self.apply_filter(&filter);
                }
                _ => {}
            },
            Some(Overlay::Text { top, .. }) => {
                if closes {
                    self.overlay = None;
                } else if let Some(m) = motion(key) {
                    let height = self.areas.overlay.height;
                    *top = (*top as i64).saturating_add(delta(m, height)).max(0) as usize;
                }
            }
            Some(Overlay::Menu(menu)) => {
                let n = menu.items.len() as i64;
                let chosen = match key.code {
                    _ if closes => {
                        self.overlay = None;
                        return;
                    }
                    KeyCode::Enter => Some(menu.selected),
                    KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() => {
                        menu.selected = (menu.selected as i64 + 1).rem_euclid(n) as usize;
                        None
                    }
                    KeyCode::Up | KeyCode::Char('k') if key.modifiers.is_empty() => {
                        menu.selected = (menu.selected as i64 - 1).rem_euclid(n) as usize;
                        None
                    }
                    KeyCode::Char(c) => menu.items.iter().position(|i| i.key == c),
                    _ => None,
                };
                if let Some(i) = chosen {
                    let action = menu.items[i].action.clone();
                    self.overlay = None;
                    self.run_action(action);
                }
            }
            // Handled above, before the overlay was borrowed.
            Some(Overlay::Columns(_)) => {}
            Some(Overlay::Follow(view)) => {
                if closes {
                    self.overlay = None;
                    return;
                }
                if let Some(m) = motion(key) {
                    match m {
                        Motion::Home => view.scroll_by(i64::MIN / 4),
                        Motion::End => view.scroll_to_end(),
                        m => view.scroll_by(delta(m, view.height)),
                    }
                    return;
                }
                match key.code {
                    KeyCode::Char('m') => {
                        let mode = view.mode.next();
                        view.set_mode(mode);
                        self.state.follow_mode = Some(mode.key().to_string());
                        self.save_state();
                    }
                    KeyCode::Char('/') => self.open_prompt(PromptKind::FollowSearch, ""),
                    KeyCode::Char('n') => self.step_stream_search(true),
                    KeyCode::Char('N') => self.step_stream_search(false),
                    KeyCode::Char('d') => {
                        let side = view.side.next();
                        view.set_side(side);
                    }
                    KeyCode::Char('f') => {
                        let filter = view.filter.clone();
                        self.overlay = None;
                        self.apply_filter(&filter);
                    }
                    KeyCode::Enter => {
                        if let Some(frame) = view.frame_at_top() {
                            self.overlay = None;
                            self.goto_frame(frame);
                        }
                    }
                    KeyCode::Char('y') => {
                        let text = view.text();
                        self.copy("stream", text);
                    }
                    KeyCode::Char('w') => {
                        let name = format!("stream-{}.bin", view.protocol.to_ascii_lowercase());
                        self.open_prompt(PromptKind::SaveStream, &name);
                    }
                    _ => {}
                }
            }
            Some(Overlay::Stats(view)) => {
                if closes {
                    self.overlay = None;
                    return;
                }
                if let Some(m) = motion(key) {
                    match m {
                        Motion::Home => view.move_by(i64::MIN / 4),
                        Motion::End => view.move_by(i64::MAX / 4),
                        m => view.move_by(delta(m, view.height)),
                    }
                    return;
                }
                match key.code {
                    KeyCode::Tab | KeyCode::Char('l') | KeyCode::Right => {
                        if view.switch_tab(1) {
                            self.request_stats();
                        }
                    }
                    KeyCode::BackTab | KeyCode::Char('h') | KeyCode::Left => {
                        if view.switch_tab(-1) {
                            self.request_stats();
                        }
                    }
                    KeyCode::Char('o') => view.cycle_sort(),
                    KeyCode::Char('r') => view.reverse_sort(),
                    KeyCode::Char('f') => {
                        // sharkd takes a filter for statistics from 4.2.
                        let too_old = self.wireshark.is_some_and(|v| v < (4, 2));
                        if too_old {
                            self.lacks("Statistics for the filtered packets only", (4, 2));
                        } else {
                            view.limit_to_filter = !view.limit_to_filter;
                            self.request_stats();
                        }
                    }
                    KeyCode::Enter => self.activate_stats_row(),
                    KeyCode::Char('a') => self.stats_filter_menu(false),
                    KeyCode::Char('p') => self.stats_filter_menu(true),
                    _ => {}
                }
            }
        }
    }

    /// The ways of filtering on the selected row of a statistics table: the
    /// whole conversation or one direction of it, on its own or combined
    /// with the filter already applied.
    fn stats_filter_menu(&mut self, prepare: bool) {
        let Some(Overlay::Stats(view)) = &self.overlay else {
            return;
        };
        let Some(row) = view.selected_row() else {
            return;
        };
        let Some(filter) = row.filter.clone() else {
            return self.info("This row cannot be used as a filter.");
        };
        let endpoint = view.kind == super::stats::Kind::Endpoints;
        let one_way = row.one_way.clone();
        let current = self.filter.applied.clone();
        let make = |expr: String| {
            if prepare {
                super::Action::PrepareFilter(expr)
            } else {
                super::Action::ApplyFilter(expr)
            }
        };
        let item = |key, label: String, expr: String| super::MenuItem {
            key,
            label: format!("{label:<22} {}", crate::util::truncate(&expr, 70)),
            action: make(expr),
        };
        let both = if endpoint {
            "To or from it"
        } else {
            "Both directions"
        };
        let mut items = vec![item('s', both.to_string(), filter.clone())];
        if let Some((there, back)) = one_way {
            let (a, b) = if endpoint {
                ("From it", "To it")
            } else {
                ("A → B only", "B → A only")
            };
            items.push(item('>', a.to_string(), there));
            items.push(item('<', b.to_string(), back));
        }
        items.push(item(
            'n',
            "Everything else".to_string(),
            format!("!({filter})"),
        ));
        if !current.is_empty() {
            items.push(item(
                'a',
                "… and this".to_string(),
                format!("({current}) && ({filter})"),
            ));
            items.push(item(
                'o',
                "… or this".to_string(),
                format!("({current}) || ({filter})"),
            ));
            items.push(item(
                'x',
                "… and not this".to_string(),
                format!("({current}) && !({filter})"),
            ));
        }
        let title = if prepare {
            "Prepare a filter"
        } else {
            "Apply as filter"
        };
        self.open_menu(title, items);
    }

    fn activate_stats_row(&mut self) {
        let Some(Overlay::Stats(view)) = &self.overlay else {
            return;
        };
        let Some(row) = view.selected_row().cloned() else {
            return;
        };
        if let Some(token) = row.token {
            let name = row.filename.filter(|n| !n.trim().is_empty());
            let safe = super::commands::safe_file_name(name.as_deref().unwrap_or("object.bin"));
            let dest =
                super::commands::unique_path(&self.download_dir.join(safe).to_string_lossy());
            self.send(Request::Download { token, dest });
        } else if let Some(filter) = row.filter {
            self.overlay = None;
            self.apply_filter(&filter);
        } else if let Some(frame) = row.frame {
            self.overlay = None;
            self.goto_frame(frame);
        }
    }

    // ---- mouse ------------------------------------------------------------

    pub(super) fn on_mouse(&mut self, mouse: MouseEvent) {
        let (x, y) = (mouse.column, mouse.row);
        let wheel = match mouse.kind {
            MouseEventKind::ScrollDown => Some(3),
            MouseEventKind::ScrollUp => Some(-3),
            _ => None,
        };
        if self.prompt.is_some() {
            return;
        }
        if let Some(overlay) = &mut self.overlay {
            if let Some(step) = wheel {
                match overlay {
                    Overlay::Help { top } | Overlay::Text { top, .. } => {
                        *top = (*top as i64 + step).max(0) as usize;
                    }
                    Overlay::Follow(view) => view.scroll_by(step),
                    Overlay::Stats(view) => view.move_by(step),
                    Overlay::Graph(graph) => graph.move_cursor(step.signum()),
                    Overlay::Menu(_) | Overlay::Columns(_) => {}
                }
            } else if mouse.kind == MouseEventKind::Down(MouseButton::Left)
                && contains(self.areas.overlay, x, y)
            {
                let line = (y - self.areas.overlay.y) as usize;
                match overlay {
                    Overlay::Stats(view) => {
                        let target = view.top + line;
                        if target < view.rows.len() {
                            view.selected = target;
                        }
                    }
                    Overlay::Menu(menu) if line < menu.items.len() => {
                        let action = menu.items[line].action.clone();
                        self.overlay = None;
                        self.run_action(action);
                    }
                    _ => {}
                }
            }
            return;
        }
        let areas = self.areas;
        if let Some(step) = wheel {
            if contains(areas.list, x, y) {
                self.list.scroll_by(step);
            } else if contains(areas.tree, x, y) {
                self.tree.scroll_by(step);
            } else if contains(areas.hex, x, y) {
                let len = self.hex_bytes().len();
                self.hex.scroll_by(step, len);
            }
            return;
        }
        if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
            return;
        }
        if contains(areas.header, x, y) {
            // A click on a column's title sorts by it; another reverses.
            let left = areas.header.x + 1;
            let cells = self
                .columns
                .layout(&self.list.widths, areas.header.width.saturating_sub(1));
            let hit = cells
                .iter()
                .position(|(cx, w)| (left + cx..left + cx + w).contains(&x));
            let title = hit
                .and_then(|i| self.columns.cols.get(i))
                .map(|c| c.title.clone());
            if let Some(title) = title {
                self.sort_by(&title, None);
            }
            return;
        }
        if contains(areas.filter, x, y) {
            self.focus_filter();
            self.filter.select_all = false;
        } else if contains(areas.list, x, y) {
            if self.focus == Focus::Filter {
                self.leave_filter();
            }
            self.focus = Focus::List;
            let index = self.list.top + u32::from(y - areas.list.y);
            if index < self.list.len() {
                self.list.select(index);
            }
        } else if contains(areas.tree, x, y) {
            if self.focus == Focus::Filter {
                self.leave_filter();
            }
            self.focus = Focus::Tree;
            let Some(detail) = &self.detail else { return };
            let index = self.tree.top + (y - areas.tree.y) as usize;
            if index < self.tree.lines.len() {
                // Clicking the selected line again toggles it.
                if index == self.tree.selected {
                    self.tree.toggle(&detail.tree);
                } else {
                    self.tree.select(index, &detail.tree);
                }
                self.sync_hex_to_tree();
            }
        } else if contains(areas.hex, x, y) {
            if self.focus == Focus::Filter {
                self.leave_filter();
            }
            self.focus = Focus::Hex;
            let row = self.hex.top + (y - areas.hex.y) as usize;
            let geometry = crate::ui::hex::Geometry::new(areas.hex.width, self.hex_bytes().len());
            let column = geometry.column_at(x - areas.hex.x);
            if let Some(column) = column {
                let offset = row * self.hex.per_row() + column;
                if offset < self.hex_bytes().len() {
                    self.hex.cursor = offset;
                    self.sync_tree_to_hex();
                }
            }
        }
    }

    fn save_stream(&mut self, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let Some(Overlay::Follow(view)) = &self.overlay else {
            return;
        };
        let payload = view.payload();
        let path = super::commands::expand_path(name);
        match std::fs::write(&path, &payload) {
            Ok(()) => self.info(format!(
                "Saved {} ({}).",
                path.display(),
                crate::util::human_bytes(payload.len() as u64)
            )),
            Err(e) => self.say(
                Level::Error,
                format!("Could not write {}: {e}", path.display()),
            ),
        }
    }
}
