//! What the app does with each answer from sharkd.

use std::time::Instant;

use super::columns::Columns;
use super::detail::Detail;
use super::{App, Level, LoadState, Overlay, contains};
use crate::sharkd::{Purpose, Reply, Seek};

impl App {
    pub(super) fn on_reply(&mut self, reply: Reply) {
        // `Restarted` is an announcement, not the answer to a request.
        if !matches!(reply, Reply::Restarted { .. }) {
            self.inflight = self.inflight.saturating_sub(1);
        }
        match reply {
            Reply::Superseded => {}
            Reply::Info(result) => {
                if let Ok(info) = result {
                    self.info = Some(info);
                    if let Some(status) = &self.status {
                        // The first page may already have been requested with
                        // the profile's columns; fetch again with ours.
                        self.columns = Columns::new(status, self.info.as_ref());
                        self.refresh_list();
                    }
                }
            }
            Reply::Loaded { path, result } => self.on_loaded(path, result),
            Reply::Count { generation, result } => {
                if generation != self.list.generation {
                    return;
                }
                match result {
                    Ok(n) => self.set_total(n),
                    Err(e) => {
                        self.list.set_total(0);
                        self.list.error = Some(e);
                    }
                }
            }
            Reply::Frames {
                generation,
                skip,
                result,
            } => {
                if generation != self.list.generation {
                    return;
                }
                match result {
                    Ok(rows) => self.list.insert_page(skip, rows),
                    Err(e) => self.list.page_failed(skip, e),
                }
            }
            Reply::Located {
                generation,
                purpose,
                seek,
                result,
            } => {
                if generation != self.list.generation {
                    // The list changed under a search; its result is moot.
                    if purpose == Purpose::Find {
                        self.end_find();
                    }
                    return;
                }
                match purpose {
                    Purpose::Select => self.on_located(result),
                    Purpose::Find => self.on_found(seek, result),
                }
            }
            Reply::Frame { num, result } => {
                if self.detail_requested != Some(num) {
                    return;
                }
                match result {
                    Ok(frame) => {
                        let detail = Detail::new(num, *frame);
                        self.tree.show(&detail.tree);
                        self.hex.reset();
                        self.detail = Some(detail);
                        self.sync_hex_to_tree();
                    }
                    Err(e) => {
                        self.detail = None;
                        self.error(format!("Could not dissect packet {num}: {e}"));
                    }
                }
            }
            Reply::Check { seq, result, .. } => {
                self.filter.on_check(seq, result);
                self.apply_checked_filter();
            }
            Reply::Complete {
                seq,
                prefix,
                result,
            } => self.filter.on_complete(seq, &prefix, result),
            Reply::Follow {
                protocol,
                filter,
                result,
            } => {
                if let Some(Overlay::Follow(view)) = &mut self.overlay
                    && view.protocol == protocol
                    && view.filter == filter
                {
                    view.set_data(result);
                }
            }
            Reply::Tap { id, result } => {
                if let Some(Overlay::Stats(view)) = &mut self.overlay
                    && view.request == id
                {
                    view.set_result(result);
                }
            }
            Reply::SetConf { name, result } => match result {
                Ok(()) => {
                    // Preferences change how packets are dissected.
                    if self.status.is_some() {
                        self.info(format!("Set {name}; reloading."));
                        self.reload();
                    }
                }
                Err(e) => self.error(format!("Could not set {name}: {e}")),
            },
            Reply::Download { dest, result } => match result {
                Ok(bytes) => self.info(format!(
                    "Saved {} ({}).",
                    dest.display(),
                    crate::util::human_bytes(bytes)
                )),
                Err(e) => self.error(e),
            },
            Reply::Restarted { reason } => {
                self.say(
                    Level::Error,
                    format!(
                        "sharkd stopped ({reason}) and was restarted. Some packets may not dissect."
                    ),
                );
                self.refresh_list();
            }
        }
    }

    fn on_loaded(
        &mut self,
        path: std::path::PathBuf,
        result: Result<(crate::sharkd::types::Status, Option<String>), String>,
    ) {
        // A capture requested with `:open`.
        if self.pending_open.as_ref() == Some(&path) {
            self.pending_open = None;
            match &result {
                Ok(_) => self.adopt_opened(path.clone()),
                Err(e) => {
                    // sharkd keeps the previous capture when an open fails,
                    // and so do we.
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    self.error(format!("Could not open {}: {e}", name.unwrap_or_default()));
                    return;
                }
            }
        } else if path != self.source {
            return;
        }
        let tailing = self.tail.is_some();
        if let Some(tail) = &mut self.tail {
            tail.loading = false;
            tail.cost = tail.started.elapsed();
            tail.started = Instant::now();
            tail.error = result.as_ref().err().cloned();
        }
        match result {
            Err(e) => {
                if tailing {
                    // The file may not hold a complete header yet. It is
                    // tried again when it grows, not before: retrying an
                    // unchanged file would spin.
                } else if self.status.is_none() {
                    self.load = LoadState::Failed(format!("{}: {e}", self.title));
                } else {
                    self.error(format!("Reload failed: {e}"));
                }
            }
            Ok((status, warning)) => {
                let first = self.status.is_none();
                self.loaded_once = true;
                self.columns = Columns::new(&status, self.info.as_ref());
                self.status = Some(status);
                self.load = LoadState::Ready;
                if first {
                    self.list.reset();
                } else {
                    self.refresh_list();
                }
                self.count_displayed();
                // A truncated tail is expected while a capture is being written.
                if let Some(w) = warning.filter(|_| !tailing) {
                    self.say(Level::Warn, format!("The capture is incomplete: {w}"));
                }
            }
        }
    }

    fn on_located(&mut self, result: Result<Option<(u32, u32)>, String>) {
        let asked = self.goto_exact.take();
        match result {
            Ok(Some((index, num))) => {
                self.list.select(index);
                self.list.center();
                if let Some(wanted) = asked.filter(|w| *w != num) {
                    self.say(
                        Level::Warn,
                        format!("Packet {wanted} is hidden by the filter; showing {num}."),
                    );
                }
            }
            Ok(None) => {}
            Err(e) => self.error(e),
        }
    }

    /// Finish an Enter that was pressed before the filter had been validated.
    fn apply_checked_filter(&mut self) {
        use super::filter::Validity;
        if !self.filter.apply_when_checked {
            return;
        }
        match self.filter.validity.clone() {
            Validity::Checking => {}
            Validity::Invalid(reason) => {
                self.filter.apply_when_checked = false;
                // Whatever was typed next assumed the filter would apply.
                self.held_keys.clear();
                self.error(format!("Invalid filter: {reason}"));
            }
            Validity::Valid | Validity::Empty => {
                let text = self.filter.input.text();
                self.apply_filter(&text);
                self.leave_filter();
                for key in std::mem::take(&mut self.held_keys) {
                    self.on_key(key);
                }
            }
        }
    }

    fn on_found(&mut self, seek: Seek, result: Result<Option<(u32, u32)>, String>) {
        match result {
            Ok(Some((_, num))) => {
                let wrapped = self.find.as_ref().is_some_and(|f| f.wrapped);
                self.goto_exact = None;
                self.locate(num, Seek::Nearest, Purpose::Select);
                if wrapped {
                    self.info("Search wrapped around.");
                }
                // Continue with any step requested meanwhile, from this hit.
                let next = self.find.as_mut().and_then(|f| {
                    f.busy = None;
                    f.wrapped = false;
                    f.queued.pop_front()
                });
                if let Some(next) = next {
                    self.send_find(num, next);
                }
            }
            Ok(None) => {
                let already_wrapped = self.find.as_ref().is_none_or(|f| f.wrapped);
                if already_wrapped {
                    self.end_find();
                    self.info("No packet matches.");
                } else {
                    if let Some(f) = &mut self.find {
                        f.wrapped = true;
                    }
                    // Start again from the other end.
                    let from = if seek == Seek::Prev { u32::MAX } else { 0 };
                    self.send_find(from, seek);
                }
            }
            Err(e) => {
                // Not a valid filter expression: treat what was typed as text.
                let plain = self.find.as_mut().and_then(|f| f.plain.take());
                if let Some(text) = plain {
                    if let Some(f) = &mut self.find {
                        f.filter = contains(&text);
                    }
                    let from = self.list.selected_num().unwrap_or(0);
                    self.send_find(from, seek);
                } else {
                    self.end_find();
                    self.error(format!("Search failed: {e}"));
                }
            }
        }
    }

    fn end_find(&mut self) {
        if let Some(f) = &mut self.find {
            f.busy = None;
            f.queued.clear();
        }
    }
}
