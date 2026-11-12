//! What the app does with each answer from sharkd.

use std::time::Instant;

use super::detail::Detail;
use super::{App, Level, LoadState, Overlay, Reveal, search};
use crate::sharkd::{DetailsStep, Purpose, Reply, Seek};

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
                    if self.status.is_some() {
                        // The first page may already have been requested with
                        // the profile's columns; fetch again with ours.
                        self.build_columns();
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
                        self.reveal_match();
                    }
                    Err(e) => {
                        self.detail = None;
                        self.error(format!("Could not dissect packet {num}: {e}"));
                    }
                }
            }
            Reply::DetailsSearched {
                generation,
                seek,
                result,
            } => {
                if generation == self.list.generation {
                    self.on_details_searched(seek, result);
                } else {
                    self.end_find();
                }
            }
            Reply::Check { seq, result, .. } => {
                self.filter.on_check(seq, result);
                self.apply_checked_filter();
            }
            Reply::FieldChecked {
                title,
                field,
                result,
            } => self.on_field_checked(title, field, result),
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
                self.status = Some(status);
                self.build_columns();
                self.load = LoadState::Ready;
                if first {
                    self.list.reset();
                } else {
                    self.refresh_list();
                }
                self.count_displayed();
                if first && self.capture.is_none() && self.tail.is_none() {
                    let source = self.source.clone();
                    self.remember_capture(&source);
                }
                if first {
                    // Marks and the way back belong to the capture that was open.
                    self.local_marks.clear();
                    self.jump_back = None;
                    if let Some(num) = self.after_open_goto.take() {
                        self.goto_frame(num);
                        self.jump_back = None;
                    }
                }
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
            Ok(Some((_, num))) => self.found(num),
            Ok(None) => self.find_ran_out(seek),
            Err(e) => {
                // Not a valid filter expression: if the text could be either,
                // treat it as text.
                let fallback = self
                    .find
                    .as_ref()
                    .and_then(|f| (f.query.kind == search::Kind::Auto).then(|| f.query.as_text()));
                match fallback.map(|query| (query.plan(), query)) {
                    Some((Ok(plan), query)) => {
                        if let Some(f) = &mut self.find {
                            f.query = query;
                            f.plan = plan;
                        }
                        let from = self.list.selected_num().unwrap_or(0);
                        self.send_find(from, seek);
                    }
                    Some((Err(reason), _)) => {
                        self.end_find();
                        self.error(reason);
                    }
                    None => {
                        self.end_find();
                        self.error(format!("Search failed: {e}"));
                    }
                }
            }
        }
    }

    /// A search landed on packet `num`: go there, and point out the match.
    fn found(&mut self, num: u32) {
        let wrapped = self.find.as_ref().is_some_and(|f| f.wrapped);
        self.reveal = self.find.as_ref().and_then(|f| {
            let pattern = f.query.pattern().ok().flatten()?;
            Some(Reveal {
                frame: num,
                target: f.query.target,
                pattern,
            })
        });
        self.goto_exact = None;
        self.note_jump();
        self.locate(num, Seek::Nearest, Purpose::Select);
        // The packet may be the one already shown, which will not arrive again.
        self.reveal_match();
        if wrapped {
            self.info("Search wrapped around.");
        } else if self
            .message
            .as_ref()
            .is_some_and(|m| m.text.starts_with("Searching"))
        {
            self.message = None;
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

    /// A search reached the end of the list without a match: try once more
    /// from the other end, then give up.
    fn find_ran_out(&mut self, seek: Seek) {
        let already_wrapped = self.find.as_ref().is_none_or(|f| f.wrapped);
        if already_wrapped {
            self.end_find();
            self.info("No packet matches.");
        } else {
            if let Some(f) = &mut self.find {
                f.wrapped = true;
            }
            let from = if seek == Seek::Prev { u32::MAX } else { 0 };
            self.send_find(from, seek);
        }
    }

    fn on_details_searched(&mut self, seek: Seek, result: Result<DetailsStep, String>) {
        // Called off while this step was running.
        if !self.searching() {
            return;
        }
        match result {
            Ok(DetailsStep::Found(num)) => self.found(num),
            Ok(DetailsStep::Continue { through }) => {
                self.info(format!(
                    "Searching… packet {} (Esc stops)",
                    crate::util::thousands(u64::from(through))
                ));
                self.send_find(through, seek);
            }
            Ok(DetailsStep::End) => self.find_ran_out(seek),
            Err(e) => {
                self.end_find();
                self.error(format!("Search failed: {e}"));
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
