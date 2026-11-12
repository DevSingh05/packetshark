//! The worker thread that owns the sharkd process.
//!
//! sharkd answers one request at a time and some answers take seconds, so all
//! calls happen here, off the UI thread. The UI sends `Request`s and gets back
//! exactly one `Reply` per request, in order. Requests that newer ones make
//! pointless (the detail of a packet the cursor has already left, a page for a
//! filter that has since changed) are answered with `Reply::Superseded`
//! without touching sharkd.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use serde_json::{Map, Value, json};

use super::client::{Client, Error, Launch};
use super::types::{
    CompleteResult, Completion, Download, Follow, FrameDetail, FrameRow, Info, Intervals,
    LoadResult, Status, Tap, TapResult,
};

/// Which way `Request::Locate` should look from the given frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seek {
    /// The first displayed frame at or after the given frame; if there is
    /// none, the last displayed frame.
    Nearest,
    /// The first displayed frame strictly after the given frame.
    Next,
    /// The last displayed frame strictly before the given frame.
    Prev,
}

/// Why a `Locate` was asked, so the app knows what to do with the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Put the cursor on this frame (go-to, filter change, jump from a link).
    Select,
    /// A search hit.
    Find,
}

#[derive(Debug, Clone)]
pub enum Request {
    /// Ask sharkd what it supports. Sent once at startup.
    Info,
    /// Load (or reload) a capture file.
    Load { path: PathBuf },
    /// Number of frames matching `filter`.
    Count { generation: u64, filter: String },
    /// A window of the packet list.
    Frames {
        generation: u64,
        filter: String,
        skip: u32,
        limit: u32,
        columns: Vec<String>,
        refs: Vec<u32>,
    },
    /// Find the position of a frame within the frames matching `filter`.
    Locate {
        generation: u64,
        filter: String,
        frame: u32,
        seek: Seek,
        purpose: Purpose,
    },
    /// Dissection tree and bytes of one frame.
    Frame {
        num: u32,
        prev: Option<u32>,
        reference: Option<u32>,
    },
    /// Validate a display filter.
    Check { seq: u64, filter: String },
    /// Complete a field name.
    Complete { seq: u64, prefix: String },
    /// Reassemble a stream.
    Follow { protocol: String, filter: String },
    /// Run statistics taps.
    Tap {
        id: u64,
        taps: Vec<String>,
        filter: String,
    },
    /// Set a Wireshark preference.
    SetConf { name: String, value: String },
    /// Fetch an exported object.
    Download { token: String, dest: PathBuf },
}

#[derive(Debug)]
pub enum Reply {
    Info(Result<Info, String>),
    Loaded {
        path: PathBuf,
        result: Result<(Status, Option<String>), String>,
    },
    Count {
        generation: u64,
        result: Result<u32, String>,
    },
    Frames {
        generation: u64,
        skip: u32,
        result: Result<Vec<FrameRow>, String>,
    },
    Located {
        generation: u64,
        purpose: Purpose,
        seek: Seek,
        /// `(index within the displayed list, frame number)`, or `None` when
        /// nothing matches in that direction.
        result: Result<Option<(u32, u32)>, String>,
    },
    Frame {
        num: u32,
        result: Result<Box<FrameDetail>, String>,
    },
    Check {
        seq: u64,
        filter: String,
        result: Result<(), String>,
    },
    Complete {
        seq: u64,
        prefix: String,
        result: Vec<Completion>,
    },
    Follow {
        protocol: String,
        filter: String,
        result: Result<Follow, String>,
    },
    Tap {
        id: u64,
        result: Result<Vec<Tap>, String>,
    },
    SetConf {
        name: String,
        result: Result<(), String>,
    },
    Download {
        dest: PathBuf,
        result: Result<u64, String>,
    },
    /// The request was dropped because a newer one replaced it.
    Superseded,
    /// sharkd died and was restarted; the capture was reloaded if there was one.
    Restarted {
        reason: String,
    },
}

/// Handle used by the UI thread.
pub struct Worker {
    tx: Option<Sender<Request>>,
    thread: Option<JoinHandle<()>>,
    pid: Arc<AtomicU32>,
    /// Set when the worker is being dropped: stop instead of carrying on.
    stopping: Arc<AtomicBool>,
}

impl Worker {
    /// Start sharkd and the worker thread. `deliver` is called on the worker
    /// thread for every reply.
    pub fn start(
        launch: Launch,
        deliver: impl Fn(Reply) + Send + 'static,
    ) -> std::io::Result<Worker> {
        let client = Client::spawn(&launch)?;
        let pid = Arc::new(AtomicU32::new(client.pid()));
        let stopping = Arc::new(AtomicBool::new(false));
        let (shared_pid, shared_stopping) = (pid.clone(), stopping.clone());
        let (tx, rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("sharkd".into())
            .spawn(move || {
                Runner {
                    launch,
                    client,
                    loaded: None,
                    deliver: Box::new(deliver),
                    pid: shared_pid,
                    stopping: shared_stopping,
                }
                .run(rx);
            })?;
        Ok(Worker {
            tx: Some(tx),
            thread: Some(thread),
            pid,
            stopping,
        })
    }

    /// Process id of the sharkd currently in use (it changes after a restart).
    pub fn pid(&self) -> u32 {
        self.pid.load(Ordering::SeqCst)
    }

    pub fn send(&self, request: Request) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(request);
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Do not wait for sharkd to finish a load or a statistics run that
        // nobody will look at: kill it, which fails the request in flight,
        // and tell the thread not to restart it or start anything queued.
        self.stopping.store(true, Ordering::SeqCst);
        self.tx.take();
        #[cfg(unix)]
        // SAFETY: `kill` has no memory-safety preconditions. The pid is that
        // of the sharkd child, which the worker thread reaps only after it
        // has stopped, and it stops only after this signal or on its own;
        // the thread is joined below, so the pid cannot have been reused.
        unsafe {
            libc::kill(self.pid() as libc::pid_t, libc::SIGKILL);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct Runner {
    launch: Launch,
    client: Client,
    loaded: Option<PathBuf>,
    deliver: Box<dyn Fn(Reply) + Send>,
    pid: Arc<AtomicU32>,
    stopping: Arc<AtomicBool>,
}

impl Runner {
    fn run(mut self, rx: Receiver<Request>) {
        let mut queue: VecDeque<Request> = VecDeque::new();
        loop {
            if queue.is_empty() {
                match rx.recv() {
                    Ok(r) => queue.push_back(r),
                    Err(_) => return,
                }
            }
            while let Ok(r) = rx.try_recv() {
                queue.push_back(r);
            }
            if self.stopping.load(Ordering::SeqCst) {
                return;
            }
            let superseded = mark_superseded(&queue);
            let request = queue.pop_front().expect("non-empty queue");
            if superseded[0] {
                (self.deliver)(Reply::Superseded);
                continue;
            }
            let reply = self.handle(request);
            (self.deliver)(reply);
        }
    }

    fn handle(&mut self, request: Request) -> Reply {
        let again = request.clone();
        let fatal = match self.execute(request) {
            Ok(reply) => return reply,
            Err(fatal) => fatal,
        };
        if self.stopping.load(Ordering::SeqCst) {
            // We killed sharkd ourselves, to shut down.
            return failure(again, fatal.to_string());
        }
        // sharkd is gone (a malformed capture can crash it). Start a new one,
        // reload the file, tell the UI, and try the request once more. If the
        // request itself is what kills sharkd, the second failure is reported
        // instead of looping.
        self.restart();
        (self.deliver)(Reply::Restarted {
            reason: fatal.to_string(),
        });
        let retry = again.clone();
        match self.execute(retry) {
            Ok(reply) => reply,
            Err(fatal) => {
                self.restart();
                failure(again, fatal.to_string())
            }
        }
    }

    fn restart(&mut self) {
        if let Ok(client) = Client::spawn(&self.launch) {
            self.pid.store(client.pid(), Ordering::SeqCst);
            self.client = client;
            if let Some(path) = self.loaded.clone() {
                let _ = self.client.call::<Value>("load", json!({ "file": path }));
            }
        }
    }

    /// Run one request. `Err` means sharkd itself is gone.
    fn execute(&mut self, request: Request) -> Result<Reply, Error> {
        Ok(match request {
            Request::Info => Reply::Info(soft(self.client.call("info", Value::Null))?),
            Request::Load { path } => {
                let result = self.load(&path)?;
                if result.is_ok() {
                    self.loaded = Some(path.clone());
                }
                Reply::Loaded { path, result }
            }
            Request::Count { generation, filter } => {
                let result = soft(self.count(&filter))?;
                Reply::Count { generation, result }
            }
            Request::Frames {
                generation,
                filter,
                skip,
                limit,
                columns,
                refs,
            } => {
                let mut params = Map::new();
                if !filter.is_empty() {
                    params.insert("filter".into(), filter.into());
                }
                // sharkd rejects an explicit zero for either of these.
                if skip > 0 {
                    params.insert("skip".into(), skip.into());
                }
                if limit > 0 {
                    params.insert("limit".into(), limit.into());
                }
                for (i, c) in columns.iter().enumerate() {
                    params.insert(format!("column{i}"), c.as_str().into());
                }
                if !refs.is_empty() {
                    let list: Vec<String> = refs.iter().map(u32::to_string).collect();
                    params.insert("refs".into(), list.join(",").into());
                }
                let result = soft(self.client.call("frames", Value::Object(params)))?;
                Reply::Frames {
                    generation,
                    skip,
                    result,
                }
            }
            Request::Locate {
                generation,
                filter,
                frame,
                seek,
                purpose,
            } => {
                let result = soft(self.locate(&filter, frame, seek))?;
                Reply::Located {
                    generation,
                    purpose,
                    seek,
                    result,
                }
            }
            Request::Frame {
                num,
                prev,
                reference,
            } => {
                let mut params = json!({ "frame": num, "proto": true, "bytes": true });
                if let Some(p) = prev {
                    params["prev_frame"] = p.into();
                }
                if let Some(r) = reference {
                    params["ref_frame"] = r.into();
                }
                let result = soft(self.client.call::<FrameDetail>("frame", params))?;
                Reply::Frame {
                    num,
                    result: result.map(Box::new),
                }
            }
            Request::Check { seq, filter } => {
                let result = if filter.trim().is_empty() {
                    Ok(())
                } else {
                    soft(
                        self.client
                            .call::<Value>("check", json!({ "filter": filter })),
                    )?
                    .map(|_| ())
                };
                Reply::Check {
                    seq,
                    filter,
                    result,
                }
            }
            Request::Complete { seq, prefix } => {
                let result = soft(
                    self.client
                        .call::<CompleteResult>("complete", json!({ "field": prefix })),
                )?;
                Reply::Complete {
                    seq,
                    prefix,
                    result: result.map(|r| r.field).unwrap_or_default(),
                }
            }
            Request::Follow { protocol, filter } => {
                let params = json!({ "follow": protocol, "filter": filter });
                let result = soft(self.client.call("follow", params))?;
                Reply::Follow {
                    protocol,
                    filter,
                    result,
                }
            }
            Request::Tap { id, taps, filter } => {
                let mut params = Map::new();
                for (i, t) in taps.iter().enumerate() {
                    params.insert(format!("tap{i}"), t.as_str().into());
                }
                if !filter.is_empty() {
                    params.insert("filter".into(), filter.into());
                }
                let result = soft(self.client.call::<TapResult>("tap", Value::Object(params)))?;
                Reply::Tap {
                    id,
                    result: result.map(|r| r.taps),
                }
            }
            Request::SetConf { name, value } => {
                let params = json!({ "name": name, "value": value });
                let result = soft(self.client.call::<Value>("setconf", params))?;
                Reply::SetConf {
                    name,
                    result: result.map(|_| ()),
                }
            }
            Request::Download { token, dest } => {
                let got = soft(
                    self.client
                        .call::<Download>("download", json!({ "token": token })),
                )?;
                let result = got.and_then(|d| {
                    use base64::Engine;
                    let data = d
                        .data
                        .ok_or_else(|| "sharkd returned no data".to_string())?;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(data.as_bytes())
                        .map_err(|e| format!("could not decode object: {e}"))?;
                    std::fs::write(&dest, &bytes)
                        .map_err(|e| format!("could not write {}: {e}", dest.display()))?;
                    Ok(bytes.len() as u64)
                });
                Reply::Download { dest, result }
            }
        })
    }

    #[allow(clippy::type_complexity)]
    fn load(&mut self, path: &PathBuf) -> Result<Result<(Status, Option<String>), String>, Error> {
        let loaded = match soft(
            self.client
                .call::<LoadResult>("load", json!({ "file": path })),
        )? {
            Ok(l) => l,
            Err(e) => return Ok(Err(e)),
        };
        // A non-zero `err` with frames loaded means the file ends mid-packet,
        // which is normal for a capture that is still being written.
        let warning = (loaded.err != 0).then_some(loaded.status);
        let status = match soft(self.client.call::<Status>("status", Value::Null))? {
            Ok(s) => s,
            Err(e) => return Ok(Err(e)),
        };
        Ok(Ok((status, warning)))
    }

    fn count(&mut self, filter: &str) -> Result<u32, Error> {
        if filter.is_empty() {
            return self
                .client
                .call::<Status>("status", Value::Null)
                .map(|s| s.frames);
        }
        self.client
            .call::<Intervals>("intervals", json!({ "filter": filter }))
            .map(|i| i.frames)
    }

    /// Frame number at `index` of the list filtered by `filter`.
    fn frame_at(&mut self, filter: &str, index: u32) -> Result<Option<u32>, Error> {
        let mut params = json!({ "limit": 1, "column0": "frame.number:1" });
        if index > 0 {
            params["skip"] = index.into();
        }
        if !filter.is_empty() {
            params["filter"] = filter.into();
        }
        let rows: Vec<FrameRow> = self.client.call("frames", params)?;
        Ok(rows.first().map(|r| r.num))
    }

    /// Binary search the displayed list for `frame`. Displayed frames are in
    /// ascending frame-number order, so about 20 cheap requests cover a
    /// million packets.
    fn locate(
        &mut self,
        filter: &str,
        frame: u32,
        seek: Seek,
    ) -> Result<Option<(u32, u32)>, Error> {
        let total = self.count(filter)?;
        if total == 0 {
            return Ok(None);
        }
        // With no filter the displayed list is every frame, in order.
        let lower_bound = |this: &mut Self, target: u32| -> Result<u32, Error> {
            if filter.is_empty() {
                return Ok(target.saturating_sub(1).min(total));
            }
            // First index whose frame number is >= target.
            let (mut lo, mut hi) = (0u32, total);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                match this.frame_at(filter, mid)? {
                    Some(n) if n < target => lo = mid + 1,
                    _ => hi = mid,
                }
            }
            Ok(lo)
        };
        let index = match seek {
            Seek::Nearest => lower_bound(self, frame)?.min(total - 1),
            Seek::Next => {
                let i = lower_bound(self, frame.saturating_add(1))?;
                if i >= total {
                    return Ok(None);
                }
                i
            }
            Seek::Prev => {
                let i = lower_bound(self, frame)?;
                if i == 0 {
                    return Ok(None);
                }
                i - 1
            }
        };
        let num = if filter.is_empty() {
            Some(index + 1)
        } else {
            self.frame_at(filter, index)?
        };
        Ok(num.map(|n| (index, n)))
    }
}

/// Split a call's outcome into "sharkd is gone" (outer `Err`) and "sharkd said
/// no" (inner `Err`, shown to the user).
fn soft<T>(result: Result<T, Error>) -> Result<Result<T, String>, Error> {
    match result {
        Ok(v) => Ok(Ok(v)),
        Err(e) if e.is_fatal() => Err(e),
        Err(e) => Ok(Err(e.to_string())),
    }
}

/// The reply that reports `reason` as the failure of `request`.
fn failure(request: Request, reason: String) -> Reply {
    match request {
        Request::Info => Reply::Info(Err(reason)),
        Request::Load { path } => Reply::Loaded {
            path,
            result: Err(reason),
        },
        Request::Count { generation, .. } => Reply::Count {
            generation,
            result: Err(reason),
        },
        Request::Frames {
            generation, skip, ..
        } => Reply::Frames {
            generation,
            skip,
            result: Err(reason),
        },
        Request::Locate {
            generation,
            seek,
            purpose,
            ..
        } => Reply::Located {
            generation,
            purpose,
            seek,
            result: Err(reason),
        },
        Request::Frame { num, .. } => Reply::Frame {
            num,
            result: Err(reason),
        },
        Request::Check { seq, filter } => Reply::Check {
            seq,
            filter,
            result: Err(reason),
        },
        Request::Complete { seq, prefix } => Reply::Complete {
            seq,
            prefix,
            result: Vec::new(),
        },
        Request::Follow { protocol, filter } => Reply::Follow {
            protocol,
            filter,
            result: Err(reason),
        },
        Request::Tap { id, .. } => Reply::Tap {
            id,
            result: Err(reason),
        },
        Request::SetConf { name, .. } => Reply::SetConf {
            name,
            result: Err(reason),
        },
        Request::Download { dest, .. } => Reply::Download {
            dest,
            result: Err(reason),
        },
    }
}

/// Decide which queued requests no longer need to run.
fn mark_superseded(queue: &VecDeque<Request>) -> Vec<bool> {
    let newest_generation = queue.iter().filter_map(generation_of).max();
    let last_load = queue
        .iter()
        .rposition(|r| matches!(r, Request::Load { .. }));
    let last = |pred: fn(&Request) -> bool| queue.iter().rposition(pred);
    let last_frame = last(|r| matches!(r, Request::Frame { .. }));
    let last_check = last(|r| matches!(r, Request::Check { .. }));
    let last_complete = last(|r| matches!(r, Request::Complete { .. }));

    queue
        .iter()
        .enumerate()
        .map(|(i, r)| match r {
            // Only the newest of each of these matters.
            Request::Frame { .. } => Some(i) != last_frame,
            Request::Check { .. } => Some(i) != last_check,
            Request::Complete { .. } => Some(i) != last_complete,
            // A reload makes an earlier load of the same file redundant.
            Request::Load { .. } => Some(i) != last_load,
            // List requests for an outdated filter or file.
            Request::Count { generation, .. }
            | Request::Frames { generation, .. }
            | Request::Locate { generation, .. } => Some(*generation) < newest_generation,
            _ => false,
        })
        .collect()
}

fn generation_of(r: &Request) -> Option<u64> {
    match r {
        Request::Count { generation, .. }
        | Request::Frames { generation, .. }
        | Request::Locate { generation, .. } => Some(*generation),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(generation: u64, skip: u32) -> Request {
        Request::Frames {
            generation,
            filter: String::new(),
            skip,
            limit: 10,
            columns: vec![],
            refs: vec![],
        }
    }

    #[test]
    fn only_newest_detail_request_runs() {
        let q: VecDeque<Request> = [
            Request::Frame {
                num: 1,
                prev: None,
                reference: None,
            },
            Request::Frame {
                num: 2,
                prev: None,
                reference: None,
            },
            Request::Frame {
                num: 3,
                prev: None,
                reference: None,
            },
        ]
        .into();
        assert_eq!(mark_superseded(&q), vec![true, true, false]);
    }

    #[test]
    fn old_generation_pages_are_dropped_but_current_ones_kept() {
        let q: VecDeque<Request> = [frames(1, 0), frames(2, 0), frames(2, 100)].into();
        assert_eq!(mark_superseded(&q), vec![true, false, false]);
    }

    #[test]
    fn unrelated_requests_are_never_dropped() {
        let q: VecDeque<Request> = [
            Request::Follow {
                protocol: "TCP".into(),
                filter: "tcp.stream==0".into(),
            },
            Request::Tap {
                id: 1,
                taps: vec!["phs".into()],
                filter: String::new(),
            },
            Request::Follow {
                protocol: "TCP".into(),
                filter: "tcp.stream==1".into(),
            },
        ]
        .into();
        assert_eq!(mark_superseded(&q), vec![false, false, false]);
    }

    #[test]
    fn repeated_loads_collapse_to_the_last() {
        let q: VecDeque<Request> = [
            Request::Load { path: "a".into() },
            Request::Check {
                seq: 1,
                filter: "tcp".into(),
            },
            Request::Load { path: "a".into() },
        ]
        .into();
        assert_eq!(mark_superseded(&q), vec![true, false, false]);
    }
}
