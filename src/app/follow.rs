//! Follow Stream: the reassembled conversation behind a packet.

use std::fmt::Write as _;

use crate::sharkd::types::Follow;
use crate::util::{decode_base64, hex_string, printable};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Ascii,
    HexDump,
    Raw,
}

impl Mode {
    pub fn next(self) -> Self {
        match self {
            Mode::Ascii => Mode::HexDump,
            Mode::HexDump => Mode::Raw,
            Mode::Raw => Mode::Ascii,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Mode::Ascii => "ASCII",
            Mode::HexDump => "hex dump",
            Mode::Raw => "raw hex",
        }
    }

    /// The name the choice is remembered under.
    pub fn key(self) -> &'static str {
        match self {
            Mode::Ascii => "ascii",
            Mode::HexDump => "hex",
            Mode::Raw => "raw",
        }
    }

    pub fn parse(key: &str) -> Mode {
        match key {
            "hex" => Mode::HexDump,
            "raw" => Mode::Raw,
            _ => Mode::Ascii,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Side {
    #[default]
    Both,
    Client,
    Server,
}

impl Side {
    pub fn next(self) -> Self {
        match self {
            Side::Both => Side::Client,
            Side::Client => Side::Server,
            Side::Server => Side::Both,
        }
    }
    fn shows(self, server: bool) -> bool {
        match self {
            Side::Both => true,
            Side::Client => !server,
            Side::Server => server,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Chunk {
    pub server: bool,
    pub frame: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub text: String,
    pub server: bool,
    pub frame: u32,
}

#[derive(Debug, Default)]
pub struct FollowView {
    pub protocol: String,
    pub filter: String,
    pub loading: bool,
    pub error: Option<String>,
    pub client: String,
    pub server: String,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub chunks: Vec<Chunk>,
    pub mode: Mode,
    pub side: Side,
    pub top: usize,
    pub height: u16,
    lines: Vec<Line>,
    /// Width the cached lines were laid out for; 0 means they must be rebuilt.
    laid_out_for: u16,
    /// What `/` last searched the stream for.
    search: Option<regex::Regex>,
}

impl FollowView {
    pub fn new(protocol: &str, filter: &str) -> FollowView {
        FollowView {
            protocol: protocol.to_string(),
            filter: filter.to_string(),
            loading: true,
            ..Default::default()
        }
    }

    pub fn set_data(&mut self, data: Result<Follow, String>) {
        self.loading = false;
        match data {
            Err(e) => self.error = Some(e),
            Ok(f) => {
                self.client = endpoint(&f.chost, &f.cport);
                self.server = endpoint(&f.shost, &f.sport);
                self.chunks = f
                    .payloads
                    .into_iter()
                    .map(|p| Chunk {
                        server: p.server != 0,
                        frame: p.frame,
                        bytes: decode_base64(&p.data),
                    })
                    .collect();
                // Count what each side sent from the payload itself; sharkd's
                // own `cbytes`/`sbytes` name the receiving side.
                let sent = |server: bool| {
                    self.chunks
                        .iter()
                        .filter(|c| c.server == server)
                        .map(|c| c.bytes.len() as u64)
                        .sum()
                };
                self.client_bytes = sent(false);
                self.server_bytes = sent(true);
            }
        }
        self.laid_out_for = 0;
        self.top = 0;
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.laid_out_for = 0;
        self.top = 0;
    }

    pub fn set_side(&mut self, side: Side) {
        self.side = side;
        self.laid_out_for = 0;
        self.top = 0;
    }

    /// The lines to draw at `width` columns.
    pub fn lines(&mut self, width: u16) -> &[Line] {
        if self.laid_out_for != width {
            self.lines = layout(&self.chunks, self.mode, self.side, width.max(8) as usize);
            self.laid_out_for = width;
            self.clamp();
        }
        &self.lines
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn scroll_by(&mut self, delta: i64) {
        self.top = (self.top as i64 + delta).max(0) as usize;
        self.clamp();
    }

    pub fn scroll_to_end(&mut self) {
        self.top = usize::MAX;
        self.clamp();
    }

    fn clamp(&mut self) {
        let max_top = self.lines.len().saturating_sub(self.height.max(1) as usize);
        self.top = self.top.min(max_top);
    }

    /// Search the stream's text as it is shown. `text` is plain text in any
    /// case, or a regular expression when written between slashes.
    pub fn set_search(&mut self, text: &str) -> Result<(), String> {
        let text = text.trim();
        if text.is_empty() {
            self.search = None;
            return Ok(());
        }
        let pattern = match text.strip_prefix('/').and_then(|t| t.strip_suffix('/')) {
            Some(regex) if !regex.is_empty() => regex.to_string(),
            _ => regex::escape(text),
        };
        let regex = regex::RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| {
                let reason = e.to_string();
                format!(
                    "Not a regular expression: {}",
                    reason.lines().last().unwrap_or(&reason).trim()
                )
            })?;
        self.search = Some(regex);
        Ok(())
    }

    pub fn searching(&self) -> bool {
        self.search.is_some()
    }

    /// Where the search matches in `line`, as byte ranges.
    pub fn matches_in(&self, line: &str) -> Vec<(usize, usize)> {
        match &self.search {
            Some(regex) => regex
                .find_iter(line)
                .map(|m| (m.start(), m.end()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Bring the next (or previous) line that matches to the top. Returns
    /// whether there is one, and whether finding it meant wrapping round.
    /// `from_here` also considers the line already at the top, as a new
    /// search should.
    pub fn find(&mut self, forward: bool, from_here: bool) -> Option<bool> {
        let regex = self.search.as_ref()?;
        let n = self.lines.len();
        if n == 0 {
            return None;
        }
        let start = if from_here { 0 } else { 1 };
        for step in start..=n {
            let index = if forward {
                (self.top + step) % n
            } else {
                (self.top + n - step % n) % n
            };
            if regex.is_match(&self.lines[index].text) {
                let wrapped = if forward {
                    index < self.top
                } else {
                    index > self.top
                };
                // The last screenful cannot be scrolled to the top; a match
                // there is on screen all the same.
                self.top = index;
                self.clamp();
                return Some(wrapped && step != 0);
            }
        }
        None
    }

    /// How many packets carry the stream's payload, and how many times the
    /// conversation changed sides.
    pub fn shape(&self) -> (usize, usize, usize) {
        let client = self.chunks.iter().filter(|c| !c.server).count();
        let turns = self
            .chunks
            .windows(2)
            .filter(|pair| pair[0].server != pair[1].server)
            .count();
        (client, self.chunks.len() - client, turns)
    }

    /// Frame number of the first visible line, for "go to packet".
    pub fn frame_at_top(&self) -> Option<u32> {
        self.lines.get(self.top).map(|l| l.frame)
    }

    /// The payload bytes of the visible side(s), in order.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for c in self.chunks.iter().filter(|c| self.side.shows(c.server)) {
            out.extend_from_slice(&c.bytes);
        }
        out
    }

    /// The stream as text in the current mode, for copying.
    pub fn text(&self) -> String {
        let lines = layout(&self.chunks, self.mode, self.side, 100_000);
        let mut out = String::new();
        for l in lines {
            out.push_str(&l.text);
            out.push('\n');
        }
        out
    }
}

fn endpoint(host: &str, port: &str) -> String {
    if port.is_empty() {
        host.to_string()
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn layout(chunks: &[Chunk], mode: Mode, side: Side, width: usize) -> Vec<Line> {
    let mut lines = Vec::new();
    // Hex dump offsets count per direction, as Wireshark does.
    let mut offsets = [0usize; 2];
    for chunk in chunks.iter().filter(|c| side.shows(c.server)) {
        let mut push = |text: String| {
            lines.push(Line {
                text,
                server: chunk.server,
                frame: chunk.frame,
            });
        };
        match mode {
            Mode::Ascii => {
                for raw in chunk.bytes.split(|b| *b == b'\n') {
                    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
                    let text: String = raw.iter().map(|&b| printable(b)).collect();
                    if text.is_empty() {
                        push(String::new());
                        continue;
                    }
                    // All characters are one cell wide, so wrap by byte count.
                    for piece in text.as_bytes().chunks(width) {
                        push(String::from_utf8_lossy(piece).into_owned());
                    }
                }
                // A chunk ending in a newline yields one empty trailing piece.
                if chunk.bytes.ends_with(b"\n") {
                    lines.pop();
                }
            }
            Mode::HexDump => {
                let per_row = if width >= 78 { 16 } else { 8 };
                let indent = if chunk.server { "    " } else { "" };
                let offset = &mut offsets[usize::from(chunk.server)];
                for row in chunk.bytes.chunks(per_row) {
                    let mut text = format!("{indent}{:08x}  ", *offset);
                    for i in 0..per_row {
                        match row.get(i) {
                            Some(b) => {
                                let _ = write!(text, "{b:02x} ");
                            }
                            None => text.push_str("   "),
                        }
                        if i == 7 && per_row == 16 {
                            text.push(' ');
                        }
                    }
                    text.push(' ');
                    text.extend(row.iter().map(|&b| printable(b)));
                    push(text);
                    *offset += row.len();
                }
            }
            Mode::Raw => {
                let hex = hex_string(&chunk.bytes);
                let step = (width & !1).max(2);
                for piece in hex.as_bytes().chunks(step) {
                    push(String::from_utf8_lossy(piece).into_owned());
                }
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharkd::types::FollowChunk;
    use crate::util::encode_base64;

    fn view() -> FollowView {
        let mut v = FollowView::new("TCP", "tcp.stream eq 0");
        v.height = 10;
        v.set_data(Ok(Follow {
            shost: "93.184.216.34".into(),
            sport: "80".into(),
            sbytes: 22,
            chost: "10.0.0.2".into(),
            cport: "40000".into(),
            cbytes: 18,
            payloads: vec![
                FollowChunk {
                    frame: 6,
                    data: encode_base64(b"GET / HTTP/1.1\r\n\r\n"),
                    server: 0,
                },
                FollowChunk {
                    frame: 8,
                    data: encode_base64(b"HTTP/1.1 200 OK\r\n\x00\x01hi"),
                    server: 1,
                },
            ],
        }));
        v
    }

    fn texts(v: &mut FollowView, width: u16) -> Vec<String> {
        v.lines(width).iter().map(|l| l.text.clone()).collect()
    }

    #[test]
    fn ascii_mode_splits_lines_and_marks_direction() {
        let mut v = view();
        assert_eq!(v.client, "10.0.0.2:40000");
        assert_eq!(v.server, "93.184.216.34:80");
        assert_eq!(
            (v.client_bytes, v.server_bytes),
            (18, 21),
            "counted from the payload"
        );
        assert_eq!(
            texts(&mut v, 80),
            ["GET / HTTP/1.1", "", "HTTP/1.1 200 OK", "..hi"]
        );
        let lines = v.lines(80);
        assert!(!lines[0].server && lines[2].server);
        assert_eq!((lines[0].frame, lines[3].frame), (6, 8));
    }

    #[test]
    fn ascii_mode_wraps_long_lines() {
        let mut v = view();
        assert_eq!(texts(&mut v, 8)[..2], ["GET / HT", "TP/1.1"]);
    }

    #[test]
    fn side_filter_and_payload() {
        let mut v = view();
        v.set_side(Side::Server);
        assert_eq!(texts(&mut v, 80), ["HTTP/1.1 200 OK", "..hi"]);
        assert_eq!(v.payload(), b"HTTP/1.1 200 OK\r\n\x00\x01hi");
        v.set_side(Side::Both);
        assert_eq!(v.payload().len(), 18 + 21);
    }

    #[test]
    fn hex_dump_counts_offsets_per_direction() {
        let mut v = view();
        v.set_mode(Mode::HexDump);
        let lines = texts(&mut v, 100);
        assert!(
            lines[0].starts_with("00000000  47 45 54 20"),
            "{}",
            lines[0]
        );
        assert!(lines[1].starts_with("00000010  0d 0a"), "{}", lines[1]);
        assert!(
            lines[2].starts_with("    00000000  48 54 54 50"),
            "server restarts at 0: {}",
            lines[2]
        );
        assert!(lines[0].ends_with("GET / HTTP/1.1.."));
    }

    #[test]
    fn raw_mode_is_plain_hex() {
        let mut v = view();
        v.set_mode(Mode::Raw);
        v.set_side(Side::Client);
        assert_eq!(texts(&mut v, 200), ["474554202f20485454502f312e310d0a0d0a"]);
        assert_eq!(texts(&mut v, 9)[0], "47455420", "wraps on whole bytes");
    }

    #[test]
    fn scrolling_is_clamped() {
        let mut v = view();
        v.height = 2;
        v.lines(80);
        v.scroll_by(100);
        assert_eq!(v.top, 2);
        assert_eq!(v.frame_at_top(), Some(8));
        v.scroll_by(-100);
        assert_eq!(v.top, 0);
    }

    #[test]
    fn errors_are_kept_for_display() {
        let mut v = FollowView::new("TCP", "tcp.stream eq 9");
        v.set_data(Err("no such stream".into()));
        assert!(!v.loading);
        assert_eq!(v.error.as_deref(), Some("no such stream"));
        assert!(v.lines(80).is_empty());
    }

    #[test]
    fn ipv6_endpoints_are_bracketed() {
        assert_eq!(endpoint("::1", "443"), "[::1]:443");
        assert_eq!(endpoint("aa:bb", ""), "aa:bb");
    }
}
