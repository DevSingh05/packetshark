//! Typed views of the JSON that `sharkd` returns.
//!
//! Field names follow sharkd's terse wire names; the Rust names say what they
//! mean. Everything optional on the wire is optional or defaulted here, so a
//! newer or older sharkd that adds or omits attributes still parses.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;
use std::marker::PhantomData;

use serde::Deserialize;
use serde::de::{Deserializer, SeqAccess, Visitor};

/// Reply to `status`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub frames: u32,
    #[serde(default)]
    pub duration: f64,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(default)]
    pub filesize: Option<u64>,
    #[serde(default)]
    pub columns: Vec<String>,
    #[serde(default)]
    pub column_info: Vec<ColumnInfo>,
}

/// One column of the user's Wireshark profile, as reported by `status`.
#[derive(Debug, Clone, Deserialize)]
pub struct ColumnInfo {
    pub title: String,
    /// `%x` for a built-in column, or `%Cus:<fields>:<occurrence>` for a custom one.
    pub format: String,
    #[serde(default = "yes")]
    pub visible: bool,
}

fn yes() -> bool {
    true
}

/// Reply to `load`. sharkd answers `{"status":"OK"}` on success and
/// `{"status":"<reason>","err":N}` when the file was only partly readable
/// (for example a capture that is still being written).
#[derive(Debug, Clone, Deserialize)]
pub struct LoadResult {
    pub status: String,
    #[serde(default)]
    pub err: i64,
}

/// One row of the packet list.
#[derive(Debug, Clone, Deserialize)]
pub struct FrameRow {
    #[serde(rename = "c", default)]
    pub cols: Vec<String>,
    pub num: u32,
    #[serde(default)]
    pub bg: Option<String>,
    #[serde(default)]
    pub fg: Option<String>,
    #[serde(rename = "ct", default)]
    pub commented: bool,
}

/// A node of the protocol dissection tree.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Node {
    #[serde(rename = "l", default)]
    pub label: String,
    /// Byte range `(start, length)` within the node's data source.
    #[serde(rename = "h", default)]
    pub range: Option<(u32, u32)>,
    /// `proto`, `framenum` or `url`.
    #[serde(rename = "t", default)]
    pub kind: Option<String>,
    /// A display filter that matches this field's value.
    #[serde(rename = "f", default)]
    pub filter: Option<String>,
    /// Field abbreviation, e.g. `tcp.srcport`.
    #[serde(rename = "fn", default)]
    pub field: Option<String>,
    /// Subtree type index; Wireshark remembers expansion per subtree type.
    #[serde(rename = "e", default)]
    pub ett: Option<i64>,
    #[serde(rename = "n", default)]
    pub children: Vec<Node>,
    /// Index of the data source the range refers to; absent means the frame itself.
    #[serde(default)]
    pub ds: Option<usize>,
    /// Expert severity: Chat, Note, Warn, Error.
    #[serde(rename = "s", default)]
    pub severity: Option<String>,
    #[serde(rename = "g", default)]
    pub generated: bool,
    #[serde(rename = "v", default)]
    pub hidden: bool,
    #[serde(default)]
    pub url: Option<String>,
    /// Target frame for `framenum` nodes ("Response in frame: 8").
    #[serde(default)]
    pub fnum: Option<u32>,
}

/// An additional data source of a frame (reassembled or decrypted bytes).
#[derive(Debug, Clone, Deserialize)]
pub struct DataSource {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub bytes: String,
}

/// Reply to `frame`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FrameDetail {
    #[serde(default)]
    pub tree: Vec<Node>,
    /// Base64 of the frame's bytes.
    #[serde(default)]
    pub bytes: Option<String>,
    #[serde(default)]
    pub ds: Vec<DataSource>,
    /// `(protocol, filter)` pairs that can be followed from this frame.
    #[serde(default, deserialize_with = "followable")]
    pub fol: Vec<(String, String)>,
    #[serde(default)]
    pub comment: Option<serde_json::Value>,
}

/// The streams a frame belongs to. sharkd lists a protocol with a null
/// filter when the frame only quotes that protocol (a UDP header inside an
/// ICMP error, say) and so is part of no stream; those are left out.
fn followable<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<(String, String)>, D::Error> {
    let pairs = Option::<Vec<(String, Option<String>)>>::deserialize(de)?.unwrap_or_default();
    Ok(pairs
        .into_iter()
        .filter_map(|(protocol, filter)| Some((protocol, filter?)))
        .collect())
}

/// Reply to `follow`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Follow {
    #[serde(default)]
    pub shost: String,
    #[serde(default)]
    pub sport: String,
    #[serde(default)]
    pub sbytes: u64,
    #[serde(default)]
    pub chost: String,
    #[serde(default)]
    pub cport: String,
    #[serde(default)]
    pub cbytes: u64,
    #[serde(default)]
    pub payloads: Vec<FollowChunk>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FollowChunk {
    /// Frame number the chunk came from.
    #[serde(rename = "n", default)]
    pub frame: u32,
    /// Base64 payload.
    #[serde(rename = "d", default)]
    pub data: String,
    /// Non-zero when the server sent this chunk.
    #[serde(rename = "s", default)]
    pub server: u8,
}

/// Reply to `intervals`; only the totals are used.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Intervals {
    #[serde(default)]
    pub frames: u32,
    #[serde(default)]
    pub bytes: u64,
}

/// One completion candidate from `complete`.
#[derive(Debug, Clone, Deserialize)]
pub struct Completion {
    #[serde(rename = "f")]
    pub field: String,
    #[serde(rename = "n", default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CompleteResult {
    #[serde(default)]
    pub field: Vec<Completion>,
}

/// Reply to `info`: what this sharkd build knows how to do.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Info {
    #[serde(default)]
    pub version: String,
    /// Built-in column formats; the position in this list is the number
    /// `frames` expects for that column.
    #[serde(default)]
    pub columns: Vec<ColumnFormat>,
    #[serde(default)]
    pub convs: Vec<NamedTap>,
    #[serde(default)]
    pub stats: Vec<NamedTap>,
    #[serde(default)]
    pub eo: Vec<NamedTap>,
    #[serde(default)]
    pub follow: Vec<NamedTap>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ColumnFormat {
    pub name: String,
    pub format: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NamedTap {
    pub name: String,
    pub tap: String,
}

/// Most rows kept from one statistics list. Captures of scans or floods can
/// hold millions of conversations; keeping them all would cost gigabytes.
pub const MAX_ROWS: usize = 100_000;

/// How much a statistics row matters; when a list is too long, the rows with
/// the largest weight are the ones kept.
pub trait Weight {
    fn weight(&self) -> u64;
}

/// A list read from JSON that keeps at most `MAX_ROWS` items (those with the
/// largest weight) and remembers how many there were. The rest are dropped
/// as they are parsed, so memory stays bounded however long the list is.
#[derive(Debug, Clone)]
pub struct Capped<T> {
    pub items: Vec<T>,
    /// Number of items in the JSON, including any that were dropped.
    pub total: usize,
}

impl<T> Default for Capped<T> {
    fn default() -> Self {
        Capped {
            items: Vec::new(),
            total: 0,
        }
    }
}

impl<T> From<Vec<T>> for Capped<T> {
    fn from(items: Vec<T>) -> Self {
        let total = items.len();
        Capped { items, total }
    }
}

impl<T> Capped<T> {
    /// The original count, if some items were dropped.
    pub fn truncated_from(&self) -> Option<usize> {
        (self.total > self.items.len()).then_some(self.total)
    }
}

/// Heap entry ordered by weight only.
struct Weighed<T>(u64, T);

impl<T> PartialEq for Weighed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<T> Eq for Weighed<T> {}
impl<T> PartialOrd for Weighed<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Weighed<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<'de, T: Deserialize<'de> + Weight> Deserialize<'de> for Capped<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CappedVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de> + Weight> Visitor<'de> for CappedVisitor<T> {
            type Value = Capped<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut total = 0;
                let mut items: Vec<T> = Vec::new();
                // Once the list overflows, switch to a min-heap of the
                // heaviest items seen so far.
                let mut heap: Option<BinaryHeap<Reverse<Weighed<T>>>> = None;
                while let Some(item) = seq.next_element::<T>()? {
                    total += 1;
                    match &mut heap {
                        None if items.len() < MAX_ROWS => items.push(item),
                        None => {
                            let mut h: BinaryHeap<_> = std::mem::take(&mut items)
                                .into_iter()
                                .map(|i| Reverse(Weighed(i.weight(), i)))
                                .collect();
                            offer(&mut h, item);
                            heap = Some(h);
                        }
                        Some(h) => offer(h, item),
                    }
                }
                if let Some(h) = heap {
                    items = h
                        .into_iter()
                        .map(|Reverse(Weighed(_, item))| item)
                        .collect();
                }
                Ok(Capped { items, total })
            }
        }

        /// Replace the lightest kept item if `item` outweighs it.
        fn offer<T: Weight>(heap: &mut BinaryHeap<Reverse<Weighed<T>>>, item: T) {
            let weight = item.weight();
            if heap
                .peek()
                .is_some_and(|Reverse(lightest)| weight > lightest.0)
            {
                heap.pop();
                heap.push(Reverse(Weighed(weight, item)));
            }
        }

        deserializer.deserialize_seq(CappedVisitor(PhantomData))
    }
}

/// Reply to `tap`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TapResult {
    #[serde(default)]
    pub taps: Vec<Tap>,
}

/// One statistics result. The variant is chosen by sharkd's `type` member.
#[derive(Debug, Clone, Deserialize)]
#[serde(from = "RawTap")]
pub enum Tap {
    Conversations {
        proto: String,
        convs: Capped<Conversation>,
    },
    Endpoints {
        proto: String,
        hosts: Capped<Endpoint>,
    },
    ProtocolHierarchy {
        protos: Vec<ProtoStat>,
    },
    Expert {
        details: Capped<ExpertItem>,
    },
    Objects {
        proto: String,
        objects: Vec<ExportObject>,
    },
    Stats {
        name: String,
        stats: Vec<StatNode>,
    },
    /// A kind of tap this version does not understand.
    Other,
}

/// The tap object as it is on the wire. Parsing into this flat struct (rather
/// than a tagged enum) lets serde stream the big lists straight into their
/// capped containers; a tagged enum would first buffer the whole object.
#[derive(Deserialize)]
struct RawTap {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    proto: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    convs: Capped<Conversation>,
    #[serde(default)]
    hosts: Capped<Endpoint>,
    #[serde(default)]
    protos: Vec<ProtoStat>,
    #[serde(default)]
    details: Capped<ExpertItem>,
    #[serde(default)]
    objects: Vec<ExportObject>,
    #[serde(default)]
    stats: Vec<StatNode>,
}

impl From<RawTap> for Tap {
    fn from(raw: RawTap) -> Tap {
        match raw.kind.as_str() {
            "conv" => Tap::Conversations {
                proto: raw.proto,
                convs: raw.convs,
            },
            "host" => Tap::Endpoints {
                proto: raw.proto,
                hosts: raw.hosts,
            },
            "phs" => Tap::ProtocolHierarchy { protos: raw.protos },
            "expert" => Tap::Expert {
                details: raw.details,
            },
            "eo" => Tap::Objects {
                proto: raw.proto,
                objects: raw.objects,
            },
            "stats" => Tap::Stats {
                name: raw.name,
                stats: raw.stats,
            },
            _ => Tap::Other,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Conversation {
    #[serde(default)]
    pub saddr: String,
    #[serde(default)]
    pub daddr: String,
    #[serde(default)]
    pub sport: Option<String>,
    #[serde(default)]
    pub dport: Option<String>,
    #[serde(default)]
    pub txf: u64,
    #[serde(default)]
    pub txb: u64,
    #[serde(default)]
    pub rxf: u64,
    #[serde(default)]
    pub rxb: u64,
    #[serde(default)]
    pub start: f64,
    #[serde(default)]
    pub stop: f64,
    #[serde(default)]
    pub filter: Option<String>,
}

impl Weight for Conversation {
    /// Busiest conversations first.
    fn weight(&self) -> u64 {
        self.txb + self.rxb
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Endpoint {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub txf: u64,
    #[serde(default)]
    pub txb: u64,
    #[serde(default)]
    pub rxf: u64,
    #[serde(default)]
    pub rxb: u64,
    #[serde(default)]
    pub filter: Option<String>,
}

impl Weight for Endpoint {
    fn weight(&self) -> u64 {
        self.txb + self.rxb
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtoStat {
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub frames: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub protos: Vec<ProtoStat>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExpertItem {
    #[serde(rename = "f", default)]
    pub frame: u32,
    #[serde(rename = "s", default)]
    pub severity: Option<String>,
    #[serde(rename = "g", default)]
    pub group: Option<String>,
    #[serde(rename = "m", default)]
    pub message: String,
    #[serde(rename = "p", default)]
    pub protocol: Option<String>,
}

/// 0 for the most serious severity.
pub fn severity_rank(severity: Option<&str>) -> u8 {
    match severity.map(str::to_ascii_lowercase).as_deref() {
        Some("error") => 0,
        Some("warn" | "warning") => 1,
        Some("note") => 2,
        Some("chat") => 3,
        _ => 4,
    }
}

impl Weight for ExpertItem {
    /// Most serious first; among equals, earliest packet first.
    fn weight(&self) -> u64 {
        let seriousness = 4 - u64::from(severity_rank(self.severity.as_deref()));
        (seriousness << 32) | u64::from(u32::MAX - self.frame)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportObject {
    #[serde(default)]
    pub pkt: u32,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(rename = "type", default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(rename = "_download", default)]
    pub token: Option<String>,
    #[serde(default)]
    pub len: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatNode {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub count: u64,
    #[serde(default)]
    pub rate: Option<f64>,
    #[serde(default)]
    pub perc: Option<f64>,
    #[serde(default)]
    pub sub: Vec<StatNode>,
}

/// Reply to `download`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Download {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub mime: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_that_only_quotes_a_protocol_has_nothing_to_follow() {
        let detail: FrameDetail =
            serde_json::from_str(r#"{"tree":[],"fol":[["UDP",null],["TCP","tcp.stream==3"]]}"#)
                .unwrap();
        assert_eq!(
            detail.fol,
            [("TCP".to_string(), "tcp.stream==3".to_string())]
        );
        let detail: FrameDetail = serde_json::from_str(r#"{"tree":[],"fol":null}"#).unwrap();
        assert!(detail.fol.is_empty());
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Item(u64);
    impl Weight for Item {
        fn weight(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn short_lists_are_kept_whole_and_in_order() {
        let c: Capped<Item> = serde_json::from_str("[3,1,2]").unwrap();
        assert_eq!(c.items, [Item(3), Item(1), Item(2)]);
        assert_eq!(c.total, 3);
        assert_eq!(c.truncated_from(), None);
    }

    #[test]
    fn long_lists_keep_the_heaviest_items() {
        // Ascending then descending, so the heaviest are neither first nor last.
        let n = MAX_ROWS as u64 + 500;
        let values: Vec<String> = (0..n).map(|i| (i * 7919 % n).to_string()).collect();
        let json = format!("[{}]", values.join(","));
        let c: Capped<Item> = serde_json::from_str(&json).unwrap();
        assert_eq!(c.total, n as usize);
        assert_eq!(c.truncated_from(), Some(n as usize));
        assert_eq!(c.items.len(), MAX_ROWS);
        let lightest = c.items.iter().map(|i| i.0).min().unwrap();
        assert_eq!(lightest, 500, "the 500 lightest were dropped");
    }

    #[test]
    fn taps_parse_with_capped_lists() {
        let json = r#"{"taps":[
            {"tap":"conv:TCP","type":"conv","proto":"TCP","convs":[
                {"saddr":"a","daddr":"b","sport":"1","dport":"2","txf":1,"txb":10,"rxf":2,"rxb":20,"start":0.5,"stop":1.5,"filter":"f"}]},
            {"tap":"expert","type":"expert","details":[{"f":3,"s":"Warn","g":"Seq","m":"msg","p":"TCP"}]},
            {"tap":"future","type":"something-new","data":[1,2,3],"extra":{"a":[{"b":1}]}}]}"#;
        let result: TapResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.taps.len(), 3);
        match &result.taps[0] {
            Tap::Conversations { convs, .. } => {
                assert_eq!(convs.items[0].weight(), 30);
                assert_eq!(convs.total, 1);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(result.taps[1], Tap::Expert { .. }));
        assert!(
            matches!(result.taps[2], Tap::Other),
            "unknown tap types are tolerated"
        );
    }

    #[test]
    fn serious_expert_items_outweigh_chatter() {
        let item = |frame, severity: &str| ExpertItem {
            frame,
            severity: Some(severity.into()),
            group: None,
            message: String::new(),
            protocol: None,
        };
        assert!(item(900, "Error").weight() > item(1, "Warn").weight());
        assert!(item(1, "Warn").weight() > item(2, "Warn").weight());
        assert!(item(5, "Chat").weight() > item(5, "Unknown").weight());
    }
}
