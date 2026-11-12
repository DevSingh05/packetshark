//! Statistics windows: conversations, endpoints, protocol hierarchy, expert
//! information and exportable objects. Each is a sortable table built from a
//! sharkd tap.

use std::cmp::Ordering;

use crate::sharkd::types::{ProtoStat, StatNode, Tap, severity_rank};
use crate::util::{human_bytes, thousands};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Conversations,
    Endpoints,
    Hierarchy,
    Expert,
    Objects,
    /// One of sharkd's many per-protocol statistics trees (`stat:http`, ...).
    Tree,
    /// Who sent what to whom, in order: a call flow.
    Flow,
}

impl Kind {
    pub fn title(self) -> &'static str {
        match self {
            Kind::Conversations => "Conversations",
            Kind::Endpoints => "Endpoints",
            Kind::Hierarchy => "Protocol hierarchy",
            Kind::Expert => "Expert information",
            Kind::Objects => "Export objects",
            Kind::Tree => "Statistics",
            Kind::Flow => "Flow sequence",
        }
    }

    /// Whether the view has one tab per protocol.
    pub fn has_tabs(self) -> bool {
        matches!(
            self,
            Kind::Conversations | Kind::Endpoints | Kind::Objects | Kind::Flow
        )
    }

    /// What Enter does on a row, for the footer hint.
    pub fn enter_hint(self) -> &'static str {
        match self {
            Kind::Conversations | Kind::Endpoints => "filter · a p filter one way, or combine",
            Kind::Hierarchy => "filter · a p combine with the filter",
            Kind::Expert => "show packets",
            Kind::Objects => "save",
            Kind::Tree => "",
            Kind::Flow => "show the two ends' packets",
        }
    }
}

/// A cell's sort key.
#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    /// Sort by this number (the cell shows it formatted).
    Num(f64),
    /// Sort by the cell's own text.
    Text,
}

fn compare_rows(a: &Row, b: &Row, column: usize) -> Ordering {
    match (a.keys.get(column), b.keys.get(column)) {
        (Some(Key::Num(x)), Some(Key::Num(y))) => x.partial_cmp(y).unwrap_or(Ordering::Equal),
        (Some(Key::Num(_)), _) => Ordering::Less,
        (_, Some(Key::Num(_))) => Ordering::Greater,
        _ => natural_cmp(cell_text(a, column), cell_text(b, column)),
    }
}

fn cell_text(row: &Row, column: usize) -> &str {
    row.cells.get(column).map_or("", String::as_str)
}

/// Compare strings so that `10.0.0.2` sorts before `10.0.0.10`.
fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (a.peek().copied(), b.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let take = |it: &mut std::iter::Peekable<std::str::Chars>| {
                    let mut n: u128 = 0;
                    while let Some(d) = it.peek().and_then(|c| c.to_digit(10)) {
                        n = n.saturating_mul(10).saturating_add(u128::from(d));
                        it.next();
                    }
                    n
                };
                match take(&mut a).cmp(&take(&mut b)) {
                    Ordering::Equal => {}
                    other => return other,
                }
            }
            (Some(x), Some(y)) => {
                match x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()) {
                    Ordering::Equal => {}
                    other => return other,
                }
                a.next();
                b.next();
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Column {
    pub title: &'static str,
    pub right: bool,
}

fn col(title: &'static str) -> Column {
    Column {
        title,
        right: false,
    }
}
fn num(title: &'static str) -> Column {
    Column { title, right: true }
}

#[derive(Debug, Clone, Default)]
pub struct Row {
    pub cells: Vec<String>,
    pub keys: Vec<Key>,
    /// Display filter that selects what this row describes.
    pub filter: Option<String>,
    /// For a conversation or an endpoint, filters for one direction only:
    /// A to B and B to A, or from the endpoint and to it.
    pub one_way: Option<(String, String)>,
    /// Packet this row points at.
    pub frame: Option<u32>,
    /// Token for downloading an exported object.
    pub token: Option<String>,
    /// Suggested file name for an exported object.
    pub filename: Option<String>,
    /// Indentation of the first cell (tree-shaped tables).
    pub depth: u16,
    /// Expert severity, for colouring.
    pub severity: Option<String>,
    /// Fraction 0..=1 drawn as a bar (protocol hierarchy).
    pub bar: Option<f64>,
}

#[derive(Debug)]
pub struct StatsView {
    pub kind: Kind,
    /// Protocol tabs (`TCP`, `UDP`, ...); empty for untabbed views.
    pub tabs: Vec<String>,
    pub tab: usize,
    /// Count only packets matching the display filter.
    pub limit_to_filter: bool,
    pub loading: bool,
    pub error: Option<String>,
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    /// Sort column and direction; `None` keeps sharkd's order (needed for trees).
    pub sort: Option<(usize, bool)>,
    pub selected: usize,
    pub top: usize,
    pub height: u16,
    /// Identifies the tap request this view is waiting for.
    pub request: u64,
    /// How many rows sharkd reported, when more than `MAX_ROWS`.
    pub truncated_from: Option<usize>,
    /// For `Kind::Tree`: the tap to run and the name to show.
    pub tree: Option<(String, String)>,
}

impl StatsView {
    pub fn new(kind: Kind, tabs: Vec<String>, tab: usize) -> StatsView {
        StatsView {
            kind,
            tabs,
            tab,
            limit_to_filter: false,
            loading: true,
            error: None,
            columns: Vec::new(),
            rows: Vec::new(),
            sort: None,
            selected: 0,
            top: 0,
            height: 0,
            request: 0,
            truncated_from: None,
            tree: None,
        }
    }

    /// A view of one of sharkd's statistics trees.
    pub fn tree(tap: &str, name: &str) -> StatsView {
        let mut view = StatsView::new(Kind::Tree, Vec::new(), 0);
        view.tree = Some((tap.to_string(), name.to_string()));
        view
    }

    pub fn title(&self) -> String {
        match &self.tree {
            Some((_, name)) => name.clone(),
            None => self.kind.title().to_string(),
        }
    }

    /// The tap name to request for the current tab.
    pub fn tap(&self) -> String {
        let proto = self.tabs.get(self.tab).map_or("", String::as_str);
        match self.kind {
            Kind::Conversations => format!("conv:{proto}"),
            Kind::Endpoints => format!("endpt:{proto}"),
            Kind::Hierarchy => "phs".to_string(),
            Kind::Expert => "expert".to_string(),
            Kind::Objects => format!("eo:{}", proto.to_ascii_lowercase()),
            Kind::Tree => self
                .tree
                .as_ref()
                .map(|(tap, _)| tap.clone())
                .unwrap_or_default(),
            Kind::Flow if proto == "All" => "seqa:any".to_string(),
            Kind::Flow => format!("seqa:{}", proto.to_ascii_lowercase()),
        }
    }

    pub fn set_loading(&mut self, request: u64) {
        self.request = request;
        self.loading = true;
        self.error = None;
    }

    pub fn set_result(&mut self, result: Result<Vec<Tap>, String>) {
        self.loading = false;
        self.rows.clear();
        self.truncated_from = None;
        self.selected = 0;
        self.top = 0;
        match result {
            Err(e) => self.error = Some(e),
            Ok(taps) => {
                self.error = None;
                match taps.into_iter().next() {
                    Some(tap) => self.fill(tap),
                    None => self.error = Some("sharkd returned no data".into()),
                }
            }
        }
        if self.sort.is_none() {
            self.sort = self.default_sort();
        }
        self.apply_sort();
    }

    fn default_sort(&self) -> Option<(usize, bool)> {
        match self.kind {
            // Busiest first: the "Bytes" column, descending.
            Kind::Conversations | Kind::Endpoints => self
                .columns
                .iter()
                .position(|c| c.title == "Bytes")
                .map(|i| (i, true)),
            _ => None,
        }
    }

    fn fill(&mut self, tap: Tap) {
        match tap {
            Tap::Conversations { convs, proto } => {
                self.truncated_from = convs.truncated_from();
                let convs = convs.items;
                let ports = convs.iter().any(|c| c.sport.is_some());
                self.columns = if ports {
                    vec![
                        col("Address A"),
                        num("Port A"),
                        col("Address B"),
                        num("Port B"),
                        num("Packets"),
                        num("Bytes"),
                        num("A → B"),
                        num("B → A"),
                        num("Start"),
                        num("Duration"),
                    ]
                } else {
                    vec![
                        col("Address A"),
                        col("Address B"),
                        num("Packets"),
                        num("Bytes"),
                        num("A → B"),
                        num("B → A"),
                        num("Start"),
                        num("Duration"),
                    ]
                };
                for c in convs {
                    let mut cells = vec![c.saddr.clone()];
                    let mut keys = vec![Key::Text];
                    let port = |p: &Option<String>| {
                        let p = p.clone().unwrap_or_default();
                        let key = p.parse::<f64>().map_or(Key::Text, Key::Num);
                        (p, key)
                    };
                    if ports {
                        let (p, k) = port(&c.sport);
                        cells.push(p);
                        keys.push(k);
                    }
                    cells.push(c.daddr.clone());
                    keys.push(Key::Text);
                    if ports {
                        let (p, k) = port(&c.dport);
                        cells.push(p);
                        keys.push(k);
                    }
                    let (frames, bytes) = (c.txf + c.rxf, c.txb + c.rxb);
                    let duration = (c.stop - c.start).max(0.0);
                    cells.extend([
                        thousands(frames),
                        human_bytes(bytes),
                        human_bytes(c.txb),
                        human_bytes(c.rxb),
                        format!("{:.3}", c.start),
                        format!("{duration:.3}"),
                    ]);
                    keys.extend([
                        Key::Num(frames as f64),
                        Key::Num(bytes as f64),
                        Key::Num(c.txb as f64),
                        Key::Num(c.rxb as f64),
                        Key::Num(c.start),
                        Key::Num(duration),
                    ]);
                    let one_way = one_way_filters(
                        &proto,
                        (&c.saddr, c.sport.as_deref()),
                        Some((&c.daddr, c.dport.as_deref())),
                    );
                    self.rows.push(Row {
                        cells,
                        keys,
                        filter: c.filter,
                        one_way,
                        ..Default::default()
                    });
                }
            }
            Tap::Endpoints { hosts, proto } => {
                self.truncated_from = hosts.truncated_from();
                let hosts = hosts.items;
                let ports = hosts.iter().any(|h| h.port.is_some());
                self.columns = vec![col("Address")];
                if ports {
                    self.columns.push(num("Port"));
                }
                self.columns.extend([
                    num("Packets"),
                    num("Bytes"),
                    num("Tx packets"),
                    num("Tx bytes"),
                    num("Rx packets"),
                    num("Rx bytes"),
                ]);
                for h in hosts {
                    let mut cells = vec![h.host.clone()];
                    let mut keys = vec![Key::Text];
                    if ports {
                        let p = h.port.clone().unwrap_or_default();
                        keys.push(p.parse::<f64>().map_or(Key::Text, Key::Num));
                        cells.push(p);
                    }
                    let (frames, bytes) = (h.txf + h.rxf, h.txb + h.rxb);
                    cells.extend([
                        thousands(frames),
                        human_bytes(bytes),
                        thousands(h.txf),
                        human_bytes(h.txb),
                        thousands(h.rxf),
                        human_bytes(h.rxb),
                    ]);
                    keys.extend(
                        [frames, bytes, h.txf, h.txb, h.rxf, h.rxb].map(|v| Key::Num(v as f64)),
                    );
                    let one_way = one_way_filters(&proto, (&h.host, h.port.as_deref()), None);
                    self.rows.push(Row {
                        cells,
                        keys,
                        filter: h.filter,
                        one_way,
                        ..Default::default()
                    });
                }
            }
            Tap::ProtocolHierarchy { protos } => {
                self.columns = vec![
                    col("Protocol"),
                    num("% Packets"),
                    num("Packets"),
                    num("% Bytes"),
                    num("Bytes"),
                ];
                let total_frames: u64 = protos.iter().map(|p| p.frames).sum();
                let total_bytes: u64 = protos.iter().map(|p| p.bytes).sum();
                fn walk(out: &mut Vec<Row>, protos: &[ProtoStat], depth: u16, totals: (u64, u64)) {
                    for p in protos {
                        let share = |n: u64, total: u64| {
                            if total == 0 {
                                0.0
                            } else {
                                n as f64 / total as f64
                            }
                        };
                        let (pf, pb) = (share(p.frames, totals.0), share(p.bytes, totals.1));
                        out.push(Row {
                            cells: vec![
                                p.proto.clone(),
                                format!("{:.1}", pf * 100.0),
                                thousands(p.frames),
                                format!("{:.1}", pb * 100.0),
                                human_bytes(p.bytes),
                            ],
                            keys: vec![
                                Key::Text,
                                Key::Num(pf),
                                Key::Num(p.frames as f64),
                                Key::Num(pb),
                                Key::Num(p.bytes as f64),
                            ],
                            filter: Some(p.proto.clone()),
                            depth,
                            bar: Some(pf),
                            ..Default::default()
                        });
                        walk(out, &p.protos, depth + 1, totals);
                    }
                }
                walk(&mut self.rows, &protos, 0, (total_frames, total_bytes));
            }
            Tap::Expert { details } => {
                self.truncated_from = details.truncated_from();
                let mut details = details.items;
                self.columns = vec![
                    col("Severity"),
                    col("Group"),
                    col("Protocol"),
                    num("Count"),
                    num("First"),
                    col("Summary"),
                ];
                // One row per distinct message, as in Wireshark's dialog: a
                // capture has thousands of routine notes and the few lines
                // that matter must not be lost among them.
                struct Group {
                    item: crate::sharkd::types::ExpertItem,
                    count: u32,
                }
                let mut groups: Vec<Group> = Vec::new();
                let mut index: std::collections::HashMap<(Option<String>, String), usize> =
                    std::collections::HashMap::new();
                details.sort_by_key(|d| d.frame);
                for d in details {
                    let key = (d.severity.clone(), d.message.clone());
                    if let Some(&i) = index.get(&key) {
                        groups[i].count += 1;
                    } else {
                        index.insert(key, groups.len());
                        groups.push(Group { item: d, count: 1 });
                    }
                }
                // Most serious first, then in capture order.
                groups.sort_by_key(|g| (severity_rank(g.item.severity.as_deref()), g.item.frame));
                for Group { item: d, count } in groups {
                    let severity = d.severity.clone().unwrap_or_default();
                    // Enter on a message seen once goes to its packet; on one
                    // seen many times it lists the packets that carry it.
                    let filter = (count > 1).then(|| {
                        let quoted = d.message.replace('\\', "\\\\").replace('"', "\\\"");
                        format!("_ws.expert.message == \"{quoted}\"")
                    });
                    self.rows.push(Row {
                        cells: vec![
                            severity.clone(),
                            d.group.clone().unwrap_or_default(),
                            d.protocol.clone().unwrap_or_default(),
                            thousands(u64::from(count)),
                            d.frame.to_string(),
                            d.message.clone(),
                        ],
                        keys: vec![
                            Key::Num(f64::from(severity_rank(d.severity.as_deref()))),
                            Key::Text,
                            Key::Text,
                            Key::Num(f64::from(count)),
                            Key::Num(f64::from(d.frame)),
                            Key::Text,
                        ],
                        filter,
                        frame: Some(d.frame),
                        severity: Some(severity),
                        ..Default::default()
                    });
                }
            }
            Tap::Flows { nodes, flows } => {
                self.truncated_from = flows.truncated_from();
                self.columns = vec![num("Time"), col("From"), col(""), col("To"), col("What")];
                let end = |node: usize, port: Option<u32>| {
                    let name = nodes.get(node).map_or("?", String::as_str);
                    match port {
                        // An IPv6 address needs brackets to tell its colons
                        // from the port's.
                        Some(port) if name.contains(':') => format!("[{name}]:{port}"),
                        Some(port) => format!("{name}:{port}"),
                        None => name.to_string(),
                    }
                };
                for flow in flows.items {
                    let (from, to) = flow.ends;
                    let (from_port, to_port) = match flow.ports {
                        Some((a, b)) if a != 0 || b != 0 => (Some(a), Some(b)),
                        _ => (None, None),
                    };
                    // Each pair keeps its sides, as in a ladder diagram: the
                    // arrow turns round, not the columns.
                    let turned = from > to;
                    let (left, right, arrow) = if turned {
                        (end(to, to_port), end(from, from_port), "◀──")
                    } else {
                        (end(from, from_port), end(to, to_port), "──▶")
                    };
                    let filter = match (nodes.get(from), nodes.get(to)) {
                        (Some(a), Some(b)) => {
                            let field = if a.contains(':') {
                                "ipv6.addr"
                            } else {
                                "ip.addr"
                            };
                            // Names that are not addresses (a resolved host)
                            // cannot be filtered on this way.
                            let address = |s: &str| {
                                s.chars()
                                    .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':'))
                            };
                            (address(a) && address(b))
                                .then(|| format!("{field} == {a} && {field} == {b}"))
                        }
                        _ => None,
                    };
                    self.rows.push(Row {
                        cells: vec![
                            flow.time.clone(),
                            left,
                            arrow.to_string(),
                            right,
                            flow.comment,
                        ],
                        keys: vec![
                            flow.time.parse::<f64>().map_or(Key::Text, Key::Num),
                            Key::Text,
                            Key::Text,
                            Key::Text,
                            Key::Text,
                        ],
                        filter,
                        ..Default::default()
                    });
                }
            }
            Tap::Objects { objects, .. } => {
                self.columns = vec![
                    num("Packet"),
                    col("Hostname"),
                    col("Content type"),
                    num("Size"),
                    col("Filename"),
                ];
                for o in objects {
                    let host = o.hostname.clone().unwrap_or_default();
                    let ctype = o.content_type.clone().unwrap_or_default();
                    let name = o.filename.clone().unwrap_or_default();
                    self.rows.push(Row {
                        cells: vec![
                            o.pkt.to_string(),
                            host.clone(),
                            ctype.clone(),
                            human_bytes(o.len),
                            name.clone(),
                        ],
                        keys: vec![
                            Key::Num(f64::from(o.pkt)),
                            Key::Text,
                            Key::Text,
                            Key::Num(o.len as f64),
                            Key::Text,
                        ],
                        frame: Some(o.pkt),
                        token: o.token,
                        filename: o.filename,
                        ..Default::default()
                    });
                }
            }
            Tap::Stats { stats, .. } => {
                self.columns = vec![col("Topic"), num("Count"), num("Rate (ms)"), num("Percent")];
                // Empty buckets ("5xx: Server Error  0") are noise.
                fn prune(nodes: &mut Vec<StatNode>) {
                    nodes.retain(|n| n.count > 0 || !n.sub.is_empty());
                    for n in nodes.iter_mut() {
                        prune(&mut n.sub);
                    }
                    nodes.retain(|n| n.count > 0 || !n.sub.is_empty());
                }
                let mut stats = stats;
                prune(&mut stats);
                fn walk(out: &mut Vec<Row>, nodes: &[StatNode], depth: u16) {
                    for n in nodes {
                        out.push(Row {
                            cells: vec![
                                n.name.clone(),
                                thousands(n.count),
                                n.rate.map(|r| format!("{r:.4}")).unwrap_or_default(),
                                n.perc.map(|p| format!("{p:.2}%")).unwrap_or_default(),
                            ],
                            keys: vec![
                                Key::Text,
                                Key::Num(n.count as f64),
                                Key::Num(n.rate.unwrap_or(0.0)),
                                Key::Num(n.perc.unwrap_or(0.0)),
                            ],
                            depth,
                            ..Default::default()
                        });
                        walk(out, &n.sub, depth + 1);
                    }
                }
                walk(&mut self.rows, &stats, 0);
            }
            Tap::Other => self.error = Some("this statistic is not supported yet".into()),
        }
    }

    /// Tree-shaped tables keep sharkd's order; sorting would scramble parents
    /// and children.
    pub fn sortable(&self) -> bool {
        // A tree's order is its shape, and a flow's is its meaning.
        !matches!(self.kind, Kind::Hierarchy | Kind::Flow) && !self.rows.iter().any(|r| r.depth > 0)
    }

    pub fn cycle_sort(&mut self) {
        if !self.sortable() || self.columns.is_empty() {
            return;
        }
        let n = self.columns.len();
        self.sort = Some(match self.sort {
            None => (0, false),
            Some((c, desc)) => ((c + 1) % n, desc),
        });
        self.apply_sort();
    }

    pub fn reverse_sort(&mut self) {
        if !self.sortable() {
            return;
        }
        if let Some((c, desc)) = self.sort {
            self.sort = Some((c, !desc));
            self.apply_sort();
        }
    }

    fn apply_sort(&mut self) {
        let Some((column, descending)) = self.sort else {
            return;
        };
        if !self.sortable() {
            return;
        }
        self.rows.sort_by(|a, b| {
            let ord = compare_rows(a, b, column);
            if descending { ord.reverse() } else { ord }
        });
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    pub fn move_by(&mut self, delta: i64) {
        if self.rows.is_empty() {
            return;
        }
        self.selected =
            (self.selected as i64 + delta).clamp(0, self.rows.len() as i64 - 1) as usize;
        self.clamp_view();
    }

    pub fn set_height(&mut self, height: u16) {
        self.height = height;
        self.clamp_view();
    }

    fn clamp_view(&mut self) {
        let height = (self.height as usize).max(1);
        if self.selected < self.top {
            self.top = self.selected;
        } else if self.selected >= self.top + height {
            self.top = self.selected + 1 - height;
        }
        self.top = self.top.min(self.rows.len().saturating_sub(height));
    }

    pub fn switch_tab(&mut self, delta: i64) -> bool {
        if self.tabs.len() < 2 {
            return false;
        }
        let n = self.tabs.len() as i64;
        self.tab = (self.tab as i64 + delta).rem_euclid(n) as usize;
        self.sort = None;
        true
    }
}

/// Display filters for one direction of a conversation (`a` to `b` and
/// back), or for traffic from and to a single endpoint when `b` is `None`.
/// `None` for protocols whose address fields are not known here.
fn one_way_filters(
    proto: &str,
    a: (&str, Option<&str>),
    b: Option<(&str, Option<&str>)>,
) -> Option<(String, String)> {
    let v6 = |address: &str| address.contains(':');
    // The address field, and the port field if the protocol has ports.
    let (address, port): (&str, Option<&str>) = match proto.to_ascii_lowercase().as_str() {
        "ethernet" | "eth" => ("eth", None),
        "ipv4" | "ip" => ("ip", None),
        "ipv6" => ("ipv6", None),
        "tcp" => (if v6(a.0) { "ipv6" } else { "ip" }, Some("tcp")),
        "udp" => (if v6(a.0) { "ipv6" } else { "ip" }, Some("udp")),
        _ => return None,
    };
    let end = |way: &str, (addr, p): (&str, Option<&str>)| {
        let mut term = format!("{address}.{way} == {addr}");
        if let (Some(port), Some(p)) = (port, p.filter(|p| !p.is_empty())) {
            term = format!("{term} && {port}.{way}port == {p}");
        }
        term
    };
    Some(match b {
        Some(b) => (
            format!("{} && {}", end("src", a), end("dst", b)),
            format!("{} && {}", end("src", b), end("dst", a)),
        ),
        None => (end("src", a), end("dst", a)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharkd::types::{Conversation, ExpertItem};

    #[test]
    fn a_conversation_can_be_filtered_one_way() {
        let (there, back) = one_way_filters(
            "TCP",
            ("10.0.0.2", Some("40000")),
            Some(("1.1.1.1", Some("80"))),
        )
        .unwrap();
        assert_eq!(
            there,
            "ip.src == 10.0.0.2 && tcp.srcport == 40000 && ip.dst == 1.1.1.1 && tcp.dstport == 80"
        );
        assert_eq!(
            back,
            "ip.src == 1.1.1.1 && tcp.srcport == 80 && ip.dst == 10.0.0.2 && tcp.dstport == 40000"
        );
        let (there, _) = one_way_filters(
            "UDP",
            ("fe80::1", Some("53")),
            Some(("fe80::2", Some("5353"))),
        )
        .unwrap();
        assert!(
            there.starts_with("ipv6.src == fe80::1 && udp.srcport == 53"),
            "{there}"
        );
        let (there, back) = one_way_filters(
            "Ethernet",
            ("aa:bb:cc:dd:ee:01", None),
            Some(("aa:bb:cc:dd:ee:02", None)),
        )
        .unwrap();
        assert_eq!(
            there,
            "eth.src == aa:bb:cc:dd:ee:01 && eth.dst == aa:bb:cc:dd:ee:02"
        );
        assert_eq!(
            back,
            "eth.src == aa:bb:cc:dd:ee:02 && eth.dst == aa:bb:cc:dd:ee:01"
        );
        // An endpoint: traffic from it, and to it.
        let (from, to) = one_way_filters("IPv4", ("10.0.0.2", None), None).unwrap();
        assert_eq!(
            (from.as_str(), to.as_str()),
            ("ip.src == 10.0.0.2", "ip.dst == 10.0.0.2")
        );
        assert!(one_way_filters("SCTP", ("10.0.0.2", None), None).is_none());
    }

    fn conv(a: &str, b: &str, bytes: u64) -> Conversation {
        Conversation {
            saddr: a.into(),
            daddr: b.into(),
            sport: Some("40000".into()),
            dport: Some("80".into()),
            txf: 2,
            txb: bytes,
            rxf: 1,
            rxb: 0,
            start: 0.5,
            stop: 2.0,
            filter: Some(format!("ip.addr=={a} && ip.addr=={b}")),
        }
    }

    fn conversations() -> StatsView {
        let mut v = StatsView::new(Kind::Conversations, vec!["TCP".into(), "UDP".into()], 0);
        v.set_height(10);
        v.set_result(Ok(vec![Tap::Conversations {
            proto: "TCP".into(),
            convs: vec![
                conv("10.0.0.10", "1.1.1.1", 100),
                conv("10.0.0.2", "1.1.1.1", 5000),
                conv("10.0.0.3", "1.1.1.1", 700),
            ]
            .into(),
        }]));
        v
    }

    fn first_cells(v: &StatsView) -> Vec<&str> {
        v.rows.iter().map(|r| r.cells[0].as_str()).collect()
    }

    #[test]
    fn conversations_default_to_busiest_first() {
        let v = conversations();
        assert_eq!(v.tap(), "conv:TCP");
        assert_eq!(first_cells(&v), ["10.0.0.2", "10.0.0.3", "10.0.0.10"]);
        assert_eq!(v.rows[0].cells[5], "5.0 kB");
        assert_eq!(v.rows[0].cells[9], "1.500");
        assert_eq!(
            v.selected_row().unwrap().filter.as_deref(),
            Some("ip.addr==10.0.0.2 && ip.addr==1.1.1.1")
        );
    }

    #[test]
    fn sorting_addresses_is_numeric_aware() {
        let mut v = conversations();
        v.sort = Some((0, false));
        v.apply_sort();
        assert_eq!(first_cells(&v), ["10.0.0.2", "10.0.0.3", "10.0.0.10"]);
        v.reverse_sort();
        assert_eq!(first_cells(&v), ["10.0.0.10", "10.0.0.3", "10.0.0.2"]);
    }

    #[test]
    fn cycling_sort_moves_through_columns() {
        let mut v = conversations();
        let start = v.sort.unwrap().0;
        v.cycle_sort();
        assert_eq!(v.sort.unwrap().0, (start + 1) % v.columns.len());
    }

    #[test]
    fn hierarchy_is_a_tree_and_not_sortable() {
        let mut v = StatsView::new(Kind::Hierarchy, vec![], 0);
        let leaf = |name: &str, frames, bytes| ProtoStat {
            proto: name.into(),
            frames,
            bytes,
            protos: vec![],
        };
        v.set_result(Ok(vec![Tap::ProtocolHierarchy {
            protos: vec![ProtoStat {
                proto: "eth".into(),
                frames: 10,
                bytes: 1000,
                protos: vec![leaf("ip", 8, 900), leaf("arp", 2, 100)],
            }],
        }]));
        assert!(!v.sortable());
        assert_eq!(
            v.rows.iter().map(|r| r.depth).collect::<Vec<_>>(),
            [0, 1, 1]
        );
        assert_eq!(v.rows[1].cells, ["ip", "80.0", "8", "90.0", "900 B"]);
        assert_eq!(v.rows[2].filter.as_deref(), Some("arp"));
        v.cycle_sort();
        assert_eq!(first_cells(&v), ["eth", "ip", "arp"], "order unchanged");
    }

    #[test]
    fn expert_items_are_grouped_by_message_and_ordered_by_severity() {
        let item = |frame, severity: &str, message: &str| ExpertItem {
            frame,
            severity: Some(severity.into()),
            group: Some("Sequence".into()),
            message: message.into(),
            protocol: Some("TCP".into()),
        };
        let mut v = StatsView::new(Kind::Expert, vec![], 0);
        v.set_result(Ok(vec![Tap::Expert {
            details: vec![
                item(9, "Chat", "Connection finish (FIN)"),
                item(4, "Error", "Bad checksum"),
                item(7, "Warn", "said \"no\" \\ twice"),
                item(2, "Warn", "said \"no\" \\ twice"),
                item(1, "Chat", "Connection finish (FIN)"),
                item(3, "Chat", "Connection finish (FIN)"),
            ]
            .into(),
        }]));
        let rows: Vec<(u32, &str, &str)> = v
            .rows
            .iter()
            .map(|r| (r.frame.unwrap(), r.cells[3].as_str(), r.cells[5].as_str()))
            .collect();
        // Most serious first; each message once, with its count and the
        // first packet that carries it.
        assert_eq!(
            rows,
            [
                (4, "1", "Bad checksum"),
                (2, "2", "said \"no\" \\ twice"),
                (1, "3", "Connection finish (FIN)"),
            ]
        );
        // A single occurrence is a place to go; several are a list to show.
        assert_eq!(v.rows[0].filter, None);
        assert_eq!(
            v.rows[1].filter.as_deref(),
            Some(r#"_ws.expert.message == "said \"no\" \\ twice""#)
        );
    }

    #[test]
    fn errors_and_empty_results() {
        let mut v = StatsView::new(Kind::Objects, vec!["HTTP".into()], 0);
        assert_eq!(v.tap(), "eo:http");
        v.set_result(Err("tap failed".into()));
        assert_eq!(v.error.as_deref(), Some("tap failed"));
        v.set_result(Ok(vec![]));
        assert!(v.error.is_some());
        v.move_by(5);
        assert_eq!(v.selected, 0);
    }

    #[test]
    fn tabs_wrap_around() {
        let mut v = conversations();
        assert!(v.switch_tab(-1));
        assert_eq!(v.tab, 1);
        assert!(v.switch_tab(1));
        assert_eq!(v.tab, 0);
        let mut single = StatsView::new(Kind::Hierarchy, vec![], 0);
        assert!(!single.switch_tab(1));
    }

    #[test]
    fn a_truncated_list_is_reported() {
        use crate::sharkd::types::Capped;
        let mut v = StatsView::new(Kind::Conversations, vec!["UDP".into()], 0);
        let convs = Capped {
            items: vec![conv("a", "b", 9), conv("c", "d", 5)],
            total: 1_000_000,
        };
        v.set_result(Ok(vec![Tap::Conversations {
            proto: "UDP".into(),
            convs,
        }]));
        assert_eq!(v.rows.len(), 2);
        assert_eq!(v.truncated_from, Some(1_000_000));
        // A later, complete result clears the notice.
        let convs = vec![conv("a", "b", 1)].into();
        v.set_result(Ok(vec![Tap::Conversations {
            proto: "UDP".into(),
            convs,
        }]));
        assert_eq!(v.truncated_from, None);
    }

    #[test]
    fn statistics_trees_drop_empty_buckets() {
        let node = |name: &str, count, sub| StatNode {
            name: name.into(),
            count,
            rate: Some(0.5),
            perc: Some(50.0),
            sub,
        };
        let mut v = StatsView::tree("stat:http", "HTTP / Packet Counter");
        assert_eq!(v.tap(), "stat:http");
        assert_eq!(v.title(), "HTTP / Packet Counter");
        v.set_result(Ok(vec![Tap::Stats {
            name: "HTTP//Packet Counter".into(),
            stats: vec![node(
                "Total",
                3,
                vec![
                    node(
                        "Requests",
                        2,
                        vec![node("GET", 2, vec![]), node("POST", 0, vec![])],
                    ),
                    node("Responses", 0, vec![node("5xx", 0, vec![])]),
                ],
            )],
        }]));
        assert_eq!(first_cells(&v), ["Total", "Requests", "GET"]);
        assert_eq!(
            v.rows.iter().map(|r| r.depth).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(v.rows[2].cells, ["GET", "2", "0.5000", "50.00%"]);
        assert!(!v.sortable());
    }

    #[test]
    fn natural_ordering() {
        assert_eq!(natural_cmp("10.0.0.2", "10.0.0.10"), Ordering::Less);
        assert_eq!(natural_cmp("abc", "ABD"), Ordering::Less);
        assert_eq!(natural_cmp("a", "a"), Ordering::Equal);
        assert_eq!(natural_cmp("a1", "a"), Ordering::Greater);
    }
}
