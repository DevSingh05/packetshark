//! The selected packet: its dissection tree and its bytes.

use std::collections::HashSet;

use crate::sharkd::types::{FrameDetail, Node};
use crate::util::decode_base64;

/// A block of bytes belonging to a packet: the frame itself, or data that a
/// dissector produced from several frames (reassembled, decrypted).
#[derive(Debug, Clone)]
pub struct Source {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Detail {
    pub num: u32,
    pub tree: Vec<Node>,
    /// `sources[0]` is the frame; a node's `ds` indexes this list.
    pub sources: Vec<Source>,
    /// `(protocol, filter)` pairs for Follow Stream.
    pub follow: Vec<(String, String)>,
}

impl Detail {
    pub fn new(num: u32, frame: FrameDetail) -> Detail {
        let bytes = frame
            .bytes
            .as_deref()
            .map(decode_base64)
            .unwrap_or_default();
        let mut sources = vec![Source {
            name: format!("Frame ({} bytes)", bytes.len()),
            bytes,
        }];
        for ds in frame.ds {
            let bytes = decode_base64(&ds.bytes);
            let name = if ds.name.is_empty() {
                format!("Data source {} ({} bytes)", sources.len(), bytes.len())
            } else {
                ds.name
            };
            sources.push(Source { name, bytes });
        }
        Detail {
            num,
            tree: frame.tree,
            sources,
            follow: frame.fol,
        }
    }

    pub fn node(&self, path: &[usize]) -> Option<&Node> {
        node_at(&self.tree, path)
    }
}

pub fn node_at<'a>(tree: &'a [Node], path: &[usize]) -> Option<&'a Node> {
    let (first, rest) = path.split_first()?;
    let mut node = tree.get(*first)?;
    for i in rest {
        node = node.children.get(*i)?;
    }
    Some(node)
}

/// What identifies a subtree for the purpose of remembering its expansion.
/// Wireshark keys this on the subtree type, so opening "Flags" in one TCP
/// packet opens it in all of them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SubtreeKey {
    Ett(i64),
    Named(String),
}

fn subtree_key(node: &Node) -> SubtreeKey {
    match node.ett {
        Some(e) => SubtreeKey::Ett(e),
        None => SubtreeKey::Named(node.field.clone().unwrap_or_else(|| node.label.clone())),
    }
}

/// One visible row of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeLine {
    pub path: Vec<usize>,
    pub depth: u16,
    pub expandable: bool,
    pub expanded: bool,
}

#[derive(Debug, Default)]
pub struct TreeState {
    pub lines: Vec<TreeLine>,
    pub selected: usize,
    pub top: usize,
    pub height: u16,
    expanded: HashSet<SubtreeKey>,
    /// Field names from the root to the node the user last selected, so the
    /// same field stays selected when moving between packets.
    remembered: Vec<String>,
    /// Expand every subtree (set by the user or the config).
    pub expand_all: bool,
}

impl TreeState {
    pub fn with_expand_all(expand_all: bool) -> TreeState {
        TreeState {
            expand_all,
            ..Default::default()
        }
    }

    fn is_expanded(&self, node: &Node) -> bool {
        self.expand_all || self.expanded.contains(&subtree_key(node))
    }

    /// Recompute the visible rows.
    pub fn rebuild(&mut self, tree: &[Node]) {
        fn walk(state: &TreeState, nodes: &[Node], path: &mut Vec<usize>, out: &mut Vec<TreeLine>) {
            for (i, node) in nodes.iter().enumerate() {
                path.push(i);
                let expandable = !node.children.is_empty();
                let expanded = expandable && state.is_expanded(node);
                out.push(TreeLine {
                    path: path.clone(),
                    depth: (path.len() - 1) as u16,
                    expandable,
                    expanded,
                });
                if expanded {
                    walk(state, &node.children, path, out);
                }
                path.pop();
            }
        }
        let mut lines = Vec::new();
        walk(self, tree, &mut Vec::new(), &mut lines);
        self.lines = lines;
        self.selected = self.selected.min(self.lines.len().saturating_sub(1));
        self.clamp_view();
    }

    /// Show a new packet, reselecting the field that was selected before.
    pub fn show(&mut self, tree: &[Node]) {
        self.rebuild(tree);
        let target = self.resolve_remembered(tree);
        self.selected = self
            .lines
            .iter()
            .position(|l| l.path == target)
            .unwrap_or(0);
        self.top = 0;
        self.clamp_view();
    }

    /// The deepest visible node matching the remembered field-name chain.
    fn resolve_remembered(&self, tree: &[Node]) -> Vec<usize> {
        let mut path = Vec::new();
        let mut nodes = tree;
        for name in &self.remembered {
            let Some(i) = nodes
                .iter()
                .position(|n| n.field.as_deref() == Some(name.as_str()))
            else {
                break;
            };
            path.push(i);
            if !self.is_expanded(&nodes[i]) {
                break;
            }
            nodes = &nodes[i].children;
        }
        path
    }

    fn remember(&mut self, tree: &[Node]) {
        let Some(line) = self.lines.get(self.selected) else {
            return;
        };
        let mut names = Vec::new();
        let mut nodes = tree;
        for i in &line.path {
            let Some(node) = nodes.get(*i) else { break };
            names.push(node.field.clone().unwrap_or_default());
            nodes = &node.children;
        }
        self.remembered = names;
    }

    pub fn selected_path(&self) -> Option<&[usize]> {
        self.lines.get(self.selected).map(|l| l.path.as_slice())
    }

    pub fn select(&mut self, index: usize, tree: &[Node]) {
        if self.lines.is_empty() {
            return;
        }
        self.selected = index.min(self.lines.len() - 1);
        self.clamp_view();
        self.remember(tree);
    }

    pub fn move_by(&mut self, delta: i64, tree: &[Node]) {
        if self.lines.is_empty() {
            return;
        }
        let target = (self.selected as i64 + delta)
            .clamp(0, self.lines.len() as i64 - 1)
            .max(0);
        self.select(target as usize, tree);
    }

    pub fn scroll_by(&mut self, delta: i64) {
        let max_top = self.lines.len().saturating_sub(self.height as usize) as i64;
        self.top = (self.top as i64 + delta).clamp(0, max_top.max(0)) as usize;
    }

    fn set_expanded(&mut self, tree: &[Node], path: &[usize], open: bool) {
        let Some(node) = node_at(tree, path) else {
            return;
        };
        if node.children.is_empty() {
            return;
        }
        let key = subtree_key(node);
        if open {
            self.expanded.insert(key);
        } else {
            // Collapsing one subtree while "expand all" is on turns the global
            // switch off but keeps everything else open.
            if self.expand_all {
                self.expand_all = false;
                collect_keys(tree, &mut self.expanded);
            }
            self.expanded.remove(&key);
        }
    }

    fn reselect(&mut self, tree: &[Node], path: &[usize]) {
        self.rebuild(tree);
        // If the node is no longer visible, fall back to its nearest visible ancestor.
        let mut path = path.to_vec();
        loop {
            if let Some(i) = self.lines.iter().position(|l| l.path == path) {
                self.selected = i;
                break;
            }
            if path.pop().is_none() {
                break;
            }
        }
        self.clamp_view();
        self.remember(tree);
    }

    pub fn toggle(&mut self, tree: &[Node]) {
        let Some(line) = self.lines.get(self.selected).cloned() else {
            return;
        };
        self.set_expanded(tree, &line.path, !line.expanded);
        self.reselect(tree, &line.path);
    }

    /// `l` / Right: open the node, or step into it if already open.
    pub fn expand_or_descend(&mut self, tree: &[Node]) {
        let Some(line) = self.lines.get(self.selected).cloned() else {
            return;
        };
        if !line.expandable {
            return;
        }
        if line.expanded {
            self.select(self.selected + 1, tree);
        } else {
            self.set_expanded(tree, &line.path, true);
            self.reselect(tree, &line.path);
        }
    }

    /// `h` / Left: close the node, or jump to its parent if already closed.
    pub fn collapse_or_ascend(&mut self, tree: &[Node]) {
        let Some(line) = self.lines.get(self.selected).cloned() else {
            return;
        };
        if line.expanded {
            self.set_expanded(tree, &line.path, false);
            self.reselect(tree, &line.path);
        } else if line.path.len() > 1 {
            let parent = &line.path[..line.path.len() - 1];
            self.reselect(tree, parent);
        }
    }

    /// Open the selected node and everything beneath it.
    pub fn expand_subtree(&mut self, tree: &[Node]) {
        let Some(line) = self.lines.get(self.selected).cloned() else {
            return;
        };
        if let Some(node) = node_at(tree, &line.path) {
            collect_keys(std::slice::from_ref(node), &mut self.expanded);
        }
        self.reselect(tree, &line.path);
    }

    pub fn set_expand_all(&mut self, tree: &[Node], on: bool) {
        let path = self
            .selected_path()
            .map(<[usize]>::to_vec)
            .unwrap_or_default();
        self.expand_all = on;
        if !on {
            self.expanded.clear();
        }
        self.reselect(tree, &path);
    }

    /// Select the node at `path`, opening its ancestors.
    pub fn reveal(&mut self, tree: &[Node], path: &[usize]) {
        for depth in 1..path.len() {
            self.set_expanded(tree, &path[..depth], true);
        }
        self.reselect(tree, path);
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
        self.top = self.top.min(self.lines.len().saturating_sub(height));
    }
}

fn collect_keys(nodes: &[Node], out: &mut HashSet<SubtreeKey>) {
    for node in nodes {
        if !node.children.is_empty() {
            out.insert(subtree_key(node));
            collect_keys(&node.children, out);
        }
    }
}

/// The path of the most specific node whose bytes include `offset` of data
/// source `source`.
pub fn deepest_at(tree: &[Node], source: usize, offset: usize) -> Option<Vec<usize>> {
    fn covers(node: &Node, source: usize, offset: usize) -> bool {
        node.ds.unwrap_or(0) == source
            && node.range.is_some_and(|(start, len)| {
                let start = start as usize;
                offset >= start && offset < start + len as usize
            })
    }
    fn walk(
        nodes: &[Node],
        source: usize,
        offset: usize,
        path: &mut Vec<usize>,
        best: &mut Option<(u32, Vec<usize>)>,
    ) {
        for (i, node) in nodes.iter().enumerate() {
            path.push(i);
            if covers(node, source, offset) {
                let len = node.range.map_or(u32::MAX, |r| r.1);
                // Prefer the narrowest range; among equals, the deepest node.
                let better = best
                    .as_ref()
                    .is_none_or(|(l, p)| len < *l || (len == *l && path.len() > p.len()));
                if better {
                    *best = Some((len, path.clone()));
                }
            }
            // A child can refer to a different data source than its parent, so
            // always descend.
            walk(&node.children, source, offset, path, best);
            path.pop();
        }
    }
    let mut best = None;
    walk(tree, source, offset, &mut Vec::new(), &mut best);
    best.map(|(_, path)| path)
}

/// The hex pane's view state.
#[derive(Debug, Default)]
pub struct HexState {
    /// Which data source is shown.
    pub source: usize,
    /// Byte under the cursor.
    pub cursor: usize,
    /// First visible row.
    pub top: usize,
    pub height: u16,
    /// Bytes per row at the last draw.
    pub per_row: usize,
}

impl HexState {
    pub fn per_row(&self) -> usize {
        if self.per_row == 0 { 16 } else { self.per_row }
    }

    pub fn reset(&mut self) {
        self.source = 0;
        self.cursor = 0;
        self.top = 0;
    }

    /// Bring a byte range into view.
    pub fn show_range(&mut self, source: usize, start: usize, len: usize) {
        if self.source != source {
            self.source = source;
            self.top = 0;
        }
        self.cursor = start;
        let per_row = self.per_row();
        let height = (self.height as usize).max(1);
        let first = start / per_row;
        let last = (start + len.max(1) - 1) / per_row;
        if first < self.top || last >= self.top + height {
            // Leave a row of context above when there is room.
            self.top = first.saturating_sub(usize::from(height > 2));
        }
    }

    pub fn move_cursor(&mut self, delta: i64, len: usize) {
        if len == 0 {
            self.cursor = 0;
            return;
        }
        self.cursor = (self.cursor as i64 + delta).clamp(0, len as i64 - 1) as usize;
        let row = self.cursor / self.per_row();
        let height = (self.height as usize).max(1);
        if row < self.top {
            self.top = row;
        } else if row >= self.top + height {
            self.top = row + 1 - height;
        }
    }

    pub fn scroll_by(&mut self, delta: i64, len: usize) {
        let rows = len.div_ceil(self.per_row());
        let max_top = rows.saturating_sub(self.height as usize) as i64;
        self.top = (self.top as i64 + delta).clamp(0, max_top.max(0)) as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(label: &str, field: &str, range: (u32, u32)) -> Node {
        Node {
            label: label.into(),
            field: Some(field.into()),
            range: Some(range),
            ..Default::default()
        }
    }

    fn branch(label: &str, field: &str, ett: i64, range: (u32, u32), children: Vec<Node>) -> Node {
        Node {
            ett: Some(ett),
            children,
            ..leaf(label, field, range)
        }
    }

    /// eth [0,14] { dst [0,6], src [6,6] }, ip [14,20] { ver [14,1], flags [20,2] { df [20,1] } }
    fn tree() -> Vec<Node> {
        vec![
            branch(
                "Ethernet",
                "eth",
                1,
                (0, 14),
                vec![
                    leaf("Destination", "eth.dst", (0, 6)),
                    leaf("Source", "eth.src", (6, 6)),
                ],
            ),
            branch(
                "IPv4",
                "ip",
                2,
                (14, 20),
                vec![
                    leaf("Version", "ip.version", (14, 1)),
                    branch(
                        "Flags",
                        "ip.flags",
                        3,
                        (20, 2),
                        vec![leaf("DF", "ip.flags.df", (20, 1))],
                    ),
                ],
            ),
        ]
    }

    fn labels(state: &TreeState, tree: &[Node]) -> Vec<String> {
        state
            .lines
            .iter()
            .map(|l| node_at(tree, &l.path).unwrap().label.clone())
            .collect()
    }

    #[test]
    fn starts_collapsed_and_expands_on_demand() {
        let t = tree();
        let mut s = TreeState::default();
        s.set_height(10);
        s.show(&t);
        assert_eq!(labels(&s, &t), ["Ethernet", "IPv4"]);
        s.select(1, &t);
        s.expand_or_descend(&t);
        assert_eq!(labels(&s, &t), ["Ethernet", "IPv4", "Version", "Flags"]);
        // A second press steps into the first child.
        s.expand_or_descend(&t);
        assert_eq!(s.selected, 2);
    }

    #[test]
    fn collapse_on_a_leaf_jumps_to_its_parent() {
        let t = tree();
        let mut s = TreeState::default();
        s.set_height(10);
        s.show(&t);
        s.select(1, &t);
        s.expand_or_descend(&t);
        s.select(2, &t);
        s.collapse_or_ascend(&t);
        assert_eq!(s.selected, 1, "moved to IPv4");
        s.collapse_or_ascend(&t);
        assert_eq!(labels(&s, &t), ["Ethernet", "IPv4"]);
    }

    #[test]
    fn expansion_and_selection_carry_over_to_the_next_packet() {
        let t = tree();
        let mut s = TreeState::default();
        s.set_height(10);
        s.show(&t);
        s.reveal(&t, &[1, 1, 0]);
        assert_eq!(labels(&s, &t)[s.selected], "DF");

        // The next packet has an extra layer in front and no DF flag.
        let mut next = tree();
        next.insert(0, leaf("Frame", "frame", (0, 34)));
        next[2].children[1].children.clear();
        s.show(&next);
        assert_eq!(
            labels(&s, &next)[s.selected],
            "Flags",
            "nearest surviving ancestor"
        );
        assert!(
            labels(&s, &next).contains(&"Version".to_string()),
            "IPv4 stayed open"
        );
    }

    #[test]
    fn expand_all_then_collapsing_one_keeps_the_rest_open() {
        let t = tree();
        let mut s = TreeState::default();
        s.set_height(10);
        s.show(&t);
        s.set_expand_all(&t, true);
        assert_eq!(s.lines.len(), 7);
        s.select(0, &t);
        s.toggle(&t);
        assert_eq!(
            labels(&s, &t),
            ["Ethernet", "IPv4", "Version", "Flags", "DF"]
        );
        s.set_expand_all(&t, false);
        assert_eq!(s.lines.len(), 2);
    }

    #[test]
    fn expand_subtree_opens_all_descendants() {
        let t = tree();
        let mut s = TreeState::default();
        s.set_height(10);
        s.show(&t);
        s.select(1, &t);
        s.expand_subtree(&t);
        assert_eq!(
            labels(&s, &t),
            ["Ethernet", "IPv4", "Version", "Flags", "DF"]
        );
    }

    #[test]
    fn byte_lookup_finds_the_most_specific_field() {
        let t = tree();
        assert_eq!(deepest_at(&t, 0, 7), Some(vec![0, 1]));
        assert_eq!(deepest_at(&t, 0, 20), Some(vec![1, 1, 0]));
        assert_eq!(deepest_at(&t, 0, 21), Some(vec![1, 1]));
        assert_eq!(deepest_at(&t, 0, 30), Some(vec![1]));
        assert_eq!(deepest_at(&t, 0, 99), None);
        assert_eq!(deepest_at(&t, 1, 7), None, "other data source");
    }

    #[test]
    fn an_empty_tree_is_harmless() {
        let mut s = TreeState::default();
        s.set_height(5);
        s.show(&[]);
        s.move_by(1, &[]);
        s.move_by(-3, &[]);
        s.select(4, &[]);
        s.toggle(&[]);
        s.expand_or_descend(&[]);
        s.collapse_or_ascend(&[]);
        s.expand_subtree(&[]);
        s.set_expand_all(&[], true);
        s.scroll_by(3);
        assert_eq!((s.selected, s.top, s.lines.len()), (0, 0, 0));
        assert!(s.selected_path().is_none());
    }

    #[test]
    fn view_follows_the_cursor() {
        let t = tree();
        let mut s = TreeState::default();
        s.set_height(3);
        s.show(&t);
        s.set_expand_all(&t, true);
        s.select(6, &t);
        assert_eq!(s.top, 4);
        s.select(0, &t);
        assert_eq!(s.top, 0);
    }

    #[test]
    fn hex_view_scrolls_to_a_range_and_tracks_the_cursor() {
        let mut h = HexState {
            height: 4,
            per_row: 16,
            ..Default::default()
        };
        h.show_range(0, 200, 4);
        assert_eq!(h.cursor, 200);
        assert_eq!(h.top, 11, "one row of context above row 12");
        h.move_cursor(-200, 512);
        assert_eq!((h.cursor, h.top), (0, 0));
        h.move_cursor(16 * 10, 512);
        assert_eq!((h.cursor, h.top), (160, 7));
        h.move_cursor(10_000, 512);
        assert_eq!(h.cursor, 511);
        h.show_range(1, 0, 8);
        assert_eq!((h.source, h.top), (1, 0));
    }
}
