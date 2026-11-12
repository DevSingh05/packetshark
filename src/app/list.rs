//! The packet list model: a window onto a list that lives in sharkd.
//!
//! Only the pages near the viewport are held in memory, so a capture with
//! millions of packets costs the same as one with a hundred.

use std::collections::{HashMap, HashSet};

use crate::sharkd::types::FrameRow;
use crate::util::width;

/// Rows per request.
pub const PAGE: u32 = 200;
/// Pages kept before the farthest ones are dropped.
const MAX_PAGES: usize = 48;

#[derive(Debug, Default)]
pub struct PacketList {
    /// Bumped whenever the rows on screen stop being valid (new filter, new
    /// columns, reload). Replies for an older generation are ignored.
    pub generation: u64,
    /// Number of displayed packets; `None` until sharkd has counted them.
    pub total: Option<u32>,
    pub selected: u32,
    pub top: u32,
    /// Rows visible at the last draw.
    pub height: u16,
    pages: HashMap<u32, Vec<FrameRow>>,
    /// Rows from before the last refresh, shown until fresh ones arrive so the
    /// list does not flash empty.
    stale: HashMap<u32, Vec<FrameRow>>,
    requested: HashSet<u32>,
    /// Widest cell seen per column.
    pub widths: Vec<u16>,
    pub error: Option<String>,
}

impl PacketList {
    pub fn len(&self) -> u32 {
        self.total.unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn row(&self, index: u32) -> Option<&FrameRow> {
        let (page, offset) = (index / PAGE, (index % PAGE) as usize);
        self.pages
            .get(&page)
            .or_else(|| self.stale.get(&page))
            .and_then(|rows| rows.get(offset))
    }

    /// The row at `index`, only if it reflects the current generation.
    pub fn fresh_row(&self, index: u32) -> Option<&FrameRow> {
        self.pages
            .get(&(index / PAGE))
            .and_then(|rows| rows.get((index % PAGE) as usize))
    }

    pub fn selected_row(&self) -> Option<&FrameRow> {
        self.row(self.selected)
    }

    pub fn selected_num(&self) -> Option<u32> {
        self.selected_row().map(|r| r.num)
    }

    /// Start over: a different filter or file.
    pub fn reset(&mut self) {
        self.generation += 1;
        self.total = None;
        self.selected = 0;
        self.top = 0;
        self.pages.clear();
        self.stale.clear();
        self.requested.clear();
        self.widths.clear();
        self.error = None;
    }

    /// The same list, but its rows must be fetched again (columns changed, or
    /// the file grew).
    pub fn refresh(&mut self) {
        self.generation += 1;
        let fresh = std::mem::take(&mut self.pages);
        self.stale.extend(fresh);
        self.requested.clear();
        self.error = None;
    }

    pub fn set_total(&mut self, total: u32) {
        self.total = Some(total);
        if total == 0 {
            self.selected = 0;
            self.top = 0;
        } else if self.selected >= total {
            self.selected = total - 1;
        }
        self.clamp_view();
    }

    /// Pages to request so the viewport (plus a margin) is covered. Each page
    /// is returned once; it is then considered in flight.
    pub fn pages_needed(&mut self) -> Vec<u32> {
        let Some(total) = self.total else {
            return Vec::new();
        };
        if total == 0 {
            return Vec::new();
        }
        let margin = PAGE / 2;
        let first = self.top.saturating_sub(margin) / PAGE;
        let last_row = (self.top + u32::from(self.height) + margin).min(total - 1);
        let last = last_row / PAGE;
        let mut needed = Vec::new();
        for page in first..=last {
            if !self.pages.contains_key(&page) && self.requested.insert(page) {
                needed.push(page);
            }
        }
        needed
    }

    pub fn insert_page(&mut self, skip: u32, rows: Vec<FrameRow>) {
        let page = skip / PAGE;
        self.requested.remove(&page);
        for row in &rows {
            if self.widths.len() < row.cols.len() {
                self.widths.resize(row.cols.len(), 0);
            }
            for (i, cell) in row.cols.iter().enumerate() {
                let w = width(cell).min(u16::MAX as usize) as u16;
                if w > self.widths[i] {
                    self.widths[i] = w;
                }
            }
        }
        self.stale.remove(&page);
        self.pages.insert(page, rows);
        self.evict();
    }

    /// Record a failed page. It stays marked as requested so it is not asked
    /// for again until the list is refreshed; retrying at once would loop.
    pub fn page_failed(&mut self, _skip: u32, error: String) {
        self.error = Some(error);
    }

    fn evict(&mut self) {
        let here = i64::from(self.top / PAGE);
        for map in [&mut self.pages, &mut self.stale] {
            while map.len() > MAX_PAGES {
                let far = *map
                    .keys()
                    .max_by_key(|p| (i64::from(**p) - here).abs())
                    .unwrap();
                map.remove(&far);
            }
        }
    }

    pub fn select(&mut self, index: u32) {
        let last = self.len().saturating_sub(1);
        self.selected = index.min(last);
        self.clamp_view();
    }

    pub fn move_by(&mut self, delta: i64) {
        let target =
            (i64::from(self.selected) + delta).clamp(0, i64::from(self.len().saturating_sub(1)));
        self.select(target as u32);
    }

    /// Scroll the view without moving the cursor more than needed to keep it
    /// on screen (mouse wheel).
    pub fn scroll_by(&mut self, delta: i64) {
        let max_top = i64::from(self.len().saturating_sub(u32::from(self.height)));
        self.top = (i64::from(self.top) + delta).clamp(0, max_top.max(0)) as u32;
        let bottom = self.top + u32::from(self.height).saturating_sub(1);
        self.selected = self
            .selected
            .clamp(self.top, bottom.min(self.len().saturating_sub(1)));
    }

    /// Put the selected row in the middle of the view.
    pub fn center(&mut self) {
        self.top = self.selected.saturating_sub(u32::from(self.height) / 2);
        self.clamp_view();
    }

    pub fn set_height(&mut self, height: u16) {
        self.height = height;
        self.clamp_view();
    }

    fn clamp_view(&mut self) {
        let height = u32::from(self.height).max(1);
        if self.selected < self.top {
            self.top = self.selected;
        } else if self.selected >= self.top + height {
            self.top = self.selected + 1 - height;
        }
        let max_top = self.len().saturating_sub(height);
        self.top = self.top.min(max_top);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(start: u32, n: u32) -> Vec<FrameRow> {
        (start..start + n)
            .map(|i| FrameRow {
                cols: vec![(i + 1).to_string(), "x".repeat((i % 7) as usize)],
                num: i + 1,
                bg: None,
                fg: None,
                commented: false,
            })
            .collect()
    }

    fn list(total: u32, height: u16) -> PacketList {
        let mut l = PacketList::default();
        l.reset();
        l.set_height(height);
        l.set_total(total);
        l
    }

    #[test]
    fn requests_each_page_once() {
        let mut l = list(1000, 20);
        assert_eq!(l.pages_needed(), vec![0]);
        assert!(l.pages_needed().is_empty(), "page 0 is already in flight");
        l.insert_page(0, rows(0, PAGE));
        assert!(l.pages_needed().is_empty());
        assert_eq!(l.row(5).unwrap().num, 6);
        // Scrolling near the end of the page pulls in the next one.
        l.select(150);
        assert_eq!(l.pages_needed(), vec![1]);
    }

    #[test]
    fn a_failed_page_is_not_retried_until_refresh() {
        let mut l = list(1000, 20);
        assert_eq!(l.pages_needed(), vec![0]);
        l.page_failed(0, "boom".into());
        assert!(l.pages_needed().is_empty());
        assert_eq!(l.error.as_deref(), Some("boom"));
        l.refresh();
        assert_eq!(l.pages_needed(), vec![0]);
        assert!(l.error.is_none());
    }

    #[test]
    fn cursor_stays_in_view() {
        let mut l = list(1000, 10);
        l.move_by(25);
        assert_eq!((l.selected, l.top), (25, 16));
        l.move_by(-20);
        assert_eq!((l.selected, l.top), (5, 5));
        l.move_by(-100);
        assert_eq!((l.selected, l.top), (0, 0));
        l.move_by(5000);
        assert_eq!((l.selected, l.top), (999, 990));
    }

    #[test]
    fn scrolling_drags_the_cursor_along() {
        let mut l = list(100, 10);
        l.scroll_by(30);
        assert_eq!((l.top, l.selected), (30, 30));
        l.select(35);
        l.scroll_by(-3);
        assert_eq!((l.top, l.selected), (27, 35));
        l.scroll_by(1000);
        assert_eq!(l.top, 90);
    }

    #[test]
    fn refresh_keeps_showing_old_rows_until_new_ones_arrive() {
        let mut l = list(300, 10);
        l.insert_page(0, rows(0, PAGE));
        let generation = l.generation;
        l.refresh();
        assert_eq!(l.generation, generation + 1);
        assert_eq!(l.row(3).unwrap().num, 4, "stale row still shown");
        assert!(l.fresh_row(3).is_none());
        assert_eq!(l.pages_needed(), vec![0], "page is fetched again");
        l.insert_page(0, rows(0, PAGE));
        assert!(l.fresh_row(3).is_some());
    }

    #[test]
    fn shrinking_total_pulls_cursor_back() {
        let mut l = list(100, 10);
        l.select(99);
        l.set_total(40);
        assert_eq!((l.selected, l.top), (39, 30));
        l.set_total(0);
        assert_eq!((l.selected, l.top), (0, 0));
        assert!(l.pages_needed().is_empty());
    }

    #[test]
    fn widths_track_widest_cell() {
        let mut l = list(10, 10);
        l.insert_page(0, rows(0, 10));
        assert_eq!(l.widths, vec![2, 6]);
    }

    #[test]
    fn far_pages_are_evicted() {
        let mut l = list(PAGE * 200, 10);
        for p in 0..100 {
            l.insert_page(p * PAGE, rows(p * PAGE, PAGE));
        }
        assert!(l.row(0).is_some());
        assert!(
            l.row(60 * PAGE).is_none(),
            "pages far from the view are dropped"
        );
    }
}
