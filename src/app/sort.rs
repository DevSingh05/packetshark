//! Sorting the packet list by a column.
//!
//! sharkd lists packets in capture order only. To sort, the worker reads
//! the one column for every displayed packet and works out the order; the
//! list then asks for its rows by their place in that order.

use std::sync::Arc;

use super::{Action, App, MenuItem};
use crate::sharkd::{Request, Seek, Sorted};

/// Most packets a list may hold and still be sorted: the order is worked
/// out from every packet's value, held in memory.
pub const SORT_LIMIT: u32 = 300_000;

#[derive(Debug)]
pub struct Sort {
    /// Title of the column sorted by.
    pub title: String,
    pub descending: bool,
    /// The order, once worked out, and the list generation it belongs to.
    order: Option<Arc<Sorted>>,
    generation: u64,
    /// The packet to put the cursor on when the order arrives.
    keep: Option<u32>,
}

impl App {
    /// The column the list is sorted by, and whether downwards.
    pub fn sorted_by(&self) -> Option<(&str, bool)> {
        self.sort.as_ref().map(|s| (s.title.as_str(), s.descending))
    }

    /// The order in force for the rows now wanted, if there is one.
    pub(super) fn sort_order(&self) -> Option<Arc<Sorted>> {
        let sort = self.sort.as_ref()?;
        sort.order
            .clone()
            .filter(|_| sort.generation == self.list.generation)
    }

    /// `:sort`: by a column's title or number, optionally `desc` or `asc`;
    /// `off` goes back to capture order; nothing lists the columns.
    pub(super) fn sort_command(&mut self, arg: &str) {
        let arg = arg.trim();
        if arg.is_empty() {
            return self.sort_menu();
        }
        if matches!(
            arg.to_ascii_lowercase().as_str(),
            "off" | "none" | "clear" | "no"
        ) {
            return self.clear_sort();
        }
        let (name, direction) = match arg.rsplit_once(char::is_whitespace) {
            Some((name, word)) => match word.to_ascii_lowercase().as_str() {
                "desc" | "descending" | "down" | "reverse" => (name.trim(), Some(true)),
                "asc" | "ascending" | "up" => (name.trim(), Some(false)),
                _ => (arg, None),
            },
            None => (arg, None),
        };
        let column = self
            .columns
            .cols
            .iter()
            .find(|c| c.title.eq_ignore_ascii_case(name))
            .or_else(|| {
                let n: usize = name.parse().ok()?;
                self.columns.cols.get(n.checked_sub(1)?)
            });
        let Some(column) = column else {
            let titles: Vec<&str> = self.columns.cols.iter().map(|c| c.title.as_str()).collect();
            return self.error(format!(
                "There is no column called {name}. The columns are: {}.",
                titles.join(", ")
            ));
        };
        let title = column.title.clone();
        self.sort_by(&title, direction);
    }

    /// Sort by the column titled `title`. With no direction given, a column
    /// already sorted by turns the other way.
    pub(super) fn sort_by(&mut self, title: &str, direction: Option<bool>) {
        if self.capturing() {
            return self
                .error("The list can be sorted once the capture has stopped (Ctrl-c stops it).");
        }
        if self.list.len() > SORT_LIMIT {
            return self.error(too_many());
        }
        let descending = direction.unwrap_or_else(|| {
            self.sort
                .as_ref()
                .is_some_and(|s| s.title == title && !s.descending)
        });
        let keep = self.list.selected_num();
        self.sort = Some(Sort {
            title: title.to_string(),
            descending,
            order: None,
            generation: 0,
            keep,
        });
        self.refresh_list();
        self.info(format!(
            "Sorted by {title}, {}. :sort off for capture order.",
            if descending {
                "descending"
            } else {
                "ascending"
            }
        ));
    }

    /// Back to the order the packets were captured in.
    pub(super) fn clear_sort(&mut self) {
        if self.sort.take().is_none() {
            return self.info("The list is in capture order.");
        }
        let keep = self.list.selected_num();
        self.refresh_list();
        if let Some(num) = keep {
            self.goto_exact = None;
            self.locate(num, Seek::Nearest, crate::sharkd::Purpose::Select);
        }
        self.info("Back in capture order.");
    }

    fn sort_menu(&mut self) {
        let keys = "abcdefghijklmnopqrstuvwxyz0123456789";
        let current = self.sorted_by().map(|(t, d)| (t.to_string(), d));
        let mut items: Vec<MenuItem> = self
            .columns
            .cols
            .iter()
            .zip(keys.chars())
            .map(|(column, key)| MenuItem {
                key,
                label: match &current {
                    Some((title, descending)) if *title == column.title => format!(
                        "{}  (sorted, {}; again to reverse)",
                        column.title,
                        if *descending {
                            "descending"
                        } else {
                            "ascending"
                        }
                    ),
                    _ => column.title.clone(),
                },
                action: Action::Command(format!("sort {}", column.title)),
            })
            .collect();
        items.push(MenuItem {
            key: '-',
            label: "Capture order (no sorting)".into(),
            action: Action::Command("sort off".into()),
        });
        self.open_menu("Sort the packets by", items);
    }

    /// Ask for the order afresh: the packets listed have changed, or the
    /// rows have to be fetched again.
    pub(super) fn request_sort(&mut self) {
        let Some(sort) = &self.sort else { return };
        let spec = self
            .columns
            .cols
            .iter()
            .position(|c| c.title == sort.title)
            .and_then(|i| self.columns.specs(self.time_format).into_iter().nth(i));
        let Some(spec) = spec else {
            // The column sorted by has been taken away.
            self.sort = None;
            return;
        };
        if self.list.len() > SORT_LIMIT {
            self.sort = None;
            return self.error(format!("{} Back in capture order.", too_many()));
        }
        let selected = self.list.selected_num();
        let generation = self.list.generation;
        let filter = self.filter.applied.clone();
        let Some(sort) = &mut self.sort else { return };
        sort.order = None;
        sort.keep = sort.keep.or(selected);
        let descending = sort.descending;
        self.send(Request::Sort {
            generation,
            filter,
            column: spec,
            descending,
        });
    }

    /// The rows are being fetched again but are the same packets: an order
    /// already worked out still holds.
    pub(super) fn carry_sort(&mut self, from: u64) {
        let now = self.list.generation;
        let Some(sort) = &mut self.sort else { return };
        if sort.order.is_some() && sort.generation == from {
            sort.generation = now;
        } else if self.list.total.is_some() {
            self.request_sort();
        }
    }

    pub(super) fn on_sorted(&mut self, generation: u64, result: Result<Sorted, String>) {
        if generation != self.list.generation || self.sort.is_none() {
            return;
        }
        let order = match result {
            Ok(order) => order,
            Err(e) => {
                self.sort = None;
                self.refresh_list();
                return self.error(format!("Could not sort: {e}"));
            }
        };
        let total = order.nums.len() as u32;
        let keep = self.sort.as_mut().and_then(|sort| {
            sort.order = Some(Arc::new(order));
            sort.generation = generation;
            sort.keep.take()
        });
        self.list.set_total(total);
        match keep {
            Some(num) => self.select_sorted(num),
            None => self.list.select(0),
        }
    }

    /// Put the cursor on packet `num` in a sorted list, or on the nearest
    /// packet listed if that one is not.
    pub(super) fn select_sorted(&mut self, num: u32) {
        let Some(order) = self.sort_order() else {
            // The order is on its way; go there when it arrives.
            if let Some(sort) = &mut self.sort {
                sort.keep = Some(num);
            }
            return;
        };
        let nums = &order.nums;
        let at = nums.iter().position(|n| *n == num).or_else(|| {
            // The first packet after it, or failing that the last before.
            let after = (0..nums.len())
                .filter(|i| nums[*i] > num)
                .min_by_key(|i| nums[*i]);
            after.or_else(|| (0..nums.len()).max_by_key(|i| nums[*i]))
        });
        self.on_located(Ok(at.map(|i| (i as u32, nums[i]))));
    }
}

fn too_many() -> String {
    format!(
        "Sorting works on up to {} packets; narrow the list with a filter first.",
        crate::util::thousands(u64::from(SORT_LIMIT))
    )
}
