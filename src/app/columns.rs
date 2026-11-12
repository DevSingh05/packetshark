//! The packet list's columns, taken from the user's Wireshark profile.

use crate::sharkd::types::{Info, Status};

/// How the time column is displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeFormat {
    /// Whatever the Wireshark profile says (usually seconds since the first packet).
    #[default]
    Profile,
    Relative,
    Delta,
    DeltaDisplayed,
    Absolute,
    AbsoluteDate,
    Utc,
    UtcDate,
}

impl TimeFormat {
    pub const ALL: [TimeFormat; 8] = [
        TimeFormat::Profile,
        TimeFormat::Relative,
        TimeFormat::Delta,
        TimeFormat::DeltaDisplayed,
        TimeFormat::Absolute,
        TimeFormat::AbsoluteDate,
        TimeFormat::Utc,
        TimeFormat::UtcDate,
    ];

    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    /// Wireshark's column format code.
    fn code(self) -> &'static str {
        match self {
            TimeFormat::Profile => "%t",
            TimeFormat::Relative => "%Rt",
            TimeFormat::Delta => "%Tt",
            TimeFormat::DeltaDisplayed => "%Gt",
            TimeFormat::Absolute => "%At",
            TimeFormat::AbsoluteDate => "%Yt",
            TimeFormat::Utc => "%Aut",
            TimeFormat::UtcDate => "%Yut",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            TimeFormat::Profile => "profile default",
            TimeFormat::Relative => "seconds since first packet",
            TimeFormat::Delta => "seconds since previous packet",
            TimeFormat::DeltaDisplayed => "seconds since previous displayed packet",
            TimeFormat::Absolute => "time of day",
            TimeFormat::AbsoluteDate => "date and time",
            TimeFormat::Utc => "UTC time of day",
            TimeFormat::UtcDate => "UTC date and time",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "default" | "profile" => TimeFormat::Profile,
            "relative" | "rel" => TimeFormat::Relative,
            "delta" => TimeFormat::Delta,
            "delta-displayed" | "deltadis" => TimeFormat::DeltaDisplayed,
            "absolute" | "abs" => TimeFormat::Absolute,
            "date" | "absolute-date" => TimeFormat::AbsoluteDate,
            "utc" => TimeFormat::Utc,
            "utc-date" => TimeFormat::UtcDate,
            _ => return None,
        })
    }
}

const TIME_CODES: [&str; 8] = ["%t", "%Rt", "%Tt", "%Gt", "%At", "%Yt", "%Aut", "%Yut"];

#[derive(Debug, Clone)]
pub struct Column {
    pub title: String,
    /// Wireshark format code (`%m`, `%s`, ... or `%Cus` for a custom column).
    pub format: String,
    /// For a custom column, the `<fields>:<occurrence>` sharkd expects.
    custom: Option<String>,
    pub align_right: bool,
    /// Takes whatever width is left over.
    pub flexible: bool,
    pub min_width: u16,
    pub max_width: u16,
}

impl Column {
    pub fn is_time(&self) -> bool {
        TIME_CODES.contains(&self.format.as_str()) || self.format.ends_with('t')
    }

    fn describe(title: &str, format: &str) -> Column {
        let (code, custom) = match format.strip_prefix("%Cus:") {
            Some(rest) => ("%Cus", Some(rest.to_string())),
            None => (format, None),
        };
        let numeric = matches!(
            code,
            "%m" | "%md" | "%L" | "%B" | "%S" | "%D" | "%uS" | "%uD"
        );
        let flexible = code == "%i";
        let title_width = crate::util::width(title) as u16;
        let (min_width, max_width) = match code {
            "%m" | "%md" => (4, 10),
            "%L" | "%B" => (5, 10),
            "%p" => (8, 14),
            "%i" => (10, u16::MAX),
            c if TIME_CODES.contains(&c) => (9, 30),
            _ => (6, 40),
        };
        Column {
            title: title.to_string(),
            format: code.to_string(),
            custom,
            align_right: numeric,
            flexible,
            min_width: min_width.max(title_width),
            max_width,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Columns {
    pub cols: Vec<Column>,
    /// Format code to the number `frames` expects, from sharkd's `info`.
    numbers: Vec<(String, usize)>,
}

impl Columns {
    pub fn new(status: &Status, info: Option<&Info>) -> Columns {
        let mut cols: Vec<Column> = status
            .column_info
            .iter()
            .filter(|c| c.visible)
            .map(|c| Column::describe(&c.title, &c.format))
            .collect();
        if cols.is_empty() {
            // Older sharkd: titles only. Guess the usual formats from the titles.
            cols = status
                .columns
                .iter()
                .map(|title| {
                    let format = match title.as_str() {
                        "No." => "%m",
                        "Time" => "%t",
                        "Source" => "%s",
                        "Destination" => "%d",
                        "Protocol" => "%p",
                        "Length" => "%L",
                        "Info" => "%i",
                        _ => "%?",
                    };
                    Column::describe(title, format)
                })
                .collect();
        }
        if !cols.iter().any(|c| c.flexible)
            && let Some(last) = cols.last_mut()
        {
            last.flexible = true;
            last.max_width = u16::MAX;
        }
        let numbers = info
            .map(|i| {
                i.columns
                    .iter()
                    .enumerate()
                    .map(|(n, c)| (c.format.clone(), n))
                    .collect()
            })
            .unwrap_or_default();
        Columns { cols, numbers }
    }

    fn number(&self, code: &str) -> Option<usize> {
        self.numbers
            .iter()
            .find(|(c, _)| c == code)
            .map(|(_, n)| *n)
    }

    /// The `columnN` values to send with a `frames` request. Empty means "let
    /// sharkd use the profile's columns", which is the fallback when any
    /// column cannot be expressed.
    pub fn specs(&self, time: TimeFormat) -> Vec<String> {
        let mut out = Vec::with_capacity(self.cols.len());
        for col in &self.cols {
            let spec = if let Some(custom) = &col.custom {
                Some(custom.clone())
            } else {
                let code = if time != TimeFormat::Profile && col.is_time() {
                    time.code()
                } else {
                    col.format.as_str()
                };
                self.number(code).map(|n| n.to_string())
            };
            match spec {
                Some(s) => out.push(s),
                None => return Vec::new(),
            }
        }
        out
    }

    /// Whether the time format can be changed (sharkd told us its column numbers).
    pub fn can_change_time(&self) -> bool {
        !self.numbers.is_empty() && self.cols.iter().any(Column::is_time)
    }

    /// Assign each column an x offset and width within `total` cells, given
    /// the widest content seen so far per column.
    pub fn layout(&self, content: &[u16], total: u16) -> Vec<(u16, u16)> {
        const GAP: u16 = 1;
        let n = self.cols.len();
        if n == 0 {
            return Vec::new();
        }
        let mut widths: Vec<u16> = self
            .cols
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let seen = content.get(i).copied().unwrap_or(0);
                seen.max(c.min_width).min(c.max_width)
            })
            .collect();
        let gaps = GAP * (n as u16 - 1);
        let flexible = self.cols.iter().position(|c| c.flexible).unwrap_or(n - 1);
        let fixed: u16 = widths
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != flexible)
            .map(|(_, w)| *w)
            .sum();
        let available = total.saturating_sub(gaps);
        if fixed + self.cols[flexible].min_width > available {
            // Too narrow: shrink the fixed columns evenly, widest first.
            let mut excess = (fixed + self.cols[flexible].min_width) - available;
            while excess > 0 {
                let Some((widest, _)) = widths
                    .iter()
                    .enumerate()
                    .filter(|(i, w)| *i != flexible && **w > 3)
                    .max_by_key(|(_, w)| **w)
                else {
                    break;
                };
                widths[widest] -= 1;
                excess -= 1;
            }
        }
        let fixed: u16 = widths
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != flexible)
            .map(|(_, w)| *w)
            .sum();
        widths[flexible] = available.saturating_sub(fixed);
        let mut x = 0;
        widths
            .into_iter()
            .map(|w| {
                let cell = (x, w);
                x += w + GAP;
                cell
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharkd::types::{ColumnFormat, ColumnInfo};

    fn status() -> Status {
        let col = |title: &str, format: &str| ColumnInfo {
            title: title.into(),
            format: format.into(),
            visible: true,
        };
        Status {
            column_info: vec![
                col("No.", "%m"),
                col("Time", "%t"),
                col("Source", "%s"),
                col("Stream", "%Cus:tcp.stream:0"),
                col("Info", "%i"),
            ],
            ..Default::default()
        }
    }

    fn info() -> Info {
        let codes = ["%At", "%Cus", "%i", "%m", "%s", "%t", "%Yt"];
        Info {
            columns: codes
                .iter()
                .map(|c| ColumnFormat {
                    name: String::new(),
                    format: c.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn specs_use_sharkd_numbers_and_custom_fields() {
        let c = Columns::new(&status(), Some(&info()));
        assert_eq!(
            c.specs(TimeFormat::Profile),
            ["3", "5", "4", "tcp.stream:0", "2"]
        );
        assert_eq!(
            c.specs(TimeFormat::Absolute),
            ["3", "0", "4", "tcp.stream:0", "2"]
        );
        assert!(c.can_change_time());
    }

    #[test]
    fn specs_fall_back_to_profile_columns_without_info() {
        let c = Columns::new(&status(), None);
        assert!(c.specs(TimeFormat::Profile).is_empty());
        assert!(!c.can_change_time());
    }

    #[test]
    fn hidden_columns_are_skipped() {
        let mut s = status();
        s.column_info[2].visible = false;
        let c = Columns::new(&s, Some(&info()));
        assert_eq!(c.cols.len(), 4);
    }

    #[test]
    fn layout_gives_leftover_space_to_info() {
        let c = Columns::new(&status(), Some(&info()));
        let cells = c.layout(&[3, 9, 15, 2, 80], 80);
        assert_eq!(cells[0], (0, 4));
        assert_eq!(cells[1], (5, 9));
        assert_eq!(cells[2], (15, 15));
        assert_eq!(cells[3], (31, 6));
        // Info starts after the last gap and runs to the right edge.
        assert_eq!(cells[4], (38, 42));
    }

    #[test]
    fn layout_shrinks_fixed_columns_when_narrow() {
        let c = Columns::new(&status(), Some(&info()));
        let cells = c.layout(&[3, 9, 40, 2, 80], 40);
        let end = cells.last().map(|(x, w)| x + w).unwrap();
        assert!(end <= 40, "columns overflow: {cells:?}");
        assert!(cells[4].1 >= 10, "info column too small: {cells:?}");
    }
}
