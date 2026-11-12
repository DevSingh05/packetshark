//! Packets over time: how busy the capture was, moment by moment.

/// One bar's worth of traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bucket {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Default)]
pub struct IoGraph {
    /// Identifies the request this view is waiting for.
    pub request: u64,
    pub loading: bool,
    pub error: Option<String>,
    /// Length of one bucket, in milliseconds.
    pub interval_ms: u64,
    /// Every packet, bucket by bucket from the start of the capture.
    pub all: Vec<Bucket>,
    /// Which bucket `all` starts with, counting from the first packet's
    /// time: zero, unless packets are stamped earlier than the first.
    pub first: i64,
    /// The packets the display filter shows, if one is applied.
    pub shown: Option<Vec<Bucket>>,
    /// The display filter the `shown` series was counted with.
    pub filter: String,
    /// Plot bytes instead of packets.
    pub bytes: bool,
    /// The bar under the cursor, counting drawn bars.
    pub cursor: usize,
    /// How many bars the last draw had room for.
    pub columns: usize,
}

/// Bucket lengths that read well: 1, 2 or 5 times a power of ten.
const STEPS: [u64; 3] = [1, 2, 5];

/// The shortest readable bucket that covers `duration` seconds in at most
/// `bars` buckets.
pub fn interval_for(duration: f64, bars: usize) -> u64 {
    let wanted = (duration.max(0.0) * 1000.0 / bars.max(1) as f64)
        .ceil()
        .max(1.0) as u64;
    let mut scale = 1u64;
    loop {
        for step in STEPS {
            let candidate = step.saturating_mul(scale);
            if candidate >= wanted {
                return candidate;
            }
        }
        scale = scale.saturating_mul(10);
    }
}

/// The next shorter (`finer`) or longer bucket length in the same series.
pub fn step_interval(interval_ms: u64, finer: bool) -> u64 {
    let mut ladder: Vec<u64> = Vec::new();
    let mut scale = 1u64;
    while scale <= 10_000_000_000 {
        ladder.extend(STEPS.iter().map(|s| s * scale));
        scale *= 10;
    }
    let at = ladder.iter().position(|v| *v >= interval_ms).unwrap_or(0);
    let next = if finer {
        at.saturating_sub(1)
    } else {
        (at + 1).min(ladder.len() - 1)
    };
    ladder[next]
}

/// The first and last bucket that `intervals` reach. The first is before
/// zero when a capture holds packets stamped earlier than its first one.
pub fn reach(intervals: &[(i64, u64, u64)], last: i64) -> (i64, i64) {
    let indexes = || intervals.iter().map(|(index, _, _)| *index);
    let first = indexes().min().unwrap_or(0).min(0);
    let last = indexes().max().unwrap_or(0).max(last).max(0);
    (first, last)
}

/// Lay sharkd's sparse list of `(index, packets, bytes)` out as one bucket
/// per interval, from `first` to `last`.
pub fn fill(intervals: &[(i64, u64, u64)], first: i64, last: i64) -> Vec<Bucket> {
    // A reply naming an absurd last bucket must not allocate the earth.
    let len = last
        .saturating_sub(first)
        .saturating_add(1)
        .clamp(1, 1_000_000) as usize;
    let mut buckets = vec![Bucket::default(); len];
    for (index, packets, bytes) in intervals {
        let at = usize::try_from(index.saturating_sub(first)).ok();
        if let Some(bucket) = at.and_then(|at| buckets.get_mut(at)) {
            bucket.packets += packets;
            bucket.bytes += bytes;
        }
    }
    buckets
}

impl IoGraph {
    /// How many buckets share one drawn bar, for the room there is.
    pub fn per_bar(&self) -> usize {
        self.all.len().div_ceil(self.columns.max(1)).max(1)
    }

    /// The value of each drawn bar: `(all, shown)`.
    pub fn bars(&self) -> Vec<(u64, u64)> {
        let per_bar = self.per_bar();
        let value = |b: &Bucket| if self.bytes { b.bytes } else { b.packets };
        let sum = |series: &[Bucket], bar: usize| -> u64 {
            series
                .iter()
                .skip(bar * per_bar)
                .take(per_bar)
                .map(value)
                .sum()
        };
        (0..self.all.len().div_ceil(per_bar))
            .map(|bar| {
                let all = sum(&self.all, bar);
                let shown = self.shown.as_ref().map_or(all, |s| sum(s, bar));
                (all, shown)
            })
            .collect()
    }

    /// The seconds a drawn bar covers: from, and up to but not including.
    pub fn span(&self, bar: usize) -> (f64, f64) {
        let per_bar = self.per_bar() as f64;
        let seconds = self.interval_ms as f64 / 1000.0;
        let start = self.first as f64 * seconds;
        (
            start + bar as f64 * per_bar * seconds,
            start + (bar as f64 + 1.0) * per_bar * seconds,
        )
    }

    /// A display filter for the packets of the bar under the cursor.
    pub fn filter_at_cursor(&self) -> String {
        let (from, to) = self.span(self.cursor);
        format!("frame.time_relative >= {from:.6} && frame.time_relative < {to:.6}")
    }

    pub fn move_cursor(&mut self, by: i64) {
        let bars = self.all.len().div_ceil(self.per_bar()).max(1);
        self.cursor = (self.cursor as i64 + by).clamp(0, bars as i64 - 1) as usize;
    }
}

/// How tall a bar is, in eighths of a row, for a chart `rows` rows high
/// whose tallest bar is `max`. Anything above zero shows at least a sliver.
pub fn height_in_eighths(value: u64, max: u64, rows: u16) -> u32 {
    if value == 0 || max == 0 {
        return 0;
    }
    let full = u64::from(rows) * 8;
    let (value, max, full) = (u128::from(value), u128::from(max), u128::from(full));
    (value * full / max).clamp(1, full) as u32
}

/// The character for one cell of a bar `eighths` tall, `row` rows up from
/// the bottom.
pub fn bar_cell(eighths: u32, row: u16) -> Option<char> {
    const PARTIAL: [char; 7] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇'];
    let below = u32::from(row) * 8;
    match eighths.saturating_sub(below) {
        0 => None,
        n if n >= 8 => Some('█'),
        n => Some(PARTIAL[n as usize - 1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_lengths_are_round_and_fit() {
        assert_eq!(
            interval_for(57.1, 240),
            500,
            "57 s in 240 bars: half a second each"
        );
        assert_eq!(interval_for(57.1, 60), 1000);
        assert_eq!(interval_for(0.191, 100), 2);
        assert_eq!(interval_for(0.0, 100), 1);
        assert_eq!(interval_for(86_400.0, 120), 1_000_000);
        // The series: 1, 2, 5, 10, 20, 50, ...
        assert_eq!(step_interval(500, true), 200);
        assert_eq!(step_interval(500, false), 1000);
        assert_eq!(
            step_interval(1, true),
            1,
            "nothing finer than a millisecond"
        );
        assert_eq!(step_interval(1000, false), 2000);
    }

    #[test]
    fn sparse_intervals_become_a_bucket_each() {
        let buckets = fill(&[(0, 2, 168), (2, 3, 244)], 0, 3);
        assert_eq!(buckets.len(), 4);
        assert_eq!(
            buckets[0],
            Bucket {
                packets: 2,
                bytes: 168
            }
        );
        assert_eq!(buckets[1], Bucket::default());
        assert_eq!(buckets[2].packets, 3);
        assert_eq!(buckets[3], Bucket::default());
        assert_eq!(
            fill(&[(9, 1, 1)], 0, 2).len(),
            3,
            "an index past the end is dropped"
        );
        // Packets stamped before the first one have negative indexes, and
        // indexes come in any order; the chart then starts before zero.
        let jumbled = [(0, 12, 100), (3, 1, 10), (-2, 7, 70), (3, 2, 20)];
        assert_eq!(reach(&jumbled, 3), (-2, 3));
        let buckets = fill(&jumbled, -2, 3);
        assert_eq!(buckets.len(), 6);
        assert_eq!(buckets[0].packets, 7);
        assert_eq!(buckets[2].packets, 12);
        assert_eq!(
            buckets[5],
            Bucket {
                packets: 3,
                bytes: 30
            }
        );
        assert_eq!(reach(&[], 0), (0, 0));
        let early = IoGraph {
            interval_ms: 1000,
            all: buckets,
            first: -2,
            columns: 80,
            ..Default::default()
        };
        assert_eq!(early.span(0), (-2.0, -1.0));
    }

    #[test]
    fn bars_merge_buckets_to_fit_and_know_their_time() {
        let bucket = |packets| Bucket {
            packets,
            bytes: packets * 100,
        };
        let mut graph = IoGraph {
            interval_ms: 500,
            all: (1..=10).map(bucket).collect(),
            shown: Some((1..=10).map(|n| bucket(n / 2)).collect()),
            columns: 5,
            ..Default::default()
        };
        assert_eq!(graph.per_bar(), 2);
        assert_eq!(
            graph.bars(),
            [(3, 1), (7, 3), (11, 5), (15, 7), (19, 9)],
            "two buckets a bar: all packets, and those the filter shows"
        );
        assert_eq!(graph.span(1), (1.0, 2.0));
        graph.cursor = 4;
        assert_eq!(
            graph.filter_at_cursor(),
            "frame.time_relative >= 4.000000 && frame.time_relative < 5.000000"
        );
        graph.move_cursor(10);
        assert_eq!(graph.cursor, 4, "the cursor stops at the last bar");
        graph.move_cursor(-10);
        assert_eq!(graph.cursor, 0);
        // Room to spare: a bar a bucket.
        graph.columns = 80;
        assert_eq!(graph.bars().len(), 10);
        graph.bytes = true;
        assert_eq!(graph.bars()[0], (100, 0));
        // No filter: both series are the same.
        graph.shown = None;
        assert_eq!(graph.bars()[9], (1000, 1000));
    }

    #[test]
    fn bars_are_drawn_in_eighths_of_a_row() {
        assert_eq!(height_in_eighths(0, 100, 10), 0);
        assert_eq!(height_in_eighths(100, 100, 10), 80);
        assert_eq!(height_in_eighths(50, 100, 10), 40);
        assert_eq!(height_in_eighths(1, 1_000_000, 10), 1, "never invisible");
        assert_eq!(height_in_eighths(5, 0, 10), 0);
        // 20 eighths: two full rows and half of the third.
        assert_eq!(bar_cell(20, 0), Some('█'));
        assert_eq!(bar_cell(20, 1), Some('█'));
        assert_eq!(bar_cell(20, 2), Some('▄'));
        assert_eq!(bar_cell(20, 3), None);
        assert_eq!(bar_cell(1, 0), Some('▁'));
    }
}
