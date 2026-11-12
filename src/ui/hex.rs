//! The packet bytes pane: offset, hex and ASCII columns.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use super::{placeholder, put, title_bar};
use crate::app::{App, Focus};
use crate::util::printable;

/// Where each part of a hex row sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub offset_width: u16,
    pub per_row: usize,
}

impl Geometry {
    /// Width needed for 16 bytes per row with 4-digit offsets.
    pub const WIDE: u16 = 4 + 2 + 16 * 3 + 1 + 1 + 16 + 1;

    pub fn new(width: u16, len: usize) -> Geometry {
        let offset_width = if len > 0x1_0000 { 8 } else { 4 };
        let needed = |n: u16| offset_width + 2 + n * 3 + u16::from(n == 16) + 1 + n;
        let per_row = if width >= needed(16) {
            16
        } else if width >= needed(8) {
            8
        } else {
            4
        };
        Geometry {
            offset_width,
            per_row,
        }
    }

    /// Column of the first hex digit of byte `i` in a row.
    pub fn hex_x(&self, i: usize) -> u16 {
        let gap = u16::from(self.per_row == 16 && i >= 8);
        self.offset_width + 2 + i as u16 * 3 + gap
    }

    /// Column of the ASCII character of byte `i` in a row.
    pub fn ascii_x(&self, i: usize) -> u16 {
        self.hex_x(self.per_row - 1) + 3 + 1 + i as u16
    }

    /// Which byte of a row is at column `x`, in either the hex or ASCII part.
    pub fn column_at(&self, x: u16) -> Option<usize> {
        let ascii_start = self.ascii_x(0);
        if x >= ascii_start {
            let i = (x - ascii_start) as usize;
            return (i < self.per_row).then_some(i);
        }
        (0..self.per_row).find(|&i| {
            let start = self.hex_x(i);
            x >= start && x < start + 3
        })
    }
}

pub fn draw(app: &mut App, buf: &mut Buffer, area: Rect) {
    let focused = app.focus == Focus::Hex && app.overlay.is_none();
    let sources = app.detail.as_ref().map_or(0, |d| d.sources.len());
    let source = app.hex.source.min(sources.saturating_sub(1));
    app.hex.source = source;
    let right = match &app.detail {
        Some(d) if sources > 1 => {
            format!("{}  [{}/{}]", d.sources[source].name, source + 1, sources)
        }
        Some(d) if sources == 1 => d.sources[0].name.clone(),
        _ => String::new(),
    };
    let title = if focused && sources > 0 {
        format!("Bytes · offset {0} (0x{0:04x})", app.hex.cursor)
    } else {
        "Bytes".to_string()
    };
    let content = title_bar(app, buf, area, focused, &title, &right);
    app.areas.hex = content;
    app.hex.height = content.height;

    let len = app.hex_bytes().len();
    let geometry = Geometry::new(content.width, len);
    app.hex.per_row = geometry.per_row;
    if len == 0 {
        if app.detail.is_some() {
            placeholder(buf, content, "No bytes", app.theme.dim);
        }
        return;
    }
    let rows = len.div_ceil(geometry.per_row);
    app.hex.top = app
        .hex
        .top
        .min(rows.saturating_sub(content.height.max(1) as usize));
    app.hex.cursor = app.hex.cursor.min(len - 1);

    let highlight = app
        .highlight()
        .filter(|(s, _, _)| *s == source)
        .map(|(_, start, n)| (start, start + n));
    let in_highlight = |i: usize| highlight.is_some_and(|(a, b)| i >= a && i < b);
    let bytes = app.hex_bytes();
    let theme = &app.theme;

    for line in 0..content.height as usize {
        let row = app.hex.top + line;
        if row >= rows {
            break;
        }
        let y = content.y + line as u16;
        let start = row * geometry.per_row;
        let offset = format!("{start:0w$x}", w = geometry.offset_width as usize);
        put(
            buf,
            content.x,
            y,
            geometry.offset_width,
            &offset,
            theme.hex_offset,
        );

        for i in 0..geometry.per_row {
            let index = start + i;
            let Some(&byte) = bytes.get(index) else { break };
            let style = if focused && index == app.hex.cursor {
                theme.hex_cursor
            } else if in_highlight(index) {
                theme.hex_highlight
            } else {
                theme.text
            };
            let x = content.x + geometry.hex_x(i);
            put(buf, x, y, 2, &format!("{byte:02x}"), style);
            // Join neighbouring highlighted bytes into one band.
            if in_highlight(index) && in_highlight(index + 1) && i + 1 < geometry.per_row {
                let gap = geometry.hex_x(i + 1) - geometry.hex_x(i) - 2;
                put(buf, x + 2, y, gap, "  ", theme.hex_highlight);
            }
            let mut ch = [0u8; 4];
            let text = printable(byte).encode_utf8(&mut ch);
            put(buf, content.x + geometry.ascii_x(i), y, 1, text, style);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_adapts_to_width() {
        assert_eq!(Geometry::new(80, 100).per_row, 16);
        assert_eq!(Geometry::new(Geometry::WIDE, 100).per_row, 16);
        assert_eq!(Geometry::new(60, 100).per_row, 8);
        assert_eq!(Geometry::new(30, 100).per_row, 4);
        assert_eq!(Geometry::new(200, 100_000).offset_width, 8);
    }

    #[test]
    fn columns_map_back_from_screen_positions() {
        let g = Geometry::new(80, 100);
        assert_eq!(g.hex_x(0), 6);
        assert_eq!(g.hex_x(7), 27);
        assert_eq!(g.hex_x(8), 31, "extra gap after eight bytes");
        for i in 0..16 {
            assert_eq!(g.column_at(g.hex_x(i)), Some(i));
            assert_eq!(g.column_at(g.hex_x(i) + 1), Some(i));
            assert_eq!(g.column_at(g.ascii_x(i)), Some(i));
        }
        assert_eq!(g.column_at(0), None, "offset column");
        assert_eq!(g.column_at(g.ascii_x(15) + 1), None, "past the end");
    }
}
