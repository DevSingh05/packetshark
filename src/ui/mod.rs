//! Drawing. Everything is rendered straight into the frame buffer from the
//! app's state; drawing also records where things ended up so the app can
//! interpret mouse clicks and page movements.

mod bars;
pub mod hex;
mod list;
mod overlays;
mod tree;

use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};

use crate::app::{App, Areas, Focus, LayoutKind, Overlay};
use crate::util::{truncate, width};

/// Draw the whole screen.
pub fn draw(app: &mut App, frame: &mut Frame) {
    let area = frame.area();
    app.areas = Areas::default();
    if area.width < 30 || area.height < 6 {
        let buf = frame.buffer_mut();
        put(
            buf,
            area.x,
            area.y,
            area.width,
            "Terminal too small",
            app.theme.warn,
        );
        return;
    }
    let filter_row = Rect { height: 1, ..area };
    let status_row = Rect {
        y: area.y + area.height - 1,
        height: 1,
        ..area
    };
    let body = Rect {
        y: area.y + 1,
        height: area.height - 2,
        ..area
    };

    let mut cursor = None;
    {
        let buf = frame.buffer_mut();
        if let Some(c) = bars::filter(app, buf, filter_row) {
            cursor = Some(c);
        }
        panes(app, buf, body);
        bars::completions(app, buf, body);
        match &app.overlay {
            None => {}
            Some(Overlay::Help { .. }) => overlays::help(app, buf, body),
            Some(Overlay::Menu(_)) => overlays::menu(app, buf, body),
            Some(Overlay::Columns(_)) => overlays::columns(app, buf, body),
            Some(Overlay::Follow(_)) => overlays::follow(
                app,
                buf,
                Rect {
                    y: area.y,
                    height: area.height - 1,
                    ..area
                },
            ),
            Some(Overlay::Stats(_)) => overlays::stats(
                app,
                buf,
                Rect {
                    y: area.y,
                    height: area.height - 1,
                    ..area
                },
            ),
        }
        if let Some(c) = bars::status(app, buf, status_row) {
            cursor = Some(c);
        }
    }
    paint_base(frame.buffer_mut(), app.theme.text);
    if app.theme.ascii {
        asciify(frame.buffer_mut());
    }
    if let Some((x, y)) = cursor {
        frame.set_cursor_position((x, y));
    }
}

/// Give every cell that was left in the terminal's own colours the theme's
/// text colours instead, so that a theme with a background covers the whole
/// screen however each part was drawn.
fn paint_base(buf: &mut Buffer, text: Style) {
    use ratatui::style::Color;
    if text.fg.is_none() && text.bg.is_none() {
        return;
    }
    for cell in &mut buf.content {
        if let Some(bg) = text.bg
            && cell.bg == Color::Reset
        {
            cell.bg = bg;
        }
        if let Some(fg) = text.fg
            && cell.fg == Color::Reset
        {
            cell.fg = fg;
        }
    }
}

/// Replace everything outside ASCII, for terminals that cannot show it.
fn asciify(buf: &mut Buffer) {
    for cell in &mut buf.content {
        let symbol = cell.symbol();
        if symbol.is_empty() {
            // The second half of a wide character that is now one cell wide.
            cell.set_char(' ');
            continue;
        }
        if symbol.is_ascii() {
            continue;
        }
        let replacement = symbol.chars().next().map_or(' ', crate::theme::ascii_for);
        cell.set_char(replacement);
    }
}

/// Lay out and draw the three panes.
fn panes(app: &mut App, buf: &mut Buffer, body: Rect) {
    let focus = match app.focus {
        Focus::Filter => Focus::List,
        f => f,
    };
    // With very little room, show only the pane being used.
    let zoom = app.zoom || body.height < 9;
    if zoom {
        match focus {
            Focus::Tree => tree::draw(app, buf, body),
            Focus::Hex => hex::draw(app, buf, body),
            _ => list::draw(app, buf, body),
        }
        return;
    }
    let [list_area, tree_area, hex_area] = match app.layout {
        LayoutKind::Stacked => {
            let h = split(body.height, &app.split, 3);
            let list = Rect {
                height: h[0],
                ..body
            };
            let tree = Rect {
                y: body.y + h[0],
                height: h[1],
                ..body
            };
            let hex = Rect {
                y: body.y + h[0] + h[1],
                height: h[2],
                ..body
            };
            [list, tree, hex]
        }
        LayoutKind::Side => {
            let h = split(body.height, &[app.split[0], app.split[1] + app.split[2]], 3);
            let list = Rect {
                height: h[0],
                ..body
            };
            let lower = Rect {
                y: body.y + h[0],
                height: h[1],
                ..body
            };
            // The bytes pane gets exactly what 16 bytes per row need, when
            // that leaves the details pane a useful width.
            let wanted = hex::Geometry::WIDE;
            let hex_width = if lower.width >= wanted + 40 {
                wanted
            } else {
                lower.width / 2
            };
            let tree = Rect {
                width: lower.width - hex_width - 1,
                ..lower
            };
            let hex = Rect {
                x: lower.x + lower.width - hex_width,
                width: hex_width,
                ..lower
            };
            // Divider between the two.
            for y in lower.y..lower.y + lower.height {
                put(buf, tree.x + tree.width, y, 1, "│", app.theme.dim);
            }
            [list, tree, hex]
        }
    };
    list::draw(app, buf, list_area);
    tree::draw(app, buf, tree_area);
    hex::draw(app, buf, hex_area);
}

/// Divide `total` rows by `weights`, giving each part at least `min`.
fn split<const N: usize>(total: u16, weights: &[u16; N], min: u16) -> [u16; N] {
    let sum: u32 = weights.iter().map(|w| u32::from(*w)).sum::<u32>().max(1);
    let mut out = [0u16; N];
    let mut used = 0;
    for i in 0..N {
        let share = (u32::from(total) * u32::from(weights[i]) / sum) as u16;
        out[i] = share.max(min);
        used += out[i];
    }
    // Give rounding leftovers to the first part; take any excess from the largest.
    while used < total {
        out[0] += 1;
        used += 1;
    }
    while used > total {
        let big = (0..N).max_by_key(|i| out[*i]).unwrap();
        if out[big] <= 1 {
            break;
        }
        out[big] -= 1;
        used -= 1;
    }
    out
}

/// Write `text` at `(x, y)`, clipped to `max` cells.
pub(crate) fn put(buf: &mut Buffer, x: u16, y: u16, max: u16, text: &str, style: Style) {
    if max == 0 || y >= buf.area.y + buf.area.height || x >= buf.area.x + buf.area.width {
        return;
    }
    let max = max.min(buf.area.x + buf.area.width - x);
    buf.set_stringn(x, y, text, max as usize, style);
}

/// Write `text` right-aligned within `max` cells starting at `x`.
pub(crate) fn put_right(buf: &mut Buffer, x: u16, y: u16, max: u16, text: &str, style: Style) {
    let text = truncate(text, max as usize);
    let w = width(&text) as u16;
    put(buf, x + max.saturating_sub(w), y, w, &text, style);
}

/// Clear a rectangle to spaces in `style`. Whatever was drawn there before
/// is gone, including its colours and attributes: a window drawn over the
/// panes must not inherit the background of the rows beneath it.
pub(crate) fn fill(buf: &mut Buffer, area: Rect, style: Style) {
    let area = area.intersection(buf.area);
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            let cell = &mut buf[(x, y)];
            cell.reset();
            cell.set_style(style);
        }
    }
}

/// A pane's one-line title bar. Returns the area left for content.
pub(crate) fn title_bar(
    app: &App,
    buf: &mut Buffer,
    area: Rect,
    focused: bool,
    title: &str,
    right: &str,
) -> Rect {
    let (style, rule) = if focused {
        (app.theme.title_focused, app.theme.rule_focused)
    } else {
        (app.theme.title, app.theme.rule)
    };
    // A rule across the row, with the title and the detail set into it.
    let bar = Rect { height: 1, ..area };
    fill(buf, bar, app.theme.text);
    for x in area.x..area.x + area.width {
        put(buf, x, area.y, 1, "─", rule);
    }
    let title_width = (width(title) as u16 + 2).min(area.width.saturating_sub(1));
    put(
        buf,
        area.x + 1,
        area.y,
        title_width,
        &format!(" {title} "),
        style,
    );
    let used = title_width + 1;
    let right_width = width(right) as u16 + 2;
    if !right.is_empty() && area.width > used + right_width + 2 {
        put(
            buf,
            area.x + area.width - right_width - 1,
            area.y,
            right_width,
            &format!(" {right} "),
            style.remove_modifier(Modifier::BOLD),
        );
    }
    Rect {
        y: area.y + 1,
        height: area.height.saturating_sub(1),
        ..area
    }
}

/// A message centred in an otherwise empty pane, wrapped if it is long.
pub(crate) fn placeholder(buf: &mut Buffer, area: Rect, text: &str, style: Style) {
    if area.height == 0 || area.width < 3 {
        return;
    }
    let lines = wrap(text, area.width.saturating_sub(4).max(1) as usize);
    let shown = lines.len().min(area.height as usize);
    let top = area.y + (area.height - shown as u16) / 2;
    for (i, line) in lines.iter().take(shown).enumerate() {
        // The last visible line carries an ellipsis if more was cut off.
        let line = if i + 1 == shown && lines.len() > shown {
            truncate(&format!("{line} …"), area.width.saturating_sub(2) as usize)
        } else {
            line.clone()
        };
        let w = width(&line) as u16;
        let x = area.x + area.width.saturating_sub(w) / 2;
        put(buf, x, top + i as u16, w, &line, style);
    }
}

/// Break `text` into lines of at most `max` cells, at spaces where possible.
pub(crate) fn wrap(text: &str, max: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let mut word = word.to_string();
        // A word longer than a whole line is cut into pieces.
        while width(&word) > max {
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            let mut head = String::new();
            let mut rest = String::new();
            for c in word.chars() {
                if rest.is_empty() && width(&head) + width(c.encode_utf8(&mut [0; 4])) <= max {
                    head.push(c);
                } else {
                    rest.push(c);
                }
            }
            lines.push(head);
            word = rest;
        }
        if !line.is_empty() && width(&line) + 1 + width(&word) > max {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// A centred box with a border and title. Returns the inner area.
pub(crate) fn popup(
    app: &App,
    buf: &mut Buffer,
    within: Rect,
    w: u16,
    h: u16,
    title: &str,
) -> Rect {
    let w = w.min(within.width);
    let h = h.min(within.height);
    let area = Rect {
        x: within.x + (within.width - w) / 2,
        y: within.y + (within.height - h) / 2,
        width: w,
        height: h,
    };
    let style = app.theme.popup;
    fill(buf, area, style);
    if w < 4 || h < 3 {
        return area;
    }
    let (right, bottom) = (area.x + w - 1, area.y + h - 1);
    for x in area.x + 1..right {
        put(buf, x, area.y, 1, "─", style);
        put(buf, x, bottom, 1, "─", style);
    }
    for y in area.y + 1..bottom {
        put(buf, area.x, y, 1, "│", style);
        put(buf, right, y, 1, "│", style);
    }
    put(buf, area.x, area.y, 1, "╭", style);
    put(buf, right, area.y, 1, "╮", style);
    put(buf, area.x, bottom, 1, "╰", style);
    put(buf, right, bottom, 1, "╯", style);
    let title = format!(" {title} ");
    put(
        buf,
        area.x + 2,
        area.y,
        w.saturating_sub(4),
        &title,
        app.theme.popup_selected,
    );
    Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: w - 2,
        height: h - 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_breaks_at_spaces_and_cuts_long_words() {
        assert_eq!(wrap("one two three four", 9), ["one two", "three", "four"]);
        assert_eq!(wrap("short", 20), ["short"]);
        assert_eq!(wrap("", 20), Vec::<String>::new());
        assert_eq!(
            wrap("ab /very/long/path/name x", 6),
            ["ab", "/very/", "long/p", "ath/na", "me x"]
        );
        assert!(wrap("a b c d e f g", 1).iter().all(|l| l.len() == 1));
    }

    #[test]
    fn split_respects_weights_and_total() {
        assert_eq!(split(40, &[40, 35, 25], 3), [16, 14, 10]);
        assert_eq!(split(10, &[40, 35, 25], 3).iter().sum::<u16>(), 10);
        let tiny = split(9, &[80, 10, 10], 3);
        assert_eq!(tiny.iter().sum::<u16>(), 9);
        assert!(tiny.iter().all(|h| *h >= 3), "{tiny:?}");
    }
}
