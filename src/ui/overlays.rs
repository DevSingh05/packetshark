//! Windows drawn over the panes: help, menus, Follow Stream and statistics.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

use super::{fill, placeholder, popup, put, put_right, title_bar};
use crate::app::follow::Side;
use crate::app::help::SECTIONS;
use crate::app::{App, Overlay};
use crate::util::{human_bytes, sanitize, thousands, truncate, width};

pub fn help(app: &mut App, buf: &mut Buffer, body: Rect) {
    const KEYS: u16 = 30;
    let mut lines: Vec<(String, String, bool)> = Vec::new();
    for section in SECTIONS {
        if !lines.is_empty() {
            lines.push((String::new(), String::new(), false));
        }
        lines.push((section.title.to_string(), String::new(), true));
        for (keys, what) in section.keys {
            lines.push((keys.to_string(), what.to_string(), false));
        }
    }
    let w = body.width.min(96);
    let h = body.height.min(lines.len() as u16 + 2);
    let inner = popup(app, buf, body, w, h, "Keys · j/k to scroll · Esc to close");
    app.areas.overlay = inner;
    let max_top = lines.len().saturating_sub(inner.height as usize);
    let Some(Overlay::Help { top }) = &mut app.overlay else {
        return;
    };
    *top = (*top).min(max_top);
    let top = *top;
    let style = app.theme.popup;
    for (line, (keys, what, heading)) in lines
        .iter()
        .skip(top)
        .take(inner.height as usize)
        .enumerate()
    {
        let y = inner.y + line as u16;
        if *heading {
            put(
                buf,
                inner.x + 1,
                y,
                inner.width - 1,
                keys,
                style.add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            );
        } else {
            put(buf, inner.x + 2, y, KEYS, keys, style.patch(app.theme.bar));
            let room = inner.width.saturating_sub(KEYS + 3);
            put(
                buf,
                inner.x + 2 + KEYS,
                y,
                room,
                &truncate(what, room as usize),
                style,
            );
        }
    }
    if top < max_top {
        put_right(
            buf,
            inner.x,
            inner.y + inner.height - 1,
            inner.width,
            "↓ more ",
            style.patch(app.theme.bar),
        );
    }
}

/// Packets over time, as a bar chart that fills the screen.
pub fn graph(app: &mut App, buf: &mut Buffer, area: Rect) {
    use crate::app::graph::{bar_cell, height_in_eighths};
    fill(buf, area, app.theme.text);
    let (dim, accent, text, error) = (
        app.theme.dim,
        app.theme.bar,
        app.theme.text,
        app.theme.error,
    );
    let cursor_style = app.theme.selected;
    let Some(Overlay::Graph(graph)) = &app.overlay else {
        return;
    };
    let unit = if graph.bytes { "Bytes" } else { "Packets" };
    let title = format!("{unit} over time");
    let right = if graph.filter.is_empty() {
        "all packets".to_string()
    } else {
        format!("all packets, and those matching: {}", graph.filter)
    };
    let content = title_bar(app, buf, area, true, &title, &right);
    let Some(Overlay::Graph(graph)) = &mut app.overlay else {
        return;
    };
    if content.height < 6 || content.width < 20 {
        return;
    }
    let footer = content.y + content.height - 1;
    put(
        buf,
        content.x + 1,
        footer,
        content.width.saturating_sub(2),
        "h l move · Enter filter to this bar · + - finer, coarser · b bytes or packets · Esc close",
        dim,
    );
    let body = Rect {
        y: content.y,
        height: content.height - 1,
        ..content
    };
    if graph.loading {
        placeholder(buf, body, "Counting…", dim);
        return;
    }
    if let Some(e) = &graph.error {
        placeholder(buf, body, e, error);
        return;
    }
    if graph.all.is_empty() {
        placeholder(buf, body, "The capture has no packets to count.", dim);
        return;
    }
    // Layout: a row saying what the cursor is on, the chart with a scale
    // down its left side, and a row of times beneath.
    const SCALE: u16 = 9;
    let chart = Rect {
        x: body.x + SCALE,
        y: body.y + 1,
        width: body.width.saturating_sub(SCALE + 1),
        height: body.height.saturating_sub(3),
    };
    graph.columns = chart.width as usize;
    let bars = graph.bars();
    graph.cursor = graph.cursor.min(bars.len().saturating_sub(1));
    let max = bars.iter().map(|(all, _)| *all).max().unwrap_or(0);
    let amount = |v: u64| {
        if graph.bytes {
            human_bytes(v)
        } else {
            thousands(v)
        }
    };

    // The scale: the tallest bar's value at the top, half of it half-way.
    put_right(buf, body.x, chart.y, SCALE - 1, &amount(max), dim);
    if chart.height >= 4 {
        put_right(
            buf,
            body.x,
            chart.y + chart.height / 2,
            SCALE - 1,
            &amount(max / 2),
            dim,
        );
    }
    put_right(
        buf,
        body.x,
        chart.y + chart.height.saturating_sub(1),
        SCALE - 1,
        "0",
        dim,
    );

    // With room to spare the bars are drawn wider, to use the screen.
    let bar_width = (chart.width / bars.len().max(1) as u16).clamp(1, 4);
    for (i, (all, shown)) in bars.iter().enumerate().take(chart.width as usize) {
        let x = chart.x + i as u16 * bar_width;
        let all_height = height_in_eighths(*all, max, chart.height);
        let shown_height = height_in_eighths(*shown, max, chart.height);
        let filtered = graph.shown.is_some();
        for row in 0..chart.height {
            let y = chart.y + chart.height - 1 - row;
            // Under a filter the whole is drawn faintly, with the packets
            // the filter shows in front of it.
            let (cell, style) = match (bar_cell(shown_height, row), bar_cell(all_height, row)) {
                (Some(c), _) if filtered => (c, accent),
                (_, Some(c)) if filtered => (c, dim),
                (_, Some(c)) => (c, accent),
                _ => continue,
            };
            let style = if i == graph.cursor {
                text.patch(style).patch(cursor_style)
            } else {
                text.patch(style)
            };
            put(
                buf,
                x,
                y,
                bar_width,
                &cell.to_string().repeat(bar_width as usize),
                style,
            );
        }
        if i == graph.cursor {
            // Mark the cursor's column even where the bar is short.
            let base = chart.y + chart.height;
            put(
                buf,
                x,
                base,
                bar_width,
                &"▲".repeat(bar_width as usize),
                accent,
            );
        }
    }

    // Times along the bottom: the start, the middle and the end.
    let axis = chart.y + chart.height;
    let (_, end) = graph.span(bars.len().saturating_sub(1));
    // Times count from the first packet, and are negative for packets
    // stamped earlier than it.
    let seconds = |s: f64| {
        if s < 0.0 {
            format!("-{}", crate::util::human_duration(-s))
        } else {
            crate::util::human_duration(s)
        }
    };
    if graph.cursor != 0 {
        let (start, _) = graph.span(0);
        let label = if start < 0.0 {
            seconds(start)
        } else {
            "0".to_string()
        };
        put(buf, chart.x, axis, chart.width, &label, dim);
    }
    let last = seconds(end);
    let drawn = (bars.len() as u16 * bar_width).min(chart.width);
    if drawn > width(&last) as u16 + 4 {
        put_right(buf, chart.x, axis, drawn, &last, dim);
    }

    // What the cursor is on.
    let (from, to) = graph.span(graph.cursor);
    let (all, shown) = bars[graph.cursor];
    let mut line = format!(
        "{} to {}: {} {}",
        seconds(from),
        seconds(to),
        amount(all),
        if graph.bytes { "" } else { "packets" }
    );
    if graph.shown.is_some() {
        line = format!("{line}, {} matching the filter", amount(shown));
    }
    let per_bar = graph.per_bar() as f64 * graph.interval_ms as f64 / 1000.0;
    put(
        buf,
        body.x + 1,
        body.y,
        body.width.saturating_sub(2),
        line.trim_end(),
        text,
    );
    put_right(
        buf,
        body.x,
        body.y,
        body.width.saturating_sub(1),
        &format!("{} a bar", seconds(per_bar)),
        dim,
    );
}

/// Plain text to read: a window that scrolls.
pub fn text(app: &mut App, buf: &mut Buffer, body: Rect) {
    let Some(Overlay::Text { title, lines, .. }) = &app.overlay else {
        return;
    };
    let longest = lines.iter().map(|l| width(l)).max().unwrap_or(0) as u16;
    let w = (longest + 4)
        .max(width(title) as u16 + 6)
        .max(30)
        .min(body.width);
    let h = (lines.len() as u16 + 2).min(body.height);
    let title = title.clone();
    let inner = popup(app, buf, body, w, h, &title);
    app.areas.overlay = inner;
    let style = app.theme.popup;
    let Some(Overlay::Text { lines, top, .. }) = &mut app.overlay else {
        return;
    };
    *top = (*top).min(lines.len().saturating_sub(inner.height as usize));
    for (row, line) in lines
        .iter()
        .skip(*top)
        .take(inner.height as usize)
        .enumerate()
    {
        put(
            buf,
            inner.x + 1,
            inner.y + row as u16,
            inner.width.saturating_sub(2),
            line,
            style,
        );
    }
    if lines.len() > inner.height as usize {
        let more = format!(
            " {}–{} of {} ",
            *top + 1,
            *top + inner.height as usize,
            lines.len()
        );
        put_right(
            buf,
            inner.x,
            inner.y + inner.height.saturating_sub(1),
            inner.width,
            &more,
            style,
        );
    }
}

/// The column editor: every column, shown or hidden, in order.
pub fn columns(app: &mut App, buf: &mut Buffer, body: Rect) {
    let Some(Overlay::Columns(editor)) = &app.overlay else {
        return;
    };
    let selected = editor.selected;
    let list = app.column_list();
    let hints = "Space show/hide  J/K move  r rename  a add field  b add built-in  d delete  R reset  Esc done";
    let title_width = list
        .iter()
        .map(|c| width(&c.title))
        .max()
        .unwrap_or(0)
        .max(5) as u16;
    let kinds: Vec<String> = list
        .iter()
        .map(|c| crate::app::columns::describe_format(&c.format))
        .collect();
    let kind_width = kinds.iter().map(|k| width(k)).max().unwrap_or(0) as u16;
    let w = (title_width + kind_width + 12)
        .max(width(hints) as u16 + 4)
        .min(body.width);
    let h = (list.len() as u16 + 5).min(body.height);
    let title = if app.columns_customised() {
        "Columns"
    } else {
        "Columns (from the Wireshark profile)"
    };
    let inner = popup(app, buf, body, w, h, title);
    if inner.height < 3 {
        return;
    }
    let theme = &app.theme;
    // Keep the cursor in view when there are more columns than rows.
    let rows = inner.height.saturating_sub(2) as usize;
    let top = selected.saturating_sub(rows.saturating_sub(1));
    for (i, (column, kind)) in list.iter().zip(&kinds).enumerate().skip(top).take(rows) {
        let y = inner.y + (i - top) as u16;
        let style = if i == selected {
            theme.popup_selected
        } else if column.visible {
            theme.popup
        } else {
            theme.popup.patch(theme.dim)
        };
        fill(
            buf,
            Rect {
                y,
                height: 1,
                ..inner
            },
            style,
        );
        let mark = if column.visible { "[x]" } else { "[ ]" };
        put(buf, inner.x + 1, y, 3, mark, style);
        put(buf, inner.x + 5, y, title_width, &column.title, style);
        put(
            buf,
            inner.x + 7 + title_width,
            y,
            inner.width.saturating_sub(8 + title_width),
            kind,
            style,
        );
    }
    let footer = inner.y + inner.height - 1;
    put(
        buf,
        inner.x + 1,
        footer,
        inner.width.saturating_sub(2),
        &truncate(hints, inner.width.saturating_sub(2) as usize),
        theme.popup.patch(theme.dim),
    );
}

pub fn menu(app: &mut App, buf: &mut Buffer, body: Rect) {
    let Some(Overlay::Menu(menu)) = &app.overlay else {
        return;
    };
    let longest = menu
        .items
        .iter()
        .map(|i| width(&i.label))
        .max()
        .unwrap_or(0) as u16;
    let w = (longest + 8)
        .max(width(&menu.title) as u16 + 6)
        .min(body.width);
    let h = menu.items.len() as u16 + 2;
    let title = menu.title.clone();
    let inner = popup(app, buf, body, w, h, &title);
    let Some(Overlay::Menu(menu)) = &app.overlay else {
        return;
    };
    for (i, item) in menu.items.iter().enumerate().take(inner.height as usize) {
        let y = inner.y + i as u16;
        let selected = i == menu.selected;
        let style = if selected {
            app.theme.popup_selected
        } else {
            app.theme.popup
        };
        fill(
            buf,
            Rect {
                y,
                height: 1,
                ..inner
            },
            style,
        );
        let key_style = if selected {
            style
        } else {
            style.patch(app.theme.bar)
        };
        put(
            buf,
            inner.x + 1,
            y,
            1,
            &item.key.to_string(),
            key_style.add_modifier(Modifier::BOLD),
        );
        let room = inner.width.saturating_sub(4);
        put(
            buf,
            inner.x + 4,
            y,
            room,
            &truncate(&item.label, room as usize),
            style,
        );
    }
    app.areas.overlay = inner;
}

pub fn follow(app: &mut App, buf: &mut Buffer, area: Rect) {
    fill(buf, area, app.theme.text);
    let (client_style, server_style, dim) = (app.theme.client, app.theme.server, app.theme.dim);
    let (text_style, error_style) = (app.theme.text, app.theme.error);
    let found_style = app.theme.hex_highlight;
    let Some(Overlay::Follow(view)) = &app.overlay else {
        return;
    };
    let title = format!("Follow {} stream", view.protocol);
    // How the conversation went: packets that carried data, and how many
    // times it changed sides.
    let (client_packets, server_packets, turns) = view.shape();
    let count = |n: usize, what: &str| format!("{n} {what}{}", if n == 1 { "" } else { "s" });
    let right = if view.loading || view.error.is_some() {
        view.filter.clone()
    } else {
        format!(
            "{} · {} · {}",
            view.filter,
            count(client_packets + server_packets, "packet"),
            count(turns, "turn")
        )
    };
    let content = title_bar(app, buf, area, true, &title, &right);
    if content.height < 3 {
        return;
    }
    let legend = Rect {
        height: 1,
        ..content
    };
    let footer = Rect {
        y: content.y + content.height - 1,
        height: 1,
        ..content
    };
    let body = Rect {
        y: content.y + 1,
        height: content.height - 2,
        ..content
    };
    app.areas.overlay = body;
    let Some(Overlay::Follow(view)) = &mut app.overlay else {
        return;
    };
    view.height = body.height;

    // Legend: who is who, and how much each side sent.
    let parts = [
        (
            format!(
                "client {} sent {}",
                view.client,
                human_bytes(view.client_bytes)
            ),
            client_style,
        ),
        (
            format!(
                "server {} sent {}",
                view.server,
                human_bytes(view.server_bytes)
            ),
            server_style,
        ),
    ];
    let side = match view.side {
        Side::Both => "both directions",
        Side::Client => "client only",
        Side::Server => "server only",
    };
    let right = format!("{} · {side}", view.mode.name());
    put_right(
        buf,
        legend.x,
        legend.y,
        legend.width.saturating_sub(1),
        &right,
        dim,
    );
    // The two sides give way to the right-hand text rather than run into it.
    let room = legend.width.saturating_sub(width(&right) as u16 + 3);
    let mut x = legend.x + 1;
    for (text, style) in parts {
        let left = room.saturating_sub(x - legend.x);
        put(
            buf,
            x,
            legend.y,
            left,
            &truncate(&text, left as usize),
            style,
        );
        x += width(&text) as u16 + 3;
    }

    put(
        buf,
        footer.x + 1,
        footer.y,
        footer.width.saturating_sub(1),
        "/ search · n N next, previous · m mode · d direction · f filter to stream · Enter go to packet · w save · y copy · Esc close",
        dim,
    );

    if view.loading {
        placeholder(buf, body, "Reassembling stream…", dim);
        return;
    }
    if let Some(e) = &view.error {
        placeholder(
            buf,
            body,
            &format!("Could not follow the stream: {e}"),
            error_style,
        );
        return;
    }
    let top = {
        let count = view.lines(body.width.saturating_sub(1)).len();
        if count == 0 {
            placeholder(buf, body, "The stream carries no payload.", dim);
            return;
        }
        view.top
    };
    let shown: Vec<(String, bool)> = view
        .lines(body.width.saturating_sub(1))
        .iter()
        .skip(top)
        .take(body.height as usize)
        .map(|entry| (entry.text.clone(), entry.server))
        .collect();
    for (line, (text, server)) in shown.iter().enumerate() {
        let style = if *server { server_style } else { client_style };
        let y = body.y + line as u16;
        put(
            buf,
            body.x + 1,
            y,
            body.width - 1,
            text,
            text_style.patch(style),
        );
        // What the stream search matched, picked out on top of the line.
        for (start, end) in view.matches_in(text) {
            let x = body.x + 1 + width(&text[..start]) as u16;
            if x < body.x + body.width {
                put(
                    buf,
                    x,
                    y,
                    body.x + body.width - x,
                    &text[start..end],
                    found_style,
                );
            }
        }
    }
    let total = view.line_count();
    if total > body.height as usize {
        let last = (top + body.height as usize).min(total);
        let position = format!(" {}–{} of {} ", top + 1, last, total);
        put_right(buf, footer.x, footer.y, footer.width, &position, dim);
    }
}

pub fn stats(app: &mut App, buf: &mut Buffer, area: Rect) {
    fill(buf, area, app.theme.text);
    let theme = app.theme.clone();
    let applied = app.filter.applied.clone();
    let Some(Overlay::Stats(view)) = &app.overlay else {
        return;
    };
    let title = view.title();
    let scope = if view.limit_to_filter && !applied.is_empty() {
        format!("only packets matching: {applied}")
    } else {
        "all packets".to_string()
    };
    let content = title_bar(app, buf, area, true, &title, &scope);
    if content.height < 4 {
        return;
    }
    let Some(Overlay::Stats(view)) = &mut app.overlay else {
        return;
    };

    // Protocol tabs.
    let mut y = content.y;
    if view.kind.has_tabs() {
        let mut x = content.x + 1;
        for (i, tab) in view.tabs.iter().enumerate() {
            let label = format!(" {tab} ");
            let style = if i == view.tab {
                theme.popup_selected
            } else {
                theme.dim
            };
            put(
                buf,
                x,
                y,
                content.width.saturating_sub(x - content.x),
                &label,
                style,
            );
            x += width(&label) as u16 + 1;
        }
        y += 1;
    }
    let footer_y = content.y + content.height - 1;
    let header_y = y;
    let body = Rect {
        y: header_y + 1,
        height: footer_y.saturating_sub(header_y + 1),
        ..content
    };
    view.set_height(body.height);

    let mut hints: Vec<String> = Vec::new();
    if !view.kind.enter_hint().is_empty() {
        hints.push(format!("Enter {}", view.kind.enter_hint()));
    }
    if view.kind.has_tabs() {
        hints.push("Tab protocol".to_string());
    }
    if view.sortable() {
        hints.push("o sort".to_string());
        hints.push("r reverse".to_string());
    }
    hints.push("f limit to filter".to_string());
    hints.push("Esc close".to_string());
    let hints = hints.join(" · ");
    put(
        buf,
        content.x + 1,
        footer_y,
        content.width.saturating_sub(1),
        &hints,
        theme.dim,
    );

    if view.loading {
        placeholder(buf, body, "Computing…", theme.dim);
        return;
    }
    if let Some(e) = &view.error {
        placeholder(buf, body, e, theme.error);
        return;
    }
    if view.rows.is_empty() {
        placeholder(buf, body, "Nothing to show.", theme.dim);
        return;
    }

    // Column widths from the content. If they do not fit, the widest text
    // columns give way first.
    const GAP: u16 = 2;
    let n = view.columns.len();
    let sorted = view.sort.filter(|_| view.sortable()).map(|(c, _)| c);
    let mut widths: Vec<u16> = view
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| width(c.title) as u16 + if sorted == Some(i) { 2 } else { 0 })
        .collect();
    for row in &view.rows {
        for (i, cell) in row.cells.iter().enumerate().take(n) {
            let indent = if i == 0 { row.depth * 2 } else { 0 };
            widths[i] = widths[i].max(width(cell) as u16 + indent);
        }
    }
    for w in &mut widths {
        *w = (*w).min(60);
    }
    let gaps = GAP * n.saturating_sub(1) as u16;
    let mut total: u16 = widths.iter().sum::<u16>() + gaps + 2;
    while total > content.width {
        let shrinkable = (0..n)
            .filter(|i| !view.columns[*i].right && widths[*i] > 8)
            .max_by_key(|i| widths[*i]);
        let Some(i) = shrinkable else { break };
        widths[i] -= 1;
        total -= 1;
    }
    let mut xs = Vec::with_capacity(n);
    let mut x = content.x + 1;
    for w in &widths {
        xs.push(x);
        x += w + GAP;
    }
    let bar_room = (content.x + content.width).saturating_sub(x + 1);

    for (i, col) in view.columns.iter().enumerate() {
        let mut title = col.title.to_string();
        if let Some((sorted, descending)) = view.sort
            && sorted == i
            && view.sortable()
        {
            title.push_str(if descending { " ▼" } else { " ▲" });
        }
        if col.right {
            put_right(buf, xs[i], header_y, widths[i], &title, theme.column_header);
        } else {
            put(buf, xs[i], header_y, widths[i], &title, theme.column_header);
        }
    }

    for line in 0..body.height as usize {
        let index = view.top + line;
        let Some(row) = view.rows.get(index) else {
            break;
        };
        let y = body.y + line as u16;
        let selected = index == view.selected;
        let base = if selected { theme.selected } else { theme.text };
        if selected {
            fill(
                buf,
                Rect {
                    y,
                    height: 1,
                    ..body
                },
                base,
            );
        }
        for (i, cell) in row.cells.iter().enumerate().take(n) {
            let mut style = base;
            if !selected
                && i == 0
                && let Some(sev) = &row.severity
            {
                style = theme.severity(sev);
            }
            let text = sanitize(cell);
            if view.columns[i].right {
                put_right(buf, xs[i], y, widths[i], &text, style);
            } else {
                let indent = if i == 0 {
                    (row.depth * 2).min(widths[i].saturating_sub(4))
                } else {
                    0
                };
                let room = widths[i] - indent;
                put(
                    buf,
                    xs[i] + indent,
                    y,
                    room,
                    &truncate(&text, room as usize),
                    style,
                );
            }
        }
        if let Some(share) = row.bar
            && bar_room >= 10
        {
            let cells = (share.clamp(0.0, 1.0) * f64::from(bar_room.min(30))).round() as usize;
            let style = if selected { base } else { theme.bar };
            put(buf, x, y, bar_room, &"█".repeat(cells), style);
        }
    }
    app.areas.overlay = body;
    let Some(Overlay::Stats(view)) = &app.overlay else {
        return;
    };
    let position = match view.truncated_from {
        Some(all) => format!(
            " {} of {} shown ({} in total) ",
            thousands((view.selected + 1) as u64),
            thousands(view.rows.len() as u64),
            thousands(all as u64)
        ),
        None => format!(" {} of {} ", view.selected + 1, view.rows.len()),
    };
    put_right(
        buf,
        content.x,
        footer_y,
        content.width,
        &position,
        theme.dim,
    );
}
