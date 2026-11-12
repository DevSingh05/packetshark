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
    let Some(Overlay::Follow(view)) = &app.overlay else {
        return;
    };
    let title = format!("Follow {} stream", view.protocol);
    let right = view.filter.clone();
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
    let mut x = legend.x + 1;
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
    for (text, style) in parts {
        put(
            buf,
            x,
            legend.y,
            legend.width.saturating_sub(x - legend.x),
            &text,
            style,
        );
        x += width(&text) as u16 + 3;
    }
    let side = match view.side {
        Side::Both => "both directions",
        Side::Client => "client only",
        Side::Server => "server only",
    };
    put_right(
        buf,
        legend.x,
        legend.y,
        legend.width.saturating_sub(1),
        &format!("{} · {side}", view.mode.name()),
        dim,
    );

    put(
        buf,
        footer.x + 1,
        footer.y,
        footer.width.saturating_sub(1),
        "m mode · d direction · f filter to stream · Enter go to packet · w save · y copy · Esc close",
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
    let lines = view.lines(body.width.saturating_sub(1));
    for (line, entry) in lines
        .iter()
        .skip(top)
        .take(body.height as usize)
        .enumerate()
    {
        let style = if entry.server {
            server_style
        } else {
            client_style
        };
        put(
            buf,
            body.x + 1,
            body.y + line as u16,
            body.width - 1,
            &entry.text,
            text_style.patch(style),
        );
    }
    let total = lines.len();
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
