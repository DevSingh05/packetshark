//! The packet details pane: the protocol dissection tree.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use super::{fill, placeholder, put, title_bar};
use crate::app::{App, Focus};
use crate::util::{sanitize, truncate};

pub fn draw(app: &mut App, buf: &mut Buffer, area: Rect) {
    let focused = app.focus == Focus::Tree && app.overlay.is_none();
    let right = match &app.detail {
        Some(d) => format!("packet {}", d.num),
        None => String::new(),
    };
    let content = title_bar(app, buf, area, focused, "Details", &right);
    app.areas.tree = content;
    app.tree.set_height(content.height);
    let Some(detail) = &app.detail else {
        if !app.list.is_empty() {
            placeholder(buf, content, "Loading packet…", app.theme.dim);
        }
        return;
    };

    for line in 0..content.height as usize {
        let index = app.tree.top + line;
        let Some(entry) = app.tree.lines.get(index) else {
            break;
        };
        let Some(node) = detail.node(&entry.path) else {
            continue;
        };
        let y = content.y + line as u16;
        let selected = index == app.tree.selected;

        let mut style = if entry.depth == 0 {
            app.theme.proto
        } else if let Some(sev) = node.severity.as_deref() {
            app.theme.severity(sev)
        } else if node
            .kind
            .as_deref()
            .is_some_and(|k| k == "framenum" || k == "url")
        {
            app.theme.link
        } else {
            app.theme.text
        };
        if selected {
            style = if focused {
                app.theme.selected
            } else {
                style.patch(app.theme.selected_unfocused)
            };
            fill(
                buf,
                Rect {
                    y,
                    height: 1,
                    ..content
                },
                style,
            );
        }

        let indent = entry.depth * 2;
        let marker = match (entry.expandable, entry.expanded) {
            (true, true) => "▾ ",
            (true, false) => "▸ ",
            (false, _) => "  ",
        };
        let x = content.x + indent.min(content.width.saturating_sub(4));
        put(buf, x, y, 2, marker, style);
        let room = content.width.saturating_sub(x - content.x + 2);
        put(
            buf,
            x + 2,
            y,
            room,
            &truncate(&sanitize(&node.label), room as usize),
            style,
        );
    }
}
