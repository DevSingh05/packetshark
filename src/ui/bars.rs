//! The filter bar on top, its completion popup, and the status bar below.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

use super::{fill, put, put_right};
use crate::app::filter::Validity;
use crate::app::{App, Focus, Level, LoadState};
use crate::util::{human_bytes, human_duration, thousands, truncate, width};

const FILTER_LABEL: &str = " Filter: ";

/// Draw the filter bar. Returns the cursor position when it has focus.
pub fn filter(app: &mut App, buf: &mut Buffer, area: Rect) -> Option<(u16, u16)> {
    app.areas.filter = area;
    let focused = app.focus == Focus::Filter && app.overlay.is_none() && app.prompt.is_none();
    let label_style = if focused {
        app.theme.title_focused
    } else {
        app.theme.title
    };
    fill(buf, area, app.theme.text);
    put(buf, area.x, area.y, area.width, FILTER_LABEL, label_style);
    let x = area.x + width(FILTER_LABEL) as u16 + 1;
    let room = area.width.saturating_sub(x - area.x + 1);

    let style = match &app.filter.validity {
        Validity::Valid => app.theme.ok,
        Validity::Invalid(_) => app.theme.error,
        Validity::Checking | Validity::Empty => app.theme.text,
    };
    if app.filter.input.is_empty() && !focused {
        put(
            buf,
            x,
            area.y,
            room,
            "none — press / to filter",
            app.theme.dim,
        );
        return None;
    }
    let (text, cursor) = app.filter.input.visible(room as usize);
    // Reverse video while the text is selected (typing will replace it).
    let style = if focused && app.filter.select_all {
        style.add_modifier(Modifier::REVERSED)
    } else {
        style
    };
    put(buf, x, area.y, room, &text, style);

    // Say whether Enter would change anything.
    if focused {
        let hint = match &app.filter.validity {
            Validity::Invalid(_) => "invalid",
            Validity::Checking => "checking…",
            _ if app.filter.dirty() => "Enter to apply",
            _ => "",
        };
        let used = width(&text) as u16 + 2;
        if !hint.is_empty() && room > used + width(hint) as u16 {
            put_right(buf, x + used, area.y, room - used, hint, app.theme.dim);
        }
        return Some((x + cursor as u16, area.y));
    }
    if app.filter.dirty() {
        let used = width(&text) as u16 + 2;
        let hint = "not applied";
        if room > used + width(hint) as u16 {
            put_right(buf, x + used, area.y, room - used, hint, app.theme.warn);
        }
    }
    None
}

/// The field-name completion popup under the filter bar.
pub fn completions(app: &App, buf: &mut Buffer, body: Rect) {
    if app.focus != Focus::Filter || !app.filter.has_completions() || app.overlay.is_some() {
        return;
    }
    let items = &app.filter.completions.items;
    let rows = (items.len() as u16).min(8).min(body.height);
    if rows == 0 {
        return;
    }
    let name_width = items.iter().map(|i| width(&i.field)).max().unwrap_or(0) as u16;
    let desc_width = items
        .iter()
        .map(|i| i.name.as_deref().map_or(0, width))
        .max()
        .unwrap_or(0) as u16;
    let w = (name_width + desc_width + 5).min(body.width).max(12);
    let x = (body.x + width(FILTER_LABEL) as u16 + 1 + app.filter.completions.start as u16)
        .min(body.x + body.width.saturating_sub(w));
    let selected = app.filter.completions.selected;
    // Keep the selected entry in view.
    let top = selected.map_or(0, |s| s.saturating_sub(rows as usize - 1));
    for line in 0..rows {
        let index = top + line as usize;
        let Some(item) = items.get(index) else { break };
        let style = if selected == Some(index) {
            app.theme.popup_selected
        } else {
            app.theme.popup
        };
        let y = body.y + line;
        fill(
            buf,
            Rect {
                x,
                y,
                width: w,
                height: 1,
            },
            style,
        );
        put(buf, x + 1, y, name_width, &item.field, style);
        if let Some(name) = &item.name {
            let room = w.saturating_sub(name_width + 4);
            put(
                buf,
                x + name_width + 3,
                y,
                room,
                &truncate(name, room as usize),
                style,
            );
        }
    }
    if items.len() > rows as usize {
        let more = format!(" +{} ", items.len() - rows as usize);
        put_right(buf, x, body.y + rows - 1, w, &more, app.theme.popup);
    }
}

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Draw the status bar (or the prompt, when one is open). Returns the cursor
/// position when the prompt has it.
pub fn status(app: &mut App, buf: &mut Buffer, area: Rect) -> Option<(u16, u16)> {
    let base = app.theme.status;
    fill(buf, area, base);

    if let Some(prompt) = &app.prompt {
        let label = prompt.label();
        let style = app.theme.text;
        fill(buf, area, style);
        put(buf, area.x, area.y, area.width, label, app.theme.status_key);
        let x = area.x + width(label) as u16;
        let room = area.width.saturating_sub(width(label) as u16 + 1);
        let (text, cursor) = prompt.input.visible(room as usize);
        put(buf, x, area.y, room, &text, style);
        return Some((x + cursor as u16, area.y));
    }

    // Right side: what the user can press.
    let hint = if app.overlay.is_some() {
        "Esc close "
    } else {
        "? help "
    };
    let hint_width = width(hint) as u16;
    put_right(buf, area.x, area.y, area.width, hint, app.theme.status_key);
    let room = area.width.saturating_sub(hint_width + 1);

    // Left side: spinner, file, counts.
    let mut x = area.x + 1;
    let busy = app.busy() || app.load == LoadState::Loading;
    let lead = if busy {
        SPINNER[(app.ticks as usize) % SPINNER.len()]
    } else {
        " "
    };
    put(buf, x, area.y, 1, lead, app.theme.status_key);
    x += 2;

    let name = truncate(&app.title, (room / 3).max(8) as usize);
    put(
        buf,
        x,
        area.y,
        room.saturating_sub(x - area.x),
        &name,
        base.add_modifier(Modifier::BOLD),
    );
    x += width(&name) as u16 + 1;

    let left = room.saturating_sub(x - area.x);
    // A filter error while typing is the most useful thing to show.
    let (text, style) =
        if let (Focus::Filter, Validity::Invalid(reason)) = (app.focus, &app.filter.validity) {
            (reason.clone(), base.patch(app.theme.error))
        } else if let Some(m) = &app.message {
            let style = match m.level {
                Level::Info => base,
                Level::Warn => base.patch(app.theme.warn),
                Level::Error => base.patch(app.theme.error),
            };
            (m.text.clone(), style)
        } else {
            (details(app), base)
        };
    put(
        buf,
        x,
        area.y,
        left,
        &format!("│ {}", truncate(&text, left.saturating_sub(2) as usize)),
        style,
    );
    None
}

/// The default status text: size, selection and capture state.
fn details(app: &mut App) -> String {
    let mut parts = Vec::new();
    if let Some(status) = &app.status {
        if let Some(size) = status.filesize {
            parts.push(human_bytes(size));
        }
        if status.duration > 0.0 {
            parts.push(human_duration(status.duration));
        }
    }
    if let Some(num) = app.list.selected_num() {
        parts.push(format!("packet {}", thousands(u64::from(num))));
    }
    if !app.marks.is_empty() {
        parts.push(format!("{} marked", app.marks.len()));
    }
    if app.zoom {
        parts.push("zoomed".to_string());
    }
    if app.capture.is_some() {
        parts.push(if app.capturing() {
            "● capturing".to_string()
        } else {
            "capture stopped".to_string()
        });
    } else if app.tail.is_some() {
        parts.push("following file".to_string());
    }
    parts.join(" · ")
}
