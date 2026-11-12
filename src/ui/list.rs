//! The packet list pane.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use super::{fill, placeholder, put, put_right, title_bar};
use crate::app::{App, Focus, LoadState};
use crate::util::{sanitize, thousands, truncate};

pub fn draw(app: &mut App, buf: &mut Buffer, area: Rect) {
    let focused = matches!(app.focus, Focus::List | Focus::Filter) && app.overlay.is_none();
    let right = summary(app);
    let content = title_bar(app, buf, area, focused, "Packets", &right);
    if content.height == 0 {
        return;
    }

    // Column header, then rows.
    let header = Rect {
        height: 1,
        ..content
    };
    let rows = Rect {
        y: content.y + 1,
        height: content.height - 1,
        ..content
    };
    app.areas.list = rows;
    app.areas.header = header;
    app.list.set_height(rows.height);

    const GUTTER: u16 = 1;
    let cells = app
        .columns
        .layout(&app.list.widths, content.width.saturating_sub(GUTTER));
    let sorted = app
        .sorted_by()
        .map(|(title, down)| (title.to_string(), down));
    for (col, (x, w)) in app.columns.cols.iter().zip(&cells) {
        let x = content.x + GUTTER + x;
        // The column sorted by carries an arrow, in place of the end of a
        // title that fills its column.
        let title = match &sorted {
            Some((title, down)) if *title == col.title => {
                let arrow = if *down { '▼' } else { '▲' };
                let room = usize::from(*w).saturating_sub(1);
                let mut kept = String::new();
                for c in col.title.chars() {
                    if crate::util::width(&kept) + crate::util::width(c.encode_utf8(&mut [0; 4]))
                        > room
                    {
                        break;
                    }
                    kept.push(c);
                }
                format!("{kept}{arrow}")
            }
            _ => col.title.clone(),
        };
        if col.align_right {
            put_right(buf, x, header.y, *w, &title, app.theme.column_header);
        } else {
            put(buf, x, header.y, *w, &title, app.theme.column_header);
        }
    }

    if let Some(text) = empty_state(app) {
        let style = if matches!(app.load, LoadState::Failed(_)) || app.list.error.is_some() {
            app.theme.error
        } else {
            app.theme.dim
        };
        placeholder(buf, rows, &text, style);
        return;
    }

    for line in 0..rows.height {
        let index = app.list.top + u32::from(line);
        if index >= app.list.len() {
            break;
        }
        let y = rows.y + line;
        let selected = index == app.list.selected;
        let Some(row) = app.list.row(index) else {
            put(buf, rows.x + GUTTER, y, 1, "·", app.theme.dim);
            continue;
        };
        let mut style = app.theme.row(row.bg.as_deref(), row.fg.as_deref());
        if selected {
            style = if focused {
                app.theme.selected
            } else {
                style.patch(app.theme.selected_unfocused)
            };
        }
        fill(
            buf,
            Rect {
                y,
                height: 1,
                ..rows
            },
            style,
        );

        let marker = if app.marks.contains(&row.num) {
            Some("●")
        } else if app.time_refs.contains(&row.num) {
            Some("@")
        } else if row.commented {
            Some("#")
        } else {
            None
        };
        if let Some(m) = marker {
            let marker_style = if selected {
                style
            } else {
                style.patch(app.theme.marked)
            };
            put(buf, rows.x, y, 1, m, marker_style);
        }

        for ((col, (x, w)), cell) in app.columns.cols.iter().zip(&cells).zip(&row.cols) {
            let x = rows.x + GUTTER + x;
            let text = sanitize(cell);
            if col.align_right {
                put_right(buf, x, y, *w, &text, style);
            } else {
                put(buf, x, y, *w, &truncate(&text, *w as usize), style);
            }
        }
    }
}

/// "12 of 3,400 packets" for the title bar.
fn summary(app: &App) -> String {
    let total = app.frames();
    if app.load != LoadState::Ready {
        return String::new();
    }
    match app.list.total {
        None => "counting…".to_string(),
        Some(shown) if app.filter.applied.is_empty() => {
            format!("{} packets", thousands(u64::from(shown)))
        }
        Some(shown) => {
            let percent = if total == 0 {
                0.0
            } else {
                f64::from(shown) * 100.0 / f64::from(total)
            };
            format!(
                "{} of {} packets ({percent:.1}%)",
                thousands(u64::from(shown)),
                thousands(u64::from(total))
            )
        }
    }
}

/// What to say instead of rows, when there are none to show.
fn empty_state(app: &App) -> Option<String> {
    match &app.load {
        LoadState::Failed(reason) => return Some(reason.clone()),
        LoadState::Loading if app.tail.is_some() => {
            // Say why, if what has arrived so far could not be read.
            return Some(match app.tail.as_ref().and_then(|t| t.error.as_deref()) {
                Some(reason) => format!("Waiting for packets… (not readable yet: {reason})"),
                None => "Waiting for packets…".to_string(),
            });
        }
        LoadState::Loading => return Some(format!("Loading {}…", app.title)),
        LoadState::Ready => {}
    }
    if let Some(e) = &app.list.error {
        return Some(format!("Filter failed: {e}"));
    }
    match app.list.total {
        None => Some("Filtering…".to_string()),
        Some(0) if !app.filter.applied.is_empty() => {
            Some("No packets match the filter. Press x to clear it.".to_string())
        }
        Some(0) if app.tail.is_some() => Some("Waiting for packets…".to_string()),
        Some(0) => Some("This capture has no packets.".to_string()),
        Some(_) => None,
    }
}
