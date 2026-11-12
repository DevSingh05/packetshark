//! Colours. The chrome uses the terminal's own 16-colour palette so it follows
//! whatever theme the user already has; only packet rows use Wireshark's exact
//! colouring-rule colours.

use ratatui::style::{Color, Modifier, Style};

use crate::util::{luminance, parse_rgb, rgb_to_256};

/// How packet rows are coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RowColors {
    /// Wireshark's foreground and background, as in the GUI.
    #[default]
    Wireshark,
    /// Only tint the text, keeping the terminal's background.
    Tint,
    /// No per-packet colours.
    Off,
}

impl RowColors {
    pub fn next(self) -> Self {
        match self {
            RowColors::Wireshark => RowColors::Tint,
            RowColors::Tint => RowColors::Off,
            RowColors::Off => RowColors::Wireshark,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            RowColors::Wireshark => "wireshark",
            RowColors::Tint => "tint",
            RowColors::Off => "off",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "wireshark" | "full" | "on" => Some(RowColors::Wireshark),
            "tint" | "fg" => Some(RowColors::Tint),
            "off" | "none" => Some(RowColors::Off),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub truecolor: bool,
    /// Whether the terminal background is dark; decides which of a rule's two
    /// colours reads best as text in `Tint` mode.
    pub dark: bool,
    pub row_colors: RowColors,

    pub text: Style,
    pub dim: Style,
    pub title: Style,
    pub title_focused: Style,
    pub column_header: Style,
    pub selected: Style,
    pub selected_unfocused: Style,
    pub status: Style,
    pub status_key: Style,
    pub ok: Style,
    pub warn: Style,
    pub error: Style,
    pub proto: Style,
    pub generated: Style,
    pub link: Style,
    pub hex_offset: Style,
    pub hex_highlight: Style,
    pub hex_cursor: Style,
    pub marked: Style,
    pub client: Style,
    pub server: Style,
    pub popup: Style,
    pub popup_selected: Style,
    pub bar: Style,
}

impl Theme {
    pub fn detect() -> Theme {
        let colorterm = std::env::var("COLORTERM")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let truecolor = colorterm.contains("truecolor") || colorterm.contains("24bit");
        // COLORFGBG is "fg;bg"; a background of 7 or 15 means a light terminal.
        let dark = std::env::var("COLORFGBG")
            .ok()
            .and_then(|v| v.rsplit(';').next().and_then(|bg| bg.parse::<u8>().ok()))
            .is_none_or(|bg| bg != 7 && bg != 15);
        Theme::new(truecolor, dark)
    }

    pub fn new(truecolor: bool, dark: bool) -> Theme {
        let base = Style::default();
        Theme {
            truecolor,
            dark,
            row_colors: RowColors::default(),
            text: base,
            dim: base.fg(Color::DarkGray),
            title: base.fg(Color::Gray).bg(Color::Indexed(236)),
            title_focused: base
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            column_header: base.add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            selected: base.fg(Color::Black).bg(Color::Cyan),
            selected_unfocused: base.add_modifier(Modifier::REVERSED),
            status: base.fg(Color::Gray).bg(Color::Indexed(236)),
            status_key: base.fg(Color::Cyan).bg(Color::Indexed(236)),
            ok: base.fg(Color::Green),
            warn: base.fg(Color::Yellow),
            error: base.fg(Color::Red),
            proto: base.add_modifier(Modifier::BOLD),
            generated: base.add_modifier(Modifier::ITALIC).fg(Color::DarkGray),
            link: base.fg(Color::Blue).add_modifier(Modifier::UNDERLINED),
            hex_offset: base.fg(Color::DarkGray),
            hex_highlight: base.fg(Color::Black).bg(Color::Yellow),
            hex_cursor: base
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            marked: base.fg(Color::Magenta).add_modifier(Modifier::BOLD),
            client: base.fg(Color::LightRed),
            server: base.fg(Color::LightBlue),
            popup: base.fg(Color::Gray).bg(Color::Indexed(237)),
            popup_selected: base.fg(Color::Black).bg(Color::Cyan),
            bar: base.fg(Color::Cyan),
        }
    }

    fn color(&self, rgb: (u8, u8, u8)) -> Color {
        if self.truecolor {
            Color::Rgb(rgb.0, rgb.1, rgb.2)
        } else {
            Color::Indexed(rgb_to_256(rgb))
        }
    }

    /// Style for a packet row given Wireshark's colouring-rule colours.
    pub fn row(&self, bg: Option<&str>, fg: Option<&str>) -> Style {
        let (bg, fg) = (bg.and_then(parse_rgb), fg.and_then(parse_rgb));
        match self.row_colors {
            RowColors::Off => self.text,
            RowColors::Wireshark => {
                let mut style = self.text;
                if let Some(c) = bg {
                    style = style.bg(self.color(c));
                }
                if let Some(c) = fg {
                    style = style.fg(self.color(c));
                }
                style
            }
            RowColors::Tint => {
                // Use whichever of the rule's colours contrasts with the
                // terminal background.
                let pick = match (bg, fg) {
                    (Some(b), Some(f)) => {
                        let lighter_is_bg = luminance(b) >= luminance(f);
                        Some(if lighter_is_bg == self.dark { b } else { f })
                    }
                    (Some(c), None) | (None, Some(c)) => Some(c),
                    (None, None) => None,
                };
                match pick {
                    Some(c) => self.text.fg(self.color(c)),
                    None => self.text,
                }
            }
        }
    }

    /// Style for an expert-info severity name.
    pub fn severity(&self, severity: &str) -> Style {
        match severity.to_ascii_lowercase().as_str() {
            "error" => self.error.add_modifier(Modifier::BOLD),
            "warn" | "warning" => self.warn,
            "note" => Style::default().fg(Color::Cyan),
            "chat" => Style::default().fg(Color::Blue),
            _ => self.text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireshark_mode_uses_both_colours() {
        let t = Theme::new(true, true);
        let s = t.row(Some("daeeff"), Some("12272e"));
        assert_eq!(s.bg, Some(Color::Rgb(0xda, 0xee, 0xff)));
        assert_eq!(s.fg, Some(Color::Rgb(0x12, 0x27, 0x2e)));
    }

    #[test]
    fn tint_mode_picks_the_readable_colour() {
        let mut t = Theme::new(true, true);
        t.row_colors = RowColors::Tint;
        // Light background rule on a dark terminal: the light colour becomes text.
        let s = t.row(Some("daeeff"), Some("12272e"));
        assert_eq!(s.fg, Some(Color::Rgb(0xda, 0xee, 0xff)));
        assert_eq!(s.bg, None);
        // "Bad TCP" is light text on black: keep the light text.
        let s = t.row(Some("12272e"), Some("f78787"));
        assert_eq!(s.fg, Some(Color::Rgb(0xf7, 0x87, 0x87)));
        // On a light terminal the dark colour is the readable one.
        let mut light = Theme::new(true, false);
        light.row_colors = RowColors::Tint;
        let s = light.row(Some("daeeff"), Some("12272e"));
        assert_eq!(s.fg, Some(Color::Rgb(0x12, 0x27, 0x2e)));
    }

    #[test]
    fn falls_back_to_256_colours() {
        let t = Theme::new(false, true);
        let s = t.row(Some("ffffff"), None);
        assert_eq!(s.bg, Some(Color::Indexed(231)));
    }
}
