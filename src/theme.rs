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
    /// Draw with ASCII only, for terminals and locales without UTF-8.
    pub ascii: bool,
    pub row_colors: RowColors,

    pub text: Style,
    pub dim: Style,
    pub title: Style,
    pub title_focused: Style,
    /// The line that runs across a pane's title row.
    pub rule: Style,
    pub rule_focused: Style,
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
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        let colorterm = var("COLORTERM").to_ascii_lowercase();
        let truecolor = colorterm.contains("truecolor") || colorterm.contains("24bit");
        // COLORFGBG is "fg;bg"; a background of 7 or 15 means a light terminal.
        let dark = std::env::var("COLORFGBG")
            .ok()
            .and_then(|v| v.rsplit(';').next().and_then(|bg| bg.parse::<u8>().ok()))
            .is_none_or(|bg| bg != 7 && bg != 15);
        // https://no-color.org: any non-empty value turns colour off.
        let mut theme = if var("NO_COLOR").is_empty() {
            Theme::new(truecolor, dark)
        } else {
            Theme::monochrome()
        };
        theme.ascii = !locale_is_utf8(&var("LC_ALL"), &var("LC_CTYPE"), &var("LANG"));
        theme
    }

    pub fn new(truecolor: bool, dark: bool) -> Theme {
        let base = Style::default();
        let accent = Color::Cyan;
        // Greys come from the fixed part of the 256-colour palette, so they
        // look the same under any terminal theme; accents use the terminal's
        // own named colours, so they follow it.
        let (surface, on_surface, raised, faint) = if dark {
            (236, 250, 240, 244)
        } else {
            (254, 238, 250, 245)
        };
        let surface_style = base
            .fg(Color::Indexed(on_surface))
            .bg(Color::Indexed(surface));
        let selected = if dark {
            base.fg(Color::Indexed(231)).bg(Color::Indexed(24))
        } else {
            base.fg(Color::Indexed(16)).bg(Color::Indexed(153))
        };
        Theme {
            truecolor,
            dark,
            ascii: false,
            row_colors: RowColors::default(),
            text: base,
            dim: base.fg(Color::Indexed(faint)),
            title: base.fg(Color::Indexed(faint)),
            title_focused: base.fg(accent).add_modifier(Modifier::BOLD),
            rule: base.fg(Color::Indexed(if dark { 239 } else { 250 })),
            rule_focused: base.fg(accent),
            column_header: base.fg(Color::Indexed(faint)).add_modifier(Modifier::BOLD),
            selected,
            // Sets the text colour too: a packet row brings its own, chosen
            // for a different background.
            selected_unfocused: if dark {
                base.fg(Color::Indexed(255)).bg(Color::Indexed(raised))
            } else {
                base.fg(Color::Indexed(16)).bg(Color::Indexed(raised))
            },
            status: surface_style,
            status_key: base.fg(accent).bg(Color::Indexed(surface)),
            ok: base.fg(Color::Green),
            warn: base.fg(Color::Yellow),
            error: base.fg(Color::Red),
            proto: base.add_modifier(Modifier::BOLD),
            generated: base
                .fg(Color::Indexed(faint))
                .add_modifier(Modifier::ITALIC),
            link: base.fg(Color::Blue).add_modifier(Modifier::UNDERLINED),
            hex_offset: base.fg(Color::Indexed(faint)),
            hex_highlight: if dark {
                base.fg(Color::Indexed(230)).bg(Color::Indexed(58))
            } else {
                base.fg(Color::Indexed(16)).bg(Color::Indexed(222))
            },
            hex_cursor: selected.add_modifier(Modifier::BOLD),
            marked: base.fg(Color::Magenta).add_modifier(Modifier::BOLD),
            client: base.fg(Color::LightRed),
            server: base.fg(Color::LightBlue),
            popup: surface_style,
            popup_selected: selected,
            bar: base.fg(accent),
        }
    }

    /// No colour at all: everything is told apart by bold, dim, underline
    /// and reverse video. Used when `NO_COLOR` is set.
    pub fn monochrome() -> Theme {
        let base = Style::default();
        let bold = base.add_modifier(Modifier::BOLD);
        let dim = base.add_modifier(Modifier::DIM);
        let reversed = base.add_modifier(Modifier::REVERSED);
        Theme {
            truecolor: false,
            dark: true,
            ascii: false,
            row_colors: RowColors::Off,
            text: base,
            dim,
            title: dim,
            title_focused: bold,
            rule: dim,
            rule_focused: base,
            column_header: bold,
            selected: reversed,
            selected_unfocused: base.add_modifier(Modifier::UNDERLINED),
            status: reversed,
            status_key: reversed.add_modifier(Modifier::BOLD),
            ok: base,
            warn: bold,
            error: bold.add_modifier(Modifier::UNDERLINED),
            proto: bold,
            generated: dim.add_modifier(Modifier::ITALIC),
            link: base.add_modifier(Modifier::UNDERLINED),
            hex_offset: dim,
            hex_highlight: reversed,
            hex_cursor: reversed.add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            marked: bold,
            client: base,
            server: bold,
            popup: base,
            popup_selected: reversed,
            bar: base,
        }
    }

    /// Switch between the dark and light palettes.
    pub fn set_dark(&mut self, dark: bool) {
        if self.dark == dark || self.monochrome_in_use() {
            return;
        }
        *self = Theme {
            ascii: self.ascii,
            row_colors: self.row_colors,
            ..Theme::new(self.truecolor, dark)
        };
    }

    /// Whether colour is in use at all.
    pub fn monochrome_in_use(&self) -> bool {
        self.status.bg.is_none()
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
            "note" if !self.monochrome_in_use() => Style::default().fg(Color::Cyan),
            "chat" if !self.monochrome_in_use() => Style::default().fg(Color::Blue),
            _ => self.text,
        }
    }
}

/// Whether the locale says the terminal takes UTF-8. The first of `LC_ALL`,
/// `LC_CTYPE` and `LANG` that is set decides, as in libc. With none set
/// nothing is known, and UTF-8 is by far the likelier answer today.
pub fn locale_is_utf8(lc_all: &str, lc_ctype: &str, lang: &str) -> bool {
    let Some(locale) = [lc_all, lc_ctype, lang].into_iter().find(|v| !v.is_empty()) else {
        return true;
    };
    let locale = locale.to_ascii_lowercase();
    locale.contains("utf-8") || locale.contains("utf8")
}

/// The closest ASCII stand-in for a character the interface draws.
pub fn ascii_for(c: char) -> char {
    match c {
        '\u{2500}' | '\u{2014}' | '\u{2013}' => '-', // ─ — –
        '\u{2502}' => '|',                           // │
        '\u{256d}' | '\u{256e}' | '\u{2570}' | '\u{256f}' => '+', // ╭ ╮ ╰ ╯
        '\u{25b8}' | '\u{2192}' => '>',              // ▸ →
        '\u{25be}' | '\u{25bc}' | '\u{2193}' => 'v', // ▾ ▼ ↓
        '\u{25b2}' | '\u{2191}' => '^',              // ▲ ↑
        '\u{2190}' => '<',                           // ←
        '\u{2026}' => '~',                           // …
        '\u{00b7}' => '.',                           // ·
        '\u{25cf}' => '*',                           // ●
        '\u{2588}' | '\u{2503}' => '#',              // █ ┃
        '\u{2800}'..='\u{28ff}' => '*',              // braille spinner
        c if c.is_ascii() => c,
        _ => '?',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_locale_decides_whether_unicode_is_drawn() {
        assert!(locale_is_utf8("", "", "en_US.UTF-8"));
        assert!(locale_is_utf8("", "", "C.utf8"));
        assert!(!locale_is_utf8("", "", "C"));
        assert!(!locale_is_utf8("", "", "en_US.ISO-8859-1"));
        // LC_ALL wins over LC_CTYPE, which wins over LANG.
        assert!(!locale_is_utf8("C", "en_US.UTF-8", "en_US.UTF-8"));
        assert!(locale_is_utf8("", "en_US.UTF-8", "C"));
        // Nothing set: assume a modern terminal.
        assert!(locale_is_utf8("", "", ""));
    }

    #[test]
    fn every_drawing_character_has_an_ascii_form() {
        for c in "─│╭╮╰╯▸▾▼▲↑↓←→…·●█—–⠋⠙".chars() {
            let plain = ascii_for(c);
            assert!(plain.is_ascii_graphic(), "{c} became {plain:?}");
            assert_ne!(plain, '?', "{c} has no stand-in");
        }
        assert_eq!(ascii_for('a'), 'a');
        assert_eq!(ascii_for('中'), '?');
    }

    #[test]
    fn monochrome_uses_no_colour() {
        let t = Theme::monochrome();
        for style in [
            t.text,
            t.dim,
            t.title,
            t.title_focused,
            t.rule,
            t.selected,
            t.selected_unfocused,
            t.status,
            t.status_key,
            t.ok,
            t.warn,
            t.error,
            t.hex_highlight,
            t.hex_cursor,
            t.popup,
            t.popup_selected,
            t.client,
            t.server,
            t.marked,
            t.link,
        ] {
            assert_eq!((style.fg, style.bg), (None, None));
        }
        assert_eq!(t.row(Some("daeeff"), Some("12272e")), t.text);
        assert_eq!(t.severity("note"), t.text);
    }

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
