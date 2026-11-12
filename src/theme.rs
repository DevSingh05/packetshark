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

/// A theme as written in a TOML file: named colours, and a style for each
/// part of the interface that the theme wants to change.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ThemeSpec {
    /// Which built-in palette fills in the parts the theme leaves out.
    pub dark: Option<bool>,
    pub colors: std::collections::BTreeMap<String, String>,
    pub styles: std::collections::BTreeMap<String, StyleSpec>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StyleSpec {
    pub fg: Option<String>,
    pub bg: Option<String>,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub reverse: bool,
}

/// The parts of the interface a theme can style, in the order they are
/// documented.
pub const ELEMENTS: &[&str] = &[
    "text",
    "dim",
    "title",
    "title_focused",
    "rule",
    "rule_focused",
    "column_header",
    "selected",
    "selected_unfocused",
    "status",
    "status_key",
    "popup",
    "popup_selected",
    "ok",
    "warn",
    "error",
    "proto",
    "generated",
    "link",
    "hex_offset",
    "hex_highlight",
    "hex_cursor",
    "marked",
    "client",
    "server",
    "bar",
];

/// Styles shared by the built-in themes; each supplies only its colours.
const COMMON_STYLES: &str = r##"
[styles]
text = { fg = "fg", bg = "bg" }
dim = { fg = "faint" }
title = { fg = "faint" }
title_focused = { fg = "accent", bold = true }
rule = { fg = "raised" }
rule_focused = { fg = "accent" }
column_header = { fg = "faint", bold = true }
selected = { fg = "select_fg", bg = "select_bg" }
selected_unfocused = { fg = "fg", bg = "raised" }
status = { fg = "fg", bg = "surface" }
status_key = { fg = "accent", bg = "surface" }
popup = { fg = "fg", bg = "surface" }
popup_selected = { fg = "select_fg", bg = "select_bg" }
ok = { fg = "green" }
warn = { fg = "yellow" }
error = { fg = "red" }
proto = { bold = true }
generated = { fg = "faint", italic = true }
link = { fg = "blue", underline = true }
hex_offset = { fg = "faint" }
hex_highlight = { fg = "mark_fg", bg = "mark_bg" }
hex_cursor = { fg = "select_fg", bg = "select_bg", bold = true }
marked = { fg = "magenta", bold = true }
client = { fg = "red" }
server = { fg = "blue" }
bar = { fg = "accent" }
"##;

/// The themes that come with the program: a name and its colours.
const BUILTIN: &[(&str, &str)] = &[
    (
        "dracula",
        r##"dark = true
[colors]
bg = "#282a36"
surface = "#343746"
raised = "#44475a"
fg = "#f8f8f2"
faint = "#6272a4"
accent = "#bd93f9"
select_bg = "#6272a4"
select_fg = "#f8f8f2"
mark_bg = "#f1fa8c"
mark_fg = "#282a36"
red = "#ff5555"
green = "#50fa7b"
yellow = "#f1fa8c"
blue = "#8be9fd"
magenta = "#ff79c6"
"##,
    ),
    (
        "gruvbox",
        r##"dark = true
[colors]
bg = "#282828"
surface = "#3c3836"
raised = "#504945"
fg = "#ebdbb2"
faint = "#928374"
accent = "#fabd2f"
select_bg = "#458588"
select_fg = "#fbf1c7"
mark_bg = "#d79921"
mark_fg = "#282828"
red = "#fb4934"
green = "#b8bb26"
yellow = "#fabd2f"
blue = "#83a598"
magenta = "#d3869b"
"##,
    ),
    (
        "nord",
        r##"dark = true
[colors]
bg = "#2e3440"
surface = "#3b4252"
raised = "#4c566a"
fg = "#d8dee9"
faint = "#7b88a1"
accent = "#88c0d0"
select_bg = "#5e81ac"
select_fg = "#eceff4"
mark_bg = "#ebcb8b"
mark_fg = "#2e3440"
red = "#bf616a"
green = "#a3be8c"
yellow = "#ebcb8b"
blue = "#81a1c1"
magenta = "#b48ead"
"##,
    ),
    (
        "solarized-dark",
        r##"dark = true
[colors]
bg = "#002b36"
surface = "#073642"
raised = "#184a56"
fg = "#93a1a1"
faint = "#586e75"
accent = "#268bd2"
select_bg = "#268bd2"
select_fg = "#fdf6e3"
mark_bg = "#b58900"
mark_fg = "#002b36"
red = "#dc322f"
green = "#859900"
yellow = "#b58900"
blue = "#2aa198"
magenta = "#d33682"
"##,
    ),
    (
        "solarized-light",
        r##"dark = false
[colors]
bg = "#fdf6e3"
surface = "#eee8d5"
raised = "#d9d2bf"
fg = "#586e75"
faint = "#93a1a1"
accent = "#268bd2"
select_bg = "#268bd2"
select_fg = "#fdf6e3"
mark_bg = "#b58900"
mark_fg = "#fdf6e3"
red = "#dc322f"
green = "#859900"
yellow = "#b58900"
blue = "#2aa198"
magenta = "#d33682"
"##,
    ),
];

/// Names a theme can be chosen by: `default`, the built-in ones, then any
/// `NAME.toml` in the user's themes directory.
pub fn theme_names(user_dir: Option<&std::path::Path>) -> Vec<String> {
    let mut names = vec!["default".to_string()];
    names.extend(BUILTIN.iter().map(|(name, _)| (*name).to_string()));
    if let Some(dir) = user_dir
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        let mut user: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
            .filter(|n| !names.contains(n))
            .collect();
        user.sort();
        names.extend(user);
    }
    names
}

/// Find a theme by name: the user's own file first, so that a built-in one
/// can be adjusted by copying it, then the built-in ones.
pub fn find_theme(name: &str, user_dir: Option<&std::path::Path>) -> Result<ThemeSpec, String> {
    let safe = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if !safe {
        return Err(format!("`{name}` is not a theme name"));
    }
    if let Some(dir) = user_dir {
        let path = dir.join(format!("{name}.toml"));
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                return toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    match BUILTIN.iter().find(|(n, _)| *n == name) {
        Some((_, colors)) => {
            Ok(toml::from_str(&format!("{colors}{COMMON_STYLES}")).expect("built-in themes parse"))
        }
        None => Err(format!("there is no theme called {name}")),
    }
}

impl Theme {
    /// A theme built from `spec`. Parts it does not mention keep the look of
    /// the default dark or light theme.
    pub fn themed(spec: &ThemeSpec, truecolor: bool) -> Result<Theme, String> {
        let mut theme = Theme::new(truecolor, spec.dark.unwrap_or(true));
        for (name, style) in &spec.styles {
            let style = theme
                .style_from(style, &spec.colors)
                .map_err(|e| format!("{name}: {e}"))?;
            let slot = match name.as_str() {
                "text" => &mut theme.text,
                "dim" => &mut theme.dim,
                "title" => &mut theme.title,
                "title_focused" => &mut theme.title_focused,
                "rule" => &mut theme.rule,
                "rule_focused" => &mut theme.rule_focused,
                "column_header" => &mut theme.column_header,
                "selected" => &mut theme.selected,
                "selected_unfocused" => &mut theme.selected_unfocused,
                "status" => &mut theme.status,
                "status_key" => &mut theme.status_key,
                "popup" => &mut theme.popup,
                "popup_selected" => &mut theme.popup_selected,
                "ok" => &mut theme.ok,
                "warn" => &mut theme.warn,
                "error" => &mut theme.error,
                "proto" => &mut theme.proto,
                "generated" => &mut theme.generated,
                "link" => &mut theme.link,
                "hex_offset" => &mut theme.hex_offset,
                "hex_highlight" => &mut theme.hex_highlight,
                "hex_cursor" => &mut theme.hex_cursor,
                "marked" => &mut theme.marked,
                "client" => &mut theme.client,
                "server" => &mut theme.server,
                "bar" => &mut theme.bar,
                other => {
                    return Err(format!(
                        "`{other}` is not a part of the interface; the parts are {}",
                        ELEMENTS.join(", ")
                    ));
                }
            };
            *slot = style;
        }
        Ok(theme)
    }

    fn style_from(
        &self,
        spec: &StyleSpec,
        colors: &std::collections::BTreeMap<String, String>,
    ) -> Result<Style, String> {
        let mut style = Style::default();
        if let Some(fg) = &spec.fg {
            style = style.fg(self.named_color(fg, colors)?);
        }
        if let Some(bg) = &spec.bg {
            style = style.bg(self.named_color(bg, colors)?);
        }
        for (on, modifier) in [
            (spec.bold, Modifier::BOLD),
            (spec.dim, Modifier::DIM),
            (spec.italic, Modifier::ITALIC),
            (spec.underline, Modifier::UNDERLINED),
            (spec.reverse, Modifier::REVERSED),
        ] {
            if on {
                style = style.add_modifier(modifier);
            }
        }
        Ok(style)
    }

    /// A colour as a theme writes it: one of the theme's own names, `#rrggbb`,
    /// a terminal colour name, or a number from the 256-colour palette.
    fn named_color(
        &self,
        text: &str,
        colors: &std::collections::BTreeMap<String, String>,
    ) -> Result<Color, String> {
        // One level of naming is enough, and cannot loop.
        let text = colors.get(text).map_or(text, String::as_str).trim();
        if let Some(hex) = text.strip_prefix('#') {
            return parse_rgb(hex)
                .filter(|_| hex.len() == 6)
                .map(|rgb| self.color(rgb))
                .ok_or_else(|| format!("`{text}` is not a colour like #1a2b3c"));
        }
        if let Ok(index) = text.parse::<u8>() {
            return Ok(Color::Indexed(index));
        }
        Ok(
            match text
                .to_ascii_lowercase()
                .replace(['-', '_', ' '], "")
                .as_str()
            {
                "default" | "reset" | "none" => Color::Reset,
                "black" => Color::Black,
                "red" => Color::Red,
                "green" => Color::Green,
                "yellow" => Color::Yellow,
                "blue" => Color::Blue,
                "magenta" => Color::Magenta,
                "cyan" => Color::Cyan,
                "gray" | "grey" => Color::Gray,
                "darkgray" | "darkgrey" => Color::DarkGray,
                "lightred" => Color::LightRed,
                "lightgreen" => Color::LightGreen,
                "lightyellow" => Color::LightYellow,
                "lightblue" => Color::LightBlue,
                "lightmagenta" => Color::LightMagenta,
                "lightcyan" => Color::LightCyan,
                "white" => Color::White,
                _ => return Err(format!("`{text}` is not a colour")),
            },
        )
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
    fn every_built_in_theme_styles_every_part() {
        for name in theme_names(None).iter().filter(|n| *n != "default") {
            let spec = find_theme(name, None).unwrap();
            for element in ELEMENTS {
                assert!(
                    spec.styles.contains_key(*element),
                    "{name} leaves out {element}"
                );
            }
            let theme = Theme::themed(&spec, true).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(theme.text.bg.is_some(), "{name} sets a background");
            // Selected text must stand out from ordinary text.
            assert_ne!(theme.selected.bg, theme.text.bg, "{name}");
            // Without 24-bit colour it still builds, from the 256 palette.
            let fallback = Theme::themed(&spec, false).unwrap();
            assert!(
                matches!(fallback.text.bg, Some(Color::Indexed(_))),
                "{name}"
            );
        }
        assert!(theme_names(None).len() >= 6);
    }

    #[test]
    fn a_user_theme_overrides_parts_and_reports_mistakes() {
        let parse = |text: &str| Theme::themed(&toml::from_str(text).unwrap(), true);
        let theme = parse(
            r##"
            dark = false
            [colors]
            ink = "#102030"
            [styles]
            selected = { fg = "ink", bg = "lightyellow", bold = true }
            warn = { fg = "208" }
            "##,
        )
        .unwrap();
        assert_eq!(theme.selected.fg, Some(Color::Rgb(0x10, 0x20, 0x30)));
        assert_eq!(theme.selected.bg, Some(Color::LightYellow));
        assert!(theme.selected.add_modifier.contains(Modifier::BOLD));
        assert_eq!(theme.warn.fg, Some(Color::Indexed(208)));
        // Left alone: the light default.
        assert_eq!(theme.error, Theme::new(true, false).error);

        let err = parse("[styles]\nselectd = { fg = \"red\" }").unwrap_err();
        assert!(err.contains("selectd") && err.contains("selected"), "{err}");
        let err = parse("[styles]\ntext = { fg = \"#12\" }").unwrap_err();
        assert!(err.contains("#12"), "{err}");
        let err = parse("[styles]\ntext = { fg = \"blurple\" }").unwrap_err();
        assert!(err.contains("blurple"), "{err}");
        assert!(toml::from_str::<ThemeSpec>("[styles]\ntext = { colour = \"red\" }").is_err());
    }

    #[test]
    fn user_themes_are_found_by_name_and_listed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("mine.toml"),
            "[styles]\nok = { fg = \"blue\" }\n",
        )
        .unwrap();
        // A user's file wins over the built-in of the same name.
        std::fs::write(
            dir.path().join("nord.toml"),
            "[styles]\nok = { fg = \"red\" }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "not a theme").unwrap();
        let names = theme_names(Some(dir.path()));
        assert!(names.contains(&"mine".to_string()) && !names.contains(&"notes".to_string()));
        assert_eq!(names.iter().filter(|n| *n == "nord").count(), 1);
        let mine = find_theme("mine", Some(dir.path())).unwrap();
        assert_eq!(Theme::themed(&mine, true).unwrap().ok.fg, Some(Color::Blue));
        let nord = find_theme("nord", Some(dir.path())).unwrap();
        assert_eq!(Theme::themed(&nord, true).unwrap().ok.fg, Some(Color::Red));
        assert!(
            find_theme("missing", Some(dir.path()))
                .unwrap_err()
                .contains("missing")
        );
        assert!(find_theme("../etc/passwd", Some(dir.path())).is_err());
    }

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
