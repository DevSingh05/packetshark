//! Small helpers shared by the app and the UI.

use base64::Engine;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn decode_base64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .unwrap_or_default()
}

pub fn encode_base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Parse sharkd's `rrggbb` colour strings.
pub fn parse_rgb(s: &str) -> Option<(u8, u8, u8)> {
    let s = s.trim_start_matches('#');
    if s.len() != 6 || !s.is_ascii() {
        return None;
    }
    let p = |i: usize| u8::from_str_radix(&s[i..i + 2], 16).ok();
    Some((p(0)?, p(2)?, p(4)?))
}

/// Perceived brightness, 0.0 (black) to 1.0 (white).
pub fn luminance((r, g, b): (u8, u8, u8)) -> f32 {
    (0.2126 * f32::from(r) + 0.7152 * f32::from(g) + 0.0722 * f32::from(b)) / 255.0
}

/// Nearest colour in the xterm 256-colour palette (cube and grey ramp).
pub fn rgb_to_256((r, g, b): (u8, u8, u8)) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let nearest = |v: u8| {
        LEVELS
            .iter()
            .enumerate()
            .min_by_key(|(_, l)| (i32::from(**l) - i32::from(v)).abs())
            .unwrap()
            .0
    };
    let (ri, gi, bi) = (nearest(r), nearest(g), nearest(b));
    let cube = (LEVELS[ri], LEVELS[gi], LEVELS[bi]);
    let grey_step = ((u32::from(r) + u32::from(g) + u32::from(b)) / 3)
        .saturating_sub(8)
        .min(230)
        / 10;
    let grey_value = (8 + grey_step * 10) as u8;
    let dist = |c: (u8, u8, u8)| {
        let d = |a: u8, b: u8| (i32::from(a) - i32::from(b)).pow(2);
        d(c.0, r) + d(c.1, g) + d(c.2, b)
    };
    if dist((grey_value, grey_value, grey_value)) < dist(cube) {
        232 + grey_step as u8
    } else {
        (16 + 36 * ri + 6 * gi + bi) as u8
    }
}

/// Human-readable byte count: `512 B`, `1.4 kB`, `3.2 MB`.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Human-readable time span: `2.7 ms`, `12.3 s`, `5m 03s`, `2h 07m`.
pub fn human_duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds <= 0.0 {
        return "0 s".to_string();
    }
    if seconds < 1.0 {
        return format!("{:.1} ms", seconds * 1000.0);
    }
    if seconds < 60.0 {
        return format!("{seconds:.1} s");
    }
    let whole = seconds.round() as u64;
    let (hours, minutes, secs) = (whole / 3600, whole % 3600 / 60, whole % 60);
    if hours == 0 {
        format!("{minutes}m {secs:02}s")
    } else {
        format!("{hours}h {minutes:02}m")
    }
}

/// Group digits: `1234567` becomes `1,234,567`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Display width of a string in terminal cells.
pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Cut `s` to at most `max` cells, ending with `…` when something was removed.
pub fn truncate(s: &str, max: usize) -> String {
    if width(s) <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > max - 1 {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

/// Replace characters that would break a terminal row (control characters,
/// newlines, tabs) with visible stand-ins.
pub fn sanitize(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .map(|c| match c {
                '\t' => ' ',
                c if c.is_control() => '·',
                c => c,
            })
            .collect(),
    )
}

/// Quote a string as a display-filter string literal.
pub fn filter_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Bytes as lowercase hex without separators.
pub fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A classic 16-bytes-per-line hex dump, as plain text.
pub fn hexdump(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", i * 16);
        for j in 0..16 {
            match chunk.get(j) {
                Some(b) => {
                    let _ = write!(out, "{b:02x} ");
                }
                None => out.push_str("   "),
            }
            if j == 7 {
                out.push(' ');
            }
        }
        out.push(' ');
        out.extend(chunk.iter().map(|&b| printable(b)));
        out.push('\n');
    }
    out
}

/// The character shown for a byte in an ASCII column.
pub fn printable(b: u8) -> char {
    if (0x20..0x7f).contains(&b) {
        b as char
    } else {
        '.'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgb_parsing() {
        assert_eq!(parse_rgb("daeeff"), Some((0xda, 0xee, 0xff)));
        assert_eq!(parse_rgb("#12272e"), Some((0x12, 0x27, 0x2e)));
        assert_eq!(parse_rgb("xyz"), None);
        assert_eq!(parse_rgb("12345"), None);
    }

    #[test]
    fn palette_mapping_hits_exact_entries() {
        assert_eq!(rgb_to_256((0, 0, 0)), 16);
        assert_eq!(rgb_to_256((255, 255, 255)), 231);
        assert_eq!(rgb_to_256((255, 0, 0)), 196);
        assert_eq!(rgb_to_256((128, 128, 128)), 244);
    }

    #[test]
    fn formatting() {
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1500), "1.5 kB");
        assert_eq!(human_bytes(3_200_000), "3.2 MB");
        assert_eq!(human_duration(0.0027), "2.7 ms");
        assert_eq!(human_duration(12.34), "12.3 s");
        assert_eq!(human_duration(303.2), "5m 03s");
        assert_eq!(human_duration(7620.0), "2h 07m");
        assert_eq!(human_duration(0.0), "0 s");
        assert_eq!(human_duration(f64::NAN), "0 s");
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(truncate("hello world", 8), "hello w…");
        assert_eq!(truncate("hello", 8), "hello");
        assert_eq!(filter_quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(sanitize("a\tb\r\n"), "a b··");
    }

    #[test]
    fn hexdump_layout() {
        let dump = hexdump(b"GET / HTTP/1.1\r\nHost: x");
        let mut lines = dump.lines();
        assert_eq!(
            lines.next().unwrap(),
            "00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1.."
        );
        assert_eq!(
            lines.next().unwrap(),
            "00000010  48 6f 73 74 3a 20 78                              Host: x"
        );
    }
}
