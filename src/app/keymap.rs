//! Key mappings: one key standing for a sequence of keys, as vim's `:map`.
//!
//! Keys are written the way vim writes them: a printable character is
//! itself, and anything else is a name in angle brackets, such as `<enter>`,
//! `<f5>` or `<C-s>`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The names of the keys that are not a single printable character.
const NAMED: &[(&str, KeyCode)] = &[
    ("space", KeyCode::Char(' ')),
    ("lt", KeyCode::Char('<')),
    ("esc", KeyCode::Esc),
    ("enter", KeyCode::Enter),
    ("cr", KeyCode::Enter),
    ("tab", KeyCode::Tab),
    ("bs", KeyCode::Backspace),
    ("del", KeyCode::Delete),
    ("up", KeyCode::Up),
    ("down", KeyCode::Down),
    ("left", KeyCode::Left),
    ("right", KeyCode::Right),
    ("pgup", KeyCode::PageUp),
    ("pgdn", KeyCode::PageDown),
    ("home", KeyCode::Home),
    ("end", KeyCode::End),
];

/// A key as the terminal reports it, reduced to what distinguishes it.
/// Shift is dropped for characters, since `A` already says it.
pub fn normalize(key: KeyEvent) -> (KeyCode, KeyModifiers) {
    let mut modifiers = key.modifiers & (KeyModifiers::CONTROL | KeyModifiers::ALT);
    let code = match key.code {
        KeyCode::BackTab => {
            modifiers |= KeyModifiers::SHIFT;
            KeyCode::Tab
        }
        other => other,
    };
    (code, modifiers)
}

/// Read a sequence of keys in vim's notation.
pub fn parse(text: &str) -> Result<Vec<KeyEvent>, String> {
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c == '<'
            && let Some(end) = rest.find('>')
            && let Some(key) = named(&rest[1..end])
        {
            keys.push(key);
            rest = &rest[end + 1..];
            continue;
        }
        if c == '<' && rest.contains('>') {
            let end = rest.find('>').unwrap_or(rest.len() - 1);
            return Err(format!(
                "{} is not a key. Keys are written like <enter>, <esc>, <f5>, <C-s> or <A-x>.",
                &rest[..=end]
            ));
        }
        keys.push(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        rest = &rest[c.len_utf8()..];
    }
    Ok(keys)
}

/// The key named between angle brackets, if it is one.
fn named(name: &str) -> Option<KeyEvent> {
    let mut modifiers = KeyModifiers::NONE;
    let mut name = name;
    loop {
        let lower = name.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("c-") {
            modifiers |= KeyModifiers::CONTROL;
            name = &name[name.len() - rest.len()..];
        } else if let Some(rest) = lower
            .strip_prefix("a-")
            .or_else(|| lower.strip_prefix("m-"))
        {
            modifiers |= KeyModifiers::ALT;
            name = &name[name.len() - rest.len()..];
        } else if let Some(rest) = lower.strip_prefix("s-") {
            modifiers |= KeyModifiers::SHIFT;
            name = &name[name.len() - rest.len()..];
        } else {
            break;
        }
    }
    let lower = name.to_ascii_lowercase();
    let code = if let Some((_, code)) = NAMED.iter().find(|(n, _)| *n == lower) {
        *code
    } else if let Some(n) = lower.strip_prefix('f').and_then(|n| n.parse::<u8>().ok()) {
        if !(1..=12).contains(&n) {
            return None;
        }
        KeyCode::F(n)
    } else {
        let mut chars = name.chars();
        match (chars.next(), chars.next()) {
            // `<C-s>`: a single character with a modifier.
            (Some(c), None) if !modifiers.is_empty() => {
                KeyCode::Char(if modifiers.contains(KeyModifiers::CONTROL) {
                    c.to_ascii_lowercase()
                } else {
                    c
                })
            }
            _ => return None,
        }
    };
    if code == KeyCode::Tab && modifiers.contains(KeyModifiers::SHIFT) {
        return Some(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
    }
    Some(KeyEvent::new(code, modifiers - KeyModifiers::SHIFT))
}

/// Write a key in the notation [`parse`] reads.
pub fn describe(key: KeyEvent) -> String {
    let (code, modifiers) = normalize(key);
    let name = match code {
        KeyCode::Char(' ') => "space".to_string(),
        KeyCode::Char('<') => "lt".to_string(),
        KeyCode::Char(c) if modifiers.is_empty() => return c.to_string(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::F(n) => format!("f{n}"),
        other => match NAMED.iter().find(|(_, c)| *c == other) {
            Some((name, _)) => (*name).to_string(),
            None => return String::new(),
        },
    };
    let mut prefix = String::new();
    if modifiers.contains(KeyModifiers::CONTROL) {
        prefix.push_str("C-");
    }
    if modifiers.contains(KeyModifiers::ALT) {
        prefix.push_str("A-");
    }
    if modifiers.contains(KeyModifiers::SHIFT) {
        prefix.push_str("S-");
    }
    format!("<{prefix}{name}>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn keys_are_read_in_vim_notation() {
        let plain = |c| key(KeyCode::Char(c), KeyModifiers::NONE);
        assert_eq!(
            parse(":conv<enter>").unwrap(),
            [
                plain(':'),
                plain('c'),
                plain('o'),
                plain('n'),
                plain('v'),
                key(KeyCode::Enter, KeyModifiers::NONE)
            ]
        );
        assert_eq!(
            parse("<C-s>").unwrap(),
            [key(KeyCode::Char('s'), KeyModifiers::CONTROL)]
        );
        assert_eq!(
            parse("<c-S>").unwrap(),
            [key(KeyCode::Char('s'), KeyModifiers::CONTROL)]
        );
        assert_eq!(
            parse("<A-/>").unwrap(),
            [key(KeyCode::Char('/'), KeyModifiers::ALT)]
        );
        assert_eq!(
            parse("<F5><f12>").unwrap(),
            [
                key(KeyCode::F(5), KeyModifiers::NONE),
                key(KeyCode::F(12), KeyModifiers::NONE)
            ]
        );
        assert_eq!(
            parse("<esc><space><Tab><S-Tab><pgdn><lt>").unwrap(),
            [
                key(KeyCode::Esc, KeyModifiers::NONE),
                plain(' '),
                key(KeyCode::Tab, KeyModifiers::NONE),
                key(KeyCode::BackTab, KeyModifiers::SHIFT),
                key(KeyCode::PageDown, KeyModifiers::NONE),
                plain('<'),
            ]
        );
        // A lone < that opens nothing is just the character.
        assert_eq!(parse("a<b").unwrap(), [plain('a'), plain('<'), plain('b')]);
        assert!(parse("<nonsense>").unwrap_err().contains("<nonsense>"));
        assert!(parse("<f13>").is_err());
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn describing_a_key_gives_back_what_parses_to_it() {
        for text in [
            "a", "Z", "/", "<space>", "<lt>", "<enter>", "<esc>", "<f5>", "<C-s>", "<A-x>",
            "<S-tab>", "<pgup>", "<C-A-d>",
        ] {
            let keys = parse(text).unwrap();
            assert_eq!(keys.len(), 1, "{text}");
            assert_eq!(describe(keys[0]), text);
        }
    }

    #[test]
    fn shift_is_part_of_the_character() {
        let typed = key(KeyCode::Char('A'), KeyModifiers::SHIFT);
        assert_eq!(normalize(typed), normalize(parse("A").unwrap()[0]));
        let back_tab = key(KeyCode::BackTab, KeyModifiers::SHIFT);
        assert_eq!(normalize(back_tab), normalize(parse("<S-tab>").unwrap()[0]));
    }
}
