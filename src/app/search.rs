//! Finding packets: what is searched (bytes, details or the summary line),
//! how the text is read (plain, a regular expression, hex or a display
//! filter), and how that turns into work for sharkd or for us.

use regex::bytes::{Regex, RegexBuilder};

use crate::sharkd::types::Node;
use crate::util::filter_quote;

/// Where to look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The packet's bytes, reassembled and decrypted data included.
    Bytes,
    /// The text of the details tree.
    Details,
    /// The summary shown in the packet list's Info column.
    Summary,
}

impl Target {
    pub const ALL: [Target; 3] = [Target::Bytes, Target::Details, Target::Summary];

    pub fn name(self) -> &'static str {
        match self {
            Target::Bytes => "bytes",
            Target::Details => "details",
            Target::Summary => "summary",
        }
    }

    pub fn parse(name: &str) -> Target {
        match name {
            "details" => Target::Details,
            "summary" | "list" => Target::Summary,
            _ => Target::Bytes,
        }
    }

    pub fn next(self) -> Target {
        let i = Self::ALL.iter().position(|t| *t == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
}

/// How the typed text is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A display filter if it is one, else plain text.
    Auto,
    Text,
    Regex,
    /// Pairs of hex digits, as in `af054c`.
    Hex,
    Filter,
}

impl Kind {
    pub const ALL: [Kind; 5] = [Kind::Auto, Kind::Text, Kind::Regex, Kind::Hex, Kind::Filter];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Auto => "filter or text",
            Kind::Text => "text",
            Kind::Regex => "regex",
            Kind::Hex => "hex",
            Kind::Filter => "filter",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Kind::Auto => "auto",
            Kind::Text => "string",
            Kind::Regex => "regex",
            Kind::Hex => "hex",
            Kind::Filter => "filter",
        }
    }

    pub fn parse(name: &str) -> Kind {
        match name {
            "string" | "text" => Kind::Text,
            "regex" => Kind::Regex,
            "hex" => Kind::Hex,
            "filter" => Kind::Filter,
            _ => Kind::Auto,
        }
    }

    pub fn next(self) -> Kind {
        let i = Self::ALL.iter().position(|k| *k == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
}

/// A search as the user asked for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub target: Target,
    pub kind: Kind,
    pub case_sensitive: bool,
    pub text: String,
}

/// How a search is carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// A display filter that matches the packets wanted: sharkd finds them.
    Filter(String),
    /// Read each packet's details in turn and look for this pattern, a
    /// regular expression, in their text.
    Details(String),
    /// Read the packet list's rows and look for this pattern in them.
    /// sharkd accepts a filter on the summary column but matches nothing
    /// with it, so this cannot be left to a display filter.
    Summary(String),
}

impl Query {
    /// The words that go in the prompt: what this search looks at and how.
    pub fn describe(target: Target, kind: Kind, case_sensitive: bool) -> String {
        match kind {
            Kind::Filter => "Find by filter: ".to_string(),
            Kind::Hex => format!("Find in {} as hex: ", target.name()),
            _ => format!(
                "Find in {} as {}, {}: ",
                target.name(),
                kind.name(),
                if case_sensitive {
                    "exact case"
                } else {
                    "any case"
                }
            ),
        }
    }

    /// The pattern to look for, as a regular expression over bytes. `None`
    /// for a display filter, which has no pattern.
    pub fn pattern(&self) -> Result<Option<String>, String> {
        let flags = if self.case_sensitive { "" } else { "(?i)" };
        Ok(Some(match self.kind {
            Kind::Filter => return Ok(None),
            Kind::Auto | Kind::Text => format!("{flags}{}", regex::escape(&self.text)),
            Kind::Regex => format!("{flags}{}", self.text),
            Kind::Hex => {
                let bytes = parse_hex(&self.text)?;
                // Raw bytes, not characters.
                let body: String = bytes.iter().map(|b| format!("\\x{b:02x}")).collect();
                format!("(?-u){body}")
            }
        }))
    }

    /// Work out how to run the search with the Wireshark in use.
    pub fn plan(&self) -> Result<Plan, String> {
        let text = self.text.as_str();
        if matches!(self.kind, Kind::Filter | Kind::Auto) {
            // For `Auto` the caller falls back to text if sharkd refuses it.
            return Ok(Plan::Filter(text.to_string()));
        }
        // Checked here so that a bad pattern is reported before any work.
        let pattern = self.pattern()?.unwrap_or_default();
        compile(&pattern)?;
        let field = match self.target {
            Target::Details => return Ok(Plan::Details(pattern)),
            Target::Summary => return Ok(Plan::Summary(pattern)),
            Target::Bytes => "frame",
        };
        Ok(Plan::Filter(match self.kind {
            Kind::Hex => {
                let bytes = parse_hex(text)?;
                let escaped: String = bytes.iter().map(|b| format!("\\x{b:02x}")).collect();
                format!("{field} contains \"{escaped}\"")
            }
            Kind::Text if self.case_sensitive => format!("{field} contains {}", filter_quote(text)),
            // Wireshark's `matches` ignores case unless told otherwise.
            Kind::Text => format!("{field} matches {}", filter_quote(&regex::escape(text))),
            Kind::Regex if self.case_sensitive => {
                format!("{field} matches {}", filter_quote(&format!("(?-i){text}")))
            }
            Kind::Regex => format!("{field} matches {}", filter_quote(text)),
            Kind::Auto | Kind::Filter => unreachable!("handled above"),
        }))
    }

    /// The same search read as plain text: what `Auto` becomes when the text
    /// turns out not to be a display filter.
    pub fn as_text(&self) -> Query {
        Query {
            kind: Kind::Text,
            ..self.clone()
        }
    }
}

/// Pairs of hex digits, with spaces, colons or dashes between them allowed.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-' | '.'))
        .collect();
    let digits = digits.strip_prefix("0x").unwrap_or(&digits);
    if digits.is_empty()
        || !digits.len().is_multiple_of(2)
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("Hex is pairs of digits, such as af054c or af:05:4c.".into());
    }
    Ok((0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("checked above"))
        .collect())
}

/// Compile a pattern made by [`Query::pattern`].
pub fn compile(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        // A packet is bytes, most of which are not text.
        .unicode(!pattern.starts_with("(?-u)"))
        .size_limit(1 << 20)
        .build()
        .map_err(|e| {
            let reason = e.to_string();
            let last = reason.lines().last().unwrap_or(&reason).trim();
            format!("Not a regular expression: {last}")
        })
}

/// The first node, in the order the tree is read, whose text matches.
pub fn find_node(tree: &[Node], regex: &Regex) -> Option<Vec<usize>> {
    fn walk(nodes: &[Node], regex: &Regex, path: &mut Vec<usize>) -> bool {
        for (i, node) in nodes.iter().enumerate() {
            path.push(i);
            if regex.is_match(node.label.as_bytes()) || walk(&node.children, regex, path) {
                return true;
            }
            path.pop();
        }
        false
    }
    let mut path = Vec::new();
    walk(tree, regex, &mut path).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(target: Target, kind: Kind, case_sensitive: bool, text: &str) -> Query {
        Query {
            target,
            kind,
            case_sensitive,
            text: text.to_string(),
        }
    }

    #[test]
    fn searches_become_display_filters_where_sharkd_can_do_the_work() {
        let plan = |q: Query| q.plan().unwrap();
        assert_eq!(
            plan(query(Target::Bytes, Kind::Text, true, "GET /a\"b")),
            Plan::Filter(r#"frame contains "GET /a\"b""#.into())
        );
        // Any case: a regular expression with the text taken literally.
        assert_eq!(
            plan(query(Target::Bytes, Kind::Text, false, "a.b")),
            Plan::Filter(r#"frame matches "a\\.b""#.into())
        );
        assert_eq!(
            plan(query(Target::Bytes, Kind::Regex, false, "GET|POST")),
            Plan::Filter(r#"frame matches "GET|POST""#.into())
        );
        assert_eq!(
            plan(query(Target::Bytes, Kind::Regex, true, "GET|POST")),
            Plan::Filter(r#"frame matches "(?-i)GET|POST""#.into())
        );
        assert_eq!(
            plan(query(Target::Bytes, Kind::Hex, false, "AF:05 4c")),
            Plan::Filter(r#"frame contains "\xaf\x05\x4c""#.into())
        );
        // A filter is passed on untouched, whatever the target.
        assert_eq!(
            plan(query(
                Target::Details,
                Kind::Filter,
                false,
                "tcp.port == 80"
            )),
            Plan::Filter("tcp.port == 80".into())
        );
        assert_eq!(
            plan(query(Target::Bytes, Kind::Auto, false, "http")),
            Plan::Filter("http".into())
        );
    }

    #[test]
    fn the_details_and_the_summary_are_searched_here() {
        let q = query(Target::Details, Kind::Text, false, "Stream index");
        assert_eq!(q.plan().unwrap(), Plan::Details("(?i)Stream index".into()));
        let q = query(Target::Summary, Kind::Regex, true, "SYN|FIN");
        assert_eq!(q.plan().unwrap(), Plan::Summary("SYN|FIN".into()));
        let q = query(Target::Summary, Kind::Hex, true, "4745");
        assert_eq!(q.plan().unwrap(), Plan::Summary(r"(?-u)\x47\x45".into()));
    }

    #[test]
    fn mistakes_are_caught_before_any_searching() {
        let bad = query(Target::Bytes, Kind::Regex, false, "a(b");
        assert!(bad.plan().unwrap_err().contains("Not a regular expression"));
        for hex in ["abc", "zz", "", "0x"] {
            let q = query(Target::Bytes, Kind::Hex, false, hex);
            assert!(q.plan().unwrap_err().contains("pairs of digits"), "{hex}");
        }
        assert_eq!(parse_hex("0xAF05").unwrap(), [0xaf, 0x05]);
        assert_eq!(parse_hex("af-05.4c").unwrap(), [0xaf, 0x05, 0x4c]);
    }

    #[test]
    fn patterns_find_text_and_raw_bytes() {
        let find = |q: Query, hay: &[u8]| {
            let regex = compile(&q.pattern().unwrap().unwrap()).unwrap();
            regex.find(hay).map(|m| (m.start(), m.end()))
        };
        let data = b"\x00\xffGET /Index.html\x80\x81";
        assert_eq!(
            find(query(Target::Bytes, Kind::Text, false, "index"), data),
            Some((7, 12))
        );
        assert_eq!(
            find(query(Target::Bytes, Kind::Text, true, "index"), data),
            None
        );
        assert_eq!(
            find(query(Target::Bytes, Kind::Regex, true, "I.d"), data),
            Some((7, 10))
        );
        // A dot in plain text is a dot.
        assert_eq!(
            find(query(Target::Bytes, Kind::Text, false, "x.html"), data),
            Some((11, 17))
        );
        assert_eq!(
            find(query(Target::Bytes, Kind::Text, false, "xyhtml"), data),
            None
        );
        // Hex finds bytes that are not text at all.
        assert_eq!(
            find(query(Target::Bytes, Kind::Hex, false, "8081"), data),
            Some((17, 19))
        );
        assert_eq!(
            find(query(Target::Bytes, Kind::Hex, false, "ff47"), data),
            Some((1, 3))
        );
        assert!(
            query(Target::Bytes, Kind::Filter, false, "tcp")
                .pattern()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn the_first_matching_line_of_the_tree_is_found() {
        let tree: Vec<Node> = serde_json::from_str(
            r#"[{"l":"Frame 1"},
                {"l":"Transmission Control Protocol","n":[
                    {"l":"Source Port: 40000"},
                    {"l":"Flags: 0x018","n":[{"l":".... 1... = Push: Set"}]}]},
                {"l":"Hypertext Transfer Protocol","n":[{"l":"Host: example.com"}]}]"#,
        )
        .unwrap();
        let find = |text: &str| find_node(&tree, &compile(text).unwrap());
        assert_eq!(find("(?i)push"), Some(vec![1, 1, 0]));
        assert_eq!(find("Host"), Some(vec![2, 0]));
        assert_eq!(
            find("Control"),
            Some(vec![1]),
            "a parent before its children"
        );
        assert_eq!(find("nowhere"), None);
    }

    #[test]
    fn the_prompt_says_what_is_searched() {
        assert_eq!(
            Query::describe(Target::Bytes, Kind::Auto, false),
            "Find in bytes as filter or text, any case: "
        );
        assert_eq!(
            Query::describe(Target::Details, Kind::Regex, true),
            "Find in details as regex, exact case: "
        );
        assert_eq!(
            Query::describe(Target::Summary, Kind::Hex, true),
            "Find in summary as hex: "
        );
        assert_eq!(
            Query::describe(Target::Details, Kind::Filter, true),
            "Find by filter: "
        );
        assert_eq!(Target::parse(Target::Summary.name()), Target::Summary);
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.key()), kind);
        }
        assert_eq!(Target::Bytes.next().next().next(), Target::Bytes);
    }
}
