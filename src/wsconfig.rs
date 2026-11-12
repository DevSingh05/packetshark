//! Wireshark's own configuration: where it lives, which profiles there are,
//! what protocols are called, and how to give sharkd a changed copy of it.
//!
//! sharkd reads "Decode As" rules only from its configuration directory, at
//! startup. To change them while running, packetshark copies the user's
//! configuration into a temporary directory, adds the rules there, and starts
//! sharkd again pointed at the copy. The user's own files are never written.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Wireshark's configuration directories.
#[derive(Debug, Clone, Default)]
pub struct Folders {
    pub personal: Option<PathBuf>,
    pub global: Option<PathBuf>,
}

/// Ask tshark where the configuration is. Without tshark, the usual places.
pub fn folders(tshark: Option<&Path>) -> Folders {
    if let Some(dir) = std::env::var_os("WIRESHARK_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return Folders {
            personal: Some(PathBuf::from(dir)),
            global: None,
        };
    }
    let listed = tshark
        .and_then(|tshark| {
            Command::new(tshark)
                .args(["-G", "folders"])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .ok()
        })
        .map(|out| parse_folders(&String::from_utf8_lossy(&out.stdout)))
        .unwrap_or_default();
    if listed.personal.is_some() {
        return listed;
    }
    let home = dirs::home_dir();
    let personal = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(|x| PathBuf::from(x).join("wireshark"))
        .into_iter()
        .chain(home.iter().map(|h| h.join(".config").join("wireshark")))
        .chain(home.iter().map(|h| h.join(".wireshark")))
        .find(|p| p.is_dir());
    Folders {
        personal,
        global: listed.global,
    }
}

/// Pick the two directories out of `tshark -G folders`.
pub fn parse_folders(text: &str) -> Folders {
    let find = |label: &str| {
        text.lines().find_map(|line| {
            let (name, path) = line.split_once(':')?;
            (name.trim() == label && !path.trim().is_empty()).then(|| PathBuf::from(path.trim()))
        })
    };
    Folders {
        personal: find("Personal configuration"),
        global: find("Global configuration"),
    }
}

/// The names of the configuration profiles there are, `Default` first.
pub fn profiles(folders: &Folders) -> Vec<String> {
    let mut names = vec!["Default".to_string()];
    for dir in [&folders.personal, &folders.global].into_iter().flatten() {
        let Ok(entries) = fs::read_dir(dir.join("profiles")) else {
            continue;
        };
        let mut found: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| !names.contains(name))
            .collect();
        found.sort();
        names.extend(found);
    }
    names
}

/// A protocol as Wireshark names it: `Syslog` for the filter name `syslog`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protocol {
    /// The short name, which is what a Decode As rule must say.
    pub short: String,
    /// The name used in display filters.
    pub filter: String,
}

/// Every protocol tshark knows, or nothing if tshark cannot be asked.
pub fn protocols(tshark: Option<&Path>) -> Vec<Protocol> {
    let Some(tshark) = tshark else {
        return Vec::new();
    };
    Command::new(tshark)
        .args(["-G", "protocols"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|out| parse_protocols(&String::from_utf8_lossy(&out.stdout)))
        .unwrap_or_default()
}

/// Read `tshark -G protocols`: name, short name and filter name, tab-separated.
pub fn parse_protocols(text: &str) -> Vec<Protocol> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let (_, short, filter) = (parts.next()?, parts.next()?, parts.next()?);
            Some(Protocol {
                short: short.to_string(),
                filter: filter.to_string(),
            })
        })
        .collect()
}

/// The short name for a protocol typed as its filter name or its short
/// name, in any case. Without a list to look in, what was typed stands.
pub fn short_name(known: &[Protocol], typed: &str) -> Result<String, String> {
    if known.is_empty() {
        return Ok(typed.to_string());
    }
    known
        .iter()
        .find(|p| p.filter.eq_ignore_ascii_case(typed) || p.short.eq_ignore_ascii_case(typed))
        .map(|p| p.short.clone())
        .ok_or_else(|| format!("Wireshark has no protocol called {typed}."))
}

/// One "Decode As" rule: packets whose `table` value is `value` are decoded
/// as `protocol`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeAs {
    /// A dissector table, such as `tcp.port`.
    pub table: String,
    pub value: String,
    /// The protocol's short name, such as `HTTP`.
    pub protocol: String,
}

impl DecodeAs {
    /// Read a rule as it is typed: `tcp.port 8080 http`, or tshark's
    /// `tcp.port==8080,http`.
    pub fn parse(text: &str) -> Result<(String, String, String), String> {
        let usage = "A rule is a table, a value and a protocol: tcp.port 8080 http";
        let cleaned = text.replace("==", " ").replace(',', " ");
        let mut parts = cleaned.split_whitespace();
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(table), Some(value), Some(protocol), None)
                if table.contains('.') || table.chars().all(|c| c.is_ascii_alphanumeric()) =>
            {
                let plain = |s: &str| {
                    !s.is_empty()
                        && s.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':')
                        })
                };
                if plain(table) && plain(value) && plain(protocol) {
                    Ok((table.to_string(), value.to_string(), protocol.to_string()))
                } else {
                    Err(usage.to_string())
                }
            }
            _ => Err(usage.to_string()),
        }
    }

    /// The line Wireshark keeps in `decode_as_entries`.
    pub fn entry(&self) -> String {
        format!(
            "decode_as_entry: {},{},(none),{}",
            self.table, self.value, self.protocol
        )
    }
}

/// The configuration sharkd has to be pointed at so that `profile` and
/// `rules` are in force, or `None` if the user's own will do as it is.
///
/// A copy is needed for Decode As rules, which sharkd reads only from its
/// configuration, and for a profile that Wireshark installs for every user:
/// sharkd accepts only personal profiles, so such a profile is copied in
/// as one.
pub fn engine_config(
    folders: &Folders,
    profile: Option<&str>,
    rules: &[DecodeAs],
) -> Result<Option<tempfile::TempDir>, String> {
    let profile = profile.filter(|p| !p.is_empty() && *p != "Default");
    let in_dir = |dir: &Option<PathBuf>, name: &str| {
        dir.as_ref()
            .map(|d| d.join("profiles").join(name))
            .filter(|p| p.is_dir())
    };
    let shared = profile.and_then(|name| match in_dir(&folders.personal, name) {
        Some(_) => None,
        None => in_dir(&folders.global, name),
    });
    if rules.is_empty() && shared.is_none() {
        return Ok(None);
    }
    let dir = tempfile::Builder::new()
        .prefix("packetshark-config-")
        .tempdir()
        .map_err(|e| format!("could not create a temporary directory: {e}"))?;
    if let (Some(shared), Some(name)) = (&shared, profile) {
        copy_dir(shared, &dir.path().join("profiles").join(name), 1);
    }
    copy_with_rules(folders.personal.as_deref(), dir.path(), profile, rules)?;
    Ok(Some(dir))
}

/// Copy the configuration in `personal` into `into`, and add `rules` to the
/// Decode As entries of `profile` (the default profile if `None`).
pub fn copy_with_rules(
    personal: Option<&Path>,
    into: &Path,
    profile: Option<&str>,
    rules: &[DecodeAs],
) -> Result<(), String> {
    if let Some(personal) = personal.filter(|p| p.is_dir()) {
        copy_dir(personal, into, 0);
    }
    let profile_dir = match profile.filter(|p| !p.is_empty() && *p != "Default") {
        Some(name) => into.join("profiles").join(name),
        None => into.to_path_buf(),
    };
    fs::create_dir_all(&profile_dir).map_err(|e| format!("{}: {e}", profile_dir.display()))?;
    let file = profile_dir.join("decode_as_entries");
    let mut text = fs::read_to_string(&file).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for rule in rules {
        text.push_str(&rule.entry());
        text.push('\n');
    }
    fs::write(&file, text).map_err(|e| format!("{}: {e}", file.display()))
}

/// Copy the small text files that make up a Wireshark configuration:
/// the directory itself and its profiles. Anything large or unreadable is
/// left behind; a configuration that is partly missing still works.
fn copy_dir(from: &Path, to: &Path, depth: u8) {
    const LARGEST: u64 = 4 * 1024 * 1024;
    if fs::create_dir_all(to).is_err() {
        return;
    }
    let Ok(entries) = fs::read_dir(from) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        let target = to.join(entry.file_name());
        if meta.is_dir() {
            // The directory, its profiles, and each profile's own files.
            if depth < 2 {
                copy_dir(&path, &target, depth + 1);
            }
        } else if meta.is_file() && meta.len() <= LARGEST {
            let _ = fs::copy(&path, &target);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_and_protocols_are_read_from_tshark() {
        let folders = parse_folders(
            "Temp:\t/tmp\nPersonal configuration:\t/home/u/.config/wireshark\nGlobal configuration:\t/usr/share/wireshark\nSystem:\t/etc\n",
        );
        assert_eq!(
            folders.personal.as_deref(),
            Some(Path::new("/home/u/.config/wireshark"))
        );
        assert_eq!(
            folders.global.as_deref(),
            Some(Path::new("/usr/share/wireshark"))
        );
        assert!(parse_folders("nothing useful").personal.is_none());

        let known = parse_protocols(
            "Hypertext Transfer Protocol\tHTTP\thttp\nSyslog Message\tSyslog\tsyslog\nbroken line\n",
        );
        assert_eq!(known.len(), 2);
        assert_eq!(short_name(&known, "syslog").unwrap(), "Syslog");
        assert_eq!(short_name(&known, "SYSLOG").unwrap(), "Syslog");
        assert_eq!(short_name(&known, "Http").unwrap(), "HTTP");
        assert!(short_name(&known, "nope").unwrap_err().contains("nope"));
        // With nothing to look in, the user is taken at their word.
        assert_eq!(short_name(&[], "Whatever").unwrap(), "Whatever");
    }

    #[test]
    fn rules_are_read_as_typed_or_as_tshark_writes_them() {
        let rule = |s: &str| DecodeAs::parse(s).unwrap();
        assert_eq!(
            rule("tcp.port 8080 http"),
            ("tcp.port".into(), "8080".into(), "http".into())
        );
        assert_eq!(rule("tcp.port==8080,http"), rule("tcp.port 8080 http"));
        assert_eq!(
            rule("  udp.port == 7777 , syslog "),
            ("udp.port".into(), "7777".into(), "syslog".into())
        );
        for bad in [
            "",
            "tcp.port 80",
            "tcp.port 80 http extra",
            "tcp.port 80 ht;tp",
            "a b\nc d",
        ] {
            assert!(DecodeAs::parse(bad).is_err(), "{bad:?}");
        }
        let entry = DecodeAs {
            table: "udp.port".into(),
            value: "7777".into(),
            protocol: "Syslog".into(),
        }
        .entry();
        assert_eq!(entry, "decode_as_entry: udp.port,7777,(none),Syslog");
    }

    #[test]
    fn a_configuration_is_copied_and_the_rules_added() {
        let home = tempfile::tempdir().unwrap();
        let personal = home.path().join("wireshark");
        fs::create_dir_all(personal.join("profiles").join("work")).unwrap();
        fs::write(personal.join("preferences"), "gui.column.format: x\n").unwrap();
        fs::write(
            personal.join("decode_as_entries"),
            "decode_as_entry: tcp.port,1,(none),HTTP",
        )
        .unwrap();
        fs::write(
            personal.join("profiles").join("work").join("colorfilters"),
            "@a@tcp@\n",
        )
        .unwrap();
        fs::create_dir_all(
            personal
                .join("profiles")
                .join("work")
                .join("deep")
                .join("deeper"),
        )
        .unwrap();
        fs::write(personal.join("huge.bin"), vec![0u8; 5 * 1024 * 1024]).unwrap();

        let rule = DecodeAs {
            table: "udp.port".into(),
            value: "7777".into(),
            protocol: "Syslog".into(),
        };
        let copy = tempfile::tempdir().unwrap();
        copy_with_rules(
            Some(&personal),
            copy.path(),
            None,
            std::slice::from_ref(&rule),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(copy.path().join("preferences")).unwrap(),
            "gui.column.format: x\n"
        );
        assert_eq!(
            fs::read_to_string(copy.path().join("decode_as_entries")).unwrap(),
            "decode_as_entry: tcp.port,1,(none),HTTP\ndecode_as_entry: udp.port,7777,(none),Syslog\n",
            "added after the user's own rules"
        );
        assert!(copy.path().join("profiles/work/colorfilters").is_file());
        assert!(
            !copy.path().join("huge.bin").exists(),
            "large files are left behind"
        );
        // The user's own configuration is untouched.
        assert_eq!(
            fs::read_to_string(personal.join("decode_as_entries")).unwrap(),
            "decode_as_entry: tcp.port,1,(none),HTTP"
        );

        // With a profile in use, the rules go into that profile.
        let copy = tempfile::tempdir().unwrap();
        copy_with_rules(Some(&personal), copy.path(), Some("work"), &[rule]).unwrap();
        assert!(
            fs::read_to_string(copy.path().join("profiles/work/decode_as_entries"))
                .unwrap()
                .contains("Syslog")
        );
        // No configuration at all is fine too.
        let copy = tempfile::tempdir().unwrap();
        copy_with_rules(None, copy.path(), None, &[]).unwrap();
        assert_eq!(
            fs::read_to_string(copy.path().join("decode_as_entries")).unwrap(),
            ""
        );

        // A profile installed for every user is copied in as a personal
        // one, which is the only kind sharkd will start with.
        let shared = home.path().join("share");
        fs::create_dir_all(shared.join("profiles").join("Classic")).unwrap();
        fs::write(
            shared.join("profiles").join("Classic").join("colorfilters"),
            "@b@udp@\n",
        )
        .unwrap();
        let folders = Folders {
            personal: Some(personal),
            global: Some(shared),
        };
        assert_eq!(profiles(&folders), ["Default", "work", "Classic"]);
        assert!(engine_config(&folders, None, &[]).unwrap().is_none());
        assert!(
            engine_config(&folders, Some("work"), &[])
                .unwrap()
                .is_none(),
            "a personal profile needs no copy"
        );
        let copy = engine_config(&folders, Some("Classic"), &[])
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::read_to_string(copy.path().join("profiles/Classic/colorfilters")).unwrap(),
            "@b@udp@\n"
        );
        assert!(
            copy.path().join("preferences").is_file(),
            "with the rest of the user's configuration"
        );
    }
}
