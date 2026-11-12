//! Keeps the README honest: every key and command in the in-app help must be
//! documented there, word for word.

use std::fmt::Write as _;

use packetshark::app::help::SECTIONS;

fn readme() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("README.md exists")
}

/// The key reference as the Markdown tables the README contains.
fn key_tables() -> String {
    let mut out = String::new();
    for section in SECTIONS {
        let _ = write!(
            out,
            "**{}**\n\n| Key | Action |\n|---|---|\n",
            section.title
        );
        for (keys, action) in section.keys {
            let _ = writeln!(out, "| `{}` | {} |", keys.replace('|', "\\|"), action);
        }
        out.push('\n');
    }
    out
}

/// Table rows without the column padding a Markdown formatter adds, so the
/// comparison is about content rather than alignment.
fn unpadded(markdown: &str) -> String {
    let mut out = String::new();
    for line in markdown.lines() {
        if line.starts_with('|') {
            let cells: Vec<&str> = line
                .split('|')
                .map(str::trim)
                .map(|cell| {
                    let rule = !cell.is_empty() && cell.chars().all(|c| c == '-' || c == ':');
                    if rule { "---" } else { cell }
                })
                .collect();
            out.push_str(&cells.join("|"));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

#[test]
fn the_readme_documents_every_key() {
    let readme = unpadded(&readme());
    let tables = key_tables();
    assert!(
        readme.contains(unpadded(&tables).trim_end()),
        "README.md is out of date with src/app/help.rs. Replace its key reference with:\n\n{tables}"
    );
}

#[test]
fn the_readme_names_the_current_version_requirements() {
    let readme = readme();
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let rust_version = manifest
        .lines()
        .find_map(|l| l.strip_prefix("rust-version = "))
        .expect("rust-version in Cargo.toml")
        .trim_matches('"');
    assert!(
        readme.contains(&format!("Rust {rust_version}")),
        "README should mention Rust {rust_version}"
    );
}

#[test]
fn the_example_config_is_valid_and_shows_the_defaults() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml"))
        .unwrap();
    let example = packetshark::config::Config::parse(&text).expect("config.example.toml parses");
    let defaults = packetshark::config::Config::default();
    assert_eq!(example.ui.row_colors, defaults.ui.row_colors);
    assert_eq!(example.ui.layout, defaults.ui.layout);
    assert_eq!(example.ui.background, defaults.ui.background);
    assert_eq!(example.ui.mouse, defaults.ui.mouse);
    assert_eq!(example.ui.expand_all, defaults.ui.expand_all);
    assert_eq!(example.ui.ascii, defaults.ui.ascii);
    assert_eq!(example.ui.copy_command, defaults.ui.copy_command);
    assert!(example.sharkd.is_none() && example.profile.is_none());
}

/// `cargo test --test docs -- --ignored --nocapture print_key_tables`
#[test]
#[ignore = "prints the tables for pasting into the README"]
fn print_key_tables() {
    println!("{}", key_tables());
}
