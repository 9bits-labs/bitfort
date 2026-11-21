//! Keeps the public CLI reference honest.
//!
//! `docs/cli.mdx` is hand written, because a dump of `--help` reads badly, and the site
//! publishes it as the page search engines land on. Hand-written prose drifts: a review of the
//! first draft found it documenting a `member promote` that does not exist, which leaves a
//! reader with no way forward. These tests compare the page against the binary in both
//! directions, so the drift fails `cargo test` instead of reaching a user.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{command_paths, help_for};

fn reference_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/cli.mdx")
        .canonicalize()
        .expect("docs/cli.mdx is missing; the CLI reference must ship with the CLI")
}

fn reference_text() -> String {
    std::fs::read_to_string(reference_path()).expect("failed to read the CLI reference")
}

/// Every command path the reference documents, read from its `### \`bitfort ...\`` headings.
fn documented_commands(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("### `bitfort ") else {
            continue;
        };
        let Some(sig) = rest.split('`').next() else {
            continue;
        };
        // Keep the leading words that name the command, and stop at the first thing that is
        // not one: an argument placeholder (`<KEY>`), or the `--` in `bitfort run -- <CMD>`.
        // A command word starts with a letter, which is what rules `--` out.
        let path: Vec<&str> = sig
            .split_whitespace()
            .take_while(|w| {
                w.starts_with(|c: char| c.is_ascii_lowercase())
                    && w.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            })
            .collect();
        if !path.is_empty() {
            found.insert(path.join(" "));
        }
    }
    found
}

#[test]
fn reference_documents_every_command() {
    let missing: Vec<_> = command_paths()
        .difference(&documented_commands(&reference_text()))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "the CLI reference is missing commands the binary has: {missing:?}\n\
         add a `### `bitfort <name>`` section to docs/cli.mdx"
    );
}

#[test]
fn reference_invents_no_command() {
    let invented: Vec<_> = documented_commands(&reference_text())
        .difference(&command_paths())
        .cloned()
        .collect();
    assert!(
        invented.is_empty(),
        "the CLI reference documents commands the binary does not have: {invented:?}\n\
         a reader following these has no way forward; remove them from docs/cli.mdx"
    );
}

#[test]
fn reference_names_every_long_flag() {
    let text = reference_text();
    let mut missing = Vec::new();
    for path in command_paths() {
        let args: Vec<&str> = path.split(' ').collect();
        for line in help_for(&args).lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed.strip_prefix("--") else {
                continue;
            };
            let flag: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '-')
                .collect();
            if flag.is_empty() {
                continue;
            }
            let flag = format!("--{flag}");
            if !text.contains(&flag) {
                missing.push(format!("{path}: {flag}"));
            }
        }
    }
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "the CLI reference never names these flags: {missing:?}\n\
         document them in docs/cli.mdx, or in its global flags table"
    );
}
