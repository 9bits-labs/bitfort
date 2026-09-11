//! Keeps the public CLI reference honest.
//!
//! `docs/cli.mdx` is hand written, because a dump of `--help` reads badly, and the site
//! publishes it as the page search engines land on. Hand-written prose drifts: a review of the
//! first draft found it documenting a `member promote` that does not exist, which leaves a
//! reader with no way forward. These tests compare the page against the binary in both
//! directions, so the drift fails `cargo test` instead of reaching a user.

use std::collections::BTreeSet;
use std::path::PathBuf;

use assert_cmd::Command;

/// Commands whose absence from the reference is deliberate.
///
/// `help` is clap's own, and documenting it would be documenting clap.
const NOT_DOCUMENTED: &[&str] = &["help"];

fn reference_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/cli.mdx")
        .canonicalize()
        .expect("docs/cli.mdx is missing; the CLI reference must ship with the CLI")
}

fn reference_text() -> String {
    std::fs::read_to_string(reference_path()).expect("failed to read the CLI reference")
}

/// `--help` for a command path, e.g. `[]` for the root or `["member"]` for a group.
fn help_for(path: &[&str]) -> String {
    let mut cmd = Command::cargo_bin("bitfort").unwrap();
    cmd.args(path);
    cmd.arg("--help");
    let out = cmd.output().expect("failed to run bitfort");
    String::from_utf8(out.stdout).expect("help output is not UTF-8")
}

/// Parse the `Commands:` block of a `--help` page into the subcommand names it lists.
///
/// clap indents each entry by two spaces and puts the name first, so the name is the first
/// token of an indented line. The block ends at the next unindented line (`Options:`).
fn subcommands(help: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut inside = false;
    for line in help.lines() {
        if line.starts_with("Commands:") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        // A blank line inside the block separates entries; a non-indented line ends it.
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with("  ") {
            break;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        // Continuation lines of a wrapped description are indented further and start
        // lowercase mid-sentence; a real entry is a bare word at exactly two spaces.
        if line.starts_with("   ") {
            continue;
        }
        if name.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            names.push(name.to_string());
        }
    }
    names
}

/// Every command path the binary accepts, as space-joined strings ("run", "member add").
fn binary_commands() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for top in subcommands(&help_for(&[])) {
        if NOT_DOCUMENTED.contains(&top.as_str()) {
            continue;
        }
        let nested = subcommands(&help_for(&[&top]));
        if nested.is_empty() {
            found.insert(top);
        } else {
            for sub in nested {
                if NOT_DOCUMENTED.contains(&sub.as_str()) {
                    continue;
                }
                found.insert(format!("{top} {sub}"));
            }
        }
    }
    found
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
    let missing: Vec<_> = binary_commands()
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
        .difference(&binary_commands())
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
    for path in binary_commands() {
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
