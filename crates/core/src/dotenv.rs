//! A small `.env` parser for the `import` on-ramp (docs/SPEC.md §6, M2). Supports the
//! common dotenv shape - `KEY=VALUE`, optional `export ` prefix, `#` comments, blank
//! lines, and single/double-quoted values - which is enough to migrate a typical
//! project's `.env`. A value is one physical line: a double-quoted one may carry `\n` and
//! the other escapes [`quoted`] writes, so a multiline secret survives `export` -> `import`,
//! but a value wrapped across real lines in a hand-written `.env` is not supported - add
//! those with `bitfort set`.

use std::fmt::Write as _;

use crate::error::{Error, Result};

/// Parse dotenv text into ordered `(key, value)` pairs. Later duplicate keys win,
/// mirroring how a shell sourcing the file would behave; the caller decides how to
/// merge them into the vault. Keys must be valid environment-variable names.
pub fn parse(input: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map(str::trim).unwrap_or(line);
        // Neither branch below quotes what it read. A line that fails to parse is very often
        // the *body* of a multi-line secret - a PEM key wraps onto lines with no `=`, and its
        // base64 padding puts one on the rest - so echoing either the raw line or the name in
        // front of `=` writes key material into the terminal, CI logs, and `--json` output.
        // The line number says where to look; the file is on the user's own disk.
        let Some((key, value)) = line.split_once('=') else {
            return Err(Error::NotAnAssignment(i + 1));
        };
        let key = key.trim();
        if !is_valid_key(key) {
            return Err(Error::Config(format!(
                "line {}: the name before `=` is not a valid environment variable name \
                 ([A-Za-z_][A-Za-z0-9_]*). The name is withheld: a mis-parsed line puts \
                 secret material there.",
                i + 1
            )));
        }
        out.push((key.to_string(), unquote(value.trim())));
    }
    Ok(out)
}

/// Serialize `pairs` back into dotenv text (`KEY=VALUE` per line, trailing newline each),
/// the inverse of [`parse`] used by `bitfort export`. A value is emitted bare when it is
/// safe to (letters, digits, and a few unambiguous punctuation chars); otherwise it is
/// double-quoted with `\`, `"`, and control chars escaped, so it stays on one physical line
/// and a full dotenv reader recovers it. Every value round-trips through [`parse`] byte for
/// byte, embedded quotes, backslashes, and newlines included: [`unquote`] reads back exactly
/// the escapes [`quoted`] writes.
pub fn to_dotenv<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<String> {
    let mut out = String::new();
    for (key, value) in pairs {
        check_key(key)?;
        out.push_str(key);
        out.push('=');
        out.push_str(&render_value(value));
        out.push('\n');
    }
    Ok(out)
}

/// Render one value for [`to_dotenv`]: bare when safe, else [`quoted`]. Escaping *every*
/// control char (not just `\n`/`\r`/`\t`) is a security requirement: a secret value carrying a
/// raw ESC/BEL/etc. would otherwise inject a terminal escape sequence when the vault is
/// exported to a TTY.
fn render_value(value: &str) -> String {
    if is_bare_safe(value) {
        return value.to_string();
    }
    quoted(value)
}

// The escape table, and both halves of it. `quoted` and `unescape` must stay exact inverses -
// an escape added to one and forgotten in the other corrupts a secret with exit 0 and no
// warning, which is the defect finding 1.14 reported - so they sit together rather than in the
// serialize and parse halves of the file, and `to_dotenv_survives_any_value` checks the
// property over arbitrary strings rather than over a list somebody has to extend.
//
//     \\  \"  \n  \r  \t      \xNN (ASCII controls)      \uNNNN (C1 and above)

/// Double-quote `text`, escaping `\`, `"`, and every control character.
///
/// Two callers with one requirement between them: it is how [`to_dotenv`] serializes a value a
/// dotenv reader must recover, and how untrusted text - a secret's own name - is put into an
/// error message without letting it drive the terminal that prints it. The message path always
/// quotes rather than going through [`render_value`], so one rejected name does not read
/// differently from the next because of its own bytes.
pub(crate) fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => escape_control(&mut out, c),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Write one control character as a dotenv escape, never as the raw byte: `\xNN` for the ASCII
/// controls (ESC, BEL, NUL, DEL) and `\u00NN` for the C1 block, whose code points are two bytes
/// in UTF-8 and so cannot be written as a single `\xNN`.
fn escape_control(out: &mut String, c: char) {
    let code = c as u32;
    if code < 0x80 {
        let _ = write!(out, "\\x{code:02x}");
    } else {
        let _ = write!(out, "\\u{code:04x}");
    }
}

/// Read the escapes [`quoted`] writes: `\\`, `\"`, `\n`, `\r`, `\t`, `\xNN`, and `\uNNNN`.
///
/// An escape this does not know is kept verbatim, backslash included. Nothing this crate
/// emits can produce one - [`quoted`] escapes every backslash - so an unknown escape only
/// arrives in a hand-written or foreign `.env`, where dropping the backslash would silently
/// change a secret.
fn unescape(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(escape) = chars.next() else {
            out.push('\\'); // a trailing backslash escapes nothing
            break;
        };
        let decoded = match escape {
            '\\' => Some('\\'),
            '"' => Some('"'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'x' => take_hex(&mut chars, 2),
            'u' => take_hex(&mut chars, 4),
            _ => None,
        };
        match decoded {
            Some(c) => out.push(c),
            // Unknown, or malformed hex digits: verbatim, one rule for both.
            None => {
                out.push('\\');
                out.push(escape);
            }
        }
    }
    out
}

/// Consume exactly `digits` hex digits and return the character they encode. `chars` is left
/// untouched unless the whole escape reads, so a malformed one falls back to verbatim.
fn take_hex(chars: &mut std::str::Chars<'_>, digits: usize) -> Option<char> {
    let mut probe = chars.clone();
    let mut code = 0u32;
    for _ in 0..digits {
        code = code * 16 + probe.next()?.to_digit(16)?;
    }
    let decoded = char::from_u32(code)?;
    *chars = probe;
    Some(decoded)
}

/// Serialize `pairs` as `export KEY=VALUE` lines for `eval`/`source`, the shell counterpart
/// of [`to_dotenv`] used by `bitfort export --format shell`. Values are quoted by
/// [`shell_quote`], so any value (spaces, `$`, backticks, newlines) survives `eval` verbatim
/// and cannot inject shell (docs/SPEC.md §6). Like [`to_dotenv`], secret-rendering with
/// escaping lives here in core and is unit-tested, not open-coded at a call site.
pub fn to_shell<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<String> {
    let mut out = String::new();
    for (key, value) in pairs {
        check_key(key)?;
        out.push_str("export ");
        out.push_str(key);
        out.push('=');
        shell_quote(&mut out, value);
        out.push('\n');
    }
    Ok(out)
}

/// Quote one value for `eval`: single quotes, with each embedded `'` closed, escaped, and
/// reopened (`'\''`). That is the only shell metacharacter that matters inside single quotes,
/// so every other byte - spaces, `$`, backticks, newlines, control characters - is emitted
/// verbatim and survives `eval` exactly.
///
/// **Emit no other quoting form here.** An attempt to escape control characters with ANSI-C
/// quoting (`$'...'`) read correctly in bash, zsh and ksh and was a *command injection* in
/// POSIX `sh`, which has no such construct: `sh` takes the `$` as a literal, opens an ordinary
/// single-quoted string, and does not honor the `\'` escape - so the string closes at that
/// quote and the rest of the value becomes shell text. A value of one tab plus `';cmd;#'` ran
/// `cmd` under `/bin/dash`, which is `/bin/sh` on Debian, Ubuntu and Alpine and the shell every
/// `make` recipe uses.
///
/// The consequence is that `--format shell` does not escape terminal control characters the way
/// [`to_dotenv`] does; a value that holds one is written raw. That is the deliberate trade:
/// this output is `eval`ed, so it must reproduce the value byte for byte in *every* shell, and
/// no in-quote escape exists to do it with. The exposure is bounded elsewhere - `export` refuses
/// to write to a terminal without `--force` (docs/SPEC.md §6), and its output is a file to
/// evaluate rather than text to read. Use `--format dotenv` or `--format json` to read one.
/// Written straight into `out` rather than returned: a returned `String` is a second copy of
/// the plaintext, up to `VALUE_SIZE_WARN` bytes of it, that nothing zeroizes.
fn shell_quote(out: &mut String, value: &str) {
    out.push('\'');
    for (i, part) in value.split('\'').enumerate() {
        if i > 0 {
            // Close the quoted run, emit a literal `'`, reopen: the one escape single quotes have.
            out.push_str("'\\''");
        }
        out.push_str(part);
    }
    out.push('\'');
}

/// [`is_valid_key`] as a refusal, with the crate's one message for a name that is not a name.
///
/// Applied at every boundary a secret name crosses: into a vault ([`Vault::set`],
/// [`Vault::replace`]), out of one ([`Vault::decrypt`]), and out of the two exporters, which
/// emit the name verbatim - so a vault carrying `BAD; touch /tmp/PWNED #` would otherwise
/// render as a second shell command under the documented
/// `eval "$(bitfort export --format shell)"` recipe (finding 1.3). One function so the four
/// cannot drift apart, and because a name that fails here is the same defect wherever it
/// surfaces.
///
/// The rejected name goes through [`quoted`] before it reaches the message, so a name carrying
/// terminal escapes cannot drive the terminal that reports it.
///
/// [`Vault::set`]: crate::vault::Vault::set
/// [`Vault::replace`]: crate::vault::Vault::replace
/// [`Vault::decrypt`]: crate::vault::Vault::decrypt
pub fn check_key(key: &str) -> Result<()> {
    if is_valid_key(key) {
        return Ok(());
    }
    Err(Error::VaultContent(format!(
        "{} is not a valid environment variable name ([A-Za-z_][A-Za-z0-9_]*)",
        quoted(key)
    )))
}

/// A value has to be storable in a process environment, which rules out exactly one byte:
/// NUL terminates a C string, so `Command::env` refuses it and *every* later `bitfort run`
/// for that environment fails to spawn at all - not just the one variable. Without this the
/// only repair is `unset`, and nothing says which key to unset.
///
/// Write side only, like the process-control rule: a vault that already holds one still
/// decrypts, so `list` and `status` can show what has to be removed.
///
/// The message names the key, never the value (invariant 6: no error quotes a secret).
pub fn check_value(key: &str, value: &str) -> Result<()> {
    if value.contains('\0') {
        return Err(Error::VaultContent(format!(
            "the value for {} contains a NUL byte, which a process environment cannot carry",
            quoted(key)
        )));
    }
    Ok(())
}

/// Whether a value can be emitted without quotes and still round-trip through [`parse`]:
/// only characters common in URLs, tokens, and paths, and no whitespace (which `parse`
/// trims), quote/`#`/backslash (which change meaning), or control chars. An empty string is
/// vacuously all-safe here, so it stays bare - and `KEY=` round-trips through `parse`.
fn is_bare_safe(value: &str) -> bool {
    value.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '@' | '+' | ',')
    })
}

/// Environment variable name rule: non-empty, `[A-Za-z_][A-Za-z0-9_]*`. Enforced here
/// (and in `set`) because names that break this can't be injected by `run`.
pub fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Strip one matching pair of surrounding quotes, un-escaping the contents of a
/// double-quoted value. An unquoted value is returned as-is; inline `#` comments after an
/// unquoted value are not stripped (kept as part of the value) to avoid silently truncating
/// a secret containing `#`.
///
/// Only double quotes carry escapes, in both directions: [`quoted`] emits them and
/// [`unescape`] reads them back, so `export` -> `import` returns the value byte for byte.
/// It did not before (finding 1.14): a password holding `"` came back with a backslash in
/// front of it and a Windows path came back with doubled separators, and `import` accepted
/// the corrupted value with exit 0 and no warning. A single-quoted value is literal, the way
/// every dotenv reader and the shell treat it, and this crate never emits one.
fn unquote(value: &str) -> String {
    // Slice only after a quote byte is matched. `bytes.len() >= 2` counts bytes, not
    // characters, so `&value[1..]` on a value starting with a multi-byte character - `éxample`
    // as a password - lands inside that character and panics, printing the character in the
    // panic message. Matching an ASCII quote first is what makes byte 1 a boundary.
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if first == b'"' && last == b'"' {
            return unescape(&value[1..value.len() - 1]);
        }
        if first == b'\'' && last == b'\'' {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        /// `quoted` and `unescape` must be exact inverses, and a fixed list of values can only
        /// ever check the escapes somebody remembered to add to it - which is how the two
        /// halves drifted apart in the first place (finding 1.14). This checks the property
        /// itself: any value at all survives `export` -> `import` byte for byte.
        ///
        /// `parse` trims a value, so a value with leading or trailing whitespace does not
        /// survive as itself. That is a real gap rather than a test artifact, and `quoted`
        /// closes it: whitespace makes a value fail `is_bare_safe`, so it is emitted quoted and
        /// the trim only ever removes what is outside the quotes.
        #[test]
        fn to_dotenv_survives_any_value(value in ".*") {
            let text = to_dotenv([("K", value.as_str())]).unwrap();
            proptest::prop_assert_eq!(text.lines().count(), 1, "value broke the line structure");
            proptest::prop_assert_eq!(parse(&text).unwrap(), vec![("K".to_string(), value)]);
        }
    }

    #[test]
    fn parses_common_shapes() {
        let input = "\
# a comment
export FOO=bar
BAZ = qux
QUOTED=\"hello world\"
SINGLE='single quoted'
EMPTY=

WITH_HASH=abc#notacomment
";
        let got = parse(input).unwrap();
        assert_eq!(
            got,
            vec![
                ("FOO".into(), "bar".into()),
                ("BAZ".into(), "qux".into()),
                ("QUOTED".into(), "hello world".into()),
                ("SINGLE".into(), "single quoted".into()),
                ("EMPTY".into(), "".into()),
                ("WITH_HASH".into(), "abc#notacomment".into()),
            ]
        );
    }

    #[test]
    fn later_duplicate_wins_ordering_preserved() {
        let got = parse("A=1\nB=2\nA=3\n").unwrap();
        assert_eq!(
            got,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "2".into()),
                ("A".into(), "3".into())
            ]
        );
    }

    #[test]
    fn rejects_missing_equals_and_bad_keys() {
        assert!(parse("NOTANASSIGNMENT\n").is_err());
        assert!(parse("1BAD=x\n").is_err());
        assert!(parse("has-dash=x\n").is_err());
    }

    #[test]
    fn to_dotenv_round_trips_every_value() {
        // Finding 1.14: `to_dotenv` escaped `\` and `"` and `unquote` never read them back,
        // so `bitfort export > .env` followed by `bitfort import .env` stored a corrupted
        // value - with exit 0 and no warning. The escaping cases are the point of this list.
        let pairs = vec![
            ("BARE".to_string(), "sk-live-1.2_3".to_string()),
            ("URL".to_string(), "postgres://u:p@h/db".to_string()),
            ("SPACED".to_string(), "hello world".to_string()),
            ("HASH".to_string(), "a#b".to_string()),
            ("EQUALS".to_string(), "a=b=c".to_string()),
            ("EMPTY".to_string(), String::new()),
            ("PW".to_string(), "p@ss\"w0rd".to_string()),
            ("WINPATH".to_string(), "C:\\Users\\app".to_string()),
            (
                "PEM".to_string(),
                "-----BEGIN-----\nbody\n-----END-----".to_string(),
            ),
            ("TABBED".to_string(), "a\tb\rc".to_string()),
            ("CONTROL".to_string(), "a\x1b[2Jb\x07\0\u{9b}".to_string()),
            ("QUOTED_WHOLE".to_string(), "\"wrapped\"".to_string()),
        ];
        let text = to_dotenv(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))).unwrap();
        assert_eq!(parse(&text).unwrap(), pairs);
    }

    #[test]
    fn single_quotes_stay_literal_and_unknown_escapes_survive() {
        // A single-quoted value is literal, as in the shell and every dotenv reader; this
        // crate never emits one, so the escapes in it come from a hand-written file.
        let got =
            parse("A='a\\nb'\nB=\"x\\qy\"\nC=\"trailing\\\\\"\nD=\"\\x2f\\u00e9\"\n").unwrap();
        assert_eq!(
            got,
            vec![
                ("A".into(), "a\\nb".into()),
                // An escape `quoted` never writes is kept whole rather than silently losing
                // its backslash and changing the secret.
                ("B".into(), "x\\qy".into()),
                ("C".into(), "trailing\\".into()),
                ("D".into(), "/é".into()),
            ]
        );
    }

    #[test]
    fn a_non_ascii_first_character_does_not_panic() {
        // Regression: `unquote` sliced off byte 1 before matching a quote byte, and
        // `bytes.len() >= 2` counts bytes. An accented password made `import` panic - and the
        // panic message named the character, which is the first byte of a secret.
        assert_eq!(
            parse("PW=éxample\nDASH=—\nQ=\"é\"\n").unwrap(),
            vec![
                ("PW".into(), "éxample".into()),
                ("DASH".into(), "—".into()),
                ("Q".into(), "é".into()),
            ]
        );
    }

    #[test]
    fn a_malformed_hex_escape_is_kept_verbatim() {
        let got = parse("A=\"\\xZZ\"\nB=\"\\u12\"\n").unwrap();
        assert_eq!(
            got,
            vec![("A".into(), "\\xZZ".into()), ("B".into(), "\\u12".into())]
        );
    }

    #[test]
    fn to_dotenv_quotes_only_when_needed() {
        assert_eq!(
            to_dotenv([("A", "plain-1.0"), ("B", "has space"), ("C", "")]).unwrap(),
            "A=plain-1.0\nB=\"has space\"\nC=\n"
        );
    }

    #[test]
    fn to_dotenv_escapes_control_and_quote_chars_onto_one_line() {
        // A newline or quote must be escaped so it can't break the dotenv line structure.
        let out = to_dotenv([("MULTI", "line1\nline2"), ("Q", "say \"hi\"")]).unwrap();
        assert_eq!(out, "MULTI=\"line1\\nline2\"\nQ=\"say \\\"hi\\\"\"\n");
        assert_eq!(
            out.lines().count(),
            2,
            "each secret stays on one physical line"
        );
    }

    #[test]
    fn to_dotenv_escapes_terminal_control_chars() {
        // A crafted escape sequence in a secret must never reach a terminal raw (it could
        // spoof the title, clear the screen, etc. when the vault is exported to a TTY).
        let out = to_dotenv([("EVIL", "a\x1b[2Jb\x07\0\u{9b}")]).unwrap();
        assert!(!out.contains('\x1b'), "raw ESC leaked: {out:?}");
        assert!(!out.contains('\x07'), "raw BEL leaked: {out:?}");
        assert!(!out.contains('\0'), "raw NUL leaked: {out:?}");
        assert!(!out.contains('\u{9b}'), "raw C1 CSI leaked: {out:?}");
        assert_eq!(out, "EVIL=\"a\\x1b[2Jb\\x07\\x00\\u009b\"\n");
    }

    #[test]
    fn to_shell_single_quotes_and_escapes_for_eval() {
        // Values with spaces, shell metacharacters, and embedded single quotes must survive
        // `eval` verbatim - the `'\''` escape closes, escapes a literal `'`, and reopens.
        let out = to_shell([("A", "plain"), ("B", "a b$c`d"), ("C", "it's \"quoted\"")]).unwrap();
        assert_eq!(
            out,
            "export A='plain'\nexport B='a b$c`d'\nexport C='it'\\''s \"quoted\"'\n"
        );
    }

    #[test]
    fn to_shell_stays_posix_single_quoted_for_every_value() {
        // Regression for the injection an ANSI-C (`$'...'`) branch introduced here. POSIX `sh`
        // has no `$'...'`: it reads the `$` as a literal, opens a plain single-quoted string,
        // and ignores the `\'` escape, so the string closes at that quote and the rest of the
        // value becomes shell text. This value ran `touch` under `/bin/dash`.
        //
        // The form is the property, so the form is what this asserts: every value is one
        // single-quoted run with `'\''` for an embedded quote, and nothing else. A test that
        // merely `eval`s the output cannot catch a regression here, because bash, zsh and ksh
        // all read `$'...'` safely - only a real POSIX shell is affected.
        let out = to_shell([("EVIL", "\t';touch /tmp/PWNED;#'")]).unwrap();
        assert!(
            !out.contains("$'"),
            "ANSI-C quoting is unsafe here: {out:?}"
        );
        assert_eq!(out, "export EVIL='\t'\\'';touch /tmp/PWNED;#'\\'''\n");

        // Control characters and newlines are emitted verbatim, which is what makes the value
        // byte-exact under `eval`. See `shell_quote` for why nothing escapes them.
        let out = to_shell([("MULTI", "line1\nline2"), ("ESC", "a\x1b[2Jb")]).unwrap();
        assert_eq!(out, "export MULTI='line1\nline2'\nexport ESC='a\x1b[2Jb'\n");
    }

    #[test]
    fn exporters_refuse_a_key_that_is_not_an_env_var_name() {
        // Finding 1.3: both exporters emit the name verbatim, so a crafted name is a second
        // command under the documented `eval "$(bitfort export --format shell)"` recipe.
        let evil = "BAD; touch /tmp/PWNED #";
        for out in [
            to_shell([(evil, "boom")]).unwrap_err(),
            to_dotenv([(evil, "boom")]).unwrap_err(),
        ] {
            assert!(
                matches!(&out, Error::VaultContent(m) if m.contains("not a valid environment variable name")),
                "expected a name rejection, got {out:?}"
            );
        }
    }

    #[test]
    fn a_rejected_key_cannot_drive_the_terminal_that_reports_it() {
        let err = to_shell([("A\x1b[2J", "x")]).unwrap_err().to_string();
        assert!(
            !err.contains('\x1b'),
            "raw ESC leaked into the error: {err}"
        );
    }

    #[test]
    fn parse_errors_withhold_the_line_and_the_name() {
        // Finding 1.13: a PEM body wraps onto lines with no `=`, and its base64 padding puts
        // one on the rest - so both branches were echoing key material into the terminal,
        // CI logs, and `--json`.
        let pem = "PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecret\n";
        let err = parse(pem).unwrap_err().to_string();
        assert!(err.contains("line 2"), "the line number is the fix: {err}");
        assert!(!err.contains("MIIEow"), "secret material leaked: {err}");

        let padded = "MIIEow+kCAQEA/secret==\n";
        let err = parse(padded).unwrap_err().to_string();
        assert!(err.contains("line 1"), "the line number is the fix: {err}");
        assert!(!err.contains("MIIEow"), "secret material leaked: {err}");
    }

    #[test]
    fn key_validation_matches_env_rules() {
        assert!(is_valid_key("DATABASE_URL"));
        assert!(is_valid_key("_private"));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("9lives"));
        assert!(!is_valid_key("a b"));
    }
}
