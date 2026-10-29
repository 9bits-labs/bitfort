//! Terminal presentation for the CLI: color, status glyphs, and the shared
//! layout vocabulary every human-facing command prints through.
//!
//! Everything degrades to plain text when the stream is not a terminal - a
//! pipe, a file, CI, or an MCP host driving `bitfort` over stdio - so machine
//! consumers and wrapped stdio protocols never receive escape codes
//! (docs/SPEC.md §6). Two layers guarantee this: [`Ui::detect`] disables color
//! off a TTY, and `anstream` independently strips any residual escapes at write
//! time. `bitfort run` stays byte-transparent and does not print through here.

use std::io::{IsTerminal, Write};

use anstyle::{AnsiColor, Style};
use anyhow::Context;

/// The error a failed write to stdout becomes, from [`Ui`]'s emitters and from [`outln!`]
/// alike, so one failure reads the same from every command.
pub const WRITE_FAILED: &str = "could not write to standard output";

/// `println!` for output that does not go through [`Ui`]: a value from `get`, the stable plain
/// lines a script matches. It returns a failed write as [`WRITE_FAILED`] where `println!`
/// panics with exit 101. It writes to `std::io::stdout()`, not anstream, because anstream
/// strips escape bytes off a terminal and a secret must arrive as stored.
macro_rules! outln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        anyhow::Context::context(writeln!(std::io::stdout(), $($arg)*), $crate::ui::WRITE_FAILED)
    }};
}
pub(crate) use outln;

/// Severity of a status line, selecting its glyph and color.
#[derive(Clone, Copy)]
pub enum Level {
    Ok,
    Warn,
    Fail,
    Info,
}

/// A CLI error that carries a literal fix command, surfaced by [`Ui::report`] as the
/// `→ try` line. The wrapped `message` is the human explanation (its first line is the
/// headline, any further lines are dim detail); `try_cmd` is the exact command to run.
/// Plain propagated errors render through the same path without a `try` line.
#[derive(Debug)]
pub struct Failure {
    message: String,
    try_cmd: String,
}

impl Failure {
    /// Build an [`anyhow::Error`] wrapping a [`Failure`], for `Err(Failure::hinted(..))`.
    pub fn hinted(message: impl Into<String>, try_cmd: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(Self {
            message: message.into(),
            try_cmd: try_cmd.into(),
        })
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// Presentation capabilities resolved once from the real output streams.
#[derive(Clone, Copy)]
pub struct Ui {
    stdout_tty: bool,
    stdin_tty: bool,
    color: bool,
    unicode: bool,
    json: bool,
    quiet: bool,
}

impl Ui {
    /// Resolve capabilities from the environment. `CLICOLOR_FORCE` forces *color* (so a
    /// user can pipe colored output into a pager, `bitfort status | less -R`) but not
    /// *layout*: read commands still emit their plain machine format when piped, so a
    /// script's `bitfort list | grep` never breaks. `NO_COLOR` disables color even when
    /// forced. Off a terminal with no force, output is a plain payload with no escape
    /// codes - the MCP/pipe guarantee. `json` is the global `--json` flag: it forces a
    /// machine payload, so it disables every human chrome layer (color, glyphs, tables).
    /// `quiet` is the global `--quiet` flag: it drops the decorative chrome (titles,
    /// next-step hints, spacer lines) while keeping the facts, data, and errors.
    pub fn detect(json: bool, quiet: bool) -> Self {
        let stdout_tty = std::io::stdout().is_terminal();
        let forced = std::env::var("CLICOLOR_FORCE").is_ok_and(|v| !v.is_empty() && v != "0");
        Self {
            stdout_tty,
            stdin_tty: std::io::stdin().is_terminal(),
            color: !json && (stdout_tty || forced) && std::env::var_os("NO_COLOR").is_none(),
            unicode: !json && (stdout_tty || forced),
            json,
            quiet,
        }
    }

    /// Whether the global `--json` flag asked for machine output. The commands that honor
    /// it branch on this to emit a structured payload instead of human text.
    pub fn json(&self) -> bool {
        self.json
    }

    /// Whether stdout is a real terminal, independent of `--json`. `export` uses this (not
    /// [`Ui::interactive`]) to refuse dumping the whole vault into terminal scrollback even
    /// when `--json` is also set.
    pub fn stdout_is_terminal(&self) -> bool {
        self.stdout_tty
    }

    /// Whether stdin is a real terminal. `set` uses this to choose between prompting for a
    /// value without echo and reading it from the pipe it was given, independently of where
    /// stdout points: the no-echo prompt writes to `/dev/tty`, so it stays correct under
    /// `bitfort set KEY > file`.
    pub fn stdin_is_terminal(&self) -> bool {
        self.stdin_tty
    }

    /// Whether to emit rich human chrome (tables). Gated on a real terminal only, so a
    /// piped or CI stream keeps its plain, parseable machine format even under
    /// `CLICOLOR_FORCE`; `--json` also turns it off. Color and glyphs, by contrast, do
    /// follow `CLICOLOR_FORCE`.
    pub fn interactive(&self) -> bool {
        self.stdout_tty && !self.json
    }

    /// Whether there is a person at the other end who can answer a question. Requires
    /// **both** streams to be terminals, not just stdout: with stdout on a terminal and
    /// stdin on a pipe, the piped bytes would answer every prompt, and a caller that reads
    /// a name, an environment, or a yes/no would take its answer from whatever produced
    /// that stream (`printf 'name\nstaging\n' | bitfort init` recorded both, and accepted
    /// the git commit offer that followed). Layout does not care where stdin points, so
    /// [`Ui::interactive`] stays the gate for tables and chrome; this one gates prompts.
    pub fn can_prompt(&self) -> bool {
        self.interactive() && self.stdin_tty
    }

    fn paint(&self, style: Style, text: &str) -> String {
        if self.color {
            format!("{style}{text}{style:#}")
        } else {
            text.to_string()
        }
    }

    fn glyph(&self, level: Level) -> &'static str {
        match (level, self.unicode) {
            (Level::Ok, true) => "✓",
            (Level::Ok, false) => "+",
            (Level::Warn, true) => "⚠",
            (Level::Warn, false) => "!",
            (Level::Fail, true) => "✗",
            (Level::Fail, false) => "x",
            (Level::Info, true) => "·",
            (Level::Info, false) => "-",
        }
    }

    fn level_style(level: Level) -> Style {
        match level {
            Level::Ok => Style::new().fg_color(Some(AnsiColor::Green.into())),
            Level::Warn => Style::new().fg_color(Some(AnsiColor::Yellow.into())),
            Level::Fail => Style::new().fg_color(Some(AnsiColor::Red.into())),
            Level::Info => Style::new().dimmed(),
        }
    }

    // --- string builders (pure, unit-tested) ---

    /// `  <glyph> <label>  <value>`, glyph colored by level, label left-padded to
    /// a fixed column so the values align.
    fn render_status(&self, level: Level, label: &str, value: &str) -> String {
        let glyph = self.paint(Self::level_style(level), self.glyph(level));
        format!("  {glyph} {label:<10}  {value}")
    }

    /// `  <label>  <value>` with no glyph, for a plain field.
    fn render_field(&self, label: &str, value: &str) -> String {
        format!("    {label:<10}  {value}")
    }

    /// `→ <text>` in dim, the next-step hint.
    fn render_hint(&self, text: &str) -> String {
        let arrow = if self.unicode { "→" } else { ">" };
        self.paint(Style::new().dimmed(), &format!("{arrow} {text}"))
    }

    /// Flatten an error's whole cause chain into individual lines, dropping empty and
    /// consecutive-duplicate lines, so an anyhow `.context(..)` wrapper reads as
    /// headline (first line) + detail (the rest).
    fn error_frames(err: &anyhow::Error) -> Vec<String> {
        let mut frames: Vec<String> = Vec::new();
        for cause in err.chain() {
            for line in cause.to_string().lines() {
                let line = line.trim_end();
                if line.is_empty() {
                    continue;
                }
                if frames.last().map(String::as_str) != Some(line) {
                    frames.push(line.to_string());
                }
            }
        }
        frames
    }

    /// Render an error as the Option A block: a red `✗` glyph on the headline, any
    /// further explanation lines dim, and - if a [`Failure`] anywhere in the chain
    /// carries one - a `→ try  <command>` line with the literal fix.
    fn render_error(&self, err: &anyhow::Error) -> String {
        let frames = Self::error_frames(err);
        let glyph = self.mark(Level::Fail);
        let headline = frames
            .first()
            .map(String::as_str)
            .unwrap_or("unknown error");
        let mut out = format!("{glyph} {headline}");
        for detail in frames.iter().skip(1) {
            out.push_str(&format!("\n  {}", self.dim(detail)));
        }
        if let Some(failure) = err.downcast_ref::<Failure>() {
            let arrow = if self.unicode { "→" } else { ">" };
            let label = self.dim(&format!("{arrow} try"));
            out.push_str(&format!("\n  {label}  {}", self.bold(&failure.try_cmd)));
        }
        out
    }

    // --- emitters ---

    /// Write one line to stdout. A failed write is an error the command returns, not one it
    /// drops: `identity new` prints the only copy of a minted key, and a full disk must not
    /// lose it under exit 0. Every emitter below returns this result for the same reason.
    fn emit(&self, line: impl std::fmt::Display) -> anyhow::Result<()> {
        writeln!(anstream::stdout(), "{line}").context(WRITE_FAILED)
    }

    /// A bold title line. Decorative, so `--quiet` drops it.
    pub fn header(&self, text: &str) -> anyhow::Result<()> {
        if self.quiet {
            return Ok(());
        }
        self.emit(self.bold(text))
    }

    pub fn status(&self, level: Level, label: &str, value: &str) -> anyhow::Result<()> {
        self.emit(self.render_status(level, label, value))
    }

    pub fn field(&self, label: &str, value: &str) -> anyhow::Result<()> {
        self.emit(self.render_field(label, value))
    }

    /// A dim `→` next-step suggestion. Guidance chrome, so `--quiet` drops it.
    pub fn hint(&self, text: &str) -> anyhow::Result<()> {
        if self.quiet {
            return Ok(());
        }
        self.emit(self.render_hint(text))
    }

    /// A spacer line. Decorative, so `--quiet` drops it to keep output compact.
    pub fn blank(&self) -> anyhow::Result<()> {
        if self.quiet {
            return Ok(());
        }
        self.emit("")
    }

    /// Emit a pre-composed line verbatim, for command-built tables.
    pub fn line(&self, text: &str) -> anyhow::Result<()> {
        self.emit(text)
    }

    // --- styled fragments, for composing table rows and titles ---

    /// A standalone status glyph colored by level (`✓`/`✗`/`⚠`/`·`), for table cells.
    pub fn mark(&self, level: Level) -> String {
        self.paint(Self::level_style(level), self.glyph(level))
    }

    /// Text colored by level.
    pub fn styled(&self, level: Level, text: &str) -> String {
        self.paint(Self::level_style(level), text)
    }

    /// Bold text (titles, emphasized cells).
    pub fn bold(&self, text: &str) -> String {
        self.paint(Style::new().bold(), text)
    }

    /// Dim text (headers, secondary cells, markers).
    pub fn dim(&self, text: &str) -> String {
        self.paint(Style::new().dimmed(), text)
    }

    /// Print an error to stderr. Under `--json` it is a `{"error": .., "try": ..}` object
    /// (the machine counterpart of the Option A block); otherwise the Option A layout.
    pub fn report(&self, err: &anyhow::Error) {
        let mut stderr = anstream::stderr();
        if self.json {
            let mut obj = serde_json::Map::new();
            obj.insert("error".into(), Self::error_frames(err).join("\n").into());
            if let Some(failure) = err.downcast_ref::<Failure>() {
                obj.insert("try".into(), failure.try_cmd.clone().into());
            }
            let _ = writeln!(stderr, "{}", serde_json::Value::Object(obj));
        } else {
            let _ = writeln!(stderr, "{}", self.render_error(err));
        }
    }

    /// Print a machine payload to stdout as a single line of JSON, for the commands that
    /// honor `--json`. Never carries escape codes; the newline keeps it line-delimited.
    pub fn emit_json(&self, value: &serde_json::Value) -> anyhow::Result<()> {
        self.emit(value)
    }

    /// Gate a destructive action (`unset`, `member rm`, a `set` overwrite) behind a
    /// confirmation, returning whether it should proceed.
    ///
    /// - `--yes` (`assume_yes`) skips the prompt and proceeds.
    /// - On an interactive terminal, print `⚠ question [y/N]` to stderr and read a line
    ///   from stdin; `y`/`yes` (any case) confirms, anything else declines (`Ok(false)`).
    /// - Off an interactive stream (pipe, CI, MCP host, or `--json`) there is no one to
    ///   answer, so refuse with a [`Failure`] whose `try` line is `try_cmd` - the same
    ///   command with `--yes`. The prompt itself is pure chrome that vanishes off a TTY,
    ///   but the safety gate still holds where a silent mistake would be worst.
    pub fn confirm(&self, question: &str, assume_yes: bool, try_cmd: &str) -> anyhow::Result<bool> {
        if assume_yes {
            return Ok(true);
        }
        if !self.can_prompt() {
            return Err(Failure::hinted(
                format!("{question}\nrefusing without confirmation on a non-interactive stream"),
                try_cmd,
            ));
        }
        let mut stderr = anstream::stderr();
        let _ = write!(
            stderr,
            "{} {question} {} ",
            self.mark(Level::Warn),
            self.dim("[y/N]")
        );
        let _ = stderr.flush();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| anyhow::anyhow!("failed to read confirmation: {e}"))?;
        Ok(is_affirmative(&answer))
    }

    /// Offer to take a helpful action the user is expected to accept, e.g. "commit the
    /// roster now?". Unlike [`Ui::confirm`], the default is **yes** (`[Y/n]`): a bare Enter
    /// accepts, only an explicit `n`/`no` declines. Returns `None` off an interactive
    /// stream - there is no one to answer - so the caller falls back to its own path
    /// (typically a refusal explaining the manual command), never acting unprompted.
    pub fn offer(&self, question: &str) -> Option<bool> {
        if !self.can_prompt() {
            return None;
        }
        let mut stderr = anstream::stderr();
        let _ = write!(
            stderr,
            "{} {question} {} ",
            self.mark(Level::Info),
            self.dim("[Y/n]")
        );
        let _ = stderr.flush();
        let mut answer = String::new();
        let read = std::io::stdin().read_line(&mut answer).unwrap_or(0);
        Some(offer_accepted(read, &answer))
    }

    /// Prompt for a line of free text with a shown `[default]`, for the `init` wizard.
    /// Off an interactive stream (pipe, CI, MCP, `--json`) it returns `default` unprompted,
    /// so `init` stays fully non-interactive there. On a TTY, an empty answer (bare Enter)
    /// or EOF also takes the default; otherwise the trimmed input is used.
    pub fn prompt(&self, question: &str, default: &str) -> String {
        if !self.can_prompt() {
            return default.to_string();
        }
        let mut stderr = anstream::stderr();
        let _ = write!(
            stderr,
            "{} {question} {} ",
            self.mark(Level::Info),
            self.dim(&format!("[{default}]"))
        );
        let _ = stderr.flush();
        let mut answer = String::new();
        let read = std::io::stdin().read_line(&mut answer).unwrap_or(0);
        resolve_prompt(read, &answer, default)
    }
}

/// Resolve a text prompt from the bytes read, the raw answer, and the default. Zero bytes
/// (EOF) or a blank line takes the default; otherwise the trimmed answer.
fn resolve_prompt(bytes_read: usize, answer: &str, default: &str) -> String {
    let trimmed = answer.trim();
    if bytes_read == 0 || trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Decide a `[Y/n]` offer from the bytes read and the answer. Zero bytes is EOF - stdin
/// gave no answer (closed or redirected from `/dev/null`), so decline rather than take
/// the yes-default and act with no one having answered. Otherwise only `n`/`no` declines.
fn offer_accepted(bytes_read: usize, answer: &str) -> bool {
    bytes_read != 0 && !is_negative(answer)
}

/// Whether a confirmation answer is a yes: `y` or `yes`, case-insensitive, trimmed.
/// Anything else (including empty input from a bare Enter) declines - the `[y/N]` default.
fn is_affirmative(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Whether an answer explicitly declines a `[Y/n]` offer: `n` or `no`, case-insensitive.
/// Empty (a bare Enter) and anything else take the default - yes - so this returns false.
fn is_negative(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A UI with styling forced on, to assert the ANSI path builds escapes.
    const COLOR: Ui = Ui {
        stdout_tty: true,
        stdin_tty: true,
        color: true,
        unicode: true,
        json: false,
        quiet: false,
    };
    /// A UI as it resolves off a TTY (a pipe / CI / an MCP host): no color, ASCII.
    const PLAIN: Ui = Ui {
        stdout_tty: false,
        stdin_tty: false,
        color: false,
        unicode: false,
        json: false,
        quiet: false,
    };

    #[test]
    fn json_mode_disables_every_chrome_layer() {
        // `--json` forces machine output: no color, no glyphs, no interactive tables,
        // regardless of TTY or CLICOLOR_FORCE.
        let ui = Ui::detect(true, false);
        assert!(ui.json());
        assert!(!ui.interactive());
        assert!(!ui.mark(Level::Ok).contains('\u{1b}'));
        assert_eq!(ui.mark(Level::Ok), "+");
    }

    #[test]
    fn plain_output_has_no_escapes_or_unicode_glyphs() {
        let line = PLAIN.render_status(Level::Ok, "roster", "v1 verified");
        assert!(
            !line.contains('\u{1b}'),
            "plain line carried ANSI: {line:?}"
        );
        assert!(
            line.contains('+'),
            "expected ASCII glyph fallback: {line:?}"
        );
        assert_eq!(line, "  + roster      v1 verified");
    }

    #[test]
    fn colored_output_wraps_the_glyph_in_ansi() {
        let line = COLOR.render_status(Level::Fail, "roster", "unverified");
        assert!(line.contains('\u{1b}'), "expected ANSI escapes: {line:?}");
        assert!(line.contains('✗'), "expected unicode glyph: {line:?}");
    }

    #[test]
    fn plain_error_is_glyph_led_with_no_escapes() {
        let err = anyhow::anyhow!("boom");
        let out = PLAIN.render_error(&err);
        assert!(!out.contains('\u{1b}'), "plain error carried ANSI: {out:?}");
        assert_eq!(out, "x boom");
    }

    #[test]
    fn colored_error_wraps_the_glyph_in_ansi() {
        let err = anyhow::anyhow!("boom");
        let out = COLOR.render_error(&err);
        assert!(out.contains('\u{1b}'), "expected ANSI escapes: {out:?}");
        assert!(out.contains('✗'), "expected unicode glyph: {out:?}");
    }

    #[test]
    fn context_chain_becomes_headline_and_dim_detail() {
        let err = anyhow::anyhow!("root cause").context("high-level failure");
        let out = PLAIN.render_error(&err);
        assert_eq!(out, "x high-level failure\n  root cause");
    }

    #[test]
    fn failure_appends_a_try_line_with_the_command() {
        let err = Failure::hinted("no identity available", "bitfort keygen");
        let out = PLAIN.render_error(&err);
        assert_eq!(out, "x no identity available\n  > try  bitfort keygen");
        // The try command survives an outer context wrapper (downcast finds it in the chain).
        let wrapped = err.context("could not load the local identity");
        let out = PLAIN.render_error(&wrapped);
        assert!(
            out.contains("> try  bitfort keygen"),
            "try line lost: {out:?}"
        );
        assert!(out.starts_with("x could not load the local identity"));
    }

    #[test]
    fn multiline_failure_splits_headline_from_dim_detail() {
        let err = Failure::hinted(
            "the roster does not verify\nits anchor does not match config.toml",
            "bitfort verify",
        );
        let out = PLAIN.render_error(&err);
        assert_eq!(
            out,
            "x the roster does not verify\n  its anchor does not match config.toml\n  > try  bitfort verify"
        );
    }

    #[test]
    fn styled_fragments_are_plain_without_color() {
        assert_eq!(PLAIN.bold("x"), "x");
        assert_eq!(PLAIN.dim("x"), "x");
        assert_eq!(PLAIN.styled(Level::Ok, "x"), "x");
        assert_eq!(PLAIN.mark(Level::Ok), "+");
    }

    #[test]
    fn affirmative_parsing_defaults_to_no() {
        for yes in ["y", "Y", "yes", "YES", " yes\n"] {
            assert!(is_affirmative(yes), "{yes:?} should confirm");
        }
        for no in ["", "\n", "n", "no", "nope", "yeah", "sure"] {
            assert!(!is_affirmative(no), "{no:?} should decline");
        }
    }

    #[test]
    fn confirm_with_yes_flag_proceeds_without_prompting() {
        // --yes short-circuits before any stdin read, even off a TTY.
        assert!(PLAIN
            .confirm("delete?", true, "bitfort unset K --yes")
            .unwrap());
    }

    #[test]
    fn offer_defaults_to_yes() {
        for yes in ["", "\n", "y", "Y", "yes", "sure", "whatever"] {
            assert!(
                !is_negative(yes),
                "{yes:?} should not decline a [Y/n] offer"
            );
        }
        for no in ["n", "N", "no", "NO", " no\n"] {
            assert!(is_negative(no), "{no:?} should decline");
        }
    }

    #[test]
    fn offer_returns_none_off_tty() {
        // No terminal to answer: the caller decides (keeps its own refusal), never acts.
        assert_eq!(PLAIN.offer("commit now?"), None);
    }

    #[test]
    fn prompt_falls_back_to_default_off_tty() {
        // Non-interactive: no prompt, the default is used, so `init` stays scriptable.
        assert_eq!(PLAIN.prompt("Your name?", "eryzhikov"), "eryzhikov");
    }

    #[test]
    fn resolve_prompt_defaults_on_blank_or_eof() {
        assert_eq!(resolve_prompt(0, "", "development"), "development"); // EOF
        assert_eq!(resolve_prompt(1, "\n", "development"), "development"); // bare Enter
        assert_eq!(resolve_prompt(4, "  \n", "development"), "development"); // whitespace
        assert_eq!(resolve_prompt(5, " prod\n", "development"), "prod"); // trimmed input
        assert_eq!(resolve_prompt(8, "staging\n", "development"), "staging");
    }

    #[test]
    fn offer_eof_declines_rather_than_defaulting_yes() {
        // stdin closed / redirected from /dev/null (0 bytes read) must NOT auto-accept a
        // [Y/n] offer - otherwise it acts with no human having answered.
        assert!(!offer_accepted(0, ""), "EOF must decline, not default yes");
        assert!(
            offer_accepted(1, "\n"),
            "a bare Enter takes the yes default"
        );
        assert!(offer_accepted(2, "y\n"));
        assert!(!offer_accepted(3, "no\n"));
        assert!(!offer_accepted(2, "n\n"));
    }

    /// stdout on a terminal, stdin on a pipe: the piped bytes would otherwise answer every
    /// prompt. No question is asked, so the gate holds and the wizard takes its defaults.
    #[test]
    fn a_piped_stdin_answers_no_prompt_even_on_a_terminal() {
        const PIPED_STDIN: Ui = Ui {
            stdout_tty: true,
            stdin_tty: false,
            color: false,
            unicode: true,
            json: false,
            quiet: false,
        };
        assert!(PIPED_STDIN.interactive(), "layout still follows stdout");
        assert!(!PIPED_STDIN.can_prompt());
        assert_eq!(PIPED_STDIN.offer("commit now?"), None);
        assert_eq!(PIPED_STDIN.prompt("Your name?", "eryzhikov"), "eryzhikov");
        assert!(PIPED_STDIN
            .confirm("delete?", false, "bitfort unset K --yes")
            .is_err());
    }

    #[test]
    fn confirm_off_tty_refuses_with_a_try_line() {
        // No terminal to answer the prompt: refuse, carrying the --yes fix command.
        let err = PLAIN
            .confirm("delete?", false, "bitfort unset K --yes")
            .unwrap_err();
        let out = PLAIN.render_error(&err);
        assert!(out.contains("delete?"), "question lost: {out:?}");
        assert!(
            out.contains("> try  bitfort unset K --yes"),
            "try line lost: {out:?}"
        );
    }

    #[test]
    fn styled_fragments_carry_ansi_with_color() {
        assert!(COLOR.bold("x").contains('\u{1b}'));
        let mark = COLOR.mark(Level::Fail);
        assert!(mark.contains('\u{1b}'), "expected ANSI: {mark:?}");
        assert!(mark.contains('✗'), "expected unicode glyph: {mark:?}");
    }
}
