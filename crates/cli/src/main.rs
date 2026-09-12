//! `bitfort` CLI entry point. This is the hot-path binary (invoked on every
//! `bitfort run`, in CI, in shell chains), so it must not pull in any GUI or
//! webview dependency. The full command surface is specified in docs/SPEC.md §6.

mod commands;
mod run;
mod ui;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::builder::styling::{AnsiColor, Style, Styles};
use clap::{CommandFactory, Parser, Subcommand};

/// clap help styling coordinated with the wordmark: section headers and usage in the same
/// cyan as the banner, and command/flag names (literals) in cyan too, so `bitfort --help`
/// reads as one design. Placeholders keep the terminal's plain default foreground - no
/// fixed color and no dim, since either can fall below contrast on a light or dark theme,
/// and legibility beats a secondary tint. clap disables all of this off a terminal and
/// under `NO_COLOR` on its own.
const HELP_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Cyan.on_default().bold())
    .usage(AnsiColor::Cyan.on_default().bold())
    .literal(AnsiColor::Cyan.on_default())
    .placeholder(Style::new());

/// Slant-art wordmark shown above `--version`, `--help`, and `help` on a terminal. Pure
/// ASCII so it renders in any font; [`styled_banner`] tints it (following `NO_COLOR`). The
/// literal opens on its own line so all five rows align at the left margin here in the
/// source; the leading newline is stripped before printing.
const BANNER: &str = r"
    ____  _ __  ______           __
   / __ )(_) /_/ ____/___  _____/ /_
  / __  / / __/ /_  / __ \/ ___/ __/
 / /_/ / / /_/ __/ / /_/ / /  / /_
/_____/_/\__/_/    \____/_/   \__/";

/// Render the wordmark, in bold cyan when `color` is set (a hue distinct from the status
/// palette, so it reads as branding not a status), plain otherwise. The source-readability
/// leading newline is stripped, but not the art's leading spaces.
fn styled_banner(color: bool) -> String {
    let art = BANNER.trim_start_matches('\n');
    if color {
        let style = anstyle::Style::new()
            .bold()
            .fg_color(Some(anstyle::AnsiColor::Cyan.into()));
        format!("{style}{art}{style:#}")
    } else {
        art.to_string()
    }
}

/// Print the wordmark above clap's help/version output when that is what the parse resolved
/// to, and only on a terminal - so a piped or scripted `bitfort --version` stays a clean,
/// parseable `bitfort 0.1.0`. Keying off clap's own [`ErrorKind`](clap::error::ErrorKind)
/// (not a hand-rolled arg scan) means a wrapped child's `--help` (`bitfort run tool --help`,
/// which parses as a `run` argument) never trips it, and a bad flag prints its error with no
/// banner. Color follows `NO_COLOR`.
fn print_banner_before_help(err: &clap::Error) {
    use clap::error::ErrorKind;
    let is_help_or_version = matches!(
        err.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            | ErrorKind::DisplayVersion
    );
    if is_help_or_version && std::io::stdout().is_terminal() {
        let color = std::env::var_os("NO_COLOR").is_none();
        println!("{}\n", styled_banner(color));
    }
}

#[derive(Parser)]
#[command(
    name = "bitfort",
    version,
    about = "Encrypted project secrets, injected at run time",
    styles = HELP_STYLES,
    // Bare `bitfort` shows the help (with the wordmark above it) rather than a terse error.
    arg_required_else_help = true
)]
struct Cli {
    /// Environment to act on (default: config `default_env`).
    #[arg(long, global = true)]
    env: Option<String>,

    /// Start directory for locating `.bitfort/` (default: current directory).
    #[arg(long, global = true)]
    dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of human text.
    ///
    /// Honored by status, list, verify, anchor, member list, env list and identity new. Other
    /// commands keep their text output. Under --json no command asks a question: a
    /// confirmation needs --yes, and init takes its defaults. The terminal guards on export
    /// and identity new still refuse a terminal. Errors become `{"error": .., "try": ..}` on stderr, except
    /// argument errors.
    #[arg(long, global = true)]
    json: bool,

    /// Skip the confirmation prompt on destructive commands.
    ///
    /// Applies to `unset`, `member rm`, and a `set` that overwrites an existing key; required
    /// to run them off an interactive terminal, where there is no one to answer.
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Drop decorative output, keeping the facts, data, and errors.
    ///
    /// Suppresses titles, next-step hints, and spacer lines.
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum EnvCommand {
    /// Create a new environment (own roster + vault, same trust anchor).
    Add {
        /// Name of the environment to create (e.g. `production`).
        name: String,
    },
    /// List environments and their verification status.
    List,
}

#[derive(Subcommand)]
enum MemberCommand {
    /// Add the identity from an invite blob to the environment's roster.
    Add {
        /// The `bfinvite1:...` blob produced by the new developer's `keygen`.
        invite: String,
        /// Add as a maintainer (can sign roster changes) instead of a plain member.
        #[arg(long)]
        maintainer: bool,
        /// Override the display name suggested in the invite.
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove a member by name and re-encrypt without their key.
    Rm {
        /// Display name of the member to remove.
        name: String,
    },
    /// List the environment's roster and verification status.
    List,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Mint a fresh identity and print its secrets, to provision a CI or container member.
    New {
        /// Display name embedded in the invite blob.
        #[arg(long)]
        name: Option<String>,
        /// Print to a terminal anyway (default: refuse, to avoid scrollback exposure).
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Show a one-screen readout of the environment's security posture and next step.
    Status,
    /// Create `.bitfort/`, generate the initializer identity, and pin the trust anchor.
    Init {
        /// Display name recorded for the initializer in the roster.
        #[arg(long)]
        name: Option<String>,
    },
    /// Generate a local identity if none exists (idempotent) and print the invite blob.
    Keygen {
        /// Suggested display name embedded in the invite.
        #[arg(long)]
        name: Option<String>,
    },
    /// Provision an identity for a machine that has no keyring (CI, containers).
    Identity {
        #[command(subcommand)]
        action: IdentityCommand,
    },
    /// Migrate an existing `.env`-format file into the vault.
    ///
    /// Quoting follows the dotenv convention every loader uses, so a value is stored as the
    /// app was already reading it: a double-quoted value is un-escaped (`\n`, `\t`, `\\`,
    /// `\"`, `\xNN`, `\uNNNN`), and a single-quoted one is literal. Check an imported value
    /// with `bitfort get` before deleting the source.
    Import {
        /// Path to the dotenv-format file to import.
        path: PathBuf,
        /// Delete the source file after a successful import.
        #[arg(long)]
        delete_source: bool,
    },
    /// Decrypt and print every secret as dotenv/shell/json (exposes all plaintext).
    Export {
        /// Output format.
        #[arg(long, value_enum, default_value = "dotenv")]
        format: commands::ExportFormat,
        /// Print to a terminal anyway (default: refuse, to avoid scrollback exposure).
        #[arg(long)]
        force: bool,
    },
    /// Verify the roster: signature chain, anchor pin, env match, anti-rollback.
    Verify {
        /// Exit non-zero on any verification failure (CI gate).
        #[arg(long)]
        strict: bool,
    },
    /// Show the trust anchor (hex + 6-word phrase) to publish out-of-band.
    Anchor {
        /// Emit a plain, copy-paste block for a README or Slack instead of styled output.
        #[arg(long)]
        share: bool,
    },
    /// Add or update a secret. Prompts for the value if `KEY` has no `=VALUE`.
    Set {
        /// `KEY` (prompt for value) or `KEY=VALUE`.
        assignment: String,
    },
    /// Decrypt and print one secret value (exposes plaintext).
    Get {
        /// Secret name to print.
        key: String,
    },
    /// Remove a secret and re-encrypt.
    Unset {
        /// Secret name to remove.
        key: String,
    },
    /// List secret keys (never values).
    List,
    /// Manage environments (each has its own roster and vault).
    Env {
        #[command(subcommand)]
        action: EnvCommand,
    },
    /// Manage the signed member roster of an environment.
    Member {
        #[command(subcommand)]
        action: MemberCommand,
    },
    /// Re-encrypt the vault to the current roster with fresh ciphertext.
    Rotate,
    /// Merge a git-conflicted vault into one clean re-encrypted vault.
    Resolve {
        /// On a key changed by both sides, keep our value.
        #[arg(long, conflicts_with = "theirs")]
        ours: bool,
        /// On a key changed by both sides, keep their value.
        #[arg(long)]
        theirs: bool,
    },
    /// Decrypt secrets, inject them into a child process, and run it.
    Run {
        /// Start from a minimal environment instead of inheriting the parent's.
        #[arg(long)]
        clean: bool,
        /// The command and its arguments, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
        command: Vec<String>,
    },
    /// Print a shell completion script (e.g. `bitfort completions zsh > _bitfort`).
    Completions {
        /// Target shell.
        shell: clap_complete::Shell,
    },
    /// Print the man page in roff (e.g. `bitfort man > bitfort.1`).
    Man,
}

fn main() -> ExitCode {
    // Rust starts with SIGPIPE ignored, so writing to a closed consumer returns EPIPE and the
    // stdout machinery panics: `bitfort export | head` printed a Rust panic at a normal
    // shell pipeline. Restore the default disposition, which is what every other CLI does -
    // the process dies quietly on the signal instead.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    // Parse by hand so the wordmark can print above clap's own help/version output (on a
    // terminal) before clap prints it and exits.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            print_banner_before_help(&err);
            err.exit();
        }
    };
    let start = cli.dir.clone();
    let env = cli.env.clone();
    let yes = cli.yes;
    let ui = ui::Ui::detect(cli.json, cli.quiet);

    let result = match cli.command {
        Command::Status => commands::status(&ui, start.as_deref(), env.as_deref()).map(|_| 0),
        Command::Init { name } => commands::init(&ui, start.as_deref(), name).map(|_| 0),
        Command::Keygen { name } => commands::keygen(&ui, name).map(|_| 0),
        Command::Identity { action } => match action {
            IdentityCommand::New { name, force } => {
                commands::identity_new(&ui, name, force).map(|_| 0)
            }
        },
        Command::Import {
            path,
            delete_source,
        } => commands::import(start.as_deref(), env.as_deref(), &path, delete_source).map(|_| 0),
        Command::Export { format, force } => {
            commands::export(&ui, start.as_deref(), env.as_deref(), format, force).map(|_| 0)
        }
        Command::Verify { strict } => {
            commands::verify(&ui, start.as_deref(), env.as_deref(), strict)
        }
        Command::Anchor { share } => commands::anchor(&ui, start.as_deref(), share).map(|_| 0),
        Command::Set { assignment } => {
            commands::set(&ui, start.as_deref(), env.as_deref(), &assignment, yes).map(|_| 0)
        }
        Command::Get { key } => commands::get(start.as_deref(), env.as_deref(), &key).map(|_| 0),
        Command::Unset { key } => {
            commands::unset(&ui, start.as_deref(), env.as_deref(), &key, yes).map(|_| 0)
        }
        Command::List => commands::list(&ui, start.as_deref(), env.as_deref()).map(|_| 0),
        Command::Env { action } => match action {
            EnvCommand::Add { name } => commands::env_add(start.as_deref(), &name).map(|_| 0),
            EnvCommand::List => commands::env_list(&ui, start.as_deref()).map(|_| 0),
        },
        Command::Member { action } => match action {
            MemberCommand::Add {
                invite,
                maintainer,
                name,
            } => commands::member_add(start.as_deref(), env.as_deref(), &invite, maintainer, name)
                .map(|_| 0),
            MemberCommand::Rm { name } => {
                commands::member_rm(&ui, start.as_deref(), env.as_deref(), &name, yes).map(|_| 0)
            }
            MemberCommand::List => {
                commands::member_list(&ui, start.as_deref(), env.as_deref()).map(|_| 0)
            }
        },
        Command::Rotate => commands::rotate(start.as_deref(), env.as_deref()).map(|_| 0),
        Command::Resolve { ours, theirs } => {
            let side = ours
                .then_some(commands::Side::Ours)
                .or(theirs.then_some(commands::Side::Theirs));
            commands::resolve(start.as_deref(), env.as_deref(), side).map(|_| 0)
        }
        Command::Run { clean, command } => {
            commands::run(start.as_deref(), env.as_deref(), clean, &command)
        }
        // Structural commands: generated from the clap definition itself, no project needed.
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "bitfort",
                &mut std::io::stdout(),
            );
            Ok(0)
        }
        Command::Man => clap_mangen::Man::new(Cli::command())
            .render(&mut std::io::stdout())
            .map(|_| 0)
            .map_err(anyhow::Error::from),
    };

    match result {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            ui.report(&e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wordmark keys off clap's classification of the parse, so assert clap resolves each
    /// case to the kind (help/version vs a normal parse) the banner logic depends on.
    #[test]
    fn help_and_version_are_classified_but_wrapped_child_flags_are_not() {
        use clap::error::ErrorKind;
        let kind = |a: &[&str]| Cli::try_parse_from(a).err().map(|e| e.kind());
        assert_eq!(kind(&["bitfort", "--help"]), Some(ErrorKind::DisplayHelp));
        assert_eq!(
            kind(&["bitfort", "member", "-h"]),
            Some(ErrorKind::DisplayHelp)
        );
        assert_eq!(
            kind(&["bitfort", "help", "run"]),
            Some(ErrorKind::DisplayHelp)
        );
        assert_eq!(
            kind(&["bitfort", "--version"]),
            Some(ErrorKind::DisplayVersion)
        );
        assert_eq!(
            kind(&["bitfort"]), // bare -> help via arg_required_else_help
            Some(ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand)
        );
        // A wrapped child's `--help` parses as a `run` argument, not a help request.
        assert!(Cli::try_parse_from(["bitfort", "run", "tool", "--help"]).is_ok());
        // A bad flag value is its own error kind - no banner.
        assert_eq!(
            kind(&["bitfort", "export", "--format", "help"]),
            Some(ErrorKind::InvalidValue)
        );
    }

    #[test]
    fn banner_color_follows_no_color() {
        // Plain form carries no escape bytes (the NO_COLOR / non-terminal path); the colored
        // form wraps the same art in ANSI. Both keep the art's distinctive bottom-left run.
        let plain = styled_banner(false);
        assert!(
            !plain.contains('\u{1b}'),
            "plain banner carried ANSI: {plain:?}"
        );
        assert!(plain.contains("/_____/"));
        let colored = styled_banner(true);
        assert!(colored.contains('\u{1b}'), "colored banner missing ANSI");
        assert!(colored.contains("/_____/"));
    }
}
