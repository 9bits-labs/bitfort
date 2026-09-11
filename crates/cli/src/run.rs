//! The `bitfort run` engine: inject decrypted secrets into a child process, forward
//! signals, and propagate the child's exit code (docs/SPEC.md §7). Secrets win over
//! inherited env vars; the parent's plaintext buffers are zeroized right after spawn.
//!
//! On Unix the child runs in its own process group with the terminal handed to it, which
//! is what a wrapper has to do to stay out of the way: a terminal signal (Ctrl-C, Ctrl-Z)
//! then reaches the child once, from the kernel, instead of once from the kernel and again
//! from this process. `bitfort` keeps forwarding a signal aimed at itself, so
//! `kill <bitfort>` still stops the child.

use std::collections::BTreeMap;
use std::process::{Child, Command, Stdio};

use anyhow::{anyhow, Context, Result};
use bitfort_core::keystore;
use zeroize::Zeroize;

/// Build the child command, inject `vars`, run it, and return the code the CLI should
/// exit with. `clean` starts from a minimal environment (PATH + HOME) instead of
/// inheriting the parent's; secrets are overlaid last so they always win.
///
/// `vars` has already been screened by [`crate::commands::refuse_process_control_vars`], which
/// every command that turns vault contents into an environment shares.
pub fn exec(vars: BTreeMap<String, String>, clean: bool, command: &[String]) -> Result<i32> {
    let vars = Plaintext(vars);
    // Opened before anything is spawned. Handlers used to be installed after `spawn`
    // returned, leaving a window - measured at 16 to 54 us - in which a SIGTERM took
    // bitfort's default action, killed it, and orphaned a child holding every secret.
    let session = Session::open()?;

    let spawned = spawn(&vars.0, clean, command, session.child_terminal());
    // The child holds its own copy of the environment by now, and on a failure it never
    // will - either way this process is finished with the plaintext. Dropping here rather
    // than at the end of the function keeps the scrub as early as it has always been.
    drop(vars);
    session.supervise(spawned?)
}

/// The decrypted values, scrubbed when they go out of scope.
///
/// A `Drop` rather than a call at the end of `exec`, because the call kept missing an error
/// path: first the ones inside `spawn`, then the `?` on `Session::open`. This is the sole
/// owner of the plaintext (`commands::run` hands over the vault's map), so nothing else can
/// keep a copy alive past this scope (invariant 6).
struct Plaintext(BTreeMap<String, String>);

impl Drop for Plaintext {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

/// Build the command and start the child.
fn spawn(
    vars: &BTreeMap<String, String>,
    clean: bool,
    command: &[String],
    terminal: Option<Handover>,
) -> Result<Child> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("no command given to `run`"))?;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if clean {
        // Minimal env: keep PATH (so the program resolves) and HOME, then secrets.
        cmd.env_clear();
        for key in ["PATH", "HOME"] {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }
    }
    // The headless recipe (docs/SPEC.md §7.1) puts the private keys in this process's own
    // environment, and without `--clean` the child inherits everything. A build step that
    // read `BITFORT_IDENTITY` would hold a key that decrypts every vault revision in git
    // history, for every environment that member belongs to (invariant 6, finding 1.5).
    for key in [keystore::ENV_ENC, keystore::ENV_SIGN, keystore::ENV_FILE] {
        cmd.env_remove(key);
    }
    for (key, value) in vars {
        cmd.env(key, value);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: the closure runs in the child between `fork` and `exec`, where only
        // async-signal-safe work is allowed. It calls four libc functions and allocates
        // nothing.
        unsafe {
            cmd.pre_exec(move || {
                enter_own_process_group(terminal);
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = terminal;

    cmd.spawn()
        .with_context(|| format!("failed to spawn `{program}`"))
}

/// Child side of the process-group move, run between `fork` and `exec`.
///
/// The parent makes the same two calls after `spawn` returns. Doing it on both sides is
/// what removes the race: whichever runs first wins, and the other is a no-op (or an
/// `EACCES` the parent ignores, which only means the child got there first).
#[cfg(unix)]
fn enter_own_process_group(terminal: Option<Handover>) {
    // SAFETY: async-signal-safe libc calls, no allocation, no shared state.
    unsafe {
        libc::setpgid(0, 0);
        if let Some(Handover { fd, sigttou }) = terminal {
            // The new group is in the background until this call lands, so `tcsetpgrp`
            // would raise SIGTTOU and stop the child before it ever ran. `Session::open`
            // already ignored it process-wide, which is what carries this call - so what
            // is put back afterwards is the disposition from *before* `run` touched it.
            // Restoring what this closure reads instead would leave the exec'd program
            // with SIGTTOU ignored, because `exec` preserves SIG_IGN.
            libc::tcsetpgrp(fd, libc::getpid());
            libc::signal(libc::SIGTTOU, sigttou);
        }
    }
}

/// What the child needs to take the terminal: the fd, and the SIGTTOU disposition to leave
/// the exec'd program with.
#[cfg(unix)]
#[derive(Clone, Copy)]
struct Handover {
    fd: std::os::unix::io::RawFd,
    sigttou: libc::sighandler_t,
}

/// Off Unix there is no terminal to hand over, and `spawn` never gets a `Some`.
#[cfg(not(unix))]
#[derive(Clone, Copy)]
struct Handover;

/// What `run` sets up around the child: the installed signal handlers, and the terminal
/// the child is given for the duration.
#[cfg(unix)]
struct Session {
    signals: signal_hook::iterator::Signals,
    terminal: Option<Terminal>,
}

/// The controlling terminal, and the process group that held it when `run` started.
///
/// Handing the terminal to the child is not decoration: a process group that is not the
/// terminal's foreground group is stopped by SIGTTIN the moment it reads stdin, which is
/// what a dev server does for its keyboard shortcuts. Dropping this puts the terminal back,
/// on every path out of `run`.
#[cfg(unix)]
struct Terminal {
    fd: std::os::unix::io::RawFd,
    previous: libc::pid_t,
    /// The SIGTTOU disposition from before `run` ignored it, for the child to exec with.
    sigttou: libc::sighandler_t,
    /// The group the terminal was last handed to, or `0`. What makes it safe to put the
    /// terminal back only when it is still where this process put it.
    handed_to: std::cell::Cell<libc::pid_t>,
}

#[cfg(unix)]
impl Terminal {
    /// The terminal `run` is entitled to hand over, if any.
    fn claimable(sigttou: libc::sighandler_t) -> Option<Self> {
        let fd = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
            .into_iter()
            .find(|fd| unsafe { libc::isatty(*fd) } == 1)?;
        let previous = unsafe { libc::tcgetpgrp(fd) };
        // Only a terminal this process already holds. Under `bitfort run ... &` the
        // foreground group is the shell's, and taking it would steal the user's terminal.
        (previous >= 0 && previous == unsafe { libc::getpgrp() }).then_some(Self {
            fd,
            previous,
            sigttou,
            handed_to: std::cell::Cell::new(0),
        })
    }

    /// What the child needs to take the terminal itself, between `fork` and `exec`.
    fn handover(&self) -> Handover {
        Handover {
            fd: self.fd,
            sigttou: self.sigttou,
        }
    }

    /// Whether this process is the terminal's foreground group right now.
    fn is_foreground(&self) -> bool {
        unsafe { libc::tcgetpgrp(self.fd) == libc::getpgrp() }
    }

    fn give_to(&self, pgid: libc::pid_t) {
        // SIGTTOU is ignored for the whole of `run` (see `Session::open`), so this cannot
        // stop us once the child is the foreground group.
        unsafe { libc::tcsetpgrp(self.fd, pgid) };
        self.handed_to.set(pgid);
    }

    /// Put the terminal back where it was, but only if it is still where this process put
    /// it. After `bg` the shell has taken it back for its own prompt, and handing it to
    /// `previous` there would take it away from the user mid-keystroke.
    fn restore(&self) {
        let handed_to = self.handed_to.get();
        if handed_to != 0 && unsafe { libc::tcgetpgrp(self.fd) } == handed_to {
            unsafe { libc::tcsetpgrp(self.fd, self.previous) };
            self.handed_to.set(0);
        }
    }
}

#[cfg(unix)]
impl Drop for Terminal {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(unix)]
impl Session {
    fn open() -> Result<Self> {
        use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};

        let signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT])
            .context("failed to install signal handlers")?;
        // Every `tcsetpgrp` below runs from a background process group once the child holds
        // the terminal, and the default action for the SIGTTOU that raises is to stop. The
        // disposition it replaces travels to the child, which must not inherit the ignore.
        // SAFETY: setting a disposition on this process, before any thread is started.
        let sigttou = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        Ok(Self {
            signals,
            terminal: Terminal::claimable(sigttou),
        })
    }

    /// What the child needs to claim the terminal between `fork` and `exec`.
    fn child_terminal(&self) -> Option<Handover> {
        self.terminal.as_ref().map(Terminal::handover)
    }

    /// Run the child to completion and return the code the CLI should exit with.
    fn supervise(self, child: Child) -> Result<i32> {
        let Self {
            mut signals,
            terminal,
        } = self;
        let pid = child.id() as libc::pid_t;

        // The parent half of the move the child also makes; see `enter_own_process_group`.
        unsafe { libc::setpgid(pid, pid) };
        // Signal the child's whole group, so a child that spawns its own tree is covered -
        // but only once the group is confirmed to be the child's. Otherwise `-pid` names
        // bitfort's own group and the forwarder would signal itself, forever.
        let target = if unsafe { libc::getpgid(pid) } == pid {
            -pid
        } else {
            pid
        };
        if let Some(t) = &terminal {
            t.give_to(pid);
        }

        let handle = signals.handle();
        let forwarder = std::thread::spawn(move || {
            for sig in signals.forever() {
                // A terminal signal reached the child directly - it is the foreground
                // group. What arrives here is aimed at bitfort itself (`kill <pid>`, or a
                // SIGHUP on hangup), and the child should see it too.
                //
                // Best-effort: the child may have already exited (ESRCH), which is fine.
                unsafe { libc::kill(target, sig) };
            }
        });

        let outcome = wait_for(pid, target, terminal.as_ref());
        handle.close();
        let _ = forwarder.join();
        outcome
    }
}

/// Wait for the child, following it into a stop when there is a terminal to follow it for.
///
/// Ctrl-Z reaches the child's group and not ours now, so nothing would otherwise stop this
/// process, and `bitfort` would sit in `waitpid` holding the terminal for a stopped child.
/// With a terminal it therefore gives the terminal back, stops alongside the child - the
/// shell sees one stopped job - and picks both up again when it is continued.
///
/// **Only** with a terminal. Off one (a pipe, CI, an MCP host) nothing put this process in a
/// job and nothing will continue it, so stopping here would strand a stopped child holding
/// every secret, take the signal forwarder down with it, and leave `kill <bitfort>` with no
/// effect. `WUNTRACED` is therefore not even asked for there, and `waitpid` blocks through a
/// stop exactly as it always did.
#[cfg(unix)]
fn wait_for(pid: libc::pid_t, target: libc::pid_t, terminal: Option<&Terminal>) -> Result<i32> {
    let flags = if terminal.is_some() {
        libc::WUNTRACED
    } else {
        0
    };
    loop {
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, flags) };
        if waited < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(anyhow::Error::new(err).context("failed to wait for child"));
        }
        if libc::WIFSTOPPED(status) {
            if let Some(t) = terminal {
                t.restore();
                // SAFETY: stopping this process. Execution resumes here on SIGCONT.
                unsafe { libc::raise(libc::SIGTSTP) };
                // `fg` makes this process the foreground group again; `bg` leaves the
                // terminal with the shell. Only the first may hand it to the child, or a
                // backgrounded job would take the user's keystrokes from their prompt.
                if t.is_foreground() {
                    t.give_to(pid);
                }
                unsafe { libc::kill(target, libc::SIGCONT) };
            }
            continue;
        }
        if libc::WIFSIGNALED(status) {
            // Unix convention: a process killed by signal N exits as 128 + N.
            return Ok(128 + libc::WTERMSIG(status));
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
    }
}

#[cfg(not(unix))]
struct Session;

#[cfg(not(unix))]
impl Session {
    fn open() -> Result<Self> {
        Ok(Self)
    }

    fn child_terminal(&self) -> Option<Handover> {
        None
    }

    fn supervise(self, mut child: Child) -> Result<i32> {
        let status = child.wait().context("failed to wait for child")?;
        Ok(status.code().unwrap_or(1))
    }
}
