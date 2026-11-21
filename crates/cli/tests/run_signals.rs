//! Signal, job-control, and exit-code behavior for `bitfort run` (docs/SPEC.md §7). Kept
//! in its own test binary because these tests spawn the CLI as a raw child, send it real
//! signals, and drive it through a pty - process-level manipulation best isolated from the
//! assert_cmd suite.
#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::{init_project, open_pty};

/// A process terminated by a signal exits as `128 + signal`. Here the child signals
/// itself, so no delivery to `bitfort` is involved - this isolates the mapping.
#[test]
fn child_killed_by_signal_maps_to_128_plus_signal() {
    let f = init_project();
    common::bf(f.dir.path(), &f.id)
        .args(["run", "--", "sh", "-c", "kill -TERM $$"])
        .assert()
        .code(143); // 128 + SIGTERM(15)
}

/// A signal delivered to `bitfort` itself must be forwarded to the child, and `bitfort`
/// must wait for the child and then exit 128 + signal - not die immediately and orphan it.
#[test]
fn signal_to_bitfort_is_forwarded_to_child() {
    let f = init_project();

    // Long-running child so there's a window to signal bitfort while it waits.
    let mut child = common::raw_bf(f.dir.path(), &f.id)
        .args(["run", "--", "sh", "-c", "sleep 10"])
        .spawn()
        .unwrap();

    // Give bitfort time to spawn the child and install its signal handlers.
    sleep(Duration::from_millis(750));

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success(), "failed to signal bitfort");

    // bitfort should exit promptly (forwarded TERM kills the sleep), well before 10s.
    let status = exit_within(&mut child, Duration::from_secs(5));
    assert_eq!(status.code(), Some(143), "expected 128 + SIGTERM(15)");
}

/// The child runs in a process group of its own, which is what keeps a terminal signal
/// from being delivered to it twice: once by the kernel, to every process in the
/// foreground group, and again by bitfort's forwarder.
///
/// Asserted structurally rather than by counting signals: a shell coalesces two SIGINTs
/// that arrive while one trap is already pending, so a count cannot tell the two cases
/// apart. Whether the child shares bitfort's group can.
#[test]
fn the_child_runs_in_its_own_process_group() {
    let f = init_project();

    let out = common::bf(f.dir.path(), &f.id)
        .args(["run", "--", "sh", "-c", "echo $$; ps -o pgid= -p $$"])
        .output()
        .unwrap();
    assert!(out.status.success(), "run failed: {out:?}");

    let text = String::from_utf8(out.stdout).unwrap();
    let mut lines = text.split_whitespace();
    let child_pid: i32 = lines.next().unwrap().parse().unwrap();
    let child_pgid: i32 = lines.next().unwrap().parse().unwrap();

    assert_eq!(
        child_pid, child_pgid,
        "the child should lead its own process group"
    );
    assert_ne!(
        child_pgid,
        our_process_group(),
        "the child should not share the group that launched bitfort"
    );
}

/// The process group of this test runner, which `bitfort` inherits.
fn our_process_group() -> i32 {
    unsafe { libc::getpgrp() }
}

/// An interactive child still owns the terminal. Moving it to its own process group makes
/// it a *background* group, and a background process that reads the terminal is stopped by
/// SIGTTIN - so `bitfort run -- npm run dev` would hang the moment the dev server read its
/// keyboard shortcuts. `run` hands the terminal over to close that; this proves it.
#[test]
fn a_child_on_a_terminal_can_still_read_stdin() {
    let f = init_project();
    let mut cmd = common::raw_bf(f.dir.path(), &f.id);
    cmd.args(["run", "--", "sh", "-c", "read line; echo got:$line"]);
    let transcript = transcript_on_terminal(cmd, b"ping\n", "got:ping");
    assert!(
        transcript.contains("got:ping"),
        "the child never read the terminal (SIGTTIN would stop it): {transcript:?}"
    );
}

/// When the child exits, `run` hands the terminal back to the group that held it. Otherwise
/// the shell that started `bitfort` is a background group on its own terminal, and its next
/// read from the terminal stops it with SIGTTIN.
#[test]
fn the_terminal_goes_back_to_the_group_that_held_it() {
    let f = init_project();

    // A shell leads the terminal's session, as a login shell does, and runs `bitfort` in its
    // own group. When `run` returns, the shell prints the terminal's foreground group and its
    // own group.
    let mut cmd = common::with_identity("sh", f.dir.path(), &f.id);
    cmd.args([
        "-c",
        r#""$0" run -- true; printf 'groups %s %s end\n' $(ps -o tpgid= -o pgid= -p $$)"#,
    ])
    .arg(assert_cmd::cargo::cargo_bin("bitfort"));
    let transcript = transcript_on_terminal(cmd, b"", " end");
    let groups: Vec<&str> = transcript
        .split("groups")
        .nth(1)
        .unwrap_or_else(|| panic!("the shell printed no groups: {transcript:?}"))
        .split_whitespace()
        .take(2)
        .collect();
    assert_eq!(
        groups[0], groups[1],
        "the terminal's foreground group is not the shell's: {transcript:?}"
    );
}

/// A signal aimed at `bitfort` goes to the child's whole process group. A shell killed while
/// it waits for a command leaves that command running after `bitfort` has exited, with every
/// secret in its environment.
#[test]
fn a_signal_to_bitfort_reaches_the_whole_group_of_the_child() {
    let f = init_project();
    let mut bitfort = common::raw_bf(f.dir.path(), &f.id)
        .args(["run", "--", "sh", "-c", "sleep 30 & echo $!; wait"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(bitfort.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let grandchild: libc::pid_t = line.trim().parse().unwrap();

    assert_eq!(
        unsafe { libc::kill(bitfort.id() as libc::pid_t, libc::SIGTERM) },
        0,
        "failed to signal bitfort"
    );
    let status = exit_within(&mut bitfort, Duration::from_secs(5));
    assert_eq!(status.code(), Some(143), "expected 128 + SIGTERM(15)");

    // Signal 0 only checks that the process still exists.
    let deadline = Instant::now() + Duration::from_secs(5);
    while unsafe { libc::kill(grandchild, 0) } == 0 {
        if Instant::now() >= deadline {
            unsafe { libc::kill(grandchild, libc::SIGKILL) };
            panic!("the child's own child outlived `bitfort run`");
        }
        sleep(Duration::from_millis(50));
    }
}

/// Run `cmd` with a new pty as its stdio and as its *controlling* terminal, in a session of
/// its own, write `input` to the terminal, and return what the terminal shows until `needle`
/// appears or 10 s pass.
///
/// Without a controlling terminal there is no foreground process group, `tcsetpgrp` fails
/// with ENOTTY, and SIGTTIN is never raised either - a test would pass without proving
/// anything.
fn transcript_on_terminal(mut cmd: Command, input: &[u8], needle: &str) -> String {
    let (master, slave) = open_pty();
    cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    // Runs after std has dup2'd the stdio fds, so fd 0 is the pty slave.
    //
    // SAFETY: the closure runs between fork and exec and calls only async-signal-safe
    // libc functions.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    // Only the child holds the slave now; keeping it open here would stop the reads below
    // from ever seeing EOF.
    drop(slave);

    let mut master = std::fs::File::from(master);
    master.write_all(input).unwrap();
    let transcript = read_until(&mut master, needle, Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();
    transcript
}

/// Wait for `child` to exit, and fail the test if it still runs after `budget`.
fn exit_within(child: &mut Child, budget: Duration) -> ExitStatus {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "bitfort did not exit after being signaled"
        );
        sleep(Duration::from_millis(50));
    }
}

/// Off a terminal there is no job control to join. Nothing put `bitfort` in a job and
/// nothing will continue it, so stopping alongside a stopped child would strand a stopped
/// child holding every secret, take the signal forwarder down with it, and leave
/// `kill <bitfort>` with no effect. It must keep waiting instead, as it always did.
///
/// `bitfort` is put in a process group of its own here, but the test runner stays in the
/// same session, so the group is *not* orphaned - an orphaned group discards SIGTSTP, and
/// the test would pass without proving anything.
#[test]
fn a_stopped_child_does_not_stop_bitfort_off_a_terminal() {
    let f = init_project();

    let mut cmd = common::raw_bf(f.dir.path(), &f.id);
    cmd.args(["run", "--", "sh", "-c", "kill -STOP $$; exit 7"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: one async-signal-safe libc call between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();

    let shell = await_child_of(child.id());
    await_state(shell, "T", "the child never stopped itself");
    assert!(
        !process_state(child.id()).starts_with('T'),
        "bitfort stopped itself with no terminal to be continued from"
    );

    // Continue the child so the run finishes, and check the exit code still comes through.
    assert!(Command::new("kill")
        .args(["-CONT", &shell.to_string()])
        .status()
        .unwrap()
        .success());
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(7), "the child's exit code was lost");
}

/// The pid of `parent`'s only child, waited for.
fn await_child_of(parent: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = Command::new("pgrep")
            .args(["-P", &parent.to_string()])
            .output()
            .unwrap();
        if let Some(pid) = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .and_then(|p| p.parse().ok())
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "no child of {parent} appeared");
        sleep(Duration::from_millis(50));
    }
}

/// Wait until `pid` reaches a state starting with `want` (`ps` state letters).
fn await_state(pid: u32, want: &str, whyfail: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !process_state(pid).starts_with(want) {
        assert!(Instant::now() < deadline, "{whyfail}");
        sleep(Duration::from_millis(50));
    }
}

fn process_state(pid: u32) -> String {
    let out = Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Read from the non-blocking pty master until `needle` appears or `budget` runs out.
fn read_until(master: &mut std::fs::File, needle: &str, budget: Duration) -> String {
    let deadline = Instant::now() + budget;
    let mut seen = String::new();
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        match master.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                if seen.contains(needle) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                sleep(Duration::from_millis(20))
            }
            Err(e) => panic!("reading the pty master failed: {e}"),
        }
    }
    seen
}
