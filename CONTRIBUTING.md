# Contributing to BitFort

BitFort keeps secrets, so every change is reviewed for what it does to them. This page says how
to report a security problem, how to build and test, and what a pull request needs.

## Report a security problem

Do not open a public issue or pull request for a vulnerability. Email
[security@bitfort.dev](mailto:security@bitfort.dev) instead. [`SECURITY.md`](SECURITY.md) says
what to include, what is in scope, and when to expect an answer.

## Before you start

For a small fix, open the pull request directly. For a new command, a change to the on-disk
format, or a new dependency, open an issue first, so the design is agreed before the code is
written.

[`docs/SPEC.md`](docs/SPEC.md) is the design source of truth. A change to a behavior that SPEC
describes updates SPEC in the same pull request.

[`AGENTS.md`](AGENTS.md) lists the security invariants. A change that breaks one is a regression
even when every test passes, so say in the pull request which invariants your change touches.
AGENTS.md also holds the checks below in the form coding agents read, so an agent you work with
follows the same rules.

## Build and test

You need Rust 1.96 or newer. On macOS, the heap-wipe check also needs the Xcode command line
tools.

Run these before you push:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
./scripts/check-cli-build.sh       # the CLI links no GUI or webview crate
```

If your change touches a command that handles a secret, also run this on macOS:

```bash
cargo build --workspace
./scripts/check-heap-wipe.sh       # no secret is left in freed heap memory
```

A new command that handles a secret gets a `watch` line in `scripts/check-heap-wipe.sh`.

For a change with runtime behavior, also run the debug binary through the command you changed.
To keep your own OS keyring out of a manual test, give the binary a throwaway identity through
the environment:

```bash
key=$(mktemp)                                  # mode 600, outside the tree
./target/debug/bitfort identity new > "$key"
set -a; . "$key"; set +a                       # exports BITFORT_IDENTITY and BITFORT_SIGN_IDENTITY
./target/debug/bitfort init                    # in a scratch directory, not in this repository
rm "$key"
```

## Continuous integration

Each pull request runs four checks: `verify linux` (the four commands above), `verify macos`
(the tests and the heap-wipe check), `workflow lint` (actionlint and zizmor on the workflows)
and `dco` (every commit is signed off, see below). All four must pass before a pull request can
merge. CI does not replace the local
run, because it does not drive the command you changed.

## What a pull request needs

- **Tests.** A new function gets a unit test. A bug fix gets a regression test that fails
  without the fix.
- **The command reference.** A change to a command, a flag or its output updates
  [`docs/cli.mdx`](docs/cli.mdx). `cargo test` compares that page with the binary and fails
  when the two differ.
- **The format.** A change to the on-disk format or to the signed bytes updates
  [`docs/FORMAT.md`](docs/FORMAT.md). Regenerate its test vectors with
  `cargo test -p bitfort-core --lib format_vectors::print -- --ignored --nocapture`. Review
  covers the vector diff, not only the test result, because a regenerated vector makes any
  change to the signed bytes pass.
- **No secrets.** No real secret, `.env` file or private key goes into a commit, a fixture or a
  log line. Tests generate their keys.
- **Dependencies.** Say in the pull request why each new dependency is needed.
  `bitfort-core` and `bitfort-cli` never take a GUI or webview dependency.
- **Commits.** Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix:`, `refactor:`, `docs:`, `test:`, `ci:`, `chore:`), one logical change per commit, with
  a message that says why the change is needed. Pull requests merge with a merge commit, so
  each commit stays in the history and builds and passes the tests on its own.

## Developer Certificate of Origin

Each commit in a pull request ends with a `Signed-off-by:` line that gives the commit author's
name and email. With that line you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change,
or you have the right to submit it under the project's licence. `git commit -s` adds the line,
and `git rebase --signoff origin/main` adds it to the commits you already made. Run
`./scripts/check-dco.sh` before you push; the `dco` check runs the same script on the pull
request.

## Licence

BitFort is licensed under Apache-2.0. See [`LICENSE`](LICENSE). The licence covers the code,
not the name: BitFort is a trademark of 9bits LLC, and Apache-2.0 grants no trademark rights
(section 6).
