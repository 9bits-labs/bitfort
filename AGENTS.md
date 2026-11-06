# BitFort

A secrets tool that keeps project config out of plaintext `.env` files: secrets live encrypted
in the repo (`vault.enc`), decryptable only by authorized developers' keys, and are injected into
a child process's environment at run time (`bitfort run -- npm run dev`).

**Design source of truth: [`docs/SPEC.md`](docs/SPEC.md).** Read the relevant section before
implementing. This file covers build, verification, and the invariants that must not regress -
not design and not general conventions (those are in SPEC "Tech stack").

## Workspace layout

Rust workspace; crate folders under `crates/` are not prefixed with `bitfort`.

| Folder | Package | Notes |
|---|---|---|
| `crates/core` | `bitfort-core` | Crypto, roster, vault engine. **No GUI/webview dependency, ever.** |
| `crates/cli` | `bitfort` | Hot-path CLI. Links only `bitfort-core`. Must run on bare Linux/CI. |

A desktop app is out of scope (`docs/SPEC.md` §9.2); do not scaffold one.

## Verification loop (run after every significant change)

"Significant" = any change to Rust source, `Cargo.toml`, or the on-disk/crypto formats. Docs- or
comment-only edits are exempt. Do not report a change done until every step below passes; paste
real output rather than inferring success from the code.

**Inner loop (optional accelerator).** While iterating, get faster test feedback with
`scripts/dev-fast.sh test --workspace` (nightly cranelift + parallel front-end, isolated
`target/cranelift/`). This is a correctness signal only - it is necessary, not sufficient. It
does not replace any step below. Cranelift produces slower binaries and says nothing about
release codegen, so always close out on the stable steps 1-3 and the behavioral run against the
**stable** binary.

**1. Mechanical.**

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
./scripts/check-cli-build.sh
```

**2. Behavioral.** For any change with runtime behavior, prove it end-to-end by running the
binary, not just unit tests:

```sh
cargo build --workspace
./target/debug/bitfort --version        # -> "bitfort 0.1.0"
# then drive the command you changed, e.g. ./target/debug/bitfort run -- printenv SOME_KEY
./scripts/check-heap-wipe.sh            # macOS only: no secret left in freed heap memory
```

`check-heap-wipe.sh` runs the debug binary through every command that handles a secret and
fails if a freed heap block still holds one (invariant 6). Normal tests cannot see this, because
the output is the same either way. It needs clang (Xcode command line tools); on Linux, skip it
and say so in the report. A new command that handles secrets gets a `watch` line in the script.

**CI.** `.github/workflows/ci.yml` runs step 1 on Linux, and `cargo test` plus
`check-heap-wipe.sh` on macOS, for each pull request and each push to `main`; `lint.yml` lints
the workflows. `release.yml` builds the release archives (macOS and static-musl Linux, arm64 and
x86_64) and the Homebrew formula with dist (`dist-workspace.toml`) on each pull request, and
publishes them on a version tag; its header lists the hand edits that `dist generate` would
undo. CI does not replace this loop: it does not drive the command you changed, and it runs no
review.

**3. Review.** BitFort is a security product, so every significant change gets reviewed before
it is called done. Run against the diff, apply the results, then re-run steps 1-2:

- `/security-review` - audit for crypto and secret-handling flaws: key/identity leakage,
  signature-verification bypass, roster rollback/downgrade, plaintext secrets reaching disk or
  logs. Any finding that violates a "Security invariant" below is blocking.
- `/code-review` - correctness bugs in the diff.
- `/simplify` - reuse, simplification, and altitude cleanups (quality only, no behavior change).

Verify each finding from `/security-review` and `/code-review` before reporting it, and drop it
when any of these holds:

- A commit message, test, or code comment states the behavior as intended. Report it anyway only
  if that intent breaks a Security invariant below, and name the invariant.
- It claims runtime behavior (output, exit status, an error) and a run of the debug binary does
  not show it. Run the binary to check such a claim; when no run is possible, say so.
- It names a risk from code that does not exist yet ("a later change could ..."). That is a
  hardening idea, not a defect; list it apart from the findings.

Mark each finding that survives as reproduced (give the command and its output) or as read from
the code only.

Every change gets test coverage: a new function gets a unit test; a bug fix gets a regression
test that fails before the fix.

## Everyday commands

```sh
cargo test -p bitfort-core version_is_reported   # one test by name
cargo run -p bitfort -- --version                # run the CLI without building a path
cargo build --release                            # optimized binary at target/release/bitfort
./scripts/check-cli-build.sh                     # dependency audit (see invariant 5)
```

Test harnesses arrive with the code that needs them: `assert_cmd` + `tempfile` are in use for the
CLI e2e suite; `insta` for on-disk format snapshots is still not a dependency.

## Security invariants (what the loop guards)

Load-bearing. A change that breaks one is a regression even if tests pass. Details in `docs/SPEC.md`.

1. **No plaintext secrets at rest.** No command writes a plaintext secret file into the tree;
   `.env*` stays gitignored; no real secrets in committed fixtures.
2. **Roster verification on every path.** Commands that re-encrypt (`set`, `member *`, `rotate`,
   `env add`, ...) verify the signed roster before writing and refuse an unverified one. Read
   paths (`run`, `get`, `list`, `export`, `status`) refuse too: the verified roster is what
   authenticates the vault payload (invariant 7). There is no warn-and-continue tier.
3. **Anti-rollback.** `roster_version` is monotonic and must be `>=` the highest version ever
   committed for that `keys.json` (`git log --full-history`, counting only revisions signed by a
   known maintainer key); reject downgrades. Revocation depends on this. The roster **chain**
   lives in `chain.json` in the tree, not in git history, so verification works in a shallow
   clone and outside a repository; git is the anti-rollback witness only, and where it cannot
   serve as one that must be reported, never folded into a zero.
4. **Deterministic signing bytes.** Roster and vault signatures are over RFC 8785 JCS with a
   per-payload domain tag, never ad-hoc key sorting - a byte-for-byte mismatch silently breaks
   verification. A signed field is never conditionally serialized: presence must not depend on
   value.
5. **The shipped CLI carries no GUI/webview dependency and no licensing code.** Keep
   `bitfort-core` and `bitfort` free of `tauri`/webkit so they load on headless Linux;
   `scripts/check-cli-build.sh` asserts it. The open CLI has no paid tier, license token, or
   token-signing code.
6. **Runtime secret hygiene.** Never log secret values or age identities; zeroize the parent's
   plaintext buffers after spawn (and on the error paths); `run` propagates the child's exit code
   and forwards signals. The `bitfort` binary's global allocator (`heap::WipeOnFree` in
   `crates/cli/src/heap.rs`) wipes every heap block before it is freed. It is the only thing that
   reaches the copies dependencies make (`serde_jcs`, `std::process::Command`) and the block a
   moving reallocation leaves, so removing or bypassing it is a regression even though every test
   still passes; `scripts/check-heap-wipe.sh` is what catches it. Any other binary that decrypts a
   vault installs it too. `run` strips `BITFORT_IDENTITY`, `BITFORT_SIGN_IDENTITY` and
   `BITFORT_IDENTITY_FILE` from the child. A variable that decides how a process runs (`PATH`,
   `NODE_OPTIONS`, `PYTHONPATH`, `PERL5LIB`, `LD_*`, `DYLD_*`, `GIT_*`, `BITFORT_*`) is refused
   at two boundaries: `Project::save_vault`, which every vault write goes through, and `run`/
   `export`, where vault contents become an environment. `Vault::decrypt` accepts one on
   purpose, so `list` and `status` can show what to remove. A secret's name must be an environment
   variable name at every boundary, a value may not carry a NUL (refused on the write side, so a
   vault already holding one still decrypts and can be repaired), and no error message quotes a
   `.env` line or a value.
   `export --format shell` emits POSIX single quotes only: `$'...'` is a bash extension that
   POSIX `sh` reads as literal `$` plus a plain quoted string, turning an escaped `'` into
   command injection.
7. **Vault origin authentication.** Every vault read verifies the payload signature and refuses a
   vault that no member of its roster signed, or that names another project or environment.
   Encryption proves nothing about authorship here - the roster's `enc_pubkey` values are public
   - so a decrypt path that skips this check hands an attacker's values to `run`. Only a roster
   member may write a vault, and the signature stays inside the payload: never move it to a
   sibling file, where an unsigned vault becomes representable. Two rules travel with it. The
   payload is checked against the roster it was **written for** - `keys.json`, or the `chain.json`
   link its `roster_version` names - because a vault older than the current roster was signed by
   a member of that older one, possibly the member since removed; checking it against today's
   roster calls an authentic file a forgery and leaves no repair. And the ciphertext must carry
   exactly as many recipient stanzas as that roster has members: a signature says who wrote the
   file, not who may open it.
