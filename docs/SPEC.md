# BitFort - Technical Specification

Status: Draft v0.2 (for implementation)
Last updated: 2026-07-03

BitFort keeps project secrets out of plaintext `.env` files. Secrets live encrypted in the
repo (`vault.enc`), decryptable only by authorized developers' keys, and are injected into a
child process's environment at run time via a wrapper (`bitfort run -- npm run dev`). This is
the SOPS/age model with a signed team roster and a runtime injector, packaged as one tool.

---

## 1. Goals and non-goals

### Goals
- No plaintext secret files at rest in the working tree. `vault.enc` is ciphertext; it is safe
  to commit.
- Per-recipient encryption: each authorized developer decrypts with a key that never leaves
  their machine (OS keyring), or, in headless environments, an identity supplied out-of-band
  (see §3.1).
- A **signed team roster** so a malicious change to the recipient list is detectable and
  rejected - adding a recipient requires a maintainer signature.
- A transparent run wrapper that injects secrets into a child process and preserves its exit
  code and signals.
- **One vault, everywhere.** The same encrypted vault drives local dev, teammates, and CI from
  a single Git-tracked source - no re-entering secrets into per-platform dashboards.
- Runs headless on Linux and in CI. The CLI is portable and has no GUI/webview dependency
  (see §9).
- Deterministic, auditable file formats that diff cleanly in Git.

### Non-goals (v1)
- **Runtime memory protection of the child.** Once secrets are in the child process
  environment they are readable by that process, its dependencies, and anything that can read
  `/proc/<pid>/environ`. BitFort removes the at-rest file; it does not sandbox runtime access.
  Documentation must not claim otherwise.
- **Retroactive secret protection.** Ciphertext committed to Git history is permanent. Removing
  a developer does not revoke access to secrets already in history (see §8, Rotation).
- Secret *values* management at the source (rotating the actual DB password on the DB) - BitFort
  can prompt for a new value but cannot rotate upstream systems.
- Cloud sync, audit logging backend, SSO. Trust and distribution ride on Git.

---

## 2. Threat model

| Actor / threat | Mitigated? | How |
|---|---|---|
| Reading `vault.enc` from the repo or Git history | Yes | Ciphertext; only listed recipients' private keys decrypt it. |
| AI tool / grep scraping a plaintext `.env` at rest | Yes | No plaintext file exists in the tree. |
| Attacker with repo write access adds their own public key to the roster to be encrypted-to on next update | **Yes (v1 core feature)** | Roster is signed by a maintainer; unverified roster changes are rejected before any encryption. See §5. |
| Removed developer decrypting **future** secrets | Yes | `bitfort rotate` re-encrypts without them. |
| Attacker with repo write access overwriting `vault.enc` with **their own** values (e.g. `LD_PRELOAD`, `NODE_OPTIONS`) to attack whatever `run` starts | **Yes** | Every `enc_pubkey` is public, so anyone can encrypt a file the team decrypts. The payload is therefore **signed** inside the ciphertext, and every read verifies that signature against the verified roster and refuses a vault no member wrote (§4.4). |
| Attacker with repo write access restoring an **older, validly-signed** `vault.enc` from history, to bring back a superseded value | Partially | A payload signed for an older `roster_version` is refused on every read, which covers the case that matters most: a vault predating a `member rm` cannot be replayed to hand back what the removed member knew. A vault restored from *within the same roster version* (an ordinary `set`, later changed) still verifies and is **not** detected; the vault has no monotonic version of its own yet. Rotating the underlying credential remains the real fix for a leaked value (§8). |
| Replaying a valid vault from another environment or another project | Yes | The signed payload carries `env` and `project_id`; both are checked on decrypt (§4.4). |
| A secret removed with `bitfort unset` coming back through an ordinary merge, so a value withdrawn on one branch is live again | Partially | `resolve` merges three-way against the common ancestor, so an *accidental* merge no longer undoes a deletion (§4.5). All three inputs are index stages, never the conflict markers in the file, so nobody can hand the merge a chosen ancestor or force it onto a two-way path by writing `vault.enc`. What remains is that whoever can push chooses the *branch point*, and so the ancestor: a branch taken before a secret was first set makes their side read as **adding** it, which is an ordinary conflict-free merge, and a branch taken before the vault existed produces an add/add with no ancestor at all. Both are indistinguishable from a teammate legitimately adding that name. `resolve` therefore names every secret a merge adds or removes, and warns whenever it has no ancestor. Closing it needs a monotonic vault version or deletion tombstones in the signed payload (§4.4). |
| A **roster member** re-encrypting the vault to their own extra key, so someone with no seat can read every value | Partially | A signature says who wrote a file, not who can open it, so every read also checks that the ciphertext carries exactly as many recipient stanzas as the roster it was written for has members (§4.4). Only the size of the audience is checkable - a stanza does not name its recipient - and a member who can read the values can pass them on by other means; the check catches the file that quietly stays readable to an outsider. |
| A **roster member** (or anyone who compromises one member's key) putting `LD_PRELOAD`, `PATH`, `NODE_OPTIONS`, `GIT_CONFIG_*`, ... in the vault, to run their own code in every teammate's `bitfort run` | Partially | A signature says a member wrote the vault, not that a member may execute code on every teammate's machine. No command writes such a name into a vault, and `run` and `export` refuse to turn one into an environment (§7), which bounds the blast radius; it is a bound, not a sandbox, since an interpreter has other hooks. |
| A secret's **name** being a shell command (`BAD; touch /tmp/PWNED #`), to run under the documented `eval "$(bitfort export --format shell)"` recipe | Yes | Every name entering a vault must be an environment variable name, checked on `set`, on a merge, and on decrypt; both exporters refuse to render one that is not (§4.4, §6). |
| A secret's **value** carrying terminal escapes, to spoof or clear the terminal of whoever exports or reads it | Partially | `--format dotenv` and `--format json` escape every control character. `--format shell` cannot: its output is `eval`ed and must be byte-exact in POSIX `sh`, which has no in-quote escape (§6). There the guard is that `export` refuses a terminal without `--force`. |
| Reverting `keys.json` to an older signed roster to silently re-add a removed member | Yes | Anti-rollback: `roster_version` must be >= the highest version ever committed for that file; downgrades are rejected (§4.3). |
| Rollback in a shallow clone (`actions/checkout` defaults to `fetch-depth: 1`) | Partially | The roster chain still verifies from `chain.json`, but truncated history cannot witness the highest committed version, so the ceiling is not trustworthy. BitFort reports it and `verify --strict` fails; CI should set `fetch-depth: 0` (§4.3, §7.1). |
| Cross-environment access (dev member reading prod secrets) | Yes | Each environment has its own roster and vault; prod is encrypted only to its own members (§4.1). |
| Removed developer decrypting secrets already in Git history | No (non-goal) | Requires rotating the upstream secret value; BitFort surfaces this in `rotate`. |
| Reading secrets from the running child process / its memory / `environ` | No (non-goal) | Secrets are plaintext at run time by design. |
| Stealing a developer's private key | Partially | Keys are in the OS keyring (Keychain / Credential Manager / libsecret). BitFort inherits OS protections; no extra hardening in v1. |
| Compromise of the CI identity in the CI secret store ("secret zero") | Partially | CI decrypts with one BitFort identity stored in the CI platform's own secret store. Whoever holds it can decrypt the vault, so it is treated as a dedicated, least-privileged, rotatable member (see §3.1, §8). BitFort does not remove the platform's root-of-trust; it consolidates N secrets into 1 rotatable key. |

---

## 3. Identity and keys

A BitFort **identity** consists of two keypairs, both generated locally on first use:

1. **Encryption key** - X25519, used as an `age` recipient/identity. Encrypts/decrypts the vault.
2. **Signing key** - Ed25519, used to sign roster changes (X25519 cannot sign).

Public halves of both keys are published into the roster (`.bitfort/keys.json`) and are safe to
commit.

Rationale for using the audited `age` crate rather than raw `x25519-dalek`: `age` implements the
full hybrid scheme (per-recipient X25519 ECDH -> HKDF -> wrapped ChaCha20-Poly1305 file key). We do
not hand-assemble the AEAD layer.

### 3.1 Identity source (keyring or headless)

Private keys are loaded from one of two sources, resolved in this order:

1. **`BITFORT_IDENTITY` environment variable** - the age identity string (and, when signing is
   required, `BITFORT_SIGN_IDENTITY`). If set, it wins. This is the headless/CI/container path:
   no OS keyring is available on an ephemeral runner.
2. **`BITFORT_IDENTITY_FILE`** - path to a key file with the same contents. Convenience for
   mounted-secret setups.
3. **OS keyring** via `keyring-rs` (the default on developer machines):
   - macOS: Keychain
   - Windows: Credential Manager
   - Linux: Secret Service (libsecret) / kwallet

   Keyring storage: service `bitfort`, a single account `identity` holding both the
   encryption and signing keys as one entry - so unlocking the identity is one keyring access
   (one macOS authorization prompt), not one per secret. The identity's *display* fingerprint -
   a short hash of the encryption public key, distinct from the **trust anchor** (§5.1), which
   hashes both public keys - names it in CLI output, not in the keyring.

Notes:
- A CI runner is supplied **both** halves of the identity. `BITFORT_IDENTITY` and
  `BITFORT_SIGN_IDENTITY` are required together: `keystore::load_identity` errors when only the
  first is set. The runner still must not mutate the roster; that is enforced by giving it a
  plain member seat, not by withholding the signing key.
- The CI identity is a normal roster **member** with its own keypair - added via `member add`
  like any teammate, then its private key placed in the CI platform's secret store. It is not a
  shared human key. This keeps it independently revocable and rotatable (see §8).
- On Linux with no Secret Service available (headless), only sources 1 and 2 work; BitFort emits
  a clear error pointing at `BITFORT_IDENTITY` rather than a cryptic keyring failure.

---

## 4. File and storage architecture

```
my-project/
├── src/
├── package.json
└── .bitfort/
    ├── config.toml            # project settings (schema, project_id, environments)
    └── environments/
        ├── development/
        │   ├── keys.json      # signed roster for this environment (public keys only)
        │   ├── chain.json     # every predecessor of keys.json, signed, in order
        │   └── vault.enc      # age-encrypted secrets, one recipient stanza per member
        └── production/
            ├── keys.json      # a *different*, usually smaller roster
            ├── chain.json
            └── vault.enc
```

Every file is committed to Git. None contains plaintext secrets or private keys.

### 4.1 Environments and least privilege

Secrets are partitioned into named **environments**, each with its **own roster and vault**.
This is deliberate: the goal is "one source of truth across laptop, team, and CI," but you
must not put production database credentials in every junior developer's vault. Separate rosters
let `production` be encrypted to a small subset (leads + the CI prod identity) while `development`
is encrypted to everyone.

- A command targets one environment via `--env <name>` (default `config.default_env`).
- Rosters are independent: being a member of `development` grants nothing in `production`.
- A CI job for a given deploy uses the identity that is a member of that environment only (a prod
  deploy runner holds the `production` identity; it cannot read `development` and vice versa).
- v1 ships with `development` created by `init`; `bitfort env add <name>` creates more.

### 4.2 `config.toml`
```toml
schema_version           = 1
project_id               = "b3f1c2..."   # random, stable per repo
default_env              = "development"
environments             = ["development", "production"]
trust_anchor_fingerprint = "bf1:9c2a…"   # see §5.1; pins the root of trust out of the roster file
```

Every name in `environments`, and `default_env`, must be a safe single path component (letters,
digits, `-`, `_`), checked when the file is parsed rather than only when `env add` writes one.
The name is joined under `environments/` to build every roster, chain and vault path, and
`config.toml` is an ordinary tracked file a merge or a pull request can change, so an unchecked
`../../evil` walks a vault write out of the project.

### 4.3 `keys.json` (signed roster, per environment)
```json
{
  "schema_version": 1,
  "project_id": "b3f1c2...",
  "env": "development",
  "roster_version": 7,
  "prev_digest": "sha256 hex of v6's signing bytes, null at version 1",
  "members": [
    {
      "name": "alice",
      "enc_pubkey":  "age1qxy...",
      "sign_pubkey": "ed25519:MCowBQ...",
      "role": "maintainer",
      "added_by": "alice",
      "added_at": "2026-07-03T00:00:00Z"
    }
  ],
  "signatures": [
    {
      "signer": "alice",
      "sign_pubkey": "ed25519:MCowBQ...",
      "signature": "base64(ed25519 sig over the signing bytes; see below)"
    }
  ]
}
```

**Signing bytes (must be exact and implementation-independent).** Do not "sort keys and strip
whitespace" ad hoc - that under-specifies number formatting, unicode escaping, and duplicate
keys, and a byte-for-byte disagreement silently breaks verification. The signed payload is the
**RFC 8785 JSON Canonicalization Scheme (JCS)** serialization of
`{schema_version, project_id, env, roster_version, prev_digest, members}` (the object without
`signatures`), prefixed with a domain-separation tag `"bitfort-roster-v1\n"` before signing.
`signatures` is never part of the signed bytes. `prev_digest` is always serialized, as `null` at
version 1: signing bytes whose shape depends on a value are not deterministic.

**The chain lives in the tree, not in Git history.** `chain.json` next to `keys.json` holds every
predecessor - versions 1..N-1, signed, in order - and `keys.json` holds version N. History is a
poor chain store: `git log` applies history simplification, so a merge can hide a committed
version; a shallow clone carries no predecessors at all; and any git failure reads as "no
history". Reading the chain from a file makes verification **total** - it works in a shallow
clone, in an exported tarball, and with no `git` binary on `PATH`. Git keeps exactly one job, the
anti-rollback witness, because that check needs an append-only record nothing in the working tree
can provide.

**Validity rules:**
- A roster is **structurally valid** if at least one signature verifies (over the signing bytes)
  against a `sign_pubkey` belonging to a member whose `role == "maintainer"` **in the previous
  valid roster** (`roster_version - 1`), which is read from `chain.json`. This chains trust from
  the init anchor forward and stops an attacker forging the maintainer set. (Bootstrapping:
  `roster_version` 1 is self-signed by the initializer, whose fingerprint is the trust anchor -
  see §5.1.)
- **`prev_digest` pins the predecessor by content**: the SHA-256 of v(N-1)'s signing bytes.
  Adjacency by version alone would let a repo-write attacker substitute a different,
  differently-signed v(N-1) into the chain file; the digest breaks that link instead.
- **Anti-rollback (monotonic version).** A validly-signed *old* roster is still a valid roster, so
  signature-checking alone does not stop a revert that silently re-adds a removed member. `verify`
  and every write path therefore also require `roster_version` to be **>= the highest version ever
  committed for this `keys.json`** (`git log --full-history`, counting only revisions signed by a
  key that holds or has held maintainer authority here, so unsigned garbage in history cannot
  wedge the project). A checked-out roster with a lower version is rejected as a downgrade with an
  explicit error naming the higher version it saw. This is the one check that can be unavailable:
  outside a repository, or in a shallow clone, BitFort reports that it is not enforced, and
  `verify --strict` fails.
- **`env` must match** the directory the roster lives in (`environments/<env>/keys.json`); a
  mismatch is rejected (prevents copying a dev roster over prod). **`project_id` must match**
  `config.toml`.

### 4.4 `vault.enc`
An **ASCII-armored** `age` file (armored so Git renders line-level diffs and can surface merge
conflicts as text; see §4.5) encrypted to every `enc_pubkey` in the roster of the same
environment. Plaintext payload before encryption is JCS-canonical JSON:
```json
{
  "schema_version": 1,
  "project_id": "b3f1c2...",
  "env": "development",
  "roster_version": 7,
  "vars": { "DATABASE_URL": "postgres://...", "API_KEY": "..." },
  "written_at": "2026-09-05T00:00:00Z",
  "signature": { "signer": "alice", "sign_pubkey": "ed25519:MCowBQ...", "signature": "base64(...)" }
}
```
`age` produces one recipient stanza per key; adding/removing a member changes only the stanzas,
keeping diffs reviewable. Re-encryption is required whenever the roster or any value changes.

**The payload is signed, and the signature is inside the ciphertext.** Encryption authenticates
nothing here: every `enc_pubkey` is public and committed, so anyone with repo write access can
encrypt a file to the whole roster and overwrite `vault.enc` with it. That forgery decrypts
cleanly, and `run` would inject its values - `LD_PRELOAD`, `NODE_OPTIONS` - into whatever the
build starts. Sign-then-encrypt closes it, and putting the signature in the payload rather than a
sibling file means a vault without one is not representable.

- **Signing bytes**: JCS of `{schema_version, project_id, env, roster_version, vars, written_at}`
  (the object without `signature`), prefixed with the domain tag `"bitfort-vault-v1\n"`.
- **Every read verifies**, and refuses: the signature must verify, its `sign_pubkey` must belong
  to a member of the roster the payload was **written for**, and `env` and `project_id` must
  match the environment the file was loaded from. `signature.signer` is a display name outside
  the signed bytes, so callers resolve the author from the roster, never from that field.
- **Which roster that is** follows `roster_version`: `keys.json` when the payload names it,
  otherwise the link `chain.json` holds for the version it names. Checking every vault against
  today's `keys.json` would be wrong, not stricter. A vault written before a membership change
  was signed by a member of the roster of that moment - possibly the member that change removed,
  which is exactly what a crash between the roster write and the vault write leaves (§5.2) - and
  refusing it as a forgery would leave the environment with no repair, `rotate` included, since
  `rotate` has to read the file to re-sign it. Staleness is a separate question, answered by the
  drift rules below. A payload naming a version neither file holds is checked against `keys.json`
  and refused on drift.
- **Only a member may write one**: encryption requires an identity listed in the roster.
- **The audience must be the roster.** A vault must carry exactly as many recipient stanzas as
  the roster it was written for has members, or it is refused. A member is authorized to write
  the vault; that does not license them to choose who else can read it, and a signature says who
  wrote a file, not who can open it. Only the *size* of the audience is checkable: a stanza
  carries an ephemeral share, not the recipient's public key, so which keys can open the file is
  not recoverable from it. Every stanza counts except the randomly tagged `*-grease` decoy every
  age header carries: `age` ignores a recipient type it does not know rather than refusing the
  file, so counting only `X25519` would let an `ssh-ed25519` stanza smuggle in a reader. The
  check is skipped only for a payload naming a version this environment has no record of, where
  there is no member count to compare against.
- `roster_version` names the roster the payload was written for, and the two directions of drift
  are not treated alike:
  - **Vault behind `keys.json`** is refused everywhere except `bitfort rotate`. Two states look
    like this. An old payload stays validly signed for ever, so restoring the file from before a
    `member rm` would hand back exactly what that member knew; and it is what a crash inside a
    membership change leaves, because the roster is published before the vault (§5.2). `rotate`
    reads it because re-signing it against the current roster is both what that command exists
    to do and the repair for the interrupted change; it warns before it does.
  - **Vault ahead of `keys.json`** is refused by every command, reads included. No write path
    produces it: `keys.json` is not the newest roster this environment has had, so it was rolled
    back, checked out at an older revision, or substituted. That is a roster downgrade, which
    the anti-rollback ceiling exists to catch and cannot outside a git repository or in a
    shallow clone - and a vault stamped for a version `keys.json` does not have is the only
    local evidence left of it. Reading would serve values against a roster that may still list a
    member the newer one removed, and re-encrypting would make that roster the live one. The
    repair is to check out `.bitfort` whole at one revision, never `rotate`, which re-encrypts to
    the roster on disk.
  - **`resolve`** applies the same rule to *both* sides of a conflict before merging. Its output
    is re-signed at the current version, so an accepted side becomes a vault every later read
    trusts: it is the laundering path around every other refusal, and it is closed.
- **Limit worth stating plainly**: the vault has no monotonic version of its own, so restoring an
  older vault written *under the same roster version* is not detected. Closing that needs a
  `vault_version` plus a git witness, the way `keys.json` has one (§4.3).
- The file stays a plain `age` document, so `age -d -i <key> vault.enc` remains the break-glass
  path when BitFort itself refuses to open it.

**Name encoding.** Every name in `vars` must be an environment variable name
(`[A-Za-z_][A-Za-z0-9_]*`), checked at the one boundary secrets enter through: `set`, the merge
`resolve` writes back, and decrypt. `run` injects these names into a child's environment and
`export` renders them into shell and dotenv text, so a name that is not a name is a command in
disguise (§6). A name that also decides how a process runs - `PATH`, `LD_*`, ... - is valid but
refused separately (§7).

**Value encoding.** Values are UTF-8 strings and may be multiline (certs, JSON blobs). Non-UTF-8
values are rejected in v1 (env vars are strings). A NUL is refused as well, and on the write side
only: NUL terminates a C string, so a value carrying one makes `Command::env` refuse and *every*
later `run` for that environment fail to spawn anything at all, not just that one variable. The
refusal is where the vault is written, the same asymmetry the process-control names use - a vault
that already holds one still decrypts, so `list` and `status` can show what to remove. BitFort
warns above a soft per-value size limit (default 512 KiB) since oversized env vars can exceed OS
`ARG_MAX`/env limits at spawn time.

### 4.5 Concurrent edits, merges, and conflicts

Two branches editing the same environment will conflict, and the files are not hand-mergeable in
the usual sense. The v1 stance:

- **Vault is armored age**, so a conflict shows up as a normal (if opaque) Git text conflict
  rather than a binary blob. The resolution is not to hand-edit the ciphertext: run
  `bitfort resolve --env <name>`, which takes *both* sides, decrypts each with your identity,
  three-way-merges the `vars` maps (conflicting keys reported for manual choice), and re-encrypts
  a single clean vault. Document "after a rebase/merge touching a vault, run `bitfort resolve`."
- **All three merge inputs come from git's index, and from nowhere else.** They are index stages 1
  (the common ancestor), 2 (ours) and 3 (theirs), which git computed from the two commits and
  keeps while the path is unmerged. The conflict markers in the working file are **not** an input,
  and the ancestor a `diff3`/`zdiff3` conflict writes into the file is dropped with them. Those
  bytes are ordinary file content: whoever can write `vault.enc` would be choosing what the merge
  sees. That matters most for the ancestor, which decides per key which side wins - a chosen one
  flips a side silently and turns the deletion rule back off for any key - but it is the same
  objection for the two sides. Each input is authenticated as any other vault read is (§4.4).
- **So `resolve` settles the conflict git has, and refuses when git has none.** The four shapes
  git can report, and the answer to each:
  - stages 1, 2, 3 - an ordinary content conflict; merge three-way.
  - stages 2 and 3 only - an add/add conflict: the merge base commit does not hold the vault, so
    git has no ancestor version. This is **not** a safe state, and reading it as "both branches
    created the vault, so nothing can have been deleted" is the trap. Any branch taken before the
    vault existed produces this shape, and its side may still carry a vault restored from history.
    The merge is two-way, and `resolve` warns.
  - stage 1 with one side - a branch deleted `vault.enc`. There are not two versions to merge, so
    `resolve` says which branch dropped it and leaves the choice to the user.
  - no unmerged entry - nothing to resolve. If the file carries conflict markers anyway, the merge
    state was dropped (`git add` on the path, or a committed merge) or never came from a merge;
    `resolve` refuses and names `git checkout --merge -- <path>`, which restores all three inputs.
- **The ancestor's `roster_version` is not policed the way a side's is.** An ancestor is expected
  to predate a membership change, and it contributes no value to the output - every value the
  merge keeps comes from one of the two sides. An ancestor *newer* than the roster is still
  refused, since no real merge produces one. An ancestor this identity cannot read, or one holding
  a name today's rules reject, degrades the merge to a two-way union with a warning rather than
  stopping it.
- **`resolve` names every secret the merge added or removed**, because a three-way merge is only
  as good as its ancestor and the ancestor follows from the branch point, which whoever pushes
  chooses. Branching before a secret was first set makes the other side read as *adding* it: an
  ordinary merge, no conflict, no warning, and no way for the tool to tell it from a teammate
  adding that name. Counts alone read as success, so the names are what the person who withdrew a
  secret needs to see. Values are never printed.
- **`roster_version` collisions** (two maintainers both bump v7 -> v8 on separate branches) are a
  **defined error**, not undefined behavior: `verify` detects two distinct v8 rosters in history
  and refuses until one maintainer rebases and re-signs the loser as v9. Version is authoritative
  and must stay unique per environment.
- A future `.gitattributes` entry will mark the vault/roster paths so a custom merge driver can be
  slotted in without changing the format. Not written yet - `init` writes only `.gitignore`.

---

## 5. Trust model (roster signing)

The central fix over the original PRD: a plaintext public-key list is *not* trustworthy on its
own, because anyone with repo write access can append their key and receive secrets on the next
update. BitFort signs the roster.

### 5.1 Bootstrapping and anchor pinning
- `bitfort init` generates the initializer's identity, writes `roster_version` 1 with the
  initializer as the sole `maintainer`, self-signs it, and records the initializer's **anchor
  fingerprint** in `config.toml` as `trust_anchor_fingerprint`. The anchor hashes **both** public
  keys of the identity (`hash(enc_pubkey | sign_pubkey)`), not just one. Binding the signing key is
  essential: `enc_pubkey` is public and committed to Git, so an anchor over the encryption key
  alone could be forged by a repo-write attacker who copies it and pairs their own signing key
  (they still cannot produce a valid v1 signature, but only because the anchor pins the signing
  key). v1 verification requires a maintainer whose two-key anchor matches this pinned value.
- The fundamental TOFU gap: a **fresh clone** has no prior state, so it trusts whatever roster v1
  is present - an attacker who rewrote history could ship their own self-signed v1. Signatures
  cannot close this; only out-of-band pinning can. v1 therefore requires the anchor fingerprint to
  be verifiable outside the roster file:
  - `trust_anchor_fingerprint` in `config.toml` is the pinned value; `verify` checks that roster
    v1's self-signature matches it.
  - `bitfort verify` **prints the anchor fingerprint** so a new contributor can compare it against
    a value published out-of-band (README badge, pinned Slack message, and ideally a signed Git
    tag `bitfort-anchor` on the init commit). Alongside the hex, the anchor is rendered as a
    6-word BIP-39 phrase (surfaced by `anchor`, `verify`, `status`, and `init`) as the human
    compare layer - the words are injective over the anchor, so a word match is a hex match; the
    hex stays the source of truth. `bitfort anchor` prints both for publishing.
  - This one out-of-band comparison is the single unavoidable human trust step. Document it
    prominently; do not pretend it is automatic.
- Each environment has its own roster but shares the **same** `trust_anchor_fingerprint`; a new
  environment's roster v1 must be signed by an anchor-rooted maintainer.

### 5.2 Adding a member
1. New dev runs `bitfort keygen`, which prints an invite blob containing their `enc_pubkey` +
   `sign_pubkey`, and sends it to a maintainer.
2. A maintainer runs `bitfort member add <invite>`, which appends the member, bumps
   `roster_version`, re-signs, and re-encrypts `vault.enc` to include the new recipient.
3. The change lands via normal PR. Reviewers see a signed roster bump.

**How the three files land.** `chain.json`, `keys.json` and `vault.enc` are written to staging
paths and fsynced before any of them is renamed into place, so everything that can fail - the
encryption, the serialization, a full disk - fails with every file still holding its old bytes.
What remains is three renames, published in that order, and the order is the same for an addition
and for a removal:

- A crash after the chain leaves a redundant tail holding the roster still in `keys.json`, which
  chain verification ignores.
- A crash after the roster leaves a vault written for the previous version - `Drift::Behind`
  (§4.4). Every read refuses it and names `bitfort rotate`, which re-encrypts and re-signs
  against the roster on disk and so completes the change in either direction. This holds even
  when the departing member was the last to write the vault, because the payload is
  authenticated against the roster it names rather than against the new one (§4.4); `rotate`
  warns that the writer is no longer a member before it adopts their contents.

Vault-first would leave the opposite state, and it is worse both ways: on an addition the vault
is readable by a key no signed roster lists, which is a silent grant; on a removal, reads
continue against a `keys.json` that still lists the member being removed, and the repair -
re-running the membership change - cannot be checked to be the *same* one, so removing anybody
else silently undoes it.

### 5.3 Rejecting a rogue key
If someone hand-edits `keys.json` to add a key without a valid maintainer signature over the new
`roster_version`, `bitfort verify` (and every encrypting command) fails with a clear error. CI
should run `bitfort verify --strict` on every PR (non-zero exit on any roster failure).

### 5.4 Maintainer promotion/demotion
**Not implemented.** There is no command that changes an existing member's role; `member add`
refuses an identity already on the roster, so a role is fixed when the member is added. Changing
one means `member rm` followed by `member add --maintainer`, and because removing the last
maintainer is refused, a second maintainer has to be added before the first can go. Were it
implemented, a role change would be a roster change and would have to be signed by an existing
maintainer. Demoting the last maintainer is refused. So is removing **yourself**: the re-encrypted vault has to be
signed by a member of the roster it is written for (§4.4), and a departing member is not one.
Revocation is someone else's action - a member who is leaving should not be the last person to
write the vault.

### 5.5 What verification does and does not protect
**Every path verifies the roster, and refuses on failure - reads included.** There is no
warn-and-continue tier. It existed because the chain was reconstructed from Git history, which is
unavailable in a shallow clone or outside a repository; the chain lives in `chain.json` now
(§4.3), so verification always works and there is nothing left to degrade to.

- **Write paths** (`set`, `unset`, `member add/rm`, `rotate`, `env add`, `import`, `resolve`)
  verify before re-encrypting. This is where trust matters most: it stops secrets being encrypted
  to a rogue or re-added key. They also report an anti-rollback witness that could not run, the
  way read paths do: a write in a shallow clone or outside a repository is exactly where a
  downgrade would go unnoticed.
- **Read paths** (`run`, `get`, `export`, `list`, `status`) verify too, for a different reason.
  Roster verification cannot grant *you* access - `age` decryption consults only your identity and
  the ciphertext - but the verified roster is what authenticates the **vault payload** (§4.4), and
  a read path that continues past a failed roster is exactly how a forged vault reaches `run`.
- The dedicated `verify` command exits non-zero on any **hard** failure in either signed file:
  a bad chain, a rollback, roster tampering, a vault no member of its roster signed, a vault
  addressed to more keys than that roster has members, a vault that has drifted from `keys.json`
  in either direction, or one that is missing or damaged. It is the gate CI runs on a pull
  request, so it must see what `run` would refuse - on the diff that introduced it, not at
  deploy time. Only two cases are reported
  as *not checked* rather than failed: no local identity, and an identity that holds no seat in
  this environment. A reviewer comparing the anchor on a fresh clone is in the first.
  `--strict` narrows to one extra meaning: **anti-rollback must be enforceable here**, so it also
  fails outside a git repository and in a shallow clone. CI runs `verify --strict`.

---

## 6. CLI surface

Binary: `bitfort`. All commands operate on the `.bitfort/` dir found by walking up from CWD.

| Command | Purpose |
|---|---|
| `bitfort status` | One-screen readout of the environment's security posture (roster, vault, git/gitignore state) and the next step. Read path. |
| `bitfort init [--name <n>]` | Create `.bitfort/`, generate initializer identity, pin anchor fingerprint, write `development` roster v1 + empty vault. Ensures `.env*` is gitignored. On a TTY it is a guided wizard (prompts name/first env, offers to import a discovered `.env` and to `git init`+commit); off a TTY it stays fully non-interactive with defaults. |
| `bitfort keygen [--name <n>]` | Generate a local identity if none exists (idempotent); print public keys / invite blob. `--name` is the display name embedded in the invite. |
| `bitfort identity new [--name <n>] [--force]` | Mint a fresh identity for a machine with no keyring (CI, containers) and print both secrets plus its invite blob (§7.1); never touches the keyring. Refuses a terminal without `--force`. `--json` prints one object with the keys `BITFORT_IDENTITY`, `BITFORT_SIGN_IDENTITY` and `invite`; that form is not an identity file. |
| `bitfort import <path> [--env <name>] [--delete-source]` | Migrate an existing `.env` (or dotenv-format file) into the vault. The adoption on-ramp; advises deleting the source `.env` (or deletes it with `--delete-source`). |
| `bitfort anchor [--share]` | Print the trust anchor (hex + 6-word phrase) to publish out-of-band; `--share` emits a plain paste block. |
| `bitfort verify [--strict]` | Verify roster: signature chain, anti-rollback vs git history, anchor pin, env match. Exits non-zero on any hard failure; `--strict` also fails when protection is best-effort (e.g. outside a git repo), for CI. |
| `bitfort set KEY[=VALUE]` | Add/update a secret. With the value omitted it is read without echo from the terminal (no shell history leak), or from stdin when stdin is not a terminal - `printf %s "$SECRET" \| bitfort set KEY`, the headless path, one trailing newline stripped. Re-encrypts. Overwriting an existing key confirms first (skip with `-y`). |
| `bitfort unset KEY` | Remove a secret. Re-encrypts. Confirms first (skip with `-y`). |
| `bitfort get KEY` | Decrypt and print one value (guarded; warns it exposes plaintext). |
| `bitfort list` | List secret **keys** (never values). |
| `bitfort run [--clean] -- <cmd> [args...]` | Decrypt in-process, inject into child env, exec, forward signals, propagate exit code. `--clean` starts from a minimal env. |
| `bitfort export [--format dotenv\|shell\|json] [--force]` | Print decrypted secrets (explicit, for CI bridges). Warns loudly; refuses to print to a terminal without `--force`. |
| `bitfort env add <name>` | Create a new environment (own roster + vault), rooted at the same trust anchor. Anchor-holder only. |
| `bitfort env list` | List environments and per-env roster/verification status. |
| `bitfort member add <invite> [--maintainer] [--name <n>]` | (maintainer) Add recipient to the target env, bump+sign roster, re-encrypt. Requires the current roster to be committed. |
| `bitfort member rm <name>` | (maintainer) Remove recipient, bump+sign roster, re-encrypt (see rotate). Refuses the last maintainer. Confirms first (skip with `-y`). |
| `bitfort member list` | Show the target env's roster and verification status. |
| `bitfort rotate` | Re-encrypt vault to current roster with fresh ciphertext; advises rotating the upstream values via `bitfort set`. |
| `bitfort resolve [--ours\|--theirs]` | After a merge/rebase conflict, merge both vault sides and re-encrypt cleanly; a key changed on both sides needs `--ours`/`--theirs` (see §4.5). |
| `bitfort completions <shell>` | Print a shell completion script (bash/zsh/fish/…) to stdout. |
| `bitfort man` | Print the man page in roff to stdout. |

Global flags: `--env <name>` (selects environment; default `config.default_env`), `--dir <path>`,
`--json` (JSON output on `status`, `list`, `verify`, `anchor`, `member list`, `env list` and
`identity new`; other commands keep their text output, no command asks a question under it, and
the terminal guards on `export` and `identity new` still refuse a terminal), `-y`/`--yes` (skip the confirmation on
destructive commands - `unset`, `member rm`, overwriting `set`; required off an interactive
terminal), `-q`/`--quiet` (drop decorative output, keeping facts/data/errors).
Almost every command is environment-scoped; `--env` selects which roster+vault under
`environments/` it acts on.

**Who may answer a prompt.** A question is asked only when **both** stdin and stdout are
terminals. With stdout on a terminal and stdin on a pipe the piped bytes would answer every
prompt in turn, so `printf 'name\nstaging\n' | bitfort init` would record that name and that
environment, and accept the git commit it is offered next. Layout does not care where stdin
points, so tables and chrome still follow stdout alone. The one read that follows stdin instead
is `set`'s value, which is a value to store rather than an answer to a question.

**Rendering secrets safely.** `export` writes text that a shell or a dotenv reader then
interprets, so both exporters are escaping code, not formatting code:

- A **name** is emitted verbatim, so both refuse one that is not an environment variable name.
  `BAD; touch /tmp/PWNED #` would otherwise be a second command under the documented
  `eval "$(bitfort export --format shell)"`. The same rule runs wherever a name enters a vault
  (§4.4), so this guard only ever fires on a payload written by something else.
- A **value** is quoted: `--format dotenv` double-quotes it with `\`, `"`, and every control
  character escaped; `--format shell` single-quotes it, escaping an embedded `'` as `'\''`, and
  emits every other byte verbatim.
- `--format shell` therefore does **not** escape control characters, and the asymmetry is
  deliberate. Its output is `eval`ed, so it must reproduce the value byte for byte in every
  shell, and POSIX `sh` has no escape inside `'...'`. ANSI-C quoting (`$'...'`) looks like the
  answer and is not: `sh` has no such construct, so it reads the `$` as a literal, opens an
  ordinary single-quoted string, and ignores the `\'` - the string closes at that quote and the
  rest of the value becomes shell text. That is command injection under `/bin/dash` (`/bin/sh`
  on Debian, Ubuntu and Alpine, and the shell every `make` recipe uses). The terminal exposure
  is bounded differently here: `export` refuses to write to a terminal without `--force`, and
  the output is a file to evaluate rather than text to read. Use `--format dotenv` or
  `--format json` to read one.
- **`--format dotenv` round-trips byte for byte**, because `import` reads back exactly the
  escapes `export` writes (`\\`, `\"`, `\n`, `\r`, `\t`, `\xNN`, `\uNNNN`). The two were
  asymmetric: `export` escaped and `import` did not un-escape, so `bitfort export > .env`
  followed by `bitfort import .env` - a documented recipe - stored a password holding `"` with a
  backslash in front of it, and doubled every separator in a Windows path, with exit 0 and no
  warning. Only double quotes carry escapes. A single-quoted value is literal, as in the shell
  and in every dotenv reader, and this crate never emits one.
- **That rule governs a hand-written `.env` too, and it is the dotenv convention rather than a
  BitFort one**: every mainstream loader un-escapes a double-quoted value and takes a
  single-quoted one literally. So `WINPATH="C:\temp"` imports with a tab, because that is the
  value the loader was already handing the app - importing it literally would have changed the
  secret on the way in. A path meant literally belongs in single quotes, and `bitfort get` shows
  what was stored before the source file is deleted.

**Parse errors withhold what they read.** A `.env` line that does not parse is usually the body
of a multi-line secret - a PEM key wraps onto lines with no `=`, and its base64 padding puts one
on the rest - so `import` reports the line *number* and never the line or the name in front of
`=`. A value is one physical line: a multi-line secret imports as a double-quoted `\n` escape,
which is what `export` writes, but one wrapped across real lines in a hand-written `.env` is not
importable and is added with `bitfort set`.

---

## 7. Runtime injection (`bitfort run`)

The corrected engine. Requirements the original snippet missed:

- **Propagate the child's exit code.** `bitfort run -- foo` must exit with `foo`'s exit code, not
  a generic error - otherwise it breaks CI, `&&` chains, and shells.
- **Signal forwarding.** SIGINT/SIGTERM to `bitfort` must reach the child; wait for it to exit.
  On non-zero-signal termination, exit with `128 + signal` (Unix convention).
- **Job control (Unix).** The child runs in a process group of its own, and the controlling
  terminal is handed to that group for the duration. A terminal signal then reaches the child
  once, from the kernel, instead of once from the kernel and again from the forwarder - which is
  what made one Ctrl-C look like two to a dev server whose second Ctrl-C means "force quit".
  Three consequences the implementation has to carry:
  - The terminal *must* be handed over. A background process group is stopped by SIGTTIN the
    moment it reads the terminal, which is what a dev server does for its keyboard shortcuts.
  - Ctrl-Z now stops the child's group and not bitfort's, so `bitfort` follows the child into
    the stop: it takes the terminal back, stops itself, and hands the terminal back when the
    shell continues it. Otherwise it would wait on a stopped child while holding the terminal.
  - The terminal goes back to the process group that held it, on every path out of `run`, and it
    is never taken at all when `bitfort` did not hold it (`bitfort run ... &`).
- **Handlers before the child.** Signal handlers are installed before `spawn`, not after. In the
  window between them a SIGTERM took bitfort's default action, killing it and orphaning a child
  that holds every secret.
- **Cross-platform command resolution.** On Windows, resolve `npm` → `npm.cmd` etc. (use a
  which-style lookup or `cmd /C` fallback). On Unix, exec the resolved path.
- **Env composition.** Inherit the parent env, then overlay BitFort secrets (secrets win). Do not
  `env_clear()` by default (breaks PATH); offer `--clean` to start from a minimal env.
- **Never hand the child the identity.** `BITFORT_IDENTITY`, `BITFORT_SIGN_IDENTITY`, and
  `BITFORT_IDENTITY_FILE` are removed from the child's environment on both the inherited and the
  `--clean` path. The CI recipe (§7.1) puts the private key in bitfort's own environment, so
  without this any build step inherits a key that decrypts every `vault.enc` revision in Git
  history, for every environment that member belongs to.
- **Refuse to inject a process control variable.** `PATH`, `NODE_OPTIONS`, `PYTHONPATH`,
  `PERL5LIB`, and anything under `LD_`, `DYLD_`, `GIT_`, or `BITFORT_` decide what the child
  *runs* rather than what it reads. A vault's signature identifies its author; it does not
  license that author to execute code on every teammate's machine (§2). Set such a variable in
  the environment that launches bitfort instead. Enforced wherever vault contents become - or
  are about to become - an environment. Two boundaries, one rule each. On the **write** side it
  is refused in `Project::save_vault`, which every command that writes a vault goes through -
  `set`, `unset`, `import`, `resolve`, `rotate` and the membership commands - so none of them
  can be forgotten (`set` and `import` also check earlier, so the refusal arrives before the
  user is asked to type a secret). On the **use** side `run` refuses to inject one and `export`
  refuses to emit one, its output being `eval`ed or read by a dotenv loader, which is the same
  injection a step later. A vault that already holds such a name still *decrypts*, deliberately,
  so `list` and `status` can show what has to be removed.
- **No stdio interception.** Inherit stdin/stdout/stderr directly.
- **Zeroize the parent's plaintext buffers** after spawn using `zeroize`, on the error paths as
  well as the success path. `Vault::decrypt`'s plaintext buffer and `Vault::encrypt`'s JCS buffer
  are zeroized on drop for the same reason, and `Vault`'s `Debug` prints names only. None of this
  protects the child (documented non-goal); it keeps plaintext out of the BitFort process's freed
  memory and out of anything that logs.

Reference shape (illustrative, not final):
```rust
use std::process::{Command, Stdio};
use std::collections::HashMap;
use zeroize::Zeroize;

pub fn run(target: &str, args: &[String], mut secrets: HashMap<String, String>) -> anyhow::Result<i32> {
    let program = resolve_program(target)?; // handles .cmd on Windows / PATH lookup

    let mut cmd = Command::new(program);
    cmd.args(args)
       .stdin(Stdio::inherit())
       .stdout(Stdio::inherit())
       .stderr(Stdio::inherit());

    for (k, v) in &secrets {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn `{target}`: {e}"))?;

    // scrub the parent's copies; the child already holds its own env
    for (_, v) in secrets.iter_mut() { v.zeroize(); }

    // waits with WUNTRACED, follows the child into a stop, and maps a signal death to 128 + N
    supervise(&mut child)
}
```
`main` returns `ExitCode::from(u8::try_from(code).unwrap_or(1))`, so the destructors that scrub plaintext still run - `std::process::exit` would skip them.

### 7.1 Headless and CI usage

`bitfort run` is the same on a laptop and in CI - the only difference is where the identity comes
from (§3.1). The integration is **one generic pattern, not per-platform code**; BitFort ships no
CI-provider integrations, only a documented recipe:

1. Create a dedicated CI identity: `(umask 077; bitfort identity new --name ci > ~/ci.key)` (on
   a trusted machine), then a maintainer runs `bitfort member add` with the invite blob it
   prints. The file goes outside the repository, and `umask 077` gives a new file the 600 mode
   the identity-file loader requires; writing over an existing file keeps that file's mode, so
   `chmod 600` it.
   `keygen` cannot serve here: it is idempotent, so it returns the operator's own identity, and
   no command but `identity new` prints private key material.
2. Store both halves as secrets in the CI platform (GitHub Actions secret, GitLab CI variable,
   etc.), exposed to the job as `BITFORT_IDENTITY` and `BITFORT_SIGN_IDENTITY`. The printed text
   block is also a valid `BITFORT_IDENTITY_FILE` if the platform mounts files instead; the
   `--json` form is not.
3. Check out **full history** - `actions/checkout` defaults to `fetch-depth: 1`, and a shallow
   clone cannot witness the highest committed `roster_version`, so anti-rollback is not enforced
   there (§4.3). Set `fetch-depth: 0` if the job runs `bitfort verify --strict`.
4. Prefix the build/deploy step: `bitfort run -- <build command>`.

Because the mechanism is just "a key in the environment + a process wrapper," the identical
recipe works on GitHub Actions, GitLab, CircleCI, Fly, Railway, and self-hosted runners. The v1
docs cover GitHub Actions as the canonical example; the rest is the same three steps.

Messaging discipline (secret zero): the honest pitch is "store **one** rotatable key in your CI
secret store instead of pasting **N** plaintext secrets into a dashboard, and keep every
environment in sync from one Git-tracked vault." BitFort does not eliminate the CI platform's
root-of-trust; it consolidates and versions it. See the threat model (§2) and §8.

---

## 8. Rotation and revocation

- `bitfort member rm` removes the recipient and re-encrypts, so the removed key cannot decrypt
  **future** `vault.enc` revisions.
- It does **not** protect secrets already committed. `bitfort rotate` therefore:
  1. Re-encrypts the vault to the current roster with fresh ciphertext.
  2. Records a `rotated_at` timestamp in `config.toml`.
  3. Advises the operator to change the real credentials at their source and `bitfort set` the new
     values - the only true revocation for a leaked/removed-member scenario. (Changing the upstream
     values is a manual step; `rotate` does not prompt for them.)
- Documentation must state plainly: *removing a member is not the same as rotating a secret.*
- **CI identity rotation.** Because the CI identity's private key lives in a CI secret store
  (§3.1), treat it as the most exposed member: rotate it on a schedule and whenever a person with
  CI access leaves. Rotation = `member rm` the old CI key, `member add` a fresh one, update the CI
  secret. This is a routine op, not an incident.

### 8.1 Account recovery (lost laptop)

Private keys live in the OS keyring and are **not** backed up or escrowed - by design, there is
no vendor-held copy. Consequences and the supported flow:

- Losing the machine = losing that identity. The developer cannot decrypt until re-added.
- Recovery is a normal onboarding: the developer runs `bitfort keygen` on the new machine and a
  **maintainer** runs `bitfort member add` with the new key (and `member rm` the old one). No data
  is lost because secrets are re-encrypted to the new roster.
- The single point of failure is the **last maintainer**. If every maintainer loses their key,
  the vault is unrecoverable (this is the cost of no escrow). Mitigation: require >= 2 maintainers
  per environment; `init` warns when an environment has only one.

**macOS signing gotcha (pin the Developer ID from day one).** The macOS Keychain scopes item
access by the app's code signature. If we ship distribution builds and *later change the signing
identity*, users can lose access to keys already stored under the old signature and be forced to
re-add their identity. This is onboarding friction, not a security hole - the fallback is just the
recovery flow above (a maintainer re-adds them) - but it is avoidable. Choose a stable Developer ID
signing identity before the first public release and keep it constant across versions.

---

## 9. Binaries and desktop UI

### 9.1 Two binaries over one core

The workspace ships **two** executables over a single `bitfort-core` crate (no duplicated logic):

- **`bitfort` (CLI)** - thin `clap` binary. **No Tauri, no webview dependency.** This is the
  hot-path artifact: invoked on every `bitfort run`, in CI, in shell chains. It must load and run
  in bare/headless environments.
- **`bitfort-desktop`** - Tauri GUI for the maintainer/editing flow.

Why not a single Tauri binary with `tauri-plugin-cli`? You *can* branch on args before
`tauri::Builder::run()` so the event loop never starts - that solves the runtime cost. But on
**Linux the executable dynamically links `webkit2gtk`/gtk**, resolved by the loader at startup,
before `main()` runs. A single binary therefore fails to load on a minimal CI container or
headless server lacking those libs - exactly where `bitfort run` must work. The separate CLI
binary avoids the GUI link-time dependency for the cost of a second `[[bin]]`. (macOS/Windows
ship the webview with the OS, so this only bites on Linux - but Linux/CI is a target.)

### 9.2 Desktop scope (minimal, v1)

Thin shell over the same Rust core - no duplicated crypto. Stack: **Tauri** (Rust backend =
reuse the core crate; web frontend). Scope for v1:

- Open a project (`.bitfort/` dir), show roster + verification status.
- View secret **keys**; add/update/remove a value (calls core `set`/`unset` -> re-encrypt).
- Maintainer flow: review a pending invite, `member add`, see the signed roster bump.

Explicitly out of scope for v1 desktop: running commands, editing raw JSON, multi-project
dashboards. The CLI remains the source of truth; the UI is a convenience over identical core
functions.

---

## 10. Free and open source

BitFort is free and open source. The CLI has no paid tier, no license token, and no server to
call.

---

## 11. Tech stack and crates

Verify latest compatible versions at implementation time (do not pin from memory).

| Concern | Choice |
|---|---|
| Language | Rust (workspace: `bitfort-core` lib, `bitfort-cli` bin = **no webview dep**, `bitfort-desktop` Tauri app; see §9.1) |
| Encryption | `age` (X25519 recipients + ChaCha20-Poly1305), **ASCII-armored** output (§4.4) |
| Signing | Ed25519 (`ed25519-dalek`) for the roster and the vault payload |
| Canonical signing bytes | RFC 8785 JCS (e.g. `serde_jcs`), domain-separated (§4.3) - not ad-hoc key sorting |
| Git history checks | shell out to `git log`/`git cat-file` (or `gix`) for anti-rollback + collision detection (§4.3, §4.5) |
| Key storage | `keyring` (keyring-rs) on dev machines; `BITFORT_IDENTITY` env / file for headless & CI (§3.1) |
| Secret hygiene | `zeroize` |
| CLI parsing | `clap` (derive) |
| Serialization | `serde` + `serde_json` + `toml` (signing uses the JCS path above, not `serde_json` default output) |
| Errors | `anyhow` (bins) / `thiserror` (core lib) |
| Signals (Unix) | `nix` or `signal-hook` |
| Desktop | `tauri` |
| Tests | `cargo test`, `assert_cmd` + `tempfile` for CLI e2e, `insta` for format snapshots |

---

## 12. Open questions

Resolved in v0.2:
- ~~Multiple environments vs single vault~~ -> **multiple**, each a separate roster+vault for
  least privilege (§4.1).
- ~~Where the trust anchor is pinned~~ -> **`trust_anchor_fingerprint` in `config.toml`**, verified
  against roster v1 and published out-of-band + optional signed Git tag (§5.1).
- ~~Invite exchange format~~ -> **copy/paste `bfinvite1:` blob** (`keygen`/`member add`).

Still open:
1. Custom Git **merge driver** for vaults: v1 ships `bitfort resolve` (manual); the `.gitattributes`
   hook (§4.5) is not written yet. Is an automatic driver worth it for v1, or v2?
2. `bitfort git-diff` textconv so `vault.enc` shows key-level (not ciphertext) diffs in review.
3. Should read paths default to `--strict` inside CI (detected via env) so tampering hard-fails
   without an explicit flag?
