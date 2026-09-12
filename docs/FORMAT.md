# BitFort on-disk format

Everything BitFort writes, at the byte level, so another implementation can read and write the
same files. [`SPEC.md`](SPEC.md) explains why the format is shaped this way and what the
verification model promises; this page is the part a compatible implementation has to match
exactly.

The vectors at the end are generated, never hand written, and pinned by the `format_vectors`
module in `crates/core/src/vault.rs`. An accidental change to a signed byte fails that test. A
deliberate one is made by rerunning the generator, so the vector diff on this page is the thing
to review, not only a green test run.

## Layout

```
.bitfort/
├── config.toml                 # project settings
└── environments/<env>/
    ├── keys.json               # the signed roster
    ├── chain.json              # every predecessor roster, in order
    └── vault.enc               # ASCII-armored age ciphertext
```

`<env>` is a single path component of ASCII letters, digits, `-` or `_`. It is validated when
`config.toml` is parsed, not only when an environment is created, because the name is joined
under `environments/` to build every path above.

`keys.json` and `chain.json` are written as pretty-printed JSON with a trailing newline. That
encoding is free: signatures are checked over recomputed canonical bytes, never over the file as
it sits on disk, so an implementation may write compact JSON and this one still verifies it.

## Encodings

| Thing | Form |
|---|---|
| Encryption public key | `age1...`, the age x25519 recipient string |
| Signing public key | `ed25519:` + standard base64 (with padding) of the 32-byte key |
| Signature | standard base64 of the 64-byte Ed25519 signature |
| Display fingerprint | `bf1:` + hex of the first 8 bytes of `SHA-256(enc_pubkey)` |
| Trust anchor | `bf1:` + hex of the first 8 bytes of `SHA-256(enc_pubkey ‖ "\|" ‖ sign_pubkey)` |
| Roster digest | hex of `SHA-256(roster signing bytes)`, all 32 bytes |
| Timestamps | RFC 3339 UTC, `YYYY-MM-DDThh:mm:ssZ` |

The anchor hashes both public keys with a `|` between them, so the two fields cannot be
re-split, and so a valid version-1 signature requires the matching signing private key.

## Rules that apply to every file

- **Objects are closed.** Every JSON object here is parsed with unknown fields rejected. An
  implementation that adds an extension field writes a file this one refuses.
- **`schema_version` is a ceiling, not a hint.** Each file carries one, and a value above the
  version the reader knows (1 today) is refused rather than parsed on a best-effort basis.
- **Signatures are verified strictly.** Ed25519 verification rejects small-order keys and
  non-canonical encodings. An implementation using a permissive verifier would accept
  signatures this one refuses.

## Signing bytes

Every signature in BitFort is over the same construction:

```
signing_bytes = domain_tag ‖ RFC8785_JCS(signing_view)
```

- `domain_tag` is `bitfort-roster-v1\n` for a roster and `bitfort-vault-v1\n` for a vault
  payload. The tags differ so a signature over one payload can never verify over the other.
- `RFC8785_JCS` is JSON Canonicalization Scheme: keys sorted by UTF-16 code unit, no
  insignificant whitespace, shortest-form numbers.
- `signing_view` is the payload with its signature fields removed, and nothing else.

Inside a signed payload, a field is never conditionally serialized: presence must not depend on
value, or the bytes move. `prev_digest` is the case to watch, and it is serialized as `null` at
version 1. (Outside the signed payloads this does not apply: `config.toml` omits `rotated_at`
until the first rotation, and nothing signs that file.)

A verifier rebuilds these bytes from the fields it read and checks the signature over them.
Ed25519 is deterministic, so the same key over the same bytes always yields the same signature,
which is why the vectors below can pin one.

## `config.toml`

Fields, in declaration order rather than on-disk order:

```toml
schema_version           = 1
project_id               = "00112233445566778899aabbccddeeff"
default_env              = "development"
environments             = ["development"]
trust_anchor_fingerprint = "bf1:087bd1e8699b49a9"
# rotated_at            = "2026-01-02T03:04:05Z"   # written by `rotate`; absent until then
```

`project_id` is 32 hex characters over 16 random bytes. Nothing signs this file; `project_id`
appears inside every signed payload, and that is what binds a vault to one project.

## `keys.json`

A field list, not a byte layout:

```json
{
  "schema_version": 1,
  "project_id": "00112233445566778899aabbccddeeff",
  "env": "development",
  "roster_version": 1,
  "prev_digest": null,
  "members": [
    {
      "name": "ada",
      "enc_pubkey": "age1...",
      "sign_pubkey": "ed25519:...",
      "role": "maintainer",
      "added_by": "ada",
      "added_at": "2026-01-02T03:04:05Z"
    }
  ],
  "signatures": [
    { "signer": "ada", "sign_pubkey": "ed25519:...", "signature": "..." }
  ]
}
```

- `role` is `member` or `maintainer`, lowercase.
- `name` is printable ASCII (U+0020 to U+007E), at most 64 characters. It travels inside the
  signed bytes and is printed back, so a control character in it would forge a row in a listing.
- `prev_digest` is `null` at version 1 and the predecessor's roster digest afterwards.
- `signatures` is the only field outside the signing view, so a signature can be appended
  without invalidating the others. `signer` is a display label; verification uses `sign_pubkey`.

The signing view is every field except `signatures`.

## `chain.json`

```json
{ "schema_version": 1, "rosters": [ <roster v1>, <roster v2>, ... ] }
```

Each element is a complete roster object in the shape above, in ascending version order. The
current version in `keys.json` is normally absent here; a tail that repeats it is tolerated,
because a crash between the two writes produces exactly that, and refusing it would leave the
environment unrepairable.

A verifier walks the chain from the pinned anchor forward and refuses any of these:

- a version-1 roster not self-signed by the identity whose anchor equals
  `trust_anchor_fingerprint`;
- a later version not signed by a maintainer of its predecessor;
- a `prev_digest` that does not equal the predecessor's digest, or a version-1 roster that
  carries one at all;
- a roster with no maintainers, which could never authorize a successor;
- an `env` or `project_id` that does not match the file it was loaded for;
- a roster version of 0.

## `vault.enc`

An ASCII-armored age document. The armor wraps the entire age file in base64 between
`-----BEGIN AGE ENCRYPTED FILE-----` and `-----END AGE ENCRYPTED FILE-----`, so the stanzas are
inside the base64, not visible as lines of the file. Decoded, the header reads:

```
age-encryption.org/v1
-> X25519 hvls8nY+z9bUnJAHjlrrIKw+cZRx4nZLfweT2C/lP3E
g1lCG32+GJWqaK/w3wacg+bNXt6u9WNOWltv8BW7QJ8
-> L-grease %P
Wuw/2RN9ksEg1VdGQCI
--- D/DSL/c86Lr/EGBIgWFY/JAUKclFAm4gCtMN46sJm4w
<binary payload>
```

**Counting recipients.** The file carries one stanza per roster member, plus one grease stanza:
a randomly tagged decoy age writes into every header, whose tag always ends in `-grease`. A
reader that counts every `-> ` line sees one recipient too many and refuses a genuine vault.
Exclude any tag ending in `-grease`, and count every other stanza type rather than only
`X25519`: age ignores a stanza type it does not know, so counting only `X25519` would miss an
added `ssh-ed25519` recipient, which is the case this rule exists to catch.

The plaintext inside is the JCS serialization of this field list:

```json
{
  "schema_version": 1,
  "project_id": "00112233445566778899aabbccddeeff",
  "env": "development",
  "roster_version": 1,
  "vars": { "API_KEY": "sk-test-123" },
  "written_at": "2026-01-02T03:04:05Z",
  "signature": { "signer": "ada", "sign_pubkey": "ed25519:...", "signature": "..." }
}
```

- The signing view is every field except `signature`.
- `vars` keys must match `[A-Za-z_][A-Za-z0-9_]*`. Values are UTF-8 and may be multiline.
- `roster_version` names the roster this payload was written for. A reader authenticates it
  against that roster, taken from `keys.json` or from the `chain.json` link of that version, and
  refuses a payload no member of it signed.
- The recipient count is checked against that roster when the version resolves to a known
  roster. A payload naming a version neither file holds is checked against `keys.json` and
  refused for drift, so no count is made.

Ciphertext bytes are not reproducible: age uses a fresh ephemeral key per encryption, and the
grease stanza is random. The signed payload is what a vector can pin.

## Rules a writer enforces

These are not checked by a verifier, so an implementation that writes files has to apply them
itself:

- A vault write refuses a `vars` name that decides how a process runs: `PATH`, `NODE_OPTIONS`,
  `PYTHONPATH`, `PERL5LIB`, or any name starting with `LD_`, `DYLD_`, `GIT_` or `BITFORT_`. A
  signature says a member wrote the file, not that a member may execute code on every
  teammate's machine. Reading such a vault is allowed on purpose, so a tool can show the user
  what to remove.
- A vault write refuses a value carrying a NUL: it would make every later process spawn fail,
  so the refusal belongs at the write, while an existing vault still decrypts and can be
  repaired.
- A membership write refuses a second member with the same name (compared without case), the
  same `sign_pubkey`, or the same `enc_pubkey`. Two seats behind one encryption key make
  removal of one silently fail to revoke the other.

## Invite blob

`bfinvite1:` + standard base64 of `{"name":..,"enc_pubkey":..,"sign_pubkey":..}`, carrying
public key material only. Decoding checks the name against the roster-name rule; the two public
keys are validated separately, before anything is written. Encoding applies neither check, so a
writer validates before it hands a blob to anyone.

## Test vectors

Two fixed identities, A and B. Their secrets are in the `format_vectors` module; only the public
halves matter here.

| Field | A | B |
|---|---|---|
| `enc_pubkey` | `age1wv5cdjkemks5sg7l06dj9ju2h9almvcll2fdud67ejd8mp9pcgpqychk7v` | `age1kn4vdzw53qcqrvls57tjpnds0nfmg820ztnaru04w9e5dmwapv9qfqwya5` |
| `sign_pubkey` | `ed25519:jGku5Qk3/X47h46w0HOUYZWWMQfYLuQUBNd8yMkxAYI=` | `ed25519:XrfzFm7LaChQRjaOEPk1d8zCmIhrhPMA01oq6oK6uTw=` |
| fingerprint | `bf1:5ba1231767d596e9` | `bf1:bda3f84a115f39e8` |
| anchor | `bf1:087bd1e8699b49a9` | `bf1:f19a418502ea45ce` |

With `project_id` `00112233445566778899aabbccddeeff`, env `development`, and every timestamp
`2026-01-02T03:04:05Z`.

### Roster v1, one maintainer (A)

Signing bytes, 389 bytes, newline after the tag:

```
bitfort-roster-v1
{"env":"development","members":[{"added_at":"2026-01-02T03:04:05Z","added_by":"ada","enc_pubkey":"age1wv5cdjkemks5sg7l06dj9ju2h9almvcll2fdud67ejd8mp9pcgpqychk7v","name":"ada","role":"maintainer","sign_pubkey":"ed25519:jGku5Qk3/X47h46w0HOUYZWWMQfYLuQUBNd8yMkxAYI="}],"prev_digest":null,"project_id":"00112233445566778899aabbccddeeff","roster_version":1,"schema_version":1}
```

- digest: `daccf26f3f0d1cffb03a11de57cae4b4e8b5ec2ffdde64732d5b23910cf2e706`
- signature by A: `yu8/piwS4PXeuQ57OZG+mYDi92WI5djxBuhyFoF2Ki98iSpYtweGt5y6An4UZBDJwM7dU3wPIxAtVDWha1hsDQ==`

### Roster v2, adding B as a member, signed by A

Signing bytes, 680 bytes:

```
bitfort-roster-v1
{"env":"development","members":[{"added_at":"2026-01-02T03:04:05Z","added_by":"ada","enc_pubkey":"age1wv5cdjkemks5sg7l06dj9ju2h9almvcll2fdud67ejd8mp9pcgpqychk7v","name":"ada","role":"maintainer","sign_pubkey":"ed25519:jGku5Qk3/X47h46w0HOUYZWWMQfYLuQUBNd8yMkxAYI="},{"added_at":"2026-01-02T03:04:05Z","added_by":"ada","enc_pubkey":"age1kn4vdzw53qcqrvls57tjpnds0nfmg820ztnaru04w9e5dmwapv9qfqwya5","name":"bob","role":"member","sign_pubkey":"ed25519:XrfzFm7LaChQRjaOEPk1d8zCmIhrhPMA01oq6oK6uTw="}],"prev_digest":"daccf26f3f0d1cffb03a11de57cae4b4e8b5ec2ffdde64732d5b23910cf2e706","project_id":"00112233445566778899aabbccddeeff","roster_version":2,"schema_version":1}
```

- digest: `efef046306e124012ef0c79f9ed9f53895087a4d9877c393c90cd24e87594ed1`
- signature by A: `hznf1ek8mEHbya36rJFJ6Dcgm716YpUgbUEXy2OEiwKzq4WgY7JDIcmnpr04r2lVLocA2fK8iaiEgD66vObeAw==`

### Vault payload, two secrets, roster version 1

Signing bytes, 235 bytes:

```
bitfort-vault-v1
{"env":"development","project_id":"00112233445566778899aabbccddeeff","roster_version":1,"schema_version":1,"vars":{"API_KEY":"sk-test-123","DATABASE_URL":"postgres://localhost/app"},"written_at":"2026-01-02T03:04:05Z"}
```

- signature by A: `3PRG0An/6Cy7DrkF8DM44HxNHY8fsSkZXLOGWkH4hXau0b7YbK/jNwka2e/2T5foqgkguN3u7xbnXTTlz8tBCg==`

The plaintext that gets encrypted is that view plus the signature object, serialized by the same
canonicalization.

### Invite blob for A

```
bfinvite1:eyJuYW1lIjoiYWRhIiwiZW5jX3B1YmtleSI6ImFnZTF3djVjZGprZW1rczVzZzdsMDZkajlqdTJoOWFsbXZjbGwyZmR1ZDY3ZWpkOG1wOXBjZ3BxeWNoazd2Iiwic2lnbl9wdWJrZXkiOiJlZDI1NTE5OmpHa3U1UWszL1g0N2g0NncwSE9VWVpXV01RZllMdVFVQk5kOHlNa3hBWUk9In0=
```

### What the vectors do not cover

`chain.json` as a file, `config.toml`, `keys.json` as written, and the age header beyond the
grease rule are described above but not pinned by a vector. An implementation should treat the
descriptions as normative and check itself against a real file this implementation wrote.

## Compatible implementations

The format is public and the vectors above are the conformance suite. Two rules carry the
security properties, and neither is optional:

1. Verify the roster chain from the pinned anchor before trusting any member list.
2. Verify the vault payload signature against the roster it names, and refuse a payload no
   member of that roster signed. Encryption proves nothing about authorship: every `enc_pubkey`
   is public.
