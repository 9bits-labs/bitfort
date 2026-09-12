# BitFort

Commit your secrets, encrypted.

BitFort encrypts your `.env` into a file only your team's keys can open. You commit that file.
BitFort decrypts it when you run your app, so no plaintext copy is ever stored.

```bash
bitfort init                      # create .bitfort/, pin the trust anchor, sign roster v1
bitfort import .env               # migrate what you already have, then delete the .env
bitfort set STRIPE_KEY            # add one secret, read without echo
bitfort run -- npm run dev        # decrypt into the child's environment, and nowhere else
```

`.bitfort/config.toml` records the project and its pinned trust anchor. Each environment then has
its own directory under `.bitfort/environments/`, holding a signed roster of public keys
(`keys.json`), the chain that proves how that roster got there (`chain.json`), and the encrypted
vault (`vault.enc`). All of it is meant to be committed. A teammate joins by sending an invite
blob:

```bash
bitfort keygen                    # on their machine: print an invite
bitfort member add bfinvite1:...  # a maintainer adds them and re-encrypts
bitfort verify                    # anyone: the roster verifies against the pinned anchor
```

## Install

There are no packaged installers yet. Build it from source with Rust 1.96 or newer:

```bash
cargo build --release             # target/release/bitfort
```

## What it does not do

- No server, no daemon, no account. The vault lives in your repository.
- No central audit log. What happened is what git recorded.
- No protection of the running process. Secrets are plaintext in the child's environment by
  design, so anything that can read that process can read them.
- No recovery of a lost key. Private keys stay in the OS keyring, and nothing escrows them.

## Support policy

The supported artifact is the `bitfort` binary. The crates in `crates/` are not published to
crates.io, carry no stable API, and may change shape in any commit. Build against the binary and
the on-disk format, never against the crates.

## Documentation

- [`docs/SPEC.md`](docs/SPEC.md) is the design source of truth: the on-disk format, the signing
  bytes, the verification model, and the threat model with what each row does and does not cover.
- [`docs/FORMAT.md`](docs/FORMAT.md) is the on-disk format at the byte level, with test vectors,
  for anyone writing a compatible implementation.
- [`docs/cli.mdx`](docs/cli.mdx) is the command reference, pinned to the binary by a test that
  fails the build when the two drift.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).
