#!/usr/bin/env bash
# Installs dist (https://github.com/axodotdev/cargo-dist), the tool that builds the release
# archives and the Homebrew formula, for .github/workflows/release.yml. It downloads the release
# archive for this machine and checks it against a SHA-256 pinned here, in place of the
# `curl | sh` installer that `dist generate` writes. The version is `cargo-dist-version` in
# dist-workspace.toml; a change there fails the check until the four hashes below match it.
#
#   scripts/install-dist.sh <bin-dir>
set -euo pipefail

bin=${1:?usage: scripts/install-dist.sh <bin-dir>}
root=$(cd "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^cargo-dist-version = "\(.*\)"$/\1/p' "$root/dist-workspace.toml")

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    target=x86_64-unknown-linux-gnu
    sha256=da68e159d5fed1ee61b00284da444e719927dbd0b7d0e2c34e57a04414453cf9 ;;
  Linux-aarch64)
    target=aarch64-unknown-linux-gnu
    sha256=e883f4c6c17f2458d6ced950d978c04b45423ed3a5fdbebcb8f8de568389e1c1 ;;
  Darwin-arm64)
    target=aarch64-apple-darwin
    sha256=b8bf041a38e9e54ecf41eee2574ca6644043796620bb0ee8340e9c0acbaaae8f ;;
  Darwin-x86_64)
    target=x86_64-apple-darwin
    sha256=e9dc303035fbb2f44295948e0a076f1d1d218a0328e9b84e16955863bba92bf4 ;;
  *)
    echo "install-dist: no pinned dist archive for $(uname -s) $(uname -m)" >&2
    exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
archive=cargo-dist-$target.tar.xz
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$archive" \
  "https://github.com/axodotdev/cargo-dist/releases/download/v$version/$archive"
if ! echo "$sha256  $tmp/$archive" | shasum -a 256 -c - >/dev/null; then
  echo "install-dist: $archive for dist $version does not match the pinned SHA-256;" \
    "update the hashes in this script when cargo-dist-version changes" >&2
  exit 1
fi
tar -xJf "$tmp/$archive" -C "$tmp"
mkdir -p "$bin"
install -m 755 "$tmp/cargo-dist-$target/dist" "$bin/dist"
"$bin/dist" --version
