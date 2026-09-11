#!/usr/bin/env bash
# Fast dev-loop build: cranelift codegen backend + parallel rustc front-end.
#
# For the inner dev loop ONLY. Cranelift skips LLVM's optimizations, so the
# binary is CORRECT but runs SLOWER. Never ship or benchmark this output, and
# always validate with the stable release build (see CLAUDE.md verification
# loop) before calling a change done.
#
# Uses a separate target dir so it never invalidates the stable target/ cache.
#
# Usage:  scripts/dev-fast.sh [cargo-args...]   (defaults to `build`)
#   scripts/dev-fast.sh build -p bitfort-cli
#   scripts/dev-fast.sh test --workspace
#   scripts/dev-fast.sh run -p bitfort-cli -- --version
set -euo pipefail

if ! rustup toolchain list | grep -q '^nightly'; then
  echo "error: nightly toolchain required -> rustup toolchain install nightly" >&2
  exit 1
fi
if ! rustup component list --toolchain nightly | grep -q 'rustc-codegen-cranelift.*(installed)'; then
  echo "error: cranelift component required ->" >&2
  echo "       rustup component add rustc-codegen-cranelift-preview --toolchain nightly" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then set -- build; fi

exec env \
  RUSTFLAGS="-Zcodegen-backend=cranelift -Zthreads=8" \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/cranelift}" \
  cargo +nightly "$@"
