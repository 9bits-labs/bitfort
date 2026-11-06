#!/usr/bin/env bash
# Invariant 5: the shipped `bitfort` binary carries no GUI/webview dependency, so it loads on
# bare Linux and CI runners (docs/SPEC.md §9.1).
#
# `cargo tree` output is captured in its own statement so that `set -e` aborts on a resolver,
# lockfile, or offline error instead of reading an empty result as a pass.
#
# Run from anywhere in the workspace.
set -euo pipefail

cd "$(dirname "$0")/.."

tree=$(cargo tree -p bitfort --edges normal --prefix none)
gui=$(printf '%s\n' "$tree" | grep -Ei '^(tauri|wry|webkit|javascriptcore)' || true)
if [ -n "$gui" ]; then
  echo "FAIL: bitfort links a GUI/webview crate:" >&2
  printf '%s\n' "$gui" >&2
  exit 1
fi
echo "ok: bitfort links no GUI/webview crate"
