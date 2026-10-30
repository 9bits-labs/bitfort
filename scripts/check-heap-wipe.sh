#!/usr/bin/env bash
# Invariant 6: no secret stays in freed heap memory. Runs the real `bitfort` binary through each
# command that handles a secret, and fails if a block it frees still holds a vault value or an
# age private key (`AGE-SECRET-KEY-1`).
#
# macOS only: `check-heap-wipe.c` interposes `free` and `realloc` through DYLD_INSERT_LIBRARIES,
# and is built with clang (Xcode command line tools). The keyring is never touched: the identity
# comes from `identity new`, through the environment and, for the last read, a file.
#
# A command that frees nothing, or exits with a status other than the expected one, fails too.
# Otherwise an interposer that did not load, or a setup step that broke, would read as a pass.
#
#   ./scripts/check-heap-wipe.sh [path/to/bitfort]    (default: target/debug/bitfort)
set -euo pipefail

if [ "$(uname -s)" != Darwin ]; then
  echo "FAIL: check-heap-wipe.sh runs on macOS only" >&2
  exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
bin=$(realpath "${1:-$root/target/debug/bitfort}")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'echo "FAIL: setup step failed at line $LINENO" >&2' ERR

lib=$work/check-heap-wipe.dylib
clang -dynamiclib -O1 -o "$lib" "$root/scripts/check-heap-wipe.c"

hex() { printf %s "$1" | xxd -p | tr -d '\n'; }
ours=heapwipe-ours-5e21c0
theirs=heapwipe-theirs-77ab94
labels=(ours key theirs)
markers="$(hex "$ours"),$(hex AGE-SECRET-KEY-1),$(hex "$theirs")"

failed=0
# watch <label> <expected exit status> <stdin> <bitfort args...>
watch() {
  local label=$1 expect=$2 input=$3
  shift 3
  local status=0 report line frees hits problems="" i
  report=$(printf %s "$input" |
    /usr/bin/env FREEWATCH_HEX="$markers" DYLD_INSERT_LIBRARIES="$lib" "$bin" "$@" \
      2>&1 >/dev/null) || status=$?
  line=$(grep '^FREEWATCH ' <<<"$report" || true)
  frees=${line#*frees=}
  frees=${frees%% *}
  hits=${line#*hits=}

  [ "$status" -eq "$expect" ] || problems+=" exit=$status (expected $expect)"
  [ -n "$line" ] && [ "$frees" -gt 0 ] || problems+=" no frees seen (interposer not loaded)"
  IFS=, read -ra counts <<<"$hits"
  for i in "${!labels[@]}"; do
    [ "${counts[$i]:-0}" -eq 0 ] || problems+=" ${labels[$i]}=${counts[$i]}"
  done
  if [ -z "$problems" ]; then
    printf 'ok    %-20s %s frees\n' "$label" "$frees"
  else
    printf 'FAIL  %-20s%s\n' "$label" "$problems" >&2
    grep -v '^FREEWATCH ' <<<"$report" | sed 's/^/      /' >&2 || true
    failed=1
  fi
}
g() { git -c user.name=t -c user.email=t@e.com -c init.defaultBranch=main "$@"; }
bf() { "$bin" "$@" >/dev/null 2>&1; }

"$bin" identity new --force >"$work/id.key" 2>/dev/null
set -a
# shellcheck source=/dev/null
. "$work/id.key"
set +a
unset BITFORT_IDENTITY_FILE
mkdir "$work/project"
cd "$work/project"

watch "identity new" 0 "" identity new --force

g init -q
bf init
g add -A
g commit -qm init

watch "set (stdin)" 0 "$ours" set A
watch "get" 0 "" get A
watch "list" 0 "" list
watch "export dotenv" 0 "" export --format dotenv
watch "export shell" 0 "" export --format shell
watch "export json" 0 "" export --format json
watch "run" 0 "" run -- /usr/bin/true
watch "run --clean" 0 "" run --clean -- /usr/bin/true
watch "set (argument)" 0 "" set "B=$ours"
printf 'C=%s\n' "$ours" >"$work/import.env"
watch "import" 0 "" import "$work/import.env"
watch "unset" 0 "" unset --yes C
watch "rotate" 0 "" rotate

# A second member, so that both membership commands re-encrypt the vault.
invite=$("$bin" identity new --force --name second 2>/dev/null |
  sed -n 's/^# \(bfinvite1:.*\)/\1/p')
watch "member add" 0 "" member add --yes "$invite"
watch "member rm" 0 "" member rm --yes second

# A conflict on A: main holds $ours, a branch holds $theirs.
bf set --yes A=base
g commit -qam base
g branch feature
bf set --yes "A=$ours"
g commit -qam ours
g checkout -q feature
bf set --yes "A=$theirs"
g commit -qam theirs
g checkout -q main
if g merge -q --no-edit feature >/dev/null 2>&1; then
  echo "FAIL: the vault edits did not conflict" >&2
  exit 1
fi
watch "resolve (no side)" 1 "" resolve
watch "resolve --theirs" 0 "" resolve --theirs

# The same identity, read from a file instead of the environment.
chmod 600 "$work/id.key"
unset BITFORT_IDENTITY BITFORT_SIGN_IDENTITY
export BITFORT_IDENTITY_FILE=$work/id.key
watch "get (identity file)" 0 "" get A

[ "$failed" -eq 0 ] || exit 1
echo "ok: no secret left in freed heap memory"
