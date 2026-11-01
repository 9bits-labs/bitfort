#!/usr/bin/env bash
# Each commit in a pull request carries a `Signed-off-by:` line for its author: the Developer
# Certificate of Origin that CONTRIBUTING.md asks for. Merge commits are skipped. Dependabot
# commits as `dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>` but signs off
# as `dependabot[bot] <support@github.com>`, so that sign-off counts for its commits.
#
# The commit list is captured in its own statement so that `set -e` aborts on a bad range
# instead of reading an empty list as a pass.
#
#   scripts/check-dco.sh [range]    (default: origin/main..HEAD)
set -euo pipefail

range=${1:-origin/main..HEAD}
commits=$(git rev-list --no-merges "$range")

fail=0
for commit in $commits; do
  signoff=$(git log -1 --format='%an <%ae>' "$commit")
  if [ "$signoff" = 'dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>' ]; then
    signoff='dependabot[bot] <support@github.com>'
  fi
  signoffs=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit")
  if ! grep -qxF -e "$signoff" <<<"$signoffs"; then
    echo "$(git log -1 --format='%h %s' "$commit"): no Signed-off-by: $signoff" >&2
    fail=1
  fi
done
if [ "$fail" -ne 0 ]; then
  echo "FAIL: sign off each commit with \`git commit -s\`;" \
    "\`git rebase --signoff origin/main\` signs off the commits you already made" >&2
  exit 1
fi
echo "ok: every commit in $range is signed off by its author"
