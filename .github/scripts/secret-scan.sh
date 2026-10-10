#!/usr/bin/env bash
# Scan the full git history for secrets with gitleaks, and prove the scan
# covered what it should. Used by .github/workflows/ci.yml; tested by
# tests/test_secret_scan_script.py.
#
#   secret-scan.sh <path-to-gitleaks> [log-file]
#
# Optional environment (set by CI on pull_request events):
#   PR_BASE_SHA, PR_HEAD_SHA  - must both be inside the scanned history.
#
# Why "-m": by default `git log -p` shows no patch for merge commits, so
# gitleaks would neither scan content introduced by a merge (for example a
# conflict resolution) nor count those commits. A pull_request checkout is a
# synthetic merge commit, which made the count fall one short of
# `git rev-list --all --count`. With "-m" every reachable commit, merges
# included, is scanned, so the expected count is exactly that number.
set -euo pipefail

gitleaks="${1:?usage: secret-scan.sh <gitleaks> [log-file]}"
log="${2:-$(mktemp)}"
fail() { echo "::error::$1"; exit 1; }

# gitleaks exits 0 when git fails or no commits are visible, so verify
# coverage instead of trusting the exit code alone.
[ "$(git rev-parse --is-shallow-repository)" = "false" ] \
  || fail "Shallow clone: secret scan would miss history."

expected="$(git rev-list --all --count)"
merges="$(git rev-list --all --merges --count)"

if [ -n "${PR_HEAD_SHA:-}" ] || [ -n "${PR_BASE_SHA:-}" ]; then
  for sha in "${PR_BASE_SHA:-}" "${PR_HEAD_SHA:-}"; do
    [ -n "$sha" ] || fail "Pull request base or head SHA is missing."
    git cat-file -e "${sha}^{commit}" 2>/dev/null \
      || fail "Pull request commit ${sha} is not in the checked-out history."
    git merge-base --is-ancestor "$sha" HEAD \
      || fail "Pull request commit ${sha} is not an ancestor of the scanned HEAD."
  done
  merge_base="$(git merge-base "$PR_BASE_SHA" "$PR_HEAD_SHA")"
  echo "Pull request range ${merge_base:0:12}..${PR_HEAD_SHA:0:12}: $(git rev-list --count "${merge_base}..${PR_HEAD_SHA}") commit(s), all inside the scanned history."
fi

status=0
"$gitleaks" git --no-banner --no-color --redact --verbose --log-opts="--all -m" . >"$log" 2>&1 || status=$?
cat "$log"

[ "$status" -eq 0 ] || fail "gitleaks exited with status $status (1 means leaks were found)."
if grep -q ' ERR ' "$log"; then
  fail "gitleaks logged an error; the scan is not trustworthy."
fi
scanned="$(sed -n 's/.* INF \([0-9][0-9]*\) commits scanned\..*/\1/p' "$log")"
[ "$scanned" = "$expected" ] \
  || fail "gitleaks scanned '${scanned}' commits; ${expected} are reachable (${merges} merge commit(s))."
echo "gitleaks scanned all ${scanned} reachable commits (${merges} merge commit(s) included) and found no leaks."
