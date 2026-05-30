#!/bin/bash
# Tests for the command helper scripts: web-safety-report.sh, web-safety-listctl.sh.
# Separate from run-tests.sh (which tests the scanner against payload buckets).
set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
REPORT="$REPO_ROOT/scripts/web-safety-report.sh"
LISTCTL="$REPO_ROOT/scripts/web-safety-listctl.sh"

PASS=0
FAIL=0
FAILURES=()
ok()  { PASS=$((PASS + 1)); printf "  ✓ %s\n" "$1"; }
bad() { FAIL=$((FAIL + 1)); FAILURES+=("$1"); printf "  ✗ %s\n" "$1"; }

for s in "$REPORT" "$LISTCTL"; do
  [ -x "$s" ] || { echo "FAIL: not executable: $s"; exit 2; }
done

CFG=$(mktemp -d)
trap 'rm -rf "$CFG"' EXIT
export WEB_SAFETY_CONFIG_DIR="$CFG"

# --- listctl: valid allow add ---
out=$("$LISTCTL" allow github.com 2>&1); ec=$?
if [ $ec -eq 0 ] && grep -qxF "github.com" "$CFG/url-allowlist.txt" 2>/dev/null; then
  ok "listctl: adds valid domain to allowlist"
else
  bad "listctl: adds valid domain to allowlist ($out)"
fi

# --- listctl: idempotent (no duplicate) ---
"$LISTCTL" allow github.com >/dev/null 2>&1
n=$(grep -cxF "github.com" "$CFG/url-allowlist.txt")
[ "$n" -eq 1 ] && ok "listctl: dedupes existing domain" || bad "listctl: dedupes (n=$n)"

# --- listctl: a pasted URL is normalized to its host (and lowercased) ---
"$LISTCTL" allow "https://Sub.Example.COM/path?x=1" >/dev/null 2>&1
grep -qxF "sub.example.com" "$CFG/url-allowlist.txt" \
  && ok "listctl: normalizes URL to host" || bad "listctl: normalizes URL to host"

# --- listctl: block writes to the blocklist ---
"$LISTCTL" block evil.test >/dev/null 2>&1
grep -qxF "evil.test" "$CFG/url-blocklist.txt" \
  && ok "listctl: block target -> blocklist" || bad "listctl: block target -> blocklist"

# --- listctl: invalid domain rejected, nothing written ---
"$LISTCTL" allow "not a domain; rm -rf" >/dev/null 2>&1; ec=$?
[ $ec -ne 0 ] && ok "listctl: rejects invalid domain (exit!=0)" || bad "listctl: rejects invalid domain"
grep -q "rm" "$CFG/url-allowlist.txt" 2>/dev/null \
  && bad "listctl: must not write junk on reject" || ok "listctl: writes no junk on reject"

# --- listctl: unknown list name rejected ---
"$LISTCTL" bogus github.com >/dev/null 2>&1; ec=$?
[ $ec -ne 0 ] && ok "listctl: rejects unknown list name" || bad "listctl: rejects unknown list name"

# --- report: missing log -> friendly message, exit 0 ---
CFG2=$(mktemp -d)
out=$(WEB_SAFETY_CONFIG_DIR="$CFG2" "$REPORT" 2>&1); ec=$?
{ [ $ec -eq 0 ] && printf '%s' "$out" | grep -qi "no audit log"; } \
  && ok "report: handles missing log" || bad "report: handles missing log"
rm -rf "$CFG2"

# --- report: summarizes a synthetic log ---
CFG3=$(mktemp -d)
cat > "$CFG3/web-safety.log" <<'LOG'
[2026-05-01 10:00:00] [HIGH] tool=WebFetch url=https://evil.com patterns="x"
[2026-05-01 10:01:00] [MEDIUM] tool=Exa url=https://blog.test/p patterns="y"
[2026-05-01 10:02:00] [HIGH] tool=WebFetch url=https://evil.com patterns="z"
[2026-05-01 10:03:00] [PRE-BLOCK] url=https://evil.com reason=blocklist
LOG
out=$(WEB_SAFETY_CONFIG_DIR="$CFG3" "$REPORT" 2>&1); ec=$?
if [ $ec -eq 0 ] \
   && printf '%s' "$out" | grep -qE '\| HIGH \| 2 \|' \
   && printf '%s' "$out" | grep -qE '\| WebFetch \| 2 \|' \
   && printf '%s' "$out" | grep -qE '\| evil\.com \| 3 \|' \
   && printf '%s' "$out" | grep -qE 'Events:\*\* 4'; then
  ok "report: summarizes synthetic log"
else
  bad "report: summarizes synthetic log"
fi
rm -rf "$CFG3"

echo ""
echo "Results: $PASS passed, $FAIL failed (total $((PASS + FAIL)))"
if [ "$FAIL" -ne 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
