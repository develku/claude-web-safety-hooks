#!/bin/bash
# Test harness for web-safety scanner.
# For each tests/payloads/<bucket>-*.txt, builds a synthetic tool-result envelope,
# pipes it through scripts/web-safety-scanner.sh, and asserts the resulting
# severity matches the filename bucket.
#
# Buckets:
#   high-*   → expect HIGH severity (systemMessage starts with "CRITICAL...")
#   med-*    → expect MEDIUM severity
#   low-*    → expect LOW severity
#   legit-*  → expect CLEAN (no output) OR cleared by Layer 5
#
# Each test runs in an isolated CONFIG_DIR so logs don't bleed across cases.
# Session state at /tmp/web-safety-session-state is wiped between tests so
# cross-tool escalation doesn't poison results.

set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
SCANNER="$REPO_ROOT/scripts/web-safety-scanner.sh"
PAYLOAD_DIR="$TESTS_DIR/payloads"

if [ ! -x "$SCANNER" ]; then
  echo "FAIL: scanner not executable at $SCANNER"
  exit 2
fi

# Stub osascript so tests don't fire macOS notifications.
FAKE_BIN=$(mktemp -d)
trap 'rm -rf "$FAKE_BIN"' EXIT
cat >"$FAKE_BIN/osascript" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$FAKE_BIN/osascript"
export PATH="$FAKE_BIN:$PATH"

PASS=0
FAIL=0
FAILURES=()

classify() {
  # $1 = scanner output (JSON or empty), $2 = scanner exit code
  local out="$1"
  local ec="$2"
  if [ "$ec" -ne 0 ] || [ -z "$out" ]; then
    echo "clean"
    return
  fi
  local msg
  msg=$(echo "$out" | jq -r '.systemMessage // ""' 2>/dev/null)
  case "$msg" in
    "CRITICAL PROMPT INJECTION DETECTED [HIGH SEVERITY]"*) echo "high" ;;
    "ESCALATED TO HIGH SEVERITY"*) echo "high" ;;
    "PROMPT INJECTION WARNING [MEDIUM SEVERITY]"*) echo "medium" ;;
    "WEB CONTENT NOTE [LOW SEVERITY]"*) echo "low" ;;
    *) echo "unknown" ;;
  esac
}

run_one() {
  local payload_file="$1"
  local basename
  basename=$(basename "$payload_file" .txt)
  local bucket="${basename%%-*}"

  # Isolated config dir per test (fresh log + no allowlist/blocklist)
  local cfg
  cfg=$(mktemp -d)

  # Wipe cross-tool session state — each test starts with no prior hits
  rm -f /tmp/web-safety-session-state /tmp/web-safety-scanner-last-notify

  local payload
  payload=$(cat "$payload_file")

  # Build synthetic Claude Code PostToolUse envelope
  local envelope
  envelope=$(jq -n \
    --arg tool "WebFetch" \
    --arg url "https://example.test/${basename}" \
    --arg output "$payload" \
    '{tool_name: $tool, tool_input: {url: $url}, tool_response: $output}')

  local out ec
  out=$(echo "$envelope" | WEB_SAFETY_CONFIG_DIR="$cfg" "$SCANNER" 2>/dev/null)
  ec=$?

  local actual
  actual=$(classify "$out" "$ec")

  rm -rf "$cfg"

  local expected
  case "$bucket" in
    high)  expected="high" ;;
    med)   expected="medium" ;;
    low)   expected="low" ;;
    legit) expected="clean" ;;
    *)     expected="unknown" ;;
  esac

  if [ "$actual" = "$expected" ]; then
    PASS=$((PASS + 1))
    printf "  ✓ %-40s  expected=%-7s actual=%s\n" "$basename" "$expected" "$actual"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("$basename: expected=$expected actual=$actual")
    printf "  ✗ %-40s  expected=%-7s actual=%s\n" "$basename" "$expected" "$actual"
  fi
}

echo "Running web-safety scanner test harness"
echo "  scanner:   $SCANNER"
echo "  payloads:  $PAYLOAD_DIR"
echo ""

shopt -s nullglob
PAYLOADS=("$PAYLOAD_DIR"/*.txt)
shopt -u nullglob

if [ ${#PAYLOADS[@]} -eq 0 ]; then
  echo "FAIL: no payload files found in $PAYLOAD_DIR"
  exit 2
fi

for f in "${PAYLOADS[@]}"; do
  run_one "$f"
done

echo ""
echo "Results: $PASS passed, $FAIL failed (total $((PASS + FAIL)))"

if [ "$FAIL" -ne 0 ]; then
  echo ""
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  exit 1
fi

exit 0
