#!/bin/bash
# Test harness for web-safety scanner.
#
# Two test shapes:
#
# 1) Single-fetch payloads — tests/payloads/<bucket>-<name>.txt
#    Run one synthetic WebFetch; assert classification matches bucket prefix.
#
# 2) Sequence (multi-fetch) payloads — tests/payloads/<bucket>-<name>/
#    Directory of numbered files run against the SAME session in order.
#    Filename `NN.txt` or `NN.LABEL.txt`. LABEL controls CLAUDE_SESSION_ID
#    so a single directory can interleave multiple sessions (for E8
#    cross-session-isolation tests). Assert FINAL fetch's classification
#    matches the directory's bucket prefix.
#
# Buckets:
#   high-*       → expect HIGH severity
#   med-*        → expect MEDIUM severity
#   low-*        → expect LOW severity
#   legit-*      → expect CLEAN (no detection or Layer 5 cleared)
#   reassembly-* → expect HIGH from E8 cross-call reassembly (sequence only)

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

expected_for_bucket() {
  case "$1" in
    high|reassembly) echo "high" ;;
    med) echo "medium" ;;
    low) echo "low" ;;
    legit) echo "clean" ;;
    *) echo "unknown" ;;
  esac
}

report() {
  local name="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    PASS=$((PASS + 1))
    printf "  ✓ %-44s  expected=%-7s actual=%s\n" "$name" "$expected" "$actual"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("$name: expected=$expected actual=$actual")
    printf "  ✗ %-44s  expected=%-7s actual=%s\n" "$name" "$expected" "$actual"
  fi
}

run_one() {
  local payload_file="$1"
  local basename
  basename=$(basename "$payload_file" .txt)
  local bucket="${basename%%-*}"

  local cfg sid
  cfg=$(mktemp -d)
  sid="test-${basename}-$$-$RANDOM"
  rm -f /tmp/web-safety-scanner-last-notify

  local payload envelope out ec
  payload=$(cat "$payload_file")
  envelope=$(jq -n \
    --arg tool "WebFetch" \
    --arg url "https://example.test/${basename}" \
    --arg output "$payload" \
    '{tool_name: $tool, tool_input: {url: $url}, tool_response: $output}')

  out=$(echo "$envelope" | \
    WEB_SAFETY_CONFIG_DIR="$cfg" CLAUDE_SESSION_ID="$sid" "$SCANNER" 2>/dev/null)
  ec=$?

  rm -rf "$cfg"
  rm -f "/tmp/web-safety-session-${sid}-"*

  report "$basename" "$(expected_for_bucket "$bucket")" "$(classify "$out" "$ec")"
}

run_sequence() {
  local seq_dir="$1"
  local basename
  basename=$(basename "$seq_dir")
  local bucket="${basename%%-*}"

  shopt -s nullglob
  local files=("$seq_dir"/*.txt)
  shopt -u nullglob
  [ ${#files[@]} -eq 0 ] && return

  # Sort by filename so numeric prefix orders deterministically.
  IFS=$'\n' files=($(printf '%s\n' "${files[@]}" | sort))
  unset IFS

  local cfg
  cfg=$(mktemp -d)
  rm -f /tmp/web-safety-scanner-last-notify

  # Track unique session labels so we can clean them up.
  local used_sids=""
  local out="" ec=0

  for f in "${files[@]}"; do
    local fn label sid
    fn=$(basename "$f" .txt)
    # Filename shape: NN.txt → label "default"
    #                 NN.LABEL.txt → label "LABEL"
    if [[ "$fn" =~ ^[0-9]+\.([A-Za-z0-9]+)$ ]]; then
      label="${BASH_REMATCH[1]}"
    else
      label="default"
    fi
    # Deterministic per-label sid (same label across the sequence = same session)
    sid="test-${basename}-${label}-$$"
    case " $used_sids " in
      *" $sid "*) ;;
      *) used_sids="$used_sids $sid" ;;
    esac

    local payload envelope
    payload=$(cat "$f")
    envelope=$(jq -n \
      --arg tool "WebFetch" \
      --arg url "https://example.test/${basename}/${fn}" \
      --arg output "$payload" \
      '{tool_name: $tool, tool_input: {url: $url}, tool_response: $output}')

    out=$(echo "$envelope" | \
      WEB_SAFETY_CONFIG_DIR="$cfg" CLAUDE_SESSION_ID="$sid" "$SCANNER" 2>/dev/null)
    ec=$?
  done

  rm -rf "$cfg"
  for sid in $used_sids; do
    rm -f "/tmp/web-safety-session-${sid}-"*
  done

  report "$basename" "$(expected_for_bucket "$bucket")" "$(classify "$out" "$ec")"
}

echo "Running web-safety scanner test harness"
echo "  scanner:   $SCANNER"
echo "  payloads:  $PAYLOAD_DIR"
echo ""

shopt -s nullglob
SINGLES=("$PAYLOAD_DIR"/*.txt)
SEQUENCES=("$PAYLOAD_DIR"/*/)
shopt -u nullglob

if [ ${#SINGLES[@]} -eq 0 ] && [ ${#SEQUENCES[@]} -eq 0 ]; then
  echo "FAIL: no payload files or sequences found in $PAYLOAD_DIR"
  exit 2
fi

IFS=$'\n' SINGLES=($(printf '%s\n' "${SINGLES[@]}" | sort))
IFS=$'\n' SEQUENCES=($(printf '%s\n' "${SEQUENCES[@]}" | sort))
unset IFS

for f in "${SINGLES[@]}"; do
  run_one "$f"
done

for d in "${SEQUENCES[@]}"; do
  run_sequence "${d%/}"
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
