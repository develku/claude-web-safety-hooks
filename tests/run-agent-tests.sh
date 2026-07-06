#!/bin/bash
# Test harness for v8 multi-agent visibility: die-but-visible kill ledger,
# per-agent escalation scoping, atomic hit recount, the Agent-result
# attribution hook, and the one-shot Stop gate.
#
# Contracts under test:
#   - Subagent context = hook input carries agent_id (verified on CLI 2.1.169).
#   - A subagent MEDIUM/ESCALATED kill stays a kill (continue:false) but writes
#     a [PENDING-KILLED] k=v row to web-safety.log and arms the egress guard.
#   - Escalation strikes are scoped per agent_id; no agent_id = session scope
#     (v7 behavior, no regression).
#   - record_session_hit recounts under the state lock, so the 3rd hit
#     escalates even under parallel scanners.
#   - web-safety-agent-result.sh (PostToolUse on Task|Agent in the parent)
#     injects additionalContext when fresh PENDING-KILLED rows match
#     tool_response.agentId; silent otherwise.
#   - web-safety-stop-gate.sh blocks Stop exactly once per finding set and
#     honors stop_hook_active.

set -u

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
SCANNER="$REPO_ROOT/scripts/web-safety-scanner.sh"
AGENT_RESULT="$REPO_ROOT/scripts/web-safety-agent-result.sh"
STOP_GATE="$REPO_ROOT/scripts/web-safety-stop-gate.sh"
HOOKS_JSON="$REPO_ROOT/hooks/hooks.json"

# Stub osascript so tests don't fire macOS notifications.
FAKE_BIN=$(mktemp -d)
cat >"$FAKE_BIN/osascript" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$FAKE_BIN/osascript"
export PATH="$FAKE_BIN:$PATH"

PASS=0
FAIL=0
FAILURES=()
CLEANUP_SIDS=()

cleanup() {
  rm -rf "$FAKE_BIN"
  for s in "${CLEANUP_SIDS[@]:-}"; do
    [ -n "$s" ] && rm -f "/tmp/web-safety-session-${s}"-* "/tmp/web-safety-session-${s}-agent-"* 2>/dev/null
  done
}
trap cleanup EXIT

report() {
  local name="$1" ok="$2" detail="${3:-}"
  if [ "$ok" = "yes" ]; then
    PASS=$((PASS+1))
    printf '  \342\234\223 %s\n' "$name"
  else
    FAIL=$((FAIL+1))
    FAILURES+=("$name: $detail")
    printf '  \342\234\227 %s  (%s)\n' "$name" "$detail"
  fi
}

MED_PAYLOAD=$(cat "$TESTS_DIR/payloads/med-evasion-cyrillic.txt")

# run_scanner <cfg> <legacy_sid> <canon_session> <agent_id|-> <url> [payload] [permission_mode]
# Prints scanner stdout. agent_id "-" omits the field (main-session shape).
# permission_mode "" (default) omits the field (older-harness / interactive shape).
run_scanner() {
  local cfg="$1" sid="$2" canon="$3" aid="$4" url="$5" payload="${6:-$MED_PAYLOAD}" mode="${7:-}"
  local envelope
  if [ "$aid" = "-" ]; then
    envelope=$(jq -n --arg url "$url" --arg output "$payload" --arg sess "$canon" --arg m "$mode" \
      '{tool_name: "WebFetch", session_id: $sess, tool_input: {url: $url}, tool_response: $output} + (if $m=="" then {} else {permission_mode: $m} end)')
  else
    envelope=$(jq -n --arg url "$url" --arg output "$payload" --arg sess "$canon" --arg aid "$aid" --arg m "$mode" \
      '{tool_name: "WebFetch", session_id: $sess, agent_id: $aid, agent_type: "general-purpose", tool_input: {url: $url}, tool_response: $output} + (if $m=="" then {} else {permission_mode: $m} end)')
  fi
  rm -f /tmp/web-safety-scanner-last-notify
  printf '%s' "$envelope" | WEB_SAFETY_CONFIG_DIR="$cfg" CLAUDE_SESSION_ID="$sid" "$SCANNER" 2>/dev/null
}

echo "Running web-safety multi-agent (v8) test harness"
echo "  scanner:  $SCANNER"
echo ""

# =============================================================================
# A. Scanner: die-but-visible + per-agent escalation
# =============================================================================
echo "scanner kill-ledger:"

# --- A1: subagent MEDIUM still kills (capability-zero containment unchanged)
cfg=$(mktemp -d); sid="agt-a1-$$"; CLEANUP_SIDS+=("$sid" "sess-$sid")
out=$(run_scanner "$cfg" "$sid" "sess-$sid" "aid0a1" "https://example.test/a1")
cont=$(printf '%s' "$out" | jq -r '.continue' 2>/dev/null)
[ "$cont" = "false" ] && report "A1 subagent MEDIUM still emits continue:false" yes \
  || report "A1 subagent MEDIUM still emits continue:false" no "continue=$cont"

# --- A2: that kill wrote a PENDING-KILLED k=v row to the log
row=$(grep -F '[PENDING-KILLED]' "$cfg/web-safety.log" 2>/dev/null | head -1)
ok=yes; detail=""
for needle in "epoch=" "session=sess-$sid" "agent=aid0a1" "severity=MEDIUM" "tool=WebFetch"; do
  case "$row" in *"$needle"*) ;; *) ok=no; detail="missing $needle in: ${row:-<no row>}";; esac
done
report "A2 kill writes [PENDING-KILLED] row (epoch/session/agent/severity)" "$ok" "$detail"

# --- A3 (v8.6 mode-conditional arming): a single subagent MEDIUM arms the egress
#     guard ONLY in non-interactive modes. The A1 run above carried NO permission_mode
#     (interactive/older-harness shape) → it must NOT have armed (the research-fan-out
#     ask-flood fix). DCA 20260706T152154.
[ -f "/tmp/web-safety-session-${sid}-armed" ] \
  && report "A3a subagent MEDIUM (interactive / no mode) does NOT arm" no "unexpected -armed file for $sid" \
  || report "A3a subagent MEDIUM (interactive / no mode) does NOT arm" yes
rm -rf "$cfg"

# --- A3b: the SAME single subagent MEDIUM kill in bypassPermissions DOES arm — the
#     backstop is kept where the guard enforces as a silent hard-block and no human
#     is in the loop.
cfg=$(mktemp -d); sidb="agt-a3b-$$"; CLEANUP_SIDS+=("$sidb" "sess-$sidb")
run_scanner "$cfg" "$sidb" "sess-$sidb" "aid0a3b" "https://example.test/a3b" "$MED_PAYLOAD" "bypassPermissions" >/dev/null
[ -f "/tmp/web-safety-session-${sidb}-armed" ] \
  && report "A3b subagent MEDIUM (bypassPermissions) arms egress guard" yes \
  || report "A3b subagent MEDIUM (bypassPermissions) failed to arm" no "no -armed file for $sidb"
rm -rf "$cfg"

# --- A4: main-session MEDIUM is byte-compatible: kill, but NO row, NO arming
cfg=$(mktemp -d); sid="agt-a4-$$"; CLEANUP_SIDS+=("$sid" "sess-$sid")
out=$(run_scanner "$cfg" "$sid" "sess-$sid" "-" "https://example.test/a4")
cont=$(printf '%s' "$out" | jq -r '.continue' 2>/dev/null)
ok=yes; detail=""
[ "$cont" = "false" ] || { ok=no; detail="continue=$cont"; }
grep -qF '[PENDING-KILLED]' "$cfg/web-safety.log" 2>/dev/null && { ok=no; detail="unexpected PENDING-KILLED row"; }
[ -f "/tmp/web-safety-session-${sid}-armed" ] && { ok=no; detail="unexpected -armed file"; }
report "A4 main-session MEDIUM unchanged (halt, no row, no arming)" "$ok" "$detail"
rm -rf "$cfg"

echo ""
echo "scanner escalation scoping:"

# --- A5: same agent 3 hits in window -> 3rd is ESCALATED
cfg=$(mktemp -d); sid="agt-a5-$$"; CLEANUP_SIDS+=("$sid" "sess-$sid")
out=""
for i in 1 2 3; do
  out=$(run_scanner "$cfg" "$sid" "sess-$sid" "aidsame" "https://example.test/a5-$i")
done
msg=$(printf '%s' "$out" | jq -r '.systemMessage // ""' 2>/dev/null)
case "$msg" in
  "ESCALATED TO HIGH SEVERITY"*) report "A5 same-agent 3rd hit escalates" yes ;;
  *) report "A5 same-agent 3rd hit escalates" no "msg=${msg:0:60}" ;;
esac

# --- A9: the ESCALATED kill also wrote a severity=ESCALATED row
grep -F '[PENDING-KILLED]' "$cfg/web-safety.log" 2>/dev/null | grep -q "severity=ESCALATED" \
  && report "A9 escalated kill writes severity=ESCALATED row" yes \
  || report "A9 escalated kill writes severity=ESCALATED row" no "no ESCALATED row in log"
rm -rf "$cfg"

# --- A6: three DIFFERENT agents, same session -> 3rd stays plain MEDIUM
cfg=$(mktemp -d); sid="agt-a6-$$"; CLEANUP_SIDS+=("$sid" "sess-$sid")
out=""
for aid in aidx aidy aidz; do
  out=$(run_scanner "$cfg" "$sid" "sess-$sid" "$aid" "https://example.test/a6-$aid")
done
msg=$(printf '%s' "$out" | jq -r '.systemMessage // ""' 2>/dev/null)
case "$msg" in
  "PROMPT INJECTION WARNING [MEDIUM SEVERITY]"*) report "A6 cross-agent hits do not pool into ESCALATED" yes ;;
  *) report "A6 cross-agent hits do not pool into ESCALATED" no "msg=${msg:0:60}" ;;
esac
rm -rf "$cfg"

# --- A7: no agent_id x3, same session -> 3rd ESCALATED (v7 fallback preserved)
cfg=$(mktemp -d); sid="agt-a7-$$"; CLEANUP_SIDS+=("$sid" "sess-$sid")
out=""
for i in 1 2 3; do
  out=$(run_scanner "$cfg" "$sid" "sess-$sid" "-" "https://example.test/a7-$i")
done
msg=$(printf '%s' "$out" | jq -r '.systemMessage // ""' 2>/dev/null)
case "$msg" in
  "ESCALATED TO HIGH SEVERITY"*) report "A7 session-scope escalation preserved without agent_id" yes ;;
  *) report "A7 session-scope escalation preserved without agent_id" no "msg=${msg:0:60}" ;;
esac
rm -rf "$cfg"

# --- A8: atomic recount — seed 1 fresh strike, run 2 scanners in PARALLEL,
#         exactly one of them must see the 3rd strike and escalate.
cfg=$(mktemp -d); sid="agt-a8-$$"; CLEANUP_SIDS+=("$sid" "sess-$sid")
state="/tmp/web-safety-session-${sid}-agent-aidrace-state"
echo "$(date +%s) WebFetch https://example.test/a8-seed H" > "$state"
o1=$(mktemp); o2=$(mktemp)
run_scanner "$cfg" "$sid" "sess-$sid" "aidrace" "https://example.test/a8-p1" > "$o1" &
p1=$!
run_scanner "$cfg" "$sid" "sess-$sid" "aidrace" "https://example.test/a8-p2" > "$o2" &
p2=$!
wait "$p1" "$p2"
esc=0
for f in "$o1" "$o2"; do
  jq -r '.systemMessage // ""' "$f" 2>/dev/null | grep -q '^ESCALATED TO HIGH SEVERITY' && esc=$((esc+1))
done
rows=$(awk '$4 == "H"' "$state" 2>/dev/null | wc -l | tr -d ' ')
ok=yes; detail=""
[ "$esc" -eq 1 ] || { ok=no; detail="escalated=$esc (want exactly 1)"; }
[ "$rows" -eq 3 ] || { ok=no; detail="$detail strikes=$rows (want 3)"; }
report "A8 parallel scanners: atomic recount escalates exactly once, no lost strikes" "$ok" "$detail"
rm -f "$o1" "$o2"; rm -rf "$cfg"

# =============================================================================
# B. Attribution hook (PostToolUse on Task|Agent in the parent session)
# =============================================================================
echo ""
echo "agent-result attribution hook:"

seed_row() { # <cfg> <epoch> <session> <agent>
  mkdir -p "$1"
  echo "[2026-06-11 12:00:00] [PENDING-KILLED] epoch=$2 session=$3 agent=$4 severity=MEDIUM tool=WebFetch url=https://example.test/x patterns=[mixed Cyrillic/Latin script]" >> "$1/web-safety.log"
}

agent_input() { # <session> <agentId>
  jq -n --arg sess "$1" --arg aid "$2" \
    '{hook_event_name:"PostToolUse", session_id:$sess, tool_name:"Agent",
      tool_input:{prompt:"x", subagent_type:"general-purpose"},
      tool_response:{status:"completed", agentId:$aid, content:[]}}'
}

# --- B1: fresh matching row -> additionalContext names the agent and the report command
cfg=$(mktemp -d)
seed_row "$cfg" "$(date +%s)" "sess-b1" "aidb1"
out=$(agent_input "sess-b1" "aidb1" | WEB_SAFETY_CONFIG_DIR="$cfg" "$AGENT_RESULT" 2>/dev/null)
ctx=$(printf '%s' "$out" | jq -r '.hookSpecificOutput.additionalContext // ""' 2>/dev/null)
ok=yes; detail=""
case "$ctx" in *"aidb1"*) ;; *) ok=no; detail="agent id missing: ${ctx:0:80}";; esac
case "$ctx" in *"/web-safety:report"*) ;; *) ok=no; detail="report cmd missing: ${ctx:0:80}";; esac
case "$ctx" in *"web-safety"*) ;; *) ok=no; detail="no web-safety mention";; esac
report "B1 fresh matching row injects additionalContext" "$ok" "$detail"
rm -rf "$cfg"

# --- B2: no row -> silent exit 0
cfg=$(mktemp -d)
out=$(agent_input "sess-b2" "aidb2" | WEB_SAFETY_CONFIG_DIR="$cfg" "$AGENT_RESULT" 2>/dev/null); ec=$?
[ -z "$out" ] && [ "$ec" -eq 0 ] \
  && report "B2 no matching row is silent" yes \
  || report "B2 no matching row is silent" no "ec=$ec out=${out:0:60}"
rm -rf "$cfg"

# --- B3: stale row (older than freshness window) -> silent
cfg=$(mktemp -d)
seed_row "$cfg" "$(( $(date +%s) - 2000 ))" "sess-b3" "aidb3"
out=$(agent_input "sess-b3" "aidb3" | WEB_SAFETY_CONFIG_DIR="$cfg" "$AGENT_RESULT" 2>/dev/null)
[ -z "$out" ] \
  && report "B3 stale row is silent" yes \
  || report "B3 stale row is silent" no "out=${out:0:60}"
rm -rf "$cfg"

# --- B4: row from a different session -> silent
cfg=$(mktemp -d)
seed_row "$cfg" "$(date +%s)" "sess-OTHER" "aidb4"
out=$(agent_input "sess-b4" "aidb4" | WEB_SAFETY_CONFIG_DIR="$cfg" "$AGENT_RESULT" 2>/dev/null)
[ -z "$out" ] \
  && report "B4 other-session row is silent" yes \
  || report "B4 other-session row is silent" no "out=${out:0:60}"
rm -rf "$cfg"

# =============================================================================
# C. One-shot Stop gate
# =============================================================================
echo ""
echo "stop gate:"

stop_input() { # <session> <active>
  jq -n --arg sess "$1" --argjson active "$2" \
    '{hook_event_name:"Stop", session_id:$sess, stop_hook_active:$active}'
}

# --- C1: fresh row -> decision:block naming the agent, once
cfg=$(mktemp -d); CLEANUP_SIDS+=("sess-c1")
rm -f "/tmp/web-safety-session-sess-c1-surfaced"
seed_row "$cfg" "$(date +%s)" "sess-c1" "aidc1"
out=$(stop_input "sess-c1" false | WEB_SAFETY_CONFIG_DIR="$cfg" "$STOP_GATE" 2>/dev/null)
dec=$(printf '%s' "$out" | jq -r '.decision // ""' 2>/dev/null)
reason=$(printf '%s' "$out" | jq -r '.reason // ""' 2>/dev/null)
ok=yes; detail=""
[ "$dec" = "block" ] || { ok=no; detail="decision=$dec"; }
case "$reason" in *"aidc1"*) ;; *) ok=no; detail="agent id missing in reason";; esac
report "C1 unsurfaced kill row blocks Stop with summary" "$ok" "$detail"

# --- C2: second invocation -> silent (one-shot marker)
out=$(stop_input "sess-c1" false | WEB_SAFETY_CONFIG_DIR="$cfg" "$STOP_GATE" 2>/dev/null)
[ -z "$out" ] \
  && report "C2 second Stop is silent (one-shot)" yes \
  || report "C2 second Stop is silent (one-shot)" no "out=${out:0:60}"
rm -rf "$cfg"

# --- C3: stop_hook_active=true -> silent even with fresh rows
cfg=$(mktemp -d); CLEANUP_SIDS+=("sess-c3")
rm -f "/tmp/web-safety-session-sess-c3-surfaced"
seed_row "$cfg" "$(date +%s)" "sess-c3" "aidc3"
out=$(stop_input "sess-c3" true | WEB_SAFETY_CONFIG_DIR="$cfg" "$STOP_GATE" 2>/dev/null)
[ -z "$out" ] \
  && report "C3 stop_hook_active=true is silent" yes \
  || report "C3 stop_hook_active=true is silent" no "out=${out:0:60}"
rm -rf "$cfg"

# --- C4: no rows -> silent
cfg=$(mktemp -d); CLEANUP_SIDS+=("sess-c4")
rm -f "/tmp/web-safety-session-sess-c4-surfaced"
out=$(stop_input "sess-c4" false | WEB_SAFETY_CONFIG_DIR="$cfg" "$STOP_GATE" 2>/dev/null); ec=$?
[ -z "$out" ] && [ "$ec" -eq 0 ] \
  && report "C4 no rows is silent" yes \
  || report "C4 no rows is silent" no "ec=$ec out=${out:0:60}"
rm -rf "$cfg"

# =============================================================================
# D. hooks.json wiring
# =============================================================================
echo ""
echo "hooks.json wiring:"

cmd=$(jq -r '.hooks.PostToolUse[] | select(.matcher == "Task|Agent") | .hooks[0].command' "$HOOKS_JSON" 2>/dev/null)
case "$cmd" in
  *web-safety-agent-result.sh) report "D1 PostToolUse Task|Agent -> agent-result hook wired" yes ;;
  *) report "D1 PostToolUse Task|Agent -> agent-result hook wired" no "cmd=${cmd:-<none>}" ;;
esac

cmd=$(jq -r '.hooks.Stop[0].hooks[0].command' "$HOOKS_JSON" 2>/dev/null)
case "$cmd" in
  *web-safety-stop-gate.sh) report "D2 Stop -> stop-gate hook wired" yes ;;
  *) report "D2 Stop -> stop-gate hook wired" no "cmd=${cmd:-<none>}" ;;
esac

echo ""
echo "Results: $PASS passed, $FAIL failed (total $((PASS+FAIL)))"
if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
