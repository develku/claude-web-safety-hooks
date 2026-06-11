#!/bin/bash
# web-safety-stop-gate.sh — Stop hook in the MAIN session. The human leg of v8
# die-but-visible: if subagents were killed this session and the kill rows have
# not been surfaced yet, block Stop exactly once and make Claude tell the user
# before the turn can end. Replaces the evaporating desktop toast as the
# human-facing carrier.
#
# One-shot by construction, twice over:
#   1. stop_hook_active=true (harness flag set on the re-run a block causes)
#      → always silent, the documented anti-loop contract.
#   2. A per-session epoch marker is advanced BEFORE the block is emitted, so
#      even a model that ends its forced turn without addressing the findings
#      cannot re-trigger the gate for the same rows.
#
# Advisory layer: every error path exits 0 (a broken gate must never trap the
# user's session — enforcement lives in the scanner kill + egress guard).

set -u

command -v jq >/dev/null 2>&1 || exit 0

INPUT=$(cat)

CONFIG_DIR="${WEB_SAFETY_CONFIG_DIR:-$HOME/.claude/hooks}"
LOG_FILE="$CONFIG_DIR/web-safety.log"
[ -f "$LOG_FILE" ] || exit 0

ACTIVE=$(printf '%s' "$INPUT" | jq -r '.stop_hook_active // false' 2>/dev/null)
[ "$ACTIVE" = "true" ] && exit 0

SESS=$(printf '%s' "$INPUT" | jq -r '.session_id // ""' 2>/dev/null | tr -cd 'A-Za-z0-9_-' | cut -c1-64)
[ -n "$SESS" ] || SESS="$PPID"

umask 0077
MARKER="/tmp/web-safety-session-${SESS}-surfaced"
LAST=$(cat "$MARKER" 2>/dev/null | tr -cd '0-9')
[ -n "$LAST" ] || LAST=0
NOW=$(date +%s)

# Rows for THIS session, newer than the last surfaced epoch, capped at 1h —
# anything older is /web-safety:report material, not end-of-turn news.
ROWS=$(tail -n 400 "$LOG_FILE" 2>/dev/null | grep -F '[PENDING-KILLED]' | grep -F "session=${SESS} ")
[ -n "$ROWS" ] || exit 0
FRESH=$(printf '%s\n' "$ROWS" | awk -v last="$LAST" -v min=$((NOW - 3600)) '{
  for (i = 1; i <= NF; i++)
    if ($i ~ /^epoch=/) { split($i, kv, "="); if (kv[2] > last && kv[2] >= min) print; break }
}')
[ -n "$FRESH" ] || exit 0

# Advance the one-shot marker BEFORE emitting — see header.
echo "$NOW" > "$MARKER" 2>/dev/null

N=$(printf '%s\n' "$FRESH" | wc -l | tr -d ' ')
# agent (severity via tool) per row; patterns/URLs deliberately excluded from
# model-facing text (detector labels can embed matched attacker substrings).
LIST=$(printf '%s\n' "$FRESH" | awk '{
  agent = ""; sev = ""; tool = "";
  for (i = 1; i <= NF; i++) {
    if      ($i ~ /^agent=/)    agent = substr($i, 7)
    else if ($i ~ /^severity=/) sev   = substr($i, 10)
    else if ($i ~ /^tool=/)     tool  = substr($i, 6)
  }
  printf "agent %s (%s via %s); ", agent, sev, tool
}' | sed 's/; $//')

REASON="web-safety: ${N} subagent(s) were terminated by the prompt-injection scanner this session and their work items were lost: ${LIST}. Before finishing, tell the user exactly this happened and point them at /web-safety:report for the flagged sources. Do not silently drop the affected work items."

jq -n --arg r "$REASON" '{decision: "block", reason: $r}'
exit 0
