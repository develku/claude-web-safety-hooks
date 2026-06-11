#!/bin/bash
# web-safety-agent-result.sh — PostToolUse hook on the Agent/Task tool, firing
# in the PARENT session when a subagent call resolves.
#
# Problem it solves (the v8 incident): a subagent killed by the scanner's
# continue:false verdict resolves in the parent as status:"completed" with
# content:[] — a silent null. The stopReason died with the subagent; the only
# other signal was a desktop toast. This hook makes the death attributable at
# the exact moment the orchestrator reads the result.
#
# Mechanism: the scanner (running inside the subagent) wrote a [PENDING-KILLED]
# k=v row to the shared audit log before halting. This hook joins that row to
# the resolving Agent call via tool_response.agentId == row's agent= field
# (probe-verified identical on CLI 2.1.169), scoped by session_id and a
# freshness window, and injects factual additionalContext next to the result.
#
# Hard contracts:
#   - Advisory layer: EVERY failure mode is a silent exit 0. Containment lives
#     in the scanner kill + armed egress guard, not here.
#   - Fast path first: no jq / no log / no agentId / no rows → exit 0 with at
#     most one tail+grep — this hook runs on every Agent completion.
#   - Injection hygiene: the context relays severity/tool/HOST only. The row's
#     patterns field (detector labels that can embed matched attacker
#     substrings) and full URLs (query strings can carry instruction text) are
#     NEVER copied into model-facing output.

set -u

command -v jq >/dev/null 2>&1 || exit 0

INPUT=$(cat)

CONFIG_DIR="${WEB_SAFETY_CONFIG_DIR:-$HOME/.claude/hooks}"
LOG_FILE="$CONFIG_DIR/web-safety.log"
[ -f "$LOG_FILE" ] || exit 0

# Whitelist-sanitize both join keys: they come from harness JSON, but they are
# grepped against a log we also write attacker-influenced fields into.
AGENT=$(printf '%s' "$INPUT" | jq -r '.tool_response.agentId // ""' 2>/dev/null | tr -cd 'A-Za-z0-9_-' | cut -c1-64)
SESS=$(printf '%s' "$INPUT" | jq -r '.session_id // ""' 2>/dev/null | tr -cd 'A-Za-z0-9_-' | cut -c1-64)
[ -n "$AGENT" ] || exit 0

# Freshness window: a row older than this belongs to /web-safety:report, not to
# this call's context. 900s comfortably covers a long subagent run.
NOW=$(date +%s)
WINDOW=900

ROWS=$(tail -n 400 "$LOG_FILE" 2>/dev/null | grep -F '[PENDING-KILLED]' | grep -F "agent=${AGENT} ")
[ -n "$ROWS" ] || exit 0
if [ -n "$SESS" ]; then
  ROWS=$(printf '%s\n' "$ROWS" | grep -F "session=${SESS} ")
  [ -n "$ROWS" ] || exit 0
fi

FRESH=$(printf '%s\n' "$ROWS" | awk -v min=$((NOW - WINDOW)) '{
  for (i = 1; i <= NF; i++)
    if ($i ~ /^epoch=/) { split($i, kv, "="); if (kv[2] >= min) print; break }
}')
[ -n "$FRESH" ] || exit 0

N=$(printf '%s\n' "$FRESH" | wc -l | tr -d ' ')
# severity via tool (host) per row; host = authority part of the url= field.
DETAIL=$(printf '%s\n' "$FRESH" | awk '{
  sev = ""; tool = ""; host = "";
  for (i = 1; i <= NF; i++) {
    if      ($i ~ /^severity=/) sev  = substr($i, 10)
    else if ($i ~ /^tool=/)     tool = substr($i, 6)
    else if ($i ~ /^url=/)      { split(substr($i, 5), p, "/"); host = p[3] }
  }
  printf "%s via %s%s; ", sev, tool, (host == "" ? "" : " (" host ")")
}' | sed 's/; $//')

CTX="web-safety: subagent ${AGENT} was terminated by the web-safety prompt-injection scanner during this call — ${N} finding(s): ${DETAIL}. Its empty or partial result is a security halt, not an ordinary failure. Do not retry the same fetch blindly; the work item can be re-dispatched excluding the flagged source. Full detail: /web-safety:report."

jq -n --arg ctx "$CTX" \
  '{hookSpecificOutput: {hookEventName: "PostToolUse", additionalContext: $ctx}}'
exit 0
