#!/bin/bash
# PreToolUse hook (Bash matcher): Layer 6 — Outbound Exfiltration Guard.
#
# When a HIGH-severity prompt-injection was flagged in THIS session within the
# last SESSION_WINDOW seconds, escalate outbound network-egress commands to a
# user confirmation (permissionDecision:"ask"). This breaks the inject->exfil
# chain: an injected instruction cannot self-approve egress; a human decides.
#
# Defers (exit 0, no stdout) in every non-triggering case. Fails OPEN on
# internal error — this is a SECONDARY defense layer and must not paralyze the
# primary workflow if the guard itself malfunctions. The normal armed+egress
# path's default is already safe (ask, never auto-allow).

# Step 0 — kill switch
[ "${WEB_SAFETY_EGRESS_GUARD_DISABLE:-0}" = "1" ] && exit 0

# jq is required to parse the command; if absent, fail open.
command -v jq >/dev/null 2>&1 || exit 0

INPUT=$(cat)
COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[ -z "$COMMAND" ] && exit 0

# Session key MUST be computed identically to the scanner's writer key
# (${CLAUDE_SESSION_ID:-$PPID}) — using the input's .session_id instead would
# risk a key mismatch that silently disarms the guard.
SESSION_ID="${CLAUDE_SESSION_ID:-$PPID}"
ARM_FILE="/tmp/web-safety-session-${SESSION_ID}-armed"
WINDOW=300   # keep in sync with SESSION_WINDOW in web-safety-scanner.sh

# Step 1 — armed & fresh?
[ -f "$ARM_FILE" ] || exit 0
ARMED_AT=$(cat "$ARM_FILE" 2>/dev/null)
case "$ARMED_AT" in ''|*[!0-9]*) exit 0 ;; esac   # garbage/empty → fail-open defer
NOW=$(date +%s)
[ $(( NOW - ARMED_AT )) -le "$WINDOW" ] || exit 0  # stale → defer

# Step 2 — is this a network-egress command? (ported sharkyger pattern set)
EGRESS_RE='(^|[^a-zA-Z0-9_])(curl|wget|ncat|nc|scp|sftp|aria2c|ftp|lynx|links|w3m)([^a-zA-Z0-9_-]|$)'
HTTPIE_RE='(^|[^a-zA-Z0-9_])https?[[:space:]]'
ONELINER_RE='(python3?|node|ruby|perl)[[:space:]]+-(c|e)[[:space:]].*(urllib|requests|socket|http\.client|httplib|fetch\(|net::http|lwp|open-uri)'

IS_EGRESS=0
printf '%s' "$COMMAND" | grep -qE  "$EGRESS_RE"   && IS_EGRESS=1
printf '%s' "$COMMAND" | grep -qE  "$HTTPIE_RE"   && IS_EGRESS=1
printf '%s' "$COMMAND" | grep -qEi "$ONELINER_RE" && IS_EGRESS=1
[ "$IS_EGRESS" = "1" ] || exit 0

# Step 3 — destination-host allowlist exemption is added in Task 3.

# Step 4 — armed + egress → ASK
CONFIG_DIR="${WEB_SAFETY_CONFIG_DIR:-$HOME/.claude/hooks}"
LOG_FILE="$CONFIG_DIR/web-safety.log"
mkdir -p "$CONFIG_DIR" 2>/dev/null
SAFE_CMD=$(printf '%s' "$COMMAND" | tr -d '\n' | cut -c1-200)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] [EGRESS-ASK] session=${SESSION_ID} cmd=\"${SAFE_CMD}\"" >> "$LOG_FILE" 2>/dev/null

osascript -e 'display notification "Outbound command after a flagged injection — review required" with title "🛡️ Exfiltration Guard" sound name "Sosumi"' >/dev/null 2>&1 &

REASON="⚠️ Outbound network command issued after a HIGH-severity prompt-injection was flagged in this session within the last 5 minutes. This may be an exfiltration attempt directed by injected web content. Approve only if YOU initiated this request."

jq -n --arg r "$REASON" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "ask",
    permissionDecisionReason: $r
  }
}'
exit 0
