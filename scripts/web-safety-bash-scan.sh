#!/bin/bash
# PostToolUse hook (Bash): Layer 8 — Bash-fetched web-content scanner (ROUTING GATE).
#
# The PostToolUse content scanner (web-safety-scanner.sh) is wired to web-fetch
# tools only, so web content pulled via a Bash command (`curl https://evil.com`)
# returns as Bash stdout and bypasses the entire detection pipeline. This gate
# closes that hole WITHOUT scanning every Bash command — blanket scanning would
# halt on routine `cat`/`ls`/`grep` output, since the scanner halts on a match:
#
#   1. read stdin once; extract .tool_input.command.
#   2. is it a web-fetch-shaped command? (is_fetch_command — narrow v1 predicate)
#        NO  -> exit 0, no scan (the false-positive-storm guard).
#        YES -> replay the BYTE-IDENTICAL stdin into web-safety-scanner.sh, reusing
#               the whole engine (8 evasion views, 600+ patterns, Layer-6 arming,
#               Layer-4 session correlation, audit log, Layer-7 kill ledger, halt
#               JSON). The verbatim replay preserves agent_id/session_id so the
#               subagent (Layer 7) and correlation (Layer 4) paths work for free —
#               do NOT rebuild the envelope with jq (that would drop those fields).
#
# Enforcement floor (all tool-agnostic, confirmed-working): detection +
# `continue:false` halt + Layer-6 arming. The scanner's toolResult-redaction
# efficacy on a *Bash* result is empirically unverified (see CHANGELOG probe);
# the HALT is the load-bearing guard, not redaction.
#
# Scope: this scans fetch OUTPUT for web-injection post-execution — it does NOT
# block the command (it is PostToolUse, structurally incapable of that). Stays
# within the plugin's "web-injection only" boundary; destructive-command control
# remains the settings.json deny layer's job.
#
# Fails OPEN on any internal error (missing jq/lib/scanner): a defense layer must
# never paralyze a normal Bash command. To disable Bash scanning entirely, unwire
# this hook in hooks.json.

# jq is required to read the command; if absent, fail open (no scan).
command -v jq >/dev/null 2>&1 || exit 0

INPUT=$(cat)

# Defensive: the matcher already scopes this to Bash, but re-check rather than
# scan an unexpected tool's payload.
TOOL_NAME=$(printf '%s' "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
[ "$TOOL_NAME" = "Bash" ] || exit 0

COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
[ -z "$COMMAND" ] && exit 0   # nothing to classify -> nothing to scan

# Shared fetch predicate (single source of truth with egress's boundary discipline).
LIB="$(cd "$(dirname "$0")" && pwd)/web-safety-lib.sh"
# shellcheck source=/dev/null
[ -f "$LIB" ] && . "$LIB"
command -v is_fetch_command >/dev/null 2>&1 || exit 0   # lib missing -> fail open

# Not a web fetch -> do not scan. This is the guard that keeps routine command
# output (cat/ls/grep/echo) from ever reaching the halting scanner.
is_fetch_command "$COMMAND" || exit 0

# Web-fetch-shaped: replay the byte-identical envelope into the scan engine. Its
# stdout (halt JSON / warning / nothing) becomes this hook's output verbatim.
SCANNER="$(cd "$(dirname "$0")" && pwd)/web-safety-scanner.sh"
if [ -x "$SCANNER" ]; then
  printf '%s' "$INPUT" | "$SCANNER"
  exit $?
fi
exit 0
