#!/bin/bash
# web-safety-report.sh — summarize the web-safety audit log into markdown.
#
# Usage: web-safety-report.sh [days]
#   days   optional positive integer — include only entries from the last N days.
#
# Reads $WEB_SAFETY_CONFIG_DIR/web-safety.log (default ~/.claude/hooks).
# Read-only: never mutates the log. Output is markdown on stdout.
set -u

CONFIG_DIR="${WEB_SAFETY_CONFIG_DIR:-$HOME/.claude/hooks}"
LOG="$CONFIG_DIR/web-safety.log"

DAYS="${1:-}"
CUTOFF=""
if [ -n "$DAYS" ]; then
  if ! printf '%s' "$DAYS" | grep -qE '^[0-9]+$'; then
    echo "usage: web-safety-report.sh [days]   (days must be a positive integer)" >&2
    exit 2
  fi
  # Cross-platform date math: GNU (-d) first, BSD (-v) fallback. CI runs both.
  CUTOFF=$(date -d "${DAYS} days ago" +%Y-%m-%d 2>/dev/null \
        || date -v-"${DAYS}"d +%Y-%m-%d 2>/dev/null || true)
fi

echo "# Web Safety Report"
echo

if [ ! -f "$LOG" ]; then
  echo "No audit log at \`$LOG\` yet — the scanner writes here the first time it"
  echo "flags web content. An empty report means nothing has tripped it."
  exit 0
fi

# Apply the optional day window once; downstream pipelines read $SRC.
# substr($1,2) drops the leading '[' so the YYYY-MM-DD compares lexically.
if [ -n "$CUTOFF" ]; then
  SRC=$(awk -v c="$CUTOFF" 'substr($1,2) >= c' "$LOG")
else
  SRC=$(cat "$LOG")
fi

TOTAL=$(printf '%s\n' "$SRC" | grep -c .)
if [ "$TOTAL" -eq 0 ]; then
  echo "No events${CUTOFF:+ since $CUTOFF}."
  exit 0
fi

FIRST=$(printf '%s\n' "$SRC" | grep . | head -1 | grep -oE '^\[[0-9-]+ [0-9:]+\]' | tr -d '[]')
LAST=$(printf  '%s\n' "$SRC" | grep . | tail -1 | grep -oE '^\[[0-9-]+ [0-9:]+\]' | tr -d '[]')

echo "- **Events:** ${TOTAL}${CUTOFF:+  (since ${CUTOFF})}"
echo "- **Window:** ${FIRST:-?}  →  ${LAST:-?}"
echo "- **Log:** \`${LOG}\`"
echo

echo "## By type"
echo
echo "| Type | Count |"
echo "|---|---|"
printf '%s\n' "$SRC" | grep -oE '^\[[^]]*\] \[[A-Z-]+\]' \
  | sed -E 's/.*\[([A-Z-]+)\]$/\1/' \
  | sort | uniq -c | sort -rn \
  | while read -r n t; do printf '| %s | %s |\n' "$t" "$n"; done
echo

echo "## Top tools"
echo
TOOLS=$(printf '%s\n' "$SRC" | grep -oE 'tool=[^ ]+' | sed 's/^tool=//' | sort | uniq -c | sort -rn | head -5)
if [ -n "$TOOLS" ]; then
  echo "| Tool | Count |"
  echo "|---|---|"
  # Strip '|' from the cell value (attacker-influenceable tool name) so it can't
  # inject a Markdown table column (#12).
  printf '%s\n' "$TOOLS" | while read -r n t; do printf '| %s | %s |\n' "$(printf '%s' "$t" | tr -d '|')" "$n"; done
else
  echo "_none recorded_"
fi
echo

echo "## Top hosts"
echo
HOSTS=$(printf '%s\n' "$SRC" | grep -oE 'url=https?://[^ /]+' | sed -E 's|url=https?://||' | sort | uniq -c | sort -rn | head -5)
if [ -n "$HOSTS" ]; then
  echo "| Host | Count |"
  echo "|---|---|"
  printf '%s\n' "$HOSTS" | while read -r n h; do printf '| %s | %s |\n' "$(printf '%s' "$h" | tr -d '|')" "$n"; done
else
  echo "_none recorded_"
fi
echo

echo "## Most recent"
echo
echo '```'
# Log lines carry attacker-influenced URLs; a backtick run could close this
# fence and inject markdown into the rendered report. Replace backticks with a
# look-alike so the fence can't be broken out of (#12).
printf '%s\n' "$SRC" | grep . | tail -8 | tr '`' "'"
echo '```'
