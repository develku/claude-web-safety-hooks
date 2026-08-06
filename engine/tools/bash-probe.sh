#!/bin/bash
# Run the production Bash scanner over stdin and print its verdict label.
#
# Isolation matches tests/run-tests.sh: a throwaway config dir, a unique session
# id, and a stubbed `osascript` so no desktop notification fires. Used by the
# differential runner and for hand-probing a single payload.
set -euo pipefail

ENGINE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ENGINE_DIR/.." && pwd)"
SCANNER="$REPO_ROOT/scripts/web-safety-scanner.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$WORK/osascript"
chmod +x "$WORK/osascript"

SESSION="probe-$$-${RANDOM}"
BODY=$(cat)

OUT=$(printf '%s' "$BODY" \
  | jq -Rs '{tool_name:"WebFetch",tool_input:{url:"https://example.test/probe"},tool_response:.}' \
  | PATH="$WORK:$PATH" \
    WEB_SAFETY_CONFIG_DIR="$WORK/config" \
    CLAUDE_SESSION_ID="$SESSION" \
    bash "$SCANNER" 2>/dev/null || true)

for suffix in state armed fragments ledger; do
  rm -f "/tmp/web-safety-session-${SESSION}-${suffix}" 2>/dev/null || true
done

if [ -z "$OUT" ]; then
  echo "clean"
  exit 0
fi

MSG=$(printf '%s' "$OUT" | jq -r '.systemMessage // .reason // ""' 2>/dev/null || echo "")
case "$MSG" in
  *"ESCALATED TO HIGH"*|*"[HIGH SEVERITY]"*) echo high ;;
  *"[MEDIUM SEVERITY]"*)                     echo medium ;;
  *"[LOW SEVERITY]"*)                        echo low ;;
  *"[INFO]"*)                                echo info ;;
  *)                                         echo "unknown: $MSG" ;;
esac
