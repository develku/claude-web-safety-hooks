#!/bin/bash
# web-safety-listctl.sh — add a validated domain to the URL allowlist or blocklist
# consumed by the PreToolUse pre-screening hook (web-safety-approve.sh).
#
# Usage: web-safety-listctl.sh <allow|block> <domain>
#   allow  -> $WEB_SAFETY_CONFIG_DIR/url-allowlist.txt
#   block  -> $WEB_SAFETY_CONFIG_DIR/url-blocklist.txt
#
# The domain is normalized (a pasted URL is reduced to its host) and strictly
# validated before any write — these files gate a security control, so a
# malformed or shell-metachar entry must never reach them. Idempotent.
set -u

CONFIG_DIR="${WEB_SAFETY_CONFIG_DIR:-$HOME/.claude/hooks}"

LIST="${1:-}"
DOMAIN="${2:-}"

case "$LIST" in
  allow) FILE="$CONFIG_DIR/url-allowlist.txt" ;;
  block) FILE="$CONFIG_DIR/url-blocklist.txt" ;;
  *) echo "usage: web-safety-listctl.sh <allow|block> <domain>" >&2; exit 2 ;;
esac

if [ -z "$DOMAIN" ]; then
  echo "error: missing domain" >&2
  exit 2
fi

# Normalize: lowercase, drop whitespace, then reduce a pasted URL to its host
# (strip scheme, path, and port).
DOMAIN=$(printf '%s' "$DOMAIN" \
  | tr '[:upper:]' '[:lower:]' \
  | tr -d '[:space:]' \
  | sed -E 's|^[a-z]+://||; s|/.*$||; s|:.*$||')

# Validate a plausible hostname: dot-separated labels of [a-z0-9-], no leading/
# trailing hyphen per label, a TLD of >=2 letters. This rejects anything with a
# shell metacharacter as a side effect (only [a-z0-9.-] can match).
if ! printf '%s' "$DOMAIN" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'; then
  echo "error: '$DOMAIN' is not a valid domain (expected e.g. github.com)" >&2
  exit 2
fi

mkdir -p "$CONFIG_DIR" 2>/dev/null

if [ -f "$FILE" ] && grep -qxF "$DOMAIN" "$FILE" 2>/dev/null; then
  echo "already in ${LIST}list: $DOMAIN"
  exit 0
fi

printf '%s\n' "$DOMAIN" >> "$FILE"
echo "added to ${LIST}list: $DOMAIN  ->  $FILE"
