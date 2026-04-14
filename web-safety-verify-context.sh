#!/bin/bash
# Web Safety Context Verifier v1.0
# Structural context verification for MED_GENERIC_DELIMITERS false positives.
#
# Determines whether a matched pattern is inside a structural context
# (code fence, YAML string, JSON string, HTML code/pre, inline code)
# that makes it likely a false positive rather than a genuine injection.
#
# Input:
#   $VERIFY_PATTERN  — the matched pattern string (e.g., "assistant: ")
#   $VERIFY_LINE_NUM — line number of the match in the original content (1-based)
#   stdin            — the raw TOOL_OUTPUT
#
# Output (JSON on stdout):
#   {"verdict": "fp",      "reason": "inside fenced code block", "context": "code_fence"}
#   {"verdict": "genuine", "reason": "standalone line, not inside any structural context"}
#
# Design:
#   - Purely structural (regex/grep), no LLM — deterministic, non-injectable
#   - Scans ±20 lines around match for structural markers
#   - Co-location guard: denies clearance if injection keywords on same line
#   - Fail-closed: any error or missing input returns "genuine"

set -euo pipefail

# Fail-closed: any unhandled error → genuine
trap 'echo "{\"verdict\":\"genuine\",\"reason\":\"verifier error\"}" ; exit 0' ERR

# =============================================================================
# Input validation (fail-closed on missing input)
# =============================================================================
if [ -z "${VERIFY_PATTERN:-}" ]; then
  echo '{"verdict":"genuine","reason":"missing VERIFY_PATTERN"}'
  exit 0
fi

if [ -z "${VERIFY_LINE_NUM:-}" ] || ! [[ "$VERIFY_LINE_NUM" =~ ^[0-9]+$ ]]; then
  echo '{"verdict":"genuine","reason":"missing or invalid VERIFY_LINE_NUM"}'
  exit 0
fi

# Read stdin into variable
CONTENT=$(cat)
if [ -z "$CONTENT" ]; then
  echo '{"verdict":"genuine","reason":"empty content"}'
  exit 0
fi

# =============================================================================
# Extract context window (±20 lines around match)
# =============================================================================
TOTAL_LINES=$(echo "$CONTENT" | wc -l | tr -d ' ')
WINDOW=20

START=$((VERIFY_LINE_NUM - WINDOW))
[ "$START" -lt 1 ] && START=1

END=$((VERIFY_LINE_NUM + WINDOW))
[ "$END" -gt "$TOTAL_LINES" ] && END="$TOTAL_LINES"

# Extract the matched line itself
MATCHED_LINE=$(echo "$CONTENT" | sed -n "${VERIFY_LINE_NUM}p")
if [ -z "$MATCHED_LINE" ]; then
  echo '{"verdict":"genuine","reason":"matched line not found at specified line number"}'
  exit 0
fi

# Extract context window (lines before the match for backward scanning)
BEFORE_CONTEXT=$(echo "$CONTENT" | sed -n "${START},$((VERIFY_LINE_NUM - 1))p" 2>/dev/null || true)
AFTER_CONTEXT=$(echo "$CONTENT" | sed -n "$((VERIFY_LINE_NUM + 1)),${END}p" 2>/dev/null || true)

# =============================================================================
# Co-location guard: check if matched line contains injection keywords
# If yes → always genuine, even inside structural context
# =============================================================================
LOWER_MATCHED=$(echo "$MATCHED_LINE" | tr '[:upper:]' '[:lower:]')

INJECTION_KEYWORDS=(
  "ignore"
  "override"
  "bypass"
  "disregard"
  "forget"
  "instructions"
  "previous"
  "system prompt"
  "jailbreak"
  "discard"
  "supersede"
  "overwrite"
)

for keyword in "${INJECTION_KEYWORDS[@]}"; do
  if echo "$LOWER_MATCHED" | grep -qF -- "$keyword"; then
    # Co-located with injection keyword — never clear
    jq -n --arg kw "$keyword" \
      '{"verdict":"genuine","reason":("co-located with injection keyword: " + $kw)}'
    exit 0
  fi
done

# =============================================================================
# Structural context detection (ordered by confidence)
# =============================================================================

# --- Check 1: Inside fenced code block ---
# Scan backward from matched line for opening ``` or ~~~ without a matching close
check_code_fence() {
  local fence_open=0
  local fence_marker=""

  # Read forward through BEFORE_CONTEXT so fence open/close toggling works correctly
  while IFS= read -r line; do
    # Check for code fence markers (``` or ~~~, optionally with language tag)
    if echo "$line" | grep -qE '^\s*(```|~~~)'; then
      if [ "$fence_open" -eq 0 ]; then
        fence_open=1
        fence_marker=$(echo "$line" | grep -oE '(```|~~~)')
      else
        fence_open=0
        fence_marker=""
      fi
    fi
  done <<< "$BEFORE_CONTEXT"

  if [ "$fence_open" -eq 1 ]; then
    # Also check: is there a closing fence in the after_context?
    # (The match might be in the last line before the close)
    echo "code_fence"
    return 0
  fi
  return 1
}

# --- Check 2: Inside YAML string literal ---
# Pattern: line with key: "...pattern..." or key: '...pattern...'
check_yaml_string() {
  local lc_pattern
  lc_pattern=$(echo "$VERIFY_PATTERN" | tr '[:upper:]' '[:lower:]')

  # Check if matched line is a YAML quoted string containing the pattern
  # Matches: key: "...pattern...", key: '...pattern...', description: "...pattern..."
  if echo "$LOWER_MATCHED" | grep -qE '^\s*[a-z_][a-z0-9_]*:\s*["\x27].*'"$lc_pattern"; then
    echo "yaml_string"
    return 0
  fi

  # Check if matched line is inside a YAML block scalar (|, >)
  # Look backward for a line ending with | or > (block scalar indicator)
  if [ -n "$BEFORE_CONTEXT" ]; then
    local last_key_line
    last_key_line=$(echo "$BEFORE_CONTEXT" | grep -nE '^\s*[a-z_][a-z0-9_]*:\s*[|>]' | tail -1)
    if [ -n "$last_key_line" ]; then
      # Check the matched line is indented (continuation of block scalar)
      if echo "$MATCHED_LINE" | grep -qE '^\s+'; then
        echo "yaml_block_scalar"
        return 0
      fi
    fi
  fi

  return 1
}

# --- Check 3: Inside JSON string ---
# Pattern: "key": "...pattern..."
check_json_string() {
  local lc_pattern
  lc_pattern=$(echo "$VERIFY_PATTERN" | tr '[:upper:]' '[:lower:]')

  if echo "$LOWER_MATCHED" | grep -qE '"[^"]*'"$lc_pattern"'[^"]*"'; then
    # Verify it looks like a JSON key-value pair (has a colon before the string)
    if echo "$LOWER_MATCHED" | grep -qE '"[^"]*"\s*:\s*"[^"]*'"$lc_pattern"; then
      echo "json_string"
      return 0
    fi
    # Or it's inside a JSON array string
    if echo "$LOWER_MATCHED" | grep -qE '\[\s*"[^"]*'"$lc_pattern"; then
      echo "json_string"
      return 0
    fi
  fi
  return 1
}

# --- Check 4: Inside HTML <code> or <pre> block ---
check_html_code() {
  # Scan backward for unclosed <code> or <pre>
  if [ -n "$BEFORE_CONTEXT" ]; then
    local code_opens
    local code_closes
    code_opens=$(echo "$BEFORE_CONTEXT" | grep -ciE '<(code|pre)[^>]*>' || true)
    code_closes=$(echo "$BEFORE_CONTEXT" | grep -ciE '</(code|pre)>' || true)
    if [ "$code_opens" -gt "$code_closes" ]; then
      echo "html_code_block"
      return 0
    fi
  fi

  # Check if both open and close are on the same line as match
  if echo "$MATCHED_LINE" | grep -qiE '<(code|pre)[^>]*>.*'"$VERIFY_PATTERN"'.*</(code|pre)>'; then
    echo "html_code_inline"
    return 0
  fi

  return 1
}

# --- Check 5: Inside markdown inline code ---
# Pattern: `...pattern...` on the same line
check_inline_code() {
  local lc_pattern
  lc_pattern=$(echo "$VERIFY_PATTERN" | tr '[:upper:]' '[:lower:]')

  # Check if pattern is between backticks on the same line
  if echo "$LOWER_MATCHED" | grep -qE '`[^`]*'"$lc_pattern"'[^`]*`'; then
    echo "markdown_inline_code"
    return 0
  fi
  return 1
}

# =============================================================================
# Run checks in order of confidence
# =============================================================================
CONTEXT_TYPE=""

CONTEXT_TYPE=$(check_code_fence) || true
if [ -z "$CONTEXT_TYPE" ]; then
  CONTEXT_TYPE=$(check_yaml_string) || true
fi
if [ -z "$CONTEXT_TYPE" ]; then
  CONTEXT_TYPE=$(check_json_string) || true
fi
if [ -z "$CONTEXT_TYPE" ]; then
  CONTEXT_TYPE=$(check_html_code) || true
fi
if [ -z "$CONTEXT_TYPE" ]; then
  CONTEXT_TYPE=$(check_inline_code) || true
fi

# =============================================================================
# Verdict
# =============================================================================
if [ -n "$CONTEXT_TYPE" ]; then
  jq -n --arg ctx "$CONTEXT_TYPE" \
    '{"verdict":"fp","reason":("inside " + $ctx),"context":$ctx}'
else
  echo '{"verdict":"genuine","reason":"no enclosing structural context"}'
fi
