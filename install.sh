#!/bin/bash
# Install web safety hooks for Claude Code
# Usage: ./install.sh OR curl -sSL https://raw.githubusercontent.com/develku/claude-web-safety-hooks/main/install.sh | bash

set -e

REPO="develku/claude-web-safety-hooks"
BASE_URL="https://raw.githubusercontent.com/$REPO/main"
HOOKS_DIR="$HOME/.claude/hooks"
HOOKS_CONFIG="$HOME/.claude/hooks.json"
SCANNER="$HOOKS_DIR/web-safety-scanner.sh"
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"

echo "Installing Claude Code web safety hooks..."

# Create hooks directory
mkdir -p "$HOOKS_DIR"

# Install scanner script
if [ -f "$SCANNER" ]; then
  echo ""
  echo "WARNING: $SCANNER already exists."
  echo "Remove it manually and re-run to update."
  echo ""
else
  if [ -f "$SCRIPT_DIR/web-safety-scanner.sh" ]; then
    cp "$SCRIPT_DIR/web-safety-scanner.sh" "$SCANNER"
  else
    curl -sSL "$BASE_URL/web-safety-scanner.sh" -o "$SCANNER"
  fi
  chmod +x "$SCANNER"
  echo "Installed web-safety-scanner.sh to $SCANNER"
fi

# Install hooks config
if [ -f "$HOOKS_CONFIG" ]; then
  echo ""
  echo "WARNING: $HOOKS_CONFIG already exists."
  echo "Please manually merge the PreToolUse and PostToolUse entries into your existing config."
  echo "See: https://github.com/$REPO for the entries to add."
  echo ""
else
  if [ -f "$SCRIPT_DIR/hooks.json" ]; then
    cp "$SCRIPT_DIR/hooks.json" "$HOOKS_CONFIG"
  else
    curl -sSL "$BASE_URL/hooks.json" -o "$HOOKS_CONFIG"
  fi
  echo "Installed hooks.json to $HOOKS_CONFIG"
fi

echo ""
echo "Done! Restart Claude Code for the hooks to take effect."
echo "Test with: claude --debug"
