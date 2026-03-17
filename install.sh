#!/bin/bash
# Install web safety hooks for Claude Code
# Usage: ./install.sh

set -e

HOOKS_DIR="$HOME/.claude/hooks"
HOOKS_CONFIG="$HOME/.claude/hooks.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing Claude Code web safety hooks..."

# Create hooks directory
mkdir -p "$HOOKS_DIR"

# Copy scanner script
cp "$SCRIPT_DIR/web-safety-scanner.sh" "$HOOKS_DIR/web-safety-scanner.sh"
chmod +x "$HOOKS_DIR/web-safety-scanner.sh"

# Install hooks config
if [ -f "$HOOKS_CONFIG" ]; then
  echo ""
  echo "WARNING: $HOOKS_CONFIG already exists."
  echo "Please manually merge the contents of hooks.json into your existing config."
  echo "See hooks.json in this repo for the configuration to add."
  echo ""
else
  cp "$SCRIPT_DIR/hooks.json" "$HOOKS_CONFIG"
  echo "Installed hooks.json to $HOOKS_CONFIG"
fi

echo ""
echo "Done! Restart Claude Code for the hooks to take effect."
echo "Test with: claude --debug"
