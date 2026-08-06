#!/usr/bin/env bash
# =============================================================================
# Isolated smoke for the DORMANT Hermes Agent 0.20.0 adapter candidate.
#
# Isolation, in full:
#   * a disposable HERMES_HOME under $TMPDIR. The real ~/.hermes is never read,
#     copied or written: no config, no sessions, no plugin registration, no
#     trust record.
#   * no model, no network, no account, no cost. The agent loop is never
#     started; only the plugin loader and the hook dispatch are exercised.
#   * the adapter is COPIED into the disposable home, so this run leaves the
#     repo checkout untouched.
#
# Usage: adapters/hermes/smoke/run-hermes-smoke.sh
# =============================================================================

set -u

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd -P)"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
ENGINE="$ROOT/engine/target/release/web-safety-engine"
: "${HERMES_SRC:=$HOME/.hermes/hermes-agent}"

[ -x "$ENGINE" ] || {
  echo "engine not built; run: (cd engine && cargo build --release)" >&2; exit 1; }
[ -d "$HERMES_SRC" ] || {
  echo "Hermes source not found at $HERMES_SRC; set HERMES_SRC" >&2; exit 1; }

# The in-tree `hermes` launcher only runs under its own interpreter, so prefer
# the installed entry point and fall back to that interpreter explicitly.
if command -v hermes >/dev/null 2>&1; then
  VERSION="$(hermes --version 2>/dev/null | head -1)"
elif [ -x "$HERMES_SRC/venv/bin/python" ]; then
  VERSION="$("$HERMES_SRC/venv/bin/python" "$HERMES_SRC/hermes" --version 2>/dev/null | head -1)"
else
  VERSION=""
fi

case "$VERSION" in
  *0.20.0*) ;;
  *) echo "this smoke is versioned for Hermes Agent 0.20.0; found: ${VERSION:-unknown}" >&2
     echo "re-certify the contract fixture before trusting a different release." >&2
     exit 1 ;;
esac

# `hermes_cli` imports its own dependencies, so the smoke runs under the
# interpreter that already has them rather than whatever python3 is first.
PY="python3"
[ -x "$HERMES_SRC/venv/bin/python" ] && PY="$HERMES_SRC/venv/bin/python"
command -v "$PY" >/dev/null 2>&1 || [ -x "$PY" ] || {
  echo "missing dependency: python3" >&2; exit 1; }

echo "Hermes:  $VERSION"
echo "engine:  $ENGINE"
echo "python:  $PY"

HERMES_SRC="$HERMES_SRC" exec "$PY" "$HERE/mock_host.py"
