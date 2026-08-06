#!/usr/bin/env bash
# =============================================================================
# Re-extract the Codex CLI 0.144.1 PostToolUse hook schemas from a local binary.
#
# The schemas under `schema/` are the AUTHORITY for the Codex mapping and
# encoder. They are not transcribed from documentation and not guessed: they are
# the JSON Schema documents the shipped binary itself carries. This script
# reproduces the extraction so a reviewer can confirm the fixtures rather than
# trust them.
#
#   engine/tests/fixtures/codex-0.144.1/extract-schemas.sh <path-to-codex-binary>
#
# Read-only. It never launches Codex, never reads `~/.codex`, never touches
# credentials, config, history or transcripts.
# =============================================================================

set -eu

BIN="${1:?usage: extract-schemas.sh <path-to-codex-binary>}"
OUT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/schema"
mkdir -p "$OUT"

command -v strings >/dev/null || { echo "missing dependency: strings" >&2; exit 1; }

echo "binary:  $BIN"
echo "sha256:  $(shasum -a 256 "$BIN" | awk '{print $1}')"

strings -a "$BIN" > "$OUT/.strings.tmp"

python3 - "$OUT/.strings.tmp" "$OUT" <<'PY'
import json, sys, pathlib

blob = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
out = pathlib.Path(sys.argv[2])

# Each schema is emitted as `<title>{...}` in the binary's string table; the
# object is taken by brace matching rather than by a regex, so a nested `}`
# inside a description cannot truncate it.
def block(title):
    i = blob.index(title + "{")
    j = i + len(title)
    depth, k = 0, j
    while True:
        c = blob[k]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return blob[j:k + 1]
        k += 1

for title in ("post-tool-use.command.input", "post-tool-use.command.output"):
    text = block(title)
    # Parse before writing: a schema that is not valid JSON would mean the
    # extraction, not the host, is what this fixture froze.
    json.loads(text)
    (out / f"{title}.json").write_text(text)
    print(f"wrote {title}.json ({len(text)} bytes)")
PY

rm -f "$OUT/.strings.tmp"
