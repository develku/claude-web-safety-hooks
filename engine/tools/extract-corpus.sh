#!/bin/bash
# Canonical corpus extractor — READ-ONLY against the production Bash scanner.
#
# The Bash arrays in scripts/web-safety-scanner.sh are the SINGLE SOURCE OF TRUTH
# for the literal pattern corpus. This script slices them out and emits
# engine/corpus/patterns.json, which the Rust core `include_str!`s at compile
# time. Nothing in the Rust tree hand-maintains a second copy of the list, so a
# pattern added to Bash cannot silently diverge from a pattern matched by Rust.
#
# Drift is enforced, not merely intended: `corpus::tests::corpus_matches_bash_source`
# re-runs this script into a temp file and fails if the checked-in artifact differs.
#
# The block reader is engine/tools/corpus-parse.awk — a strict DATA parser. This
# script never evaluates, sources or otherwise interprets a corpus source as
# shell; see that file's header for the accepted grammar.
#
# Usage:
#   engine/tools/extract-corpus.sh [output.json]
# Default output: engine/corpus/patterns.json
#
# The two source paths may be overridden so the extractor can be exercised
# against fixtures instead of only the production scanner:
#   WEB_SAFETY_SCANNER_SRC=... WEB_SAFETY_VERIFIER_SRC=... extract-corpus.sh out.json
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
ENGINE_DIR="$(cd "$TOOLS_DIR/.." && pwd)"
REPO_ROOT="$(cd "$ENGINE_DIR/.." && pwd)"
SCANNER="${WEB_SAFETY_SCANNER_SRC:-$REPO_ROOT/scripts/web-safety-scanner.sh}"
AWK_PARSER="$TOOLS_DIR/corpus-parse.awk"
OUT="${1:-$ENGINE_DIR/corpus/patterns.json}"

[ -f "$SCANNER" ] || { echo "scanner not found: $SCANNER" >&2; exit 2; }
[ -f "$AWK_PARSER" ] || { echo "parser not found: $AWK_PARSER" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

HIGH_ARRAYS=(HIGH_LLM_TOKENS HIGH_TOOL_FAKING HIGH_EXFIL)
MED_ARRAYS=(MED_INSTRUCTION_OVERRIDE MED_ROLE_MANIPULATION MED_GENERIC_DELIMITERS
            MED_PROMPT_EXTRACTION MED_JAILBREAK MED_AUTHORITY MED_GENERIC_EXFIL
            MED_TOOL_JSON MED_ENCODING MED_MULTILINGUAL MED_HTML_COMMENTS
            MED_DELIMITER_BREAKING MED_PAYLOAD_SPLITTING MED_COGNITIVE)
LOW_ARRAYS=(LOW_HTML_CSS LOW_MARKDOWN_IMAGES LOW_TOPIC_VOCAB)
OTHER_ARRAYS=(LEET_PATTERNS CONTEXT_GATE_REGISTRY INJECTION_KEYWORDS)

# Read one `NAME=(` … `)` literal block as DATA.
#
# This used to slice the block out and hand it to `eval`, which meant every run
# of the drift check EXECUTED the scanner source. corpus-parse.awk implements
# the documented literal-array grammar and rejects everything outside it, so
# nothing in a corpus source can expand, substitute or run.
#
# The parser reports its own entry count on the first line. Asserting that
# against the number of payload lines keeps the original guarantee: a pattern
# carrying a newline would split into two JSON entries, and is caught here
# rather than silently doubling the corpus.
to_json_array() {
  local name="$1" file="$2" parsed want got
  parsed="$WORK/parsed.$name"
  LC_ALL=C awk -v name="$name" -f "$AWK_PARSER" "$file" > "$parsed" || exit 2
  want=$(head -1 "$parsed")
  got=$(( $(wc -l < "$parsed") - 1 ))
  [ "$want" = "$got" ] || {
    echo "array $name: parser declared $want entries but emitted $got lines" >&2
    exit 2
  }
  tail -n +2 "$parsed" | jq -R . | jq -s .
}

# Arrays are emitted as an ORDERED LIST, not a JSON object: the Bash
# lowercase->original-casing map walks the arrays in declaration order, so a
# literal that appears in two arrays takes its rule id from the first. A JSON
# object would let the consumer's map re-sort them and silently reattribute it.
emit_group() {
  local sev="$1" file="$2"; shift 2
  local first=1 name
  printf '    "%s": [\n' "$sev"
  for name in "$@"; do
    [ $first -eq 1 ] || printf ',\n'
    first=0
    printf '      {"array": "%s", "patterns": ' "$name"
    to_json_array "$name" "$file" | jq -c .
    printf '}'
  done
  printf '\n    ]'
}

VERIFIER="${WEB_SAFETY_VERIFIER_SRC:-$REPO_ROOT/scripts/web-safety-verify-context.sh}"
[ -f "$VERIFIER" ] || { echo "verifier not found: $VERIFIER" >&2; exit 2; }

mkdir -p "$(dirname "$OUT")"
{
  printf '{\n'
  printf '  "source": "scripts/web-safety-scanner.sh",\n'
  printf '  "extracted_by": "engine/tools/extract-corpus.sh",\n'
  printf '  "groups": {\n'
  emit_group high   "$SCANNER" "${HIGH_ARRAYS[@]}"; printf ',\n'
  emit_group medium "$SCANNER" "${MED_ARRAYS[@]}"; printf ',\n'
  emit_group low    "$SCANNER" "${LOW_ARRAYS[@]}"; printf ',\n'
  # INJECTION_KEYWORDS lives in the verifier, not the scanner — same
  # single-source rule, different file.
  printf '    "other": [\n'
  printf '      {"array": "LEET_PATTERNS", "patterns": ';         to_json_array LEET_PATTERNS "$SCANNER" | jq -c .; printf '},\n'
  printf '      {"array": "CONTEXT_GATE_REGISTRY", "patterns": '; to_json_array CONTEXT_GATE_REGISTRY "$SCANNER" | jq -c .; printf '},\n'
  printf '      {"array": "INJECTION_KEYWORDS", "patterns": ';    to_json_array INJECTION_KEYWORDS "$VERIFIER" | jq -c .; printf '}\n'
  printf '    ]\n'
  printf '  }\n'
  printf '}\n'
} > "$OUT.tmp"
jq empty "$OUT.tmp" || { echo "extractor produced invalid JSON" >&2; rm -f "$OUT.tmp"; exit 2; }
mv "$OUT.tmp" "$OUT"

jq -r '
  .groups
  | to_entries[]
  | "\(.key)\t\([.value[].patterns | length] | add)\t\(.value | length)"
' "$OUT" | awk -F'\t' '{printf "%-8s %4d patterns across %2d arrays\n", $1, $2, $3; t+=$2} END{printf "%-8s %4d\n", "TOTAL", t}'
