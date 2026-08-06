# Strict DATA parser for one Bash literal-array declaration.
#
# The corpus arrays in scripts/web-safety-scanner.sh are the single source of
# truth for the literal pattern set, and engine/tools/extract-corpus.sh reads
# them on every `cargo test` via the drift check. Reading them by handing the
# sliced block to `eval` meant every one of those runs EXECUTED the scanner
# source: a `$(...)`, a backtick, or an extra command after the closing paren
# would run with the developer's — or CI's — privileges. This parser reads the
# same blocks as data and can execute nothing.
#
# Grammar, and nothing outside it:
#
#   NAME=(
#     # comment line
#     "literal"
#   )
#
# * The declaration line is exactly `NAME=(` and the terminator exactly `)`.
# * An entry is ONE double-quoted string per line, optionally indented; the
#   closing quote must be the last character on the line.
# * The only escapes are \" and \\. Everything else — including \n and \t — is
#   rejected rather than guessed at.
# * `$` and backticks are rejected outright: they carry no meaning to a data
#   parser, and their presence means the source is not the inert literal list
#   this contract assumes.
# * A blank line or a #-comment inside the block is skipped.
#
# Usage:  awk -v name=ARRAY_NAME -f corpus-parse.awk <file>
# Output: the entry count on the first line, then one decoded entry per line.
#         The header lets the caller verify no entry smuggled in a newline.
# Exit:   0 on success, 2 on any rejection (reason on stderr).
#
# Run under LC_ALL=C so substr() is byte-oriented and non-ASCII literals
# (MED_MULTILINGUAL) round-trip byte for byte.

function fail(msg) {
    printf("corpus-parse: %s: %s\n", name, msg) > "/dev/stderr"
    failed = 1
    exit 2
}

# Decode one `"…"` entry line, or fail. Returns the literal's bytes.
function decode(line,   len, i, c, nxt, out, closed) {
    len = length(line)
    if (len < 2 || substr(line, 1, 1) != "\"")
        fail("line " NR ": entries must be double-quoted string literals")

    out = ""
    closed = 0
    i = 2
    while (i <= len) {
        c = substr(line, i, 1)
        if (c == "\\") {
            if (i == len)
                fail("line " NR ": trailing backslash")
            nxt = substr(line, i + 1, 1)
            if (nxt != "\"" && nxt != "\\")
                fail("line " NR ": unsupported escape \\" nxt "; only \\\" and \\\\ are defined")
            out = out nxt
            i += 2
            continue
        }
        if (c == "\"") {
            # The first unescaped quote closes the literal, and must end the line:
            # anything after it is a second entry or a smuggled command.
            if (i != len)
                fail("line " NR ": unexpected content after the closing quote")
            closed = 1
            i++
            continue
        }
        if (c == "$" || c == "`")
            fail("line " NR ": '" c "' is a shell substitution, not corpus data")
        out = out c
        i++
    }
    if (!closed)
        fail("line " NR ": unterminated string literal")
    return out
}

BEGIN {
    if (name == "")
        fail("no array name given (-v name=NAME)")
    decl = name "=("
    seen = 0
    inblk = 0
    n = 0
}

{
    if ($0 == decl) {
        # A second declaration makes the extracted list depend on which one the
        # parser reached first — the silent-divergence class the single-source
        # rule exists to prevent.
        if (seen)
            fail("duplicate declaration at line " NR)
        seen = 1
        inblk = 1
        next
    }
    if (!inblk)
        next
    if ($0 == ")") {
        inblk = 0
        next
    }

    line = $0
    sub(/^[ \t]+/, "", line)
    sub(/[ \t]+$/, "", line)
    if (line == "" || substr(line, 1, 1) == "#")
        next

    entries[++n] = decode(line)
}

END {
    if (failed)
        exit 2
    if (!seen) {
        printf("corpus-parse: %s: array not declared in %s\n", name, FILENAME) > "/dev/stderr"
        exit 2
    }
    if (inblk) {
        printf("corpus-parse: %s: unterminated array — no closing ')'\n", name) > "/dev/stderr"
        exit 2
    }
    if (n == 0) {
        printf("corpus-parse: %s: array is empty\n", name) > "/dev/stderr"
        exit 2
    }
    print n
    for (i = 1; i <= n; i++)
        print entries[i]
}
