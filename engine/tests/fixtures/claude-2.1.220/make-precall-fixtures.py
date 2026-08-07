#!/usr/bin/env python3
"""Turn raw Claude Code PreToolUse captures into redacted pre-call fixtures.

Same conventions as make-fixtures.py (same synthetic ids, same placeholder
paths, same benign texts), applied to the PRE-call envelope. Redaction touches
VALUES only — key sets, nesting and JSON types stay byte-for-byte what the
host emitted, because the shape IS what the fixture certifies.

Usage: make-precall-fixtures.py <capture.jsonl> <dst-dir>

<capture.jsonl> is the append-file produced by an isolated capture harness
(`--setting-sources "" --settings <harness>/settings.json`) whose ONLY hook
captures stdin and then blocks the call, one JSON envelope per line, covering
WebFetch, WebSearch and Bash.
"""
import json
import pathlib
import sys

SRC = pathlib.Path(sys.argv[1])
DST = pathlib.Path(sys.argv[2])

SESSION = "00000000-0000-4000-8000-000000000001"
PROMPT = "00000000-0000-4000-8000-000000000002"
AGENT = "aaaaaaaaaaaaaaaaa"
TOOL_USE = "toolu_00000000000000000000000"
CWD = "/fixture/project"
TRANSCRIPT = "/fixture/transcript.jsonl"

# Benign per-key stand-ins for `tool_input` values. Applied per key PRESENT in
# the capture — never inserted for a key the host did not emit.
TOOL_INPUT_VALUES = {
    "url": "https://example.test/doc",
    "prompt": "what is the page title",
    "query": "reserved example domains",
    "command": "curl -s https://example.test/doc",
    "description": "Fetch the documentation page",
}


def redact_tool_input(v):
    if not isinstance(v, dict):
        return v
    out = {}
    for k, val in v.items():
        if k in TOOL_INPUT_VALUES and isinstance(val, str):
            out[k] = TOOL_INPUT_VALUES[k]
        elif isinstance(val, str):
            out[k] = "benign fixture text"
        else:
            # Non-string leaves (numbers, booleans, containers) carry no
            # account or content data in a pre-call tool_input; keep the
            # captured value so the TYPE stays exactly what the host emitted.
            out[k] = val
    return out


def redact(env):
    e = dict(env)
    for key, value in [
        ("session_id", SESSION),
        ("prompt_id", PROMPT),
        ("agent_id", AGENT),
        ("tool_use_id", TOOL_USE),
        ("cwd", CWD),
        ("transcript_path", TRANSCRIPT),
    ]:
        if key in e:
            e[key] = value
    if "tool_input" in e:
        e["tool_input"] = redact_tool_input(e["tool_input"])
    return e


captures = {}
for line in SRC.read_text().splitlines():
    line = line.strip()
    if line:
        d = json.loads(line)
        captures[d["tool_name"]] = d

NAMES = {
    "WebFetch": "pretooluse-webfetch.json",
    "WebSearch": "pretooluse-websearch.json",
    "Bash": "pretooluse-bash.json",
}

missing = [t for t in NAMES if t not in captures]
if missing:
    sys.exit(f"capture.jsonl is missing envelopes for: {missing}")

for tool, name in NAMES.items():
    env = redact(captures[tool])
    (DST / name).write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")
    print("wrote", name, "keys:", sorted(env.keys()))
