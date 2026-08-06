#!/usr/bin/env python3
"""Turn raw Claude Code 2.1.220 PostToolUse captures into minimal redacted fixtures.

Redaction rules (applied to EVERY captured envelope, no exceptions):
  * `transcript_path` / `cwd`         -> fixed placeholder paths (machine paths out)
  * `session_id` / `prompt_id`        -> fixed synthetic UUIDs (account metadata out)
  * `agent_id` / `tool_use_id`        -> fixed synthetic ids
  * `duration_ms` / timing / byte     -> fixed constants (non-deterministic noise out)
  * every attacker-reachable text     -> replaced with short benign fixture text

Nothing about the SHAPE is altered: key sets, nesting and JSON types are exactly
what Claude Code 2.1.220 emitted.
"""
import json
import pathlib
import sys

SRC = pathlib.Path(sys.argv[1])
DST = pathlib.Path(sys.argv[2])
DST.mkdir(parents=True, exist_ok=True)

SESSION = "00000000-0000-4000-8000-000000000001"
PROMPT = "00000000-0000-4000-8000-000000000002"
AGENT = "aaaaaaaaaaaaaaaaa"
TOOL_USE = "toolu_00000000000000000000000"
CWD = "/fixture/project"
TRANSCRIPT = "/fixture/transcript.jsonl"

BENIGN_PAGE = 'The page title is "Example Domain."\nThis domain is for use in documentation examples.\n'
BENIGN_SEARCH = "Reserved example domains are described by RFC 2606.\nSecond line of the benign summary.\n"
BENIGN_MCP = "NOTICE\nThis document is benign fixture content.\nLine three of the notice.\n"


def load(path):
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def base(env):
    e = dict(env)
    e["session_id"] = SESSION
    if "prompt_id" in e:
        e["prompt_id"] = PROMPT
    if "agent_id" in e:
        e["agent_id"] = AGENT
    e["tool_use_id"] = TOOL_USE
    e["cwd"] = CWD
    e["transcript_path"] = TRANSCRIPT
    e["duration_ms"] = 1
    return e


def webfetch(env, body):
    e = base(env)
    e["tool_input"] = {"url": "https://example.test/doc", "prompt": "what is the page title"}
    r = dict(e["tool_response"])
    r["result"] = body
    r["bytes"] = len(body)
    r["durationMs"] = 1
    r["url"] = "https://example.test/doc"
    e["tool_response"] = r
    return e


def websearch(env, body):
    e = base(env)
    e["tool_input"] = {"query": "reserved example domains"}
    r = dict(e["tool_response"])
    r["query"] = "reserved example domains"
    r["durationSeconds"] = 1.0
    r["searchCount"] = 1
    first = dict(r["results"][0])
    first["tool_use_id"] = "srvtoolu_0000000000000000000000"
    first["content"] = [{"title": "RFC 2606", "url": "https://example.test/rfc2606"}]
    r["results"] = [first, body]
    e["tool_response"] = r
    return e


def mcp(env, body):
    e = base(env)
    e["tool_input"] = {"topic": "demo"}
    e["tool_response"] = [{"type": "text", "text": body}]
    return e


web = {d["tool_name"]: d for d in load(SRC / "web.jsonl")}
sub = [d for d in load(SRC / "subagent.jsonl") if d["tool_name"] == "WebSearch"]
mcpcap = [d for d in load(SRC / "mcp.jsonl") if d["tool_name"].startswith("mcp__")]

fixtures = {
    "webfetch-main.json": webfetch(web["WebFetch"], BENIGN_PAGE),
    "websearch-main.json": websearch(web["WebSearch"], BENIGN_SEARCH),
    "mcp-content-array.json": mcp(mcpcap[0], BENIGN_MCP),
    "websearch-subagent.json": websearch(sub[0], BENIGN_SEARCH),
}

# prompt_id absent: `prompt_id` is documented as requiring Claude Code v2.1.196+,
# so an older host omits it. 2.1.220 always emitted it in every capture taken
# here, so this fixture is DERIVED from the real WebFetch capture by deleting
# that one optional key. No field, type or nesting is invented.
no_prompt = dict(fixtures["webfetch-main.json"])
del no_prompt["prompt_id"]
fixtures["webfetch-no-prompt-id.json"] = no_prompt

for name, env in fixtures.items():
    (DST / name).write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")
    print("wrote", name)
