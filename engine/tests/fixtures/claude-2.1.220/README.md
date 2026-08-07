# Claude Code 2.1.220 PostToolUse fixtures

Frozen `PostToolUse` hook envelopes, captured from a **live** Claude Code
`2.1.220 (Claude Code)` on macOS, then redacted. They exist so the Claude
response encoder can be tested against the shapes the host actually emits
rather than against the shapes its documentation illustrates — the two differ
(see "Documentation drift" below).

## How they were captured

An isolated, throw-away harness. Nothing installed was read or written:

```
claude -p "<benign prompt>"                      \
  --setting-sources ""                           \  # no user/project/local settings → no plugins, no production hook
  --settings <harness>/settings.json             \  # ONLY a capture hook: `cat >> $WEB_SAFETY_CAPTURE_FILE`
  --allowedTools "<the one tool under capture>"  \
  --model claude-haiku-4-5-20251001
```

* The production `web-safety` plugin never loaded (`--setting-sources ""`).
* `hooks/hooks.json`, installed settings and the installed plugin were not touched.
* Content was benign throughout: `https://example.test`-class documentation
  pages, one RFC-2606 search, and a local stdio MCP server returning a fixed
  three-line notice.
* No credentials, account metadata or unrelated environment data reached these
  fixtures — every value in them is redacted or synthetic (see "Redaction").

### Capture transcripts: still present, pending operator cleanup

An earlier revision of this file claimed the harness transcripts had been
deleted. They have **not** been. The deletion was attempted and denied, and the
local directory still exists on the capture machine:

```text
~/.claude/projects/-Users-kudmini-multica-workspaces-679583d4-f9bf-48d7-bb72-7390b2c3393a-06233534-workdir--capture-proj
```

What IS true:

* Nothing from that directory is in this repository or in any handoff archive —
  the fixtures here were produced by `make-fixtures.py`, which redacts every
  value it copies.
* The capture content was benign by construction (`example.test`-class pages,
  one RFC-2606 search, a local MCP server returning a fixed notice).

Cleanup of that directory is an **operator action, outside this stage's
boundaries**. It is recorded here rather than quietly restated as done.

## Redaction

Applied uniformly by `make-fixtures.py` at capture time:

| Field | Replaced with |
|---|---|
| `session_id`, `prompt_id` | fixed synthetic UUIDs |
| `agent_id`, `tool_use_id` | fixed synthetic ids |
| `cwd`, `transcript_path` | `/fixture/...` placeholders |
| `duration_ms`, `durationMs`, `durationSeconds`, `bytes` | fixed constants |
| every text leaf | short benign fixture text |

**Key sets, nesting and JSON types are byte-for-byte what 2.1.220 emitted.**
Only values changed.

## The fixtures

| File | Tool | Notes |
|---|---|---|
| `webfetch-main.json` | `WebFetch` | main session; object `tool_response` |
| `websearch-main.json` | `WebSearch` | main session |
| `websearch-subagent.json` | `WebSearch` | carries `agent_id` **and** `agent_type` |
| `mcp-content-array.json` | `mcp__fixture__fetch_notice` | MCP content-block **array** |
| `webfetch-no-prompt-id.json` | `WebFetch` | `prompt_id` absent — see below |

### Observed `tool_response` shapes

```
WebFetch  { "bytes": int, "code": int, "codeText": str,
            "result": str, "durationMs": int, "url": str }

WebSearch { "query": str, "durationSeconds": float, "searchCount": int,
            "results": [ {"tool_use_id": str,
                          "content": [{"title": str, "url": str}]},
                         str ] }          # heterogeneous: the trailing string
                                          # is the model-facing summary

MCP       [ {"type": "text", "text": str} ]        # a bare ARRAY, not an object
```

### `prompt_id` absent

`prompt_id` is documented as requiring Claude Code **v2.1.196+**, so a host
older than that omits it. Every envelope 2.1.220 emitted during capture
carried it, in the main session and inside a subagent alike, so the absent case
could not be observed live on this version. `webfetch-no-prompt-id.json` is
therefore **derived** from the real `webfetch-main.json` capture by deleting
that one documented-optional key. No field, type or nesting is invented — the
fixture exercises the optionality the host documents, nothing more.

### Documentation drift (recorded, not corrected)

The published hooks reference illustrates `Read`/`Edit` output as
`{"status": "success", "file_path": ..., "content": ...}`. A live 2.1.220
`Read` returns
`{"type":"text","file":{"filePath":...,"content":...,"numLines":...,"startLine":...,"totalLines":...}}`.
The captured shapes above — not the documented illustrations — are what the
encoder validates against, which is exactly why this stage froze real fixtures.

These key sets are **exact**, and the encoder matches them exactly: an extra
key — even a benign one a future version adds — makes the shape unknown, and an
unknown shape takes the replacement-free `continue:false` stop path. A subset
match would mean cloning the hostile response and patching the leaves the check
happened to look at, which is the containment leak this stage exists to close.

## PreToolUse fixtures — DERIVED, not live-captured

`pretooluse-webfetch.json`, `pretooluse-websearch.json` and
`pretooluse-bash.json` are **derived from the production Bash authority, not a
fresh live capture**. A live capture was attempted on 2026-08-07 (CLI 2.1.223)
and blocked on `claude -p` reporting "OAuth session expired and could not be
refreshed"; re-authentication is an operator action, and misrepresenting a
derived fixture as captured is exactly what this README exists to prevent.

What "derived from the production Bash authority" means concretely — every
field name comes from a `jq` expression a production hook has been reading from
live PreToolUse envelopes for months:

| Field | Production reader |
|---|---|
| `.tool_name` | `web-safety-egress.sh` |
| `.tool_input.url // .URL` | `web-safety-approve.sh` (Layer 1) |
| `.tool_input.url // .URL // .uri // .href // .urls[0]` | `web-safety-egress.sh` (Layer 6 fetch channel) |
| `.tool_input.command` | `web-safety-egress.sh` (Bash channel), `web-safety-bash-scan.sh` |
| `.tool_input.query` | `web-safety-egress.sh` (WebSearch downgrade log) |
| `.permission_mode` | `web-safety-egress.sh` (mode-aware enforcement) |
| `.session_id`, `.prompt_id` | live-captured on this version's PostToolUse envelopes (above); common hook-input fields per the hooks reference |

The surrounding envelope keys (`cwd`, `hook_event_name`, `transcript_path`,
`tool_use_id`) mirror the live-captured PostToolUse envelopes and the published
hook-input contract; the Rust mapping reads none of them. Values follow the
same redaction conventions as the captured fixtures (synthetic UUIDs,
`/fixture/...` paths, benign RFC-2606-class text).

**Upgrade path:** after `claude --login`, re-run the isolated harness above
with a PreToolUse capture hook and replace these three files with redacted
live captures, then delete this section's "derived" caveat. The conformance
suite (`tests/claude_precall_conformance.rs`) locks the field READS, so a live
capture that agrees changes nothing and a live capture that disagrees fails the
suite loudly — which is the point.

### Not captured on 2.1.220

A **string-valued** `WebFetch` `tool_response`. Every observed WebFetch result
— success and cross-host-redirect alike — was the object above. A string is
therefore treated by the encoder as an *unknown* shape for a built-in and fails
closed (stop + withhold) rather than emitting a replacement the host would
silently ignore.

A `WebSearch` `results` array with **no** string element. The captured shape
always carried the trailing model-facing summary string, which is where the
withheld receipt has to go; an array without one would force the encoder to
change the array's structure to deliver it, so that case fails closed too.

MCP content blocks other than `{"type": "text", "text": …}` — image, resource
and annotated blocks were never emitted during capture, so they are unknown
shapes as well.
