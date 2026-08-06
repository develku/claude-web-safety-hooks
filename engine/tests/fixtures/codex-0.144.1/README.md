# Codex CLI 0.144.1 PostToolUse fixtures

The authority for the Codex host mapping and encoder. Two artefacts live here,
and they carry different weight:

| Artefact | What it is | Authority |
|---|---|---|
| `schema/post-tool-use.command.input.json` | the host's own envelope JSON Schema | **authoritative** — extracted from the shipped binary |
| `schema/post-tool-use.command.output.json` | the host's own hook-output JSON Schema | **authoritative** — same |
| `*.json` envelopes | test inputs | mixed: see "Provenance" below |

## Where the schemas came from

Codex ships its hook contract as JSON Schema documents inside the binary. They
were extracted, not transcribed:

```bash
engine/tests/fixtures/codex-0.144.1/extract-schemas.sh \
  /opt/homebrew/Caskroom/codex/0.144.1/codex-aarch64-apple-darwin
```

| | |
|---|---|
| binary | `codex-aarch64-apple-darwin`, Homebrew cask `codex` 0.144.1 |
| `codex --version` | `codex-cli 0.144.1` |
| sha256 | `29915529b97697def1a957b0505e770aa6a45744435d62fc263e98d7619e167a` |

The script is read-only: it never launches Codex and never reads `~/.codex`,
credentials, config, history or transcripts. Re-running it on the same binary
reproduces both files byte-for-byte.

## The contract, as the host states it

### Envelope — `post-tool-use.command.input`

`additionalProperties: false`. **Required:** `cwd`, `hook_event_name`, `model`,
`permission_mode`, `session_id`, `tool_input`, `tool_name`, `tool_response`,
`tool_use_id`, `transcript_path`, `turn_id`. **Optional:** `agent_id`,
`agent_type`.

* `hook_event_name` is `const: "PostToolUse"`.
* `permission_mode` is a closed enum: `default`, `acceptEdits`, `plan`,
  `dontAsk`, `bypassPermissions`.
* `transcript_path` is `NullableString`. The adapter type-checks it and
  **never reads its value** — it points at hostile conversation metadata and is
  not a stable interface.
* `tool_input` and `tool_response` are schema-typed `true`: literally any JSON.
  The engine is deliberately stricter than the host on `tool_response` (see
  "Deliberate tightening" below).
* `turn_id` is described as *"Codex extension: expose the active turn id to
  internal turn-scoped hooks"* — it is the task/execution dimension, the
  analogue of Claude's `prompt_id`.

### Hook output — `post-tool-use.command.output`

`additionalProperties: false`, at the top level **and** inside
`hookSpecificOutput`. Accepted keys: `continue`, `decision`,
`hookSpecificOutput`, `reason`, `stopReason`, `suppressOutput`, `systemMessage`;
inside `hookSpecificOutput`: `additionalContext`, `hookEventName` (required,
`const: "PostToolUse"`), `updatedMCPToolOutput`.

`decision` has exactly one accepted value — `block` (`BlockDecisionWire`).

The runtime's own rejection strings, also from the binary, settle what "accepted
by the schema" is worth:

```text
PostToolUse hook returned unsupported updatedMCPToolOutput
PostToolUse hook returned unsupported suppressOutput
PostToolUse hook returned reason without decision
hook returned invalid post-tool-use JSON output
PostToolUse hook stopped execution
PostToolUse hook exited with code 2 but did not write feedback to stderr
```

So `updatedMCPToolOutput` and `suppressOutput` **parse but are unsupported**:
returning either fails the hook, and a failed hook means the **original** tool
output is processed normally. Emitting one would turn containment into a no-op.
Both the Rust encoder and the shell adapter refuse them.

## Live capture: what was and was not observed

An isolated live run WAS obtained, without credentials and without cost, by
pointing a disposable `CODEX_HOME` at a local offline mock provider that speaks
the Responses API. Nothing in `~/.codex` was read, copied or written; no
account, subscription or network egress was involved.

```bash
CODEX_HOME=<disposable>  codex exec \
  --dangerously-bypass-hook-trust --skip-git-repo-check "<benign prompt>"
```

### Observed, and it corrected a wrong assumption

A live `exec_command` call reached the hook as:

```json
{ "tool_name": "Bash",
  "tool_input": { "command": "printf '…'" },
  "tool_response": "Chunk ID: …\nWall time: …\nProcess exited with code 0\n…" }
```

Two things a schema read alone would have got wrong:

1. **`tool_name` is `Bash`**, not `exec_command`. The host normalizes its
   unified-exec tool onto the Claude-compatible label before the hook sees it.
2. **`tool_input.command` is a STRING**, not the array the model-facing tool
   schema declares.

`agent_id` and `agent_type` were **absent** from the main-session envelope,
confirming their schema optionality in practice.

### Not observed

| Path | Why not |
|---|---|
| MCP tool result | MCP tools are exposed through a `mcp__<server>` **namespace** tool in this build; a nested MCP dispatch was not obtained from the mock. |
| `apply_patch` result | Not advertised in the captured tool list under the unified-exec configuration used for capture. |
| a subagent envelope carrying `agent_id` | No subagent turn was driven. |
| hosted `WebSearch` | Observed as *never dispatching a hook at all* — which is the point. See below. |

### Hosted `WebSearch` is confirmed uncovered

The live request Codex sent advertises it as `{"type": "web_search",
"external_web_access": true}` — a **hosted** tool with no `name`, so it never
enters the local function-tool dispatcher. A turn in which the provider returned
a completed `web_search_call` item produced **zero** PostToolUse hook
invocations. This is a measured result, not an inference from documentation.

## Provenance of each envelope

| File | Provenance | Notes |
|---|---|---|
| `bash-exec-main.json` | **LIVE** (redacted) | `exec_command` → `tool_name: "Bash"`, string `command` |
| `bash-exec-bypass-permissions.json` | **LIVE** (mode value) | `permission_mode: "bypassPermissions"` as the host reported it |
| `bash-exec-subagent.json` | DERIVED | live envelope + the two optional identity fields |
| `apply-patch-main.json` | DERIVED | object result shape inferred from the tool contract |
| `mcp-content-array.json` | DERIVED | MCP content-block array |
| `local-function-scalar-input.json` | DERIVED | non-object `tool_input`, which the schema permits |

### Redaction

| Field | Replaced with |
|---|---|
| `session_id`, `turn_id`, `agent_id` | fixed synthetic UUIDs |
| `tool_use_id` | fixed synthetic call ids |
| `cwd` | `/fixture/project` |
| `transcript_path` | `null` (the live value was a real rollout path) |
| timing / chunk ids / token counts | fixed constants |
| every text leaf | short benign fixture text |

Key sets, nesting and JSON types are unchanged. Only values differ.

## Deliberate tightening over the host schema

The host types `tool_response` as `true` — any JSON, including `null`, a number
or a boolean. The engine accepts only a string, array or object.

A scalar `tool_response` has no string leaves, so it would flatten to empty
content and therefore to a **clean verdict**: an envelope shape this build has
never observed would buy a pass. Failing closed on it costs a containment on an
unobserved shape instead. This is recorded here because it is a real, deliberate
divergence from the published contract, not an oversight.

## Agent identity

`agent_id` is **optional**. An envelope without one is indistinguishable from a
subagent that simply did not report — and correlating those calls together would
merge unrelated agents into one bucket, which is the MAC-21 failure the scope key
exists to prevent. No Codex subagent envelope carrying `agent_id` has been
observed live on this version.

So a stateful Codex call with no `agent_id` is a typed identity failure:
`--state-mode report` says so and still delivers the scan, `--state-mode
enforce` contains. Neither correlates. The candidate adapter's default is
`--state-mode off`, so none of this is reached unless an operator opts in.

No Claude-style subagent quarantine claim is made for this host.
