# Hermes Agent 0.20.0 adapter candidate — DORMANT

Not installed, not enabled, not trusted. Nothing under `~/.hermes/`, no project
`.hermes/plugins/`, no `cli-config.yaml` and no trust record refers to this directory,
and `hooks/hooks.json` still runs the Bash scanner. Bash remains both the authority and
the rollback path.

## Why Python, when the engine is Rust

Not a compromise — the loader leaves no other option. `hermes_cli/plugins.py:1860-1886`
requires an importable `__init__.py` and loads it with `spec_from_file_location` +
`exec_module`; the only other path is a pip entry point, also a Python module.
`plugin.yaml` has no `command` / `exec` / `binary` key. **A compiled binary cannot be
registered as a Hermes plugin.**

So this file is Python and its logic is ~0: locate the binary, hand it the envelope,
enforce a deadline, check the answer is one the host will act on. Every pattern, severity
rule, normalization step and state transition stays in the one Rust engine.

## What it covers, and what it does not

| Layer | Hook | Covered |
|---|---|---|
| 2-5 tool-result scanning | `transform_tool_result` | yes |
| 8 terminal output | `transform_terminal_output` | yes |
| 1 URL pre-screening | `pre_tool_call` | yes |
| 6 egress guard | `pre_tool_call` | yes |
| 7 subagent ISOLATION | (distinct child `session_id`) | **yes, automatically** |
| 7 subagent ATTRIBUTION | `subagent_stop` | **no — blocked upstream** |

Layer 7 splits in two on this host, and only one half is missing.

## Web-tools-only scope (disjoint from security-guidance)

This adapter acts on **exactly** the web ingress/sink tools in its allowlist, and is
silent on every other tool (the hook returns `None`, so the result passes through
untouched). That scope is what makes web-safety provably disjoint from Hermes' bundled
`security-guidance` plugin, which registers the same two hooks
(`transform_tool_result`, `pre_tool_call`) but targets file-write tools
(`write_file`, `patch`, `skill_manage`). Under Hermes' **first-valid-string-wins**
dispatch, two plugins that act on the same result race — whichever callback returns a
string first owns the result, so either could silently clobber the other's value. Because
no tool is ever in both plugins' target sets, neither can override the other: coverage is
disjoint **by construction**, not by luck of hook ordering.

The allowlist is grounded in Hermes 0.20.0's own tool registry (`tools/*.py`):

| Kind | Tools |
|---|---|
| exact | `web_search`, `web_extract`, `x_search` |
| prefix `web_` | future web search/extract tools |
| prefix `browser_` | `browser_navigate`, `browser_snapshot`, `browser_console`, ... (GUI browser) |
| prefix `cua_browser_` | typed-browser actions: navigate, click, type, pointer, dialog, state, ... |

MCP fetch/search tools are server-defined (wire name `mcp__<server>__<tool>`) and cannot
be enumerated here, so they are allowlisted **individually by exact wire name** via
`WEB_SAFETY_TOOLS` — nothing is ever matched by the `mcp__` prefix alone, which would
sweep in every non-web MCP tool and break the disjointness property.

**Safety net:** on start, `register()` runs a read-only doctor check
(`_warn_if_coenabled`). If both web-safety and security-guidance ever appear enabled
together it logs a diagnostic warning so a future edit that widens either plugin's tool
scope cannot silently start racing the other. It reads `config.yaml` only, never enables
or installs anything.

## The three properties this host forces

**Isolation is free.** A `delegate_task` child gets its own session id, and its tool calls
carry it, so the engine's session scope already separates parent from child. `agent_id`
mapping to `None` is accurate here, not a gap — Claude needs `agentId` precisely because
its subagents share the parent's session id.

**Attribution is blocked upstream.** It needs the parent to know which child died AND to
say so, and Hermes 0.20.0 puts those in different hooks with no shared key:
`subagent_stop` carries `child_session_id` but its return value is ignored, while
`transform_tool_result` on `delegate_task` can rewrite what the parent reads but receives
no child identifier — the result entries are built with `task_index` / `status` /
`summary` only. Correlating them by iteration order would be a confident guess, so it is
not done. Full provenance in `engine/tests/fixtures/hermes-0.20.0/README.md`.

## The three properties this host forces

1. **A returned `str` replaces what the model reads; `None` changes nothing; every other
   type is discarded with no warning.** So a JSON object here is not a partial success —
   it is silently no protection. Every return path is a `str` or `None`.
2. **Hook exceptions are logged and ignored** (`plugins.py:1934-1945`). Raising cannot
   stop a turn, so nothing is allowed to escape and no path returns `None` because
   something failed — failures return the containment string.
3. **There is no host-side timeout.** A blocking callback appears to block the agent loop
   indefinitely, so the deadline is enforced here, over a process group, so a forked
   grandchild holding stdout open cannot outlive it.

Two non-obvious details in that third property, both found by the smoke rather than by
reading:

- **The process group is captured at spawn, not at kill time.** The engine can exit while
  a forked grandchild keeps the stdout pipe open; `communicate` then reaps the direct
  child, and a later `os.getpgid(proc.pid)` raises `ProcessLookupError` — skipping the
  group kill in exactly the case it exists for. Measured before the fix: the grandchild
  outlived the hook.
- **The kill refuses to signal its own process group.** `killpg` takes a group, and a
  child spawned without `start_new_session` shares the caller's — the agent's. Unguarded,
  a scanner timeout would SIGKILL Hermes itself.

## The documentation trap

Hermes' bundled hook reference documents kwarg names its dispatch does not pass —
`arguments` for the real `args`, `exit_code`/`cwd` for the real `returncode` (with `cwd`
never passed at all). Since `invoke_hook` binds by keyword and swallows the resulting
`TypeError`, **a callback written from those docs registers cleanly, raises on every
invocation, and silently transforms nothing.**

Both callbacks here therefore take `**kwargs` only and read keys explicitly. Provenance
and the reproduction: `engine/tests/fixtures/hermes-0.20.0/README.md`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WEB_SAFETY_ENGINE` | `<repo>/engine/target/release/web-safety-engine` | explicit binary path |
| `WEB_SAFETY_TIMEOUT` | `5` | per-scan wall-clock budget, seconds |
| `WEB_SAFETY_TOOLS` | *(empty)* | comma-separated extra web-tool wire names to allowlist (e.g. MCP fetch/search tools such as `mcp__nous__fetch`) |

PATH is never searched: a binary that merely shares the name is not this engine.

## Smoke

```bash
adapters/hermes/smoke/run-hermes-smoke.sh
```

Loads this package through Hermes' **own** `PluginManager` under a disposable
`HERMES_HOME` — the real `~/.hermes` is never read or written — then drives the
registered callbacks through dispatch semantics copied from the runtime, including every
fail-closed path: engine missing, deadline exceeded, non-zero exit, wrong-typed return,
and a forked child holding stdout open.
