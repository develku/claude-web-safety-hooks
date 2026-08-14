# Hermes Agent 0.20.0 adapter candidate — DORMANT

Not installed, not enabled, not trusted. Nothing under `~/.hermes/`, no project
`.hermes/plugins/`, no `cli-config.yaml` and no trust record refers to this directory.
(The engine this adapter calls IS live elsewhere: since v9.0.0 `hooks/hooks.json` wires
it as the Claude Code scanner authority. That changes nothing here — this adapter stays
dormant until a Hermes trust record is deliberately created, and the Bash scripts stay
in-tree as the frozen differential oracle.)

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

The terminal hook is a separate interception seam: it already scans every
foreground terminal result before truncation, and it does not participate in
`transform_tool_result` dispatch.  Gmail handling below therefore does **not** add
`terminal` to this allowlist or create a first-valid-string race with
security-guidance.

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

## Gmail untrusted-data boundary

Hermes retrieves Gmail through the bundled google-workspace compatibility script,
so the host reports it as terminal output rather than as a distinct Gmail tool.  A
clean content scan alone is not a semantic trust decision: message sender, subject,
snippet, and body remain external data even when no detector fires.

After the existing fail-closed engine scan returns clean, the adapter wraps output
only when the terminal command is conservatively proven to be one successful,
read-only invocation of the exact script under the active
`HERMES_HOME/skills` tree (or the exact `HERMES_BUNDLED_SKILLS` tree explicitly
advertised by a source/package checkout):

```text
.../skills/productivity/google-workspace/scripts/google_api.py gmail search ...
.../skills/productivity/google-workspace/scripts/google_api.py gmail get ...
```

The frame labels the payload as untrusted Gmail data and uses a fresh 128-bit nonce
in matching begin/end delimiters.  If either generated delimiter already occurs in
the payload, the nonce is regenerated; repeated collisions fail closed. Mixed shell
commands, separators, pipes, every redirect/descriptor form, here-strings, command
substitution, newlines, glob/expansion forms, interpreter flags/wrappers,
suffix-identical lookalike scripts, non-zero exits, Calendar operations, and Gmail
writes are not labelled as Gmail. They retain the pre-existing terminal behavior
and are still scanned normally.

Scanner containment and scanner failures always outrank the frame: a finding,
missing engine, malformed verdict, or timeout returns the static containment string
without exposing message content.

### Verification evidence and proof boundary

The Gmail boundary is tested through Hermes' real `PluginManager` and the compiled
Rust engine, with controlled command and output fixtures. The 2026-08-14 reference
run on the current working tree produced:

| Gate | Result |
|---|---:|
| Hermes adapter smoke | 108 passed, 0 failed |
| Rust `cargo test --locked` | 561 passed, 0 failed |
| Legacy shell suites (7) | 359 passed, 0 failed |
| Python `py_compile`, `git diff --check` | passed |
| `cargo fmt --check`, Clippy with warnings denied | passed |

The focused smoke proves the implemented contract for clean authenticated framing,
direct injection containment, delimiter-forgery resistance, exact nonce-collision
regeneration, canonical-path enforcement, read-versus-write discrimination, shell
composition rejection, unrelated-terminal preservation, and fail-closed scanner
missing/timeout paths. In the containment cases it also asserts that the original
mail fixture is absent from the model-visible result.

This is strong executable evidence for those specified properties, **not** a formal
proof that every possible email attack is impossible. The reference run did not
access a Gmail account, perform an OAuth/API round trip, prove that any particular
Hermes profile is running this checkout, fuzz every shell spelling, or independently
audit the detector. A controlled read-only Gmail end-to-end deployment test is still
required before claiming live-account or installed-profile verification.

## Diagnostic (doctor)

The adapter fails CLOSED: when the engine is missing, not executable, times out, or
returns anything the host would discard, every web tool result becomes the fixed
`CONTAINMENT` string — and that string is deliberately uniform, never saying *why*.
The *why* lives in an out-of-band command, run on purpose, never in a tool result:

```bash
python3 adapters/hermes/doctor.py          # or ./adapters/hermes/doctor.py
```

It reproduces the adapter's exact engine resolution (`_engine_path()`) and walks the
M1–M5 failure table from `docs/engine-distribution.md`, ending with a HEALTHY result or
a concrete fail-closed cause plus the exact shell command to fix it:

| # | Cause | Doctor checks | Remediation it prints |
|---|---|---|---|
| M1 | `WEB_SAFETY_ENGINE` set but bad | path exists? `+x`? | unset it / fix the path |
| M2 | in-tree engine not built | expected file present? | `cd engine && cargo build --release` |
| M3 | in-tree engine not `+x` | exec bit off? | `chmod +x …/web-safety-engine` |
| M4 | built but broken at runtime | `info` runs? probe scan? | `cd engine && cargo build --release --locked` |
| M5 | contract/toolchain drift | `info` schema_version ≠ 1 | rebuild pinned; bump `contract.rs` deliberately |

Honors the same environment as the adapter: `WEB_SAFETY_ENGINE`, `WEB_SAFETY_TIMEOUT`.

## Smoke

```bash
adapters/hermes/smoke/run-hermes-smoke.sh
```

Loads this package through Hermes' **own** `PluginManager` under a disposable
`HERMES_HOME` — the real `~/.hermes` is never read or written — then drives the
registered callbacks through dispatch semantics copied from the runtime, including every
fail-closed path: engine missing, deadline exceeded, non-zero exit, wrong-typed return,
and a forked child holding stdout open.
