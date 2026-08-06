# Hermes Agent 0.20.0 — host contract provenance

Certifies the `Host::Hermes` mapping in `engine/src/hosts.rs`, which was
**provisional** before this fixture existed.

## Version and extraction method

| | |
|---|---|
| Runtime | Hermes Agent **v0.20.0 (2026.8.3)** |
| Reported by | `hermes --version` |
| Install root | `/Users/kudmini/.hermes/hermes-agent` (source install, not a compiled binary) |
| Extraction | Read directly from the installed Python source and its own test suite |
| Extracted | 2026-08-06 |

Unlike Codex 0.144.1 — whose contract came from JSON Schemas embedded in a shipped
binary — Hermes installs as readable Python. The contract is therefore taken from the
**dispatch call sites**, cross-checked against **Hermes' own tests**. Where the shipped
documentation disagrees with the code, the code and its tests are authoritative and the
disagreement is recorded below, because following the documentation produces a security
hook that silently does nothing.

## Interception surface

Hermes plugin hooks are Python callbacks registered by a source-only plugin. The loader
requires an importable module — `hermes_cli/plugins.py:1860-1886` raises
`FileNotFoundError` without `__init__.py`, then `spec_from_file_location` +
`exec_module`. The only other load path is a pip entry point (`:1888`), also a Python
module. `plugin.yaml` has no `command` / `exec` / `binary` / `entrypoint` key: a
compiled binary cannot be registered as a plugin.

Four hooks matter to this engine. `hermes_cli/plugins.py:136-139` lists the tool-scoped
subset; the full hook set (session, LLM, gateway, approval, subagent) is larger and out
of scope here.

### `pre_tool_call` — can veto

- **Fires:** `model_tools.py`, inside `handle_function_call()`, before the handler runs.
  Once per tool call; 3 parallel tool calls fire it 3 times.
- **Kwargs:** `tool_name: str`, `args: dict`, `task_id: str` (empty string when unset).
- **Veto:** return `{"action": "block", "message": str}`. The agent short-circuits the
  tool and `message` becomes the error handed to the model.
- **Precedence:** first matching block directive wins, **Python plugins before shell
  hooks**. Any other return value is ignored.

### `post_tool_call` — observational only

- **Kwargs:** `tool_name`, `args`, `result: str` (always a JSON string), `task_id`,
  `duration_ms: int`.
- **Return value: ignored.** Cannot withhold, replace, or block. Unusable as an
  enforcement point.
- Does not fire on an unhandled tool exception; the error is caught and passed as
  `result` instead.

### `transform_tool_result` — the primary containment seam

- **Fires:** `model_tools.py:1472-1497`, after any tool returns, after
  `post_tool_call`, **before the result is appended back into conversation context** —
  i.e. before the model sees it.
- **Kwargs actually passed** (`model_tools.py:1479-1493`): `tool_name`, **`args`**,
  `result`, `task_id`, `session_id`, `tool_call_id`, `turn_id`, `api_request_id`,
  `duration_ms`, `status`, `error_type`, `error_message`, plus
  `telemetry_schema_version` injected by `invoke_hook` (`plugins.py:1931`).
- **Return:** a `str` replaces the result; `None` leaves it unchanged. **First valid
  string return wins; non-string returns are ignored silently.**
- Gated on `has_hook` — the no-listener path skips dispatch entirely.

### `transform_terminal_output` — earlier, terminal only

- **Fires:** `tools/terminal_tool.py:3007-3020`, inside the `terminal` tool's
  foreground-output path, **before** truncation, ANSI-strip, and secret redaction.
- **Kwargs actually passed:** `command`, `output`, **`returncode`**, `task_id`,
  **`env_type`**.
- **Return:** a `str` replaces the output; first valid string wins.

## Fail-open — the governing property

`hermes_cli/plugins.py:1934-1945`, `invoke_hook`:

```
try:
    ret = cb(**kwargs)
    if ret is not None:
        results.append(ret)
except Exception as exc:
    logger.warning("Hook '%s' callback %s raised: %s", ...)
```

Every callback is individually wrapped. A raise is logged at WARNING and the agent loop
continues with the untransformed result. The same posture appears throughout the core:
`agent/turn_finalizer.py:563`, `:584`; `agent/conversation_loop.py:582`;
`agent/turn_context.py:1103`.

**Consequence for this engine:** the adapter can never rely on raising, on a non-zero
exit, or on an exception to stop a turn. Containment must be delivered as a returned
replacement string. A hook that fails is indistinguishable, from the model's side, from
a hook that is not installed.

## Documentation defects found — 2 of 2 transform hooks

The bundled reference (`website/docs/user-guide/features/hooks.md`) documents callback
signatures that do not match dispatch. Because Python binds hook kwargs by name and
`invoke_hook` swallows the resulting `TypeError`, a plugin written to the documentation
**registers successfully, raises on every invocation, and silently transforms nothing**.

| Hook | Documented | Actually passed | Effect |
|---|---|---|---|
| `transform_tool_result` | `arguments` (hooks.md:1173) | `args` (model_tools.py:1481) | missing-kwarg `TypeError`, hook dead |
| `transform_terminal_output` | `exit_code`, `cwd` (hooks.md:1218-1221) | `returncode`; `cwd` never passed; `env_type` undocumented | same |

Hermes' own test asserts the code, not the docs:
`tests/test_transform_tool_result_hook.py:85` — `assert captured["args"] == {"a": 1, "b": "x"}`.

Reproduced against the real `invoke_hook` semantics: with the documented signature the
model receives the original unmodified payload and the only trace is one WARNING line;
with the code signature the replacement is applied. This is precisely the fail-open this
project exists to prevent, so the adapter binds `**kwargs` and reads keys explicitly
rather than declaring named parameters.

## Consequences for `Host::Hermes`

1. The response encoding must produce a **bare replacement string**, not a JSON envelope
   with a decision field. Hermes has no `continue` / `decision` / `systemMessage`
   vocabulary; the only lever is "what string does the model see".
2. A non-string return is discarded **without a warning**, so an encoder that emitted the
   wrong JSON type would fail open silently — the mapping must never be best-effort.
3. `pre_tool_call` is the only blocking surface and it is dict-shaped
   (`{"action": "block", "message": …}`), a different response shape from the transform
   hooks. Layers 1 and 6 need that shape; Layers 2-5 need the string shape.
4. `task_id` is `""` when unset — an empty string is a legitimate value, not absence, so
   state scoping must not treat it as a missing field.

## Subagent identity (Layer 7) — extracted, and it does not join up

Delegation is the `delegate_task` tool. A child gets its OWN session id
(`delegate_tool.py:2943` sets `set_current_session_id(child.session_id)`), and the child's
own tool calls carry it: `agent_runtime_helpers.py:3030` passes
`session_id=getattr(agent, "session_id", "")`, which for a child IS the child's.

**Consequence for state scoping:** isolation is ALREADY correct on this host. Where Claude
gives a subagent the parent's session id plus a distinct `agentId`, Hermes gives it a
distinct session id outright, so the engine's session scope separates parent from child
with no `agent_id` at all. `Host::Hermes` mapping `agent_id` to `None` is therefore not an
isolation defect — it is accurate.

### The two subagent hooks, as dispatched

`subagent_start` (`delegate_tool.py:1604-1613`):

| kwarg | note |
|---|---|
| `parent_session_id`, `parent_turn_id`, `parent_subagent_id` | parent side |
| `child_session_id` | **the join key** |
| `child_subagent_id` | present HERE ONLY |
| `child_role`, `child_goal` | |

`subagent_stop` (`delegate_tool.py:2719-2728`), fired parent-side:

| kwarg | note |
|---|---|
| `parent_session_id`, `parent_turn_id` | parent side |
| `child_session_id` | **the join key** |
| `child_role`, `child_summary`, `child_status` | outcome |
| `tool_call_history`, `duration_ms` | |

Note the asymmetry: **`child_subagent_id` is on `start` and NOT on `stop`.** The only
identifier common to both is `child_session_id`, which is also what the child's own hooks
report — so that, not `child_subagent_id`, is the durable key.

### Why attribution still cannot be wired in 0.20.0

Layer 7 needs two things in the PARENT: knowing which child died, and telling the model.
This host puts them in different hooks with no shared correlation key.

| | carries a child id? | can rewrite what the parent model reads? |
|---|---|---|
| `subagent_stop` | yes — `child_session_id` | **no** — return value ignored |
| `transform_tool_result` on `delegate_task` | **no** | yes |

The result entries the model receives are assembled at `delegate_tool.py:2404-2408` with
`task_index`, `status`, `summary`, `duration_seconds`. `_child_role` and `_child_cost_usd`
are `pop`ped off before the model sees them (`:2706-2707`), and **no child session id is
ever placed in the result**. So the hook that knows the identity cannot speak, and the
hook that can speak does not know the identity.

Matching them by iteration order is possible in principle — `subagent_stop` fires per
result entry inside `_execute_and_aggregate` — but positional correlation across two
independent hook streams is exactly the kind of inference that produces a confident wrong
attribution. Not done, deliberately.

### Status

Layer 7 attribution is **uncovered on Hermes 0.20.0**, and the blocker is upstream, not in
this adapter. Isolation is covered by the distinct child session id. Revisit if a future
release either puts a child identifier in the `delegate_task` result or honours a return
value from `subagent_stop`.

## Known cost: a NOTE carries the whole result back

Claude delivers a NOTE in `systemMessage` and leaves the result untouched. Hermes has no
field beside the result, so the only non-destructive way to say anything is to append to
content the scan already cleared — which means the entire cleared result travels back
through the hook as the replacement string.

Measured against the built CLI: an 800,000-byte clean-but-truncated result returns an
800,046-byte string. That is not amplification — the model was going to read those bytes
either way — but it is a real per-call cost on large results that the other two hosts do
not pay, and it lands on the same latency budget the adapter has to meet. Locked in by
`hermes_conformance.rs::a_note_appends_its_receipt_instead_of_replacing_the_result`.

The alternative — dropping the notice and returning `None` — was rejected: it would make
a truncated result indistinguishable from a complete one.

## Still unknown

- Behaviour under a **slow** hook: no timeout was found around `invoke_hook`. A hook that
  blocks appears to block the agent loop indefinitely. The adapter must therefore own its
  own deadline, as the Claude and Codex adapters already do.
- Whether hook ordering across multiple plugins is stable beyond "registration order".
- The gateway and subagent paths (`subagent_start` / `subagent_stop`) have not been
  examined; Layer 7 attribution for Hermes is not covered by this fixture.
