#!/usr/bin/env python3
"""Generate the Codex CLI 0.144.1 PostToolUse fixture envelopes.

Two provenance classes, and the distinction is load-bearing — see README.md:

  * LIVE      — the key set, types and values were observed coming out of a real
                local `codex exec` 0.144.1 run against an offline mock provider
                (no credentials, no network, disposable CODEX_HOME). Values are
                redacted; SHAPE is exactly what the host emitted.
  * DERIVED   — built from the host's own `post-tool-use.command.input` JSON
                Schema, frozen under `schema/` by `extract-schemas.sh`. Field
                names, required set, types and the `permission_mode` enum are
                authoritative; the `tool_response` payload shape is inferred
                from the tool's contract and has NOT been observed live.

Every value is benign or synthetic. No credential, account, real path or
transcript from the capture machine is present.
"""
import json
import pathlib

DST = pathlib.Path(__file__).resolve().parent

SESSION = "00000000-0000-4000-8000-000000000001"
TURN = "00000000-0000-4000-8000-000000000002"
AGENT = "00000000-0000-4000-8000-000000000003"
CWD = "/fixture/project"
MODEL = "gpt-5.1-codex"

BENIGN_SHELL = (
    "Chunk ID: 000000\n"
    "Wall time: 0.0000 seconds\n"
    "Process exited with code 0\n"
    "Original token count: 10\n"
    "Output:\n"
    "README.md\nsrc\ntests\n"
)
BENIGN_PATCH = "Success. Updated the following files:\nM src/lib.rs\n"
BENIGN_MCP = "NOTICE\nThis document is benign fixture content.\nLine three of the notice.\n"
BENIGN_PLAN = "Plan updated.\n"


def envelope(tool, tool_input, tool_response, call, extra=None):
    """One envelope carrying exactly the schema's required set, plus `extra`.

    Keys are emitted sorted, which is also the order a live 0.144.1 envelope
    came back in, so a fixture diffs cleanly against both the schema's property
    listing and a fresh capture.
    """
    env = {
        "cwd": CWD,
        "hook_event_name": "PostToolUse",
        "model": MODEL,
        "permission_mode": "default",
        "session_id": SESSION,
        "tool_input": tool_input,
        "tool_name": tool,
        "tool_response": tool_response,
        "tool_use_id": call,
        # NullableString. Never read by the adapter or the engine; present
        # because the host marks it required. A live capture carried a real
        # rollout path here; it is redacted to a placeholder.
        "transcript_path": None,
        "turn_id": TURN,
    }
    env.update(extra or {})
    return dict(sorted(env.items()))


FIXTURES = {
    # LIVE. A `exec_command` call, which the host reports to the hook under the
    # Claude-compatible label `Bash` with a STRING `tool_input.command` — not
    # the `exec_command` / array shape the model-facing tool schema uses. That
    # normalization is exactly why a live capture was worth chasing.
    "bash-exec-main.json": envelope(
        "Bash",
        {"command": "ls -1"},
        BENIGN_SHELL,
        "call_00000000000000000001",
    ),
    # DERIVED from the live envelope above by adding the two OPTIONAL identity
    # fields the schema lists. Their optionality is the whole reason stateful
    # Codex correlation is refused without one — see README "Agent identity".
    # No live subagent capture was obtained, so this is derived, not observed.
    "bash-exec-subagent.json": envelope(
        "Bash",
        {"command": "ls -1"},
        BENIGN_SHELL,
        "call_00000000000000000002",
        {"agent_id": AGENT, "agent_type": "reviewer"},
    ),
    # DERIVED. `apply_patch` was not advertised in the captured tool list under
    # the unified-exec configuration used for capture, so its result shape is
    # inferred rather than observed.
    "apply-patch-main.json": envelope(
        "apply_patch",
        {"input": "*** Begin Patch\n*** Update File: src/lib.rs\n*** End Patch\n"},
        {"output": BENIGN_PATCH, "success": True},
        "call_00000000000000000003",
    ),
    # DERIVED. MCP tools are exposed under a NAMESPACE tool (`mcp__<server>`)
    # in this build, and a live nested MCP dispatch was not obtained — see
    # README "Live capture: what was and was not observed". The content-block
    # ARRAY below is the shape both hosts' MCP bridges emit.
    "mcp-content-array.json": envelope(
        "mcp__fixture__fetch_notice",
        {"url": "https://example.test/notice"},
        [{"type": "text", "text": BENIGN_MCP}],
        "call_00000000000000000004",
    ),
    # DERIVED. A local function tool whose `tool_input` is NOT an object —
    # legitimate, because 0.144.1 types `tool_input` as `true` (any JSON).
    "local-function-scalar-input.json": envelope(
        "update_plan",
        "refresh the plan",
        {"output": BENIGN_PLAN},
        "call_00000000000000000005",
    ),
    # LIVE (mode value). The capture ran under `approval_policy = "never"` +
    # `sandbox_mode = "danger-full-access"`, and the host reported
    # `permission_mode: "bypassPermissions"` — a real value from the closed
    # enum, observed rather than copied out of the schema.
    "bash-exec-bypass-permissions.json": envelope(
        "Bash",
        {"command": "ls -1"},
        BENIGN_SHELL,
        "call_00000000000000000006",
        {"permission_mode": "bypassPermissions"},
    ),
}

for name, env in FIXTURES.items():
    (DST / name).write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")
    print(f"wrote {name}")
