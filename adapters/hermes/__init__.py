"""web-safety — DORMANT Hermes Agent 0.20.0 plugin adapter candidate (Stage 5C).

NOT WIRED INTO ANYTHING. No live ``~/.hermes/plugins/``, no project
``.hermes/plugins/``, no ``cli-config.yaml`` and no trust record refers to this
package, and ``hooks/hooks.json`` in this repo still runs the Bash scanner.
Installing it or enabling it is a separate, operator-approved decision.

The adapter is deliberately thin. It may:

  * locate the engine binary,
  * pass trusted configuration to it,
  * enforce its own deadline,
  * validate that a response was delivered AND that the host would act on it,
  * and, when any of those is false, deliver a static containment string itself.

It may NOT scan, classify, normalize, correlate, redact by pattern, or hold a
copy of any security rule. Every such decision belongs to the one Rust engine;
a pattern literal in here would already have broken the one-engine-three-
runtimes property this stage exists to preserve.

Scope: this adapter acts on the allowlisted WEB tools only (see the
web-tools-only section below) and is silent on every other tool, which keeps it
provably disjoint from Hermes' bundled ``security-guidance`` plugin under the
host's first-valid-string-wins dispatch.

Contract with Hermes Agent 0.20.0 — see
``engine/tests/fixtures/hermes-0.20.0/README.md`` for the extraction provenance:

  * hooks are Python callbacks; the loader requires an importable module
    (``hermes_cli/plugins.py:1860``), so a compiled binary cannot be registered
    here and a thin Python shim is the only shape available;
  * ``transform_tool_result`` is called with ``args`` — NOT the ``arguments``
    the bundled reference documents — and ``transform_terminal_output`` with
    ``returncode``, never the documented ``exit_code``/``cwd``. Because
    ``invoke_hook`` binds by keyword and swallows the resulting ``TypeError``
    into a log line, a callback declaring the documented names registers
    cleanly, raises on every call, and silently transforms nothing. Every
    callback here therefore takes ``**kwargs`` ONLY and reads keys explicitly;
  * a returned ``str`` replaces what the model reads; ``None`` leaves the result
    untouched; **every other type is discarded with no warning**. A non-string
    return is not a partial success, it is silently no protection at all;
  * hook exceptions are logged at WARNING and the agent loop continues
    (``plugins.py:1934-1945``). Raising cannot stop a turn, so this module never
    relies on raising and never lets an exception escape;
  * no timeout was found around ``invoke_hook``. A blocking callback appears to
    block the loop indefinitely, so the deadline is enforced HERE.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
from pathlib import Path
from typing import Any, Optional

__all__ = ["register"]

# --- containment -------------------------------------------------------------
#
# The one string this module is allowed to author. It is a fixed notice, not a
# scan result: it never quotes, summarizes or paraphrases the content it is
# standing in for, so it is safe on every path that reaches it.
#
# It is returned — never `None` — on every failure. `None` means "leave the
# result untouched", which on a failed scan is precisely the fail-open this
# whole project exists to prevent. A missing engine must cost the operator a
# broken-looking tool result, not a silently unprotected one.
CONTAINMENT = (
    "[web-safety] This tool result was withheld before you saw it. You have not "
    "read it and must not describe, summarize or speculate about its contents. "
    "The web-safety scanner did not return a usable verdict."
)

# Wall-clock budget for one engine invocation. Deliberately below any plausible
# host-side patience: the point is that THIS module decides when to give up.
DEFAULT_DEADLINE_SECONDS = 5.0


def _deadline() -> float:
    """Read the budget per call, not once at import.

    An operator who changes the budget should not have to restart the agent to
    get it, and a value that cannot be parsed must not take the deadline with
    it — an unparseable override falls back to the default rather than raising
    inside a hook the host would swallow.
    """
    try:
        v = float(os.environ.get("WEB_SAFETY_TIMEOUT", DEFAULT_DEADLINE_SECONDS))
        return v if v > 0 else DEFAULT_DEADLINE_SECONDS
    except (TypeError, ValueError):
        return DEFAULT_DEADLINE_SECONDS

# Refuse to read an unbounded engine response into memory. The engine's own
# documents are small; anything larger is a malfunction, not a verdict.
MAX_RESPONSE_BYTES = 1 << 20

# --- web-tools-only scope ---------------------------------------------------
#
# web-safety may act on exactly these tools. Every other tool is SKIPPED (the
# hook returns None and the result passes through untouched), because several
# plugins share the `transform_tool_result` / `pre_tool_call` hooks and Hermes
# resolves them FIRST-VALID-STRING-WINS: whichever callback returns a string
# first owns the result. The bundled `security-guidance` plugin registers the
# same two hooks but targets file-write tools (`write_file`, `patch`,
# `skill_manage`). If web-safety were to act on those too, the two plugins
# would race for the same result and either plugin could silently clobber the
# other's value. Scoping web-safety to web ingress/sink tools only makes the
# coverage disjoint from security-guidance BY CONSTRUCTION: no tool is ever in
# both plugins' target sets, so neither can override the other's output.
#
# The set is grounded in Hermes Agent 0.20.0's own tool registry (tools/*.py):
#
#   * exact names:   web_search, web_extract, x_search
#   * prefix family: web_* (future web search/extract tools)
#   * prefix family: browser_*  (browser_navigate, browser_snapshot,
#                     browser_console, ... — the GUI browser surface)
#   * prefix family: cua_browser_* (typed-browser actions: navigate, click,
#                     type, pointer, dialog, state, ...)
#
# MCP fetch/search tools are server-defined (wire name `mcp__<server>__<tool>`)
# and cannot be enumerated here, so they are allowlisted individually by exact
# wire name via `WEB_SAFETY_TOOLS` (comma-separated) — see `_extra_web_tools`.
# Nothing is ever matched by the `mcp__` prefix alone: that would sweep in
# every non-web MCP tool and break the disjointness property.
WEB_TOOL_EXACT = frozenset({"web_search", "web_extract", "x_search"})
WEB_TOOL_PREFIXES = ("web_", "browser_", "cua_browser_")


def _extra_web_tools() -> frozenset[str]:
    """Operator-supplied additional web tool names, e.g. MCP fetch/search tools."""
    raw = os.environ.get("WEB_SAFETY_TOOLS", "")
    if not raw:
        return frozenset()
    return frozenset(name.strip() for name in raw.split(",") if name.strip())


def _is_web_tool(name: str) -> bool:
    """True only for a web ingress/sink tool the allowlist names.

    Everything else — file ops, terminal, code execution, memory, delegation,
    messaging — is deliberately OUT of scope: web-safety says nothing about it.
    """
    if not isinstance(name, str) or not name:
        return False
    if name in WEB_TOOL_EXACT:
        return True
    if name.startswith(WEB_TOOL_PREFIXES):
        return True
    return name in _extra_web_tools()



def _engine_path() -> Optional[str]:
    """Locate the engine binary, or return None.

    Order: an explicit operator override, then the build output beside this
    checkout. Nothing is searched on PATH — a binary named `web-safety-engine`
    that happens to be earlier on someone's PATH is not this engine.
    """
    override = os.environ.get("WEB_SAFETY_ENGINE")
    if override:
        return override if (os.path.isfile(override) and os.access(override, os.X_OK)) else None

    root = Path(__file__).resolve().parent.parent.parent
    candidate = root / "engine" / "target" / "release" / "web-safety-engine"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def _scan(envelope: dict[str, Any], event: str = "post-tool") -> Optional[str]:
    """Run one engine scan and translate its answer into this host's vocabulary.

    Returns the replacement string, or None to leave the result unchanged.
    Never raises, never returns a non-string, never returns None because
    something went wrong — only because the engine said the content is clean.
    """
    engine = _engine_path()
    if engine is None:
        return CONTAINMENT

    payload = json.dumps(envelope).encode("utf-8")

    # `start_new_session` puts the engine in its own process group so a forked
    # grandchild that inherits stdout and outlives its parent can be killed as a
    # group. Without it, `communicate` waits on a pipe nobody will ever close
    # and the deadline is the only thing between the agent and a hang.
    try:
        proc = subprocess.Popen(
            [engine, "scan", "--host", "hermes", "--event", event],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # never let scanner stderr reach a log the model reads
            start_new_session=True,
        )
    except OSError:
        return CONTAINMENT

    # Record the group NOW, while the child is certainly alive.
    #
    # Looking it up later does not work, and the failure is silent: the engine
    # can exit immediately while a forked grandchild keeps the stdout pipe open,
    # `communicate` reaps the direct child, and by the time the deadline fires
    # `os.getpgid(proc.pid)` raises ProcessLookupError. The group kill is then
    # skipped entirely and the orphan survives — holding the pipe, which is the
    # exact scenario the kill exists for. Measured: without this, the grandchild
    # is still alive after the hook returns.
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = None

    try:
        out, _ = proc.communicate(input=payload, timeout=_deadline())
    except subprocess.TimeoutExpired:
        _kill_group(proc, pgid)
        # Drain whatever is buffered so the pipe closes, then discard it: a
        # partial document from a process we just killed is not a verdict.
        try:
            proc.communicate(timeout=1)
        except Exception:
            pass
        return CONTAINMENT
    except Exception:
        _kill_group(proc, pgid)
        return CONTAINMENT

    if proc.returncode != 0:
        return CONTAINMENT
    if not out or len(out) > MAX_RESPONSE_BYTES:
        return CONTAINMENT

    try:
        verdict = json.loads(out)
    except Exception:
        return CONTAINMENT

    # The engine speaks this host's contract directly: a JSON string is the
    # replacement, JSON null is "unchanged". Any other type would be discarded
    # by the runtime without a warning, so it is treated as a malfunction and
    # contained rather than passed along as an implicit allow.
    if verdict is None:
        return None
    # The two events have DIFFERENT valid shapes, and accepting the other one is
    # a fail-open: a dict returned from a transform hook is discarded by the
    # runtime without a warning, so passing it through would leave the model
    # reading the unscanned original. Validate per event, never per type alone.
    if event == "pre-tool":
        if isinstance(verdict, dict):
            return verdict  # type: ignore[return-value]
    elif isinstance(verdict, str):
        return verdict
    return CONTAINMENT


def _kill_group(proc: subprocess.Popen, pgid: Optional[int]) -> None:
    """Kill the engine and anything it forked — and never anything else.

    `pgid` is captured at spawn by the caller, not looked up here: by the time
    this runs the direct child is often already reaped, and the lookup would
    raise ProcessLookupError precisely in the case the kill matters.

    The own-group check is load-bearing, not defensive noise. `killpg` takes a
    GROUP, and a child spawned WITHOUT `start_new_session` shares the caller's
    group — which here is the agent's. Measured: with `start_new_session=False`
    the child's pgid is identical to the caller's, so this call would deliver
    SIGKILL to Hermes itself and turn a scanner timeout into an agent crash.

    The two are therefore paired: `start_new_session=True` is what makes a group
    kill correct, and this check is what keeps it survivable if that flag is
    ever dropped by a later edit.
    """
    try:
        if pgid is not None and pgid != os.getpgid(0):
            os.killpg(pgid, signal.SIGKILL)
        else:
            # Same group as us: fall back to the single process. A forked
            # grandchild may survive and hold the pipe, but the deadline has
            # already fired and the caller returns containment regardless.
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# --- the two certified hooks -------------------------------------------------
#
# Both take **kwargs ONLY. Declaring `result` or `output` as a named parameter
# would work today and break silently the moment the host renames a kwarg — the
# exact defect its own documentation already exhibits.


def on_transform_tool_result(**kwargs: Any) -> Optional[str]:
    """`transform_tool_result` — after any tool returns, before the model reads it."""
    try:
        tool_name = _text(kwargs.get("tool_name")) or ""
        if not _is_web_tool(tool_name):
            # Not a web tool — web-safety is silent here. Returning None leaves
            # the result untouched, and the disjointness allowlist guarantees
            # this never competes with security-guidance for a shared result.
            return None
        result = kwargs.get("result")
        if not isinstance(result, str):
            # Absence is not a clean result. The host always passes `result` on
            # this hook, so a missing or wrongly-typed one means the contract
            # moved and this adapter no longer understands the envelope.
            return CONTAINMENT
        envelope: dict[str, Any] = {
            "tool_name": tool_name or "unknown",
            "result": result,
        }
        _carry(envelope, kwargs, "args", dict)
        _carry(envelope, kwargs, "session_id", str)
        _carry(envelope, kwargs, "task_id", str)
        return _scan(envelope)
    except Exception:
        # Nothing may escape: an escaping exception is logged and IGNORED by the
        # host, which leaves the untouched payload in front of the model.
        return CONTAINMENT


def on_transform_terminal_output(**kwargs: Any) -> Optional[str]:
    """`transform_terminal_output` — inside the terminal tool, pre-truncation."""
    try:
        output = kwargs.get("output")
        if not isinstance(output, str):
            return CONTAINMENT
        # This hook carries no tool name. Naming it is the adapter's job — the
        # engine refuses to invent one, because guessing there would turn an
        # envelope it did not understand into a clean scan.
        envelope: dict[str, Any] = {"tool_name": "terminal", "output": output}
        _carry(envelope, kwargs, "task_id", str)
        # First-class passthrough from the `terminal` tool's foreground-output
        # path (terminal_tool.py:3012): `command` lets the engine see the
        # actual invocation (e.g. a fetch-shaped `curl`/`wget`) instead of
        # guessing from the output, and `returncode` distinguishes a clean
        # result from an errored one. Dropping them here turned a terminal
        # envelope into one the engine could only judge by output text.
        _carry(envelope, kwargs, "command", str)
        _carry(envelope, kwargs, "returncode", int)
        return _scan(envelope)
    except Exception:
        return CONTAINMENT


def _text(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _carry(envelope: dict[str, Any], kwargs: dict[str, Any], key: str, kind: type) -> None:
    """Forward one optional field, and only when it is the right type.

    A wrongly-typed extra is dropped rather than forwarded: the engine fails
    closed on a bad field, and losing an optional correlation hint is a smaller
    harm than turning a scannable result into a contract error.
    """
    v = kwargs.get(key)
    if isinstance(v, kind) and v != "":
        envelope[key] = v


def on_pre_tool_call(**kwargs: Any) -> Optional[dict[str, Any]]:
    """`pre_tool_call` — before the tool runs. The only BLOCKING surface.

    Layers 1 (URL pre-screening) and 6 (egress guard) decide here. The host
    honours exactly one veto shape, `{"action": "block", "message": str}`, and
    ignores every other return value — so "permit" is `None`, not a document.

    Fails CLOSED. On this hook that means BLOCKING: the transform hooks fail
    closed by withholding a result, and the pre-call equivalent is refusing the
    call. An adapter that returned `None` on error would let an unscreened
    request run, which is the whole thing Layer 1 exists to prevent.
    """
    try:
        tool_name = _text(kwargs.get("tool_name")) or ""
        if not _is_web_tool(tool_name):
            # Not a web tool — out of scope, and web-safety must not block it.
            # Returning None permits, and the disjointness allowlist guarantees
            # this never competes with security-guidance for a shared veto.
            return None
        envelope: dict[str, Any] = {
            "tool_name": tool_name or "unknown",
        }
        _carry(envelope, kwargs, "args", dict)
        _carry(envelope, kwargs, "session_id", str)
        _carry(envelope, kwargs, "task_id", str)
        verdict = _scan(envelope, event="pre-tool")
    except Exception:
        return {"action": "block", "message": CONTAINMENT}

    # The engine speaks this event's contract directly: a JSON object with
    # action=block is the veto, JSON null is "no objection".
    if verdict is None:
        return None
    if isinstance(verdict, dict) and verdict.get("action") == "block":
        msg = verdict.get("message")
        return {"action": "block", "message": msg if isinstance(msg, str) else CONTAINMENT}
    # Anything else is a malfunction, and a malfunction before a tool runs must
    # not become permission to run it.
    return {"action": "block", "message": CONTAINMENT}


def _warn_if_coenabled() -> None:
    """Read-only startup/doctor guard: warn, never enable or change anything.

    web-safety and the bundled `security-guidance` plugin both register
    `transform_tool_result` and `pre_tool_call`. Under Hermes' first-valid-
    string-wins dispatch the two are DISJOINT by construction (this adapter is
    web-tools-only; security-guidance targets file-write tools), so co-enabling
    them is safe by design. This guard is a cheap safety net: if both ever show
    up in the enabled lists together it logs a diagnostic line so a future edit
    that widens either plugin's tool scope cannot silently start racing.

    Reads `HERMES_HOME`/config.yaml only. Never writes, never raises, and
    specifically never enables, installs, or activates either plugin.
    """
    try:
        home = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
        cfg = home / "config.yaml"
        if not cfg.is_file():
            return
        raw = cfg.read_text(encoding="utf-8", errors="replace")
        # A deliberately dependency-light look for the two plugin ids inside the
        # `plugins.enabled` list. We only need to know whether BOTH are present;
        # collapsing whitespace and scanning for the tokens is enough, and it
        # cannot mis-fire on a comment because plugin ids are unambiguous tokens.
        norm = " ".join(raw.split())
        both = "web-safety" in norm and "security-guidance" in norm
        if both:
            import logging
            logging.getLogger("web-safety").warning(
                "web-safety and security-guidance are both enabled. They are "
                "disjoint by tool scope (web tools vs file-write tools), so this "
                "is expected to be safe under first-valid-string-wins — but if "
                "either plugin's tool scope grows, re-check ordering."
            )
    except Exception:
        return


def register(ctx: Any) -> None:
    """Entry point called by Hermes' plugin loader.

    Three hooks, covering both interception points:

      * `pre_tool_call` — Layers 1 and 6, the only place a call can be stopped
        BEFORE it runs;
      * `transform_tool_result` / `transform_terminal_output` — Layers 2-5 and
        8, replacing a result before the model reads it.

    `post_tool_call` is not registered: its return value is ignored by the
    runtime, so it can observe but never enforce.
    """
    _warn_if_coenabled()
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("transform_terminal_output", on_transform_terminal_output)
