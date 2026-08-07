#!/usr/bin/env python3
"""web-safety Hermes adapter — diagnostic (doctor).

An out-of-band counterpart to the dormant adapter in this directory. The
adapter fails CLOSED: when the engine is missing, not executable, times out,
or returns anything the host would discard, every web tool result becomes the
fixed CONTAINMENT string (`__init__.py:65-69`). The containment string is
deliberately uniform and never says *why* — a self-describing string would be
a fail-open leak (`docs/engine-distribution.md`). So the *why* lives here, in
a command the operator runs on purpose, never in a tool result.

The doctor reproduces the adapter's exact engine resolution
(`_engine_path()`, `__init__.py:150-165`) and enumerates, in resolve order,
every failure mode the adapter can hit — the M1-M5 table from
`docs/engine-distribution.md` — pairing each with an actionable remediation
(a shell command), never a bare "engine missing."

Run (no install, no registry, no `~/.hermes` touched):

    python3 adapters/hermes/doctor.py

Honors the same environment the adapter does:

    WEB_SAFETY_ENGINE   explicit binary path (checked first)
    WEB_SAFETY_TIMEOUT  per-probe wall-clock budget, seconds (default 5)
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

# The engine's wire contract this adapter is compiled against. Must track
# `SCHEMA_VERSION` in `engine/src/contract.rs:17`. A mismatch is M5 (toolchain/
# contract drift): the wrong build answers in a shape the adapter does not
# understand, so every call fails closed for a reason that has nothing to do
# with the content being scanned.
EXPECTED_SCHEMA_VERSION = 1

# Default script location: <repo>/adapters/hermes/doctor.py.
_HERE = Path(__file__).resolve().parent

# Path to the adapter it diagnoses, and the module we load for the canonical
# resolution function. Loading it is side-effect free: `__init__.py` only
# defines functions and constants at import; `register` is never called.
_ADAPTER_INIT = _HERE / "__init__.py"


def _deadline() -> float:
    """Mirror the adapter's `_deadline()`: unparseable values fall back."""
    try:
        v = float(os.environ.get("WEB_SAFETY_TIMEOUT", "5"))
        return v if v > 0 else 5.0
    except (TypeError, ValueError):
        return 5.0


def _load_adapter() -> Any:
    """Import the adapter module out-of-band and return the module object.

    `adapters/` is not a package (no `__init__.py` there), so this loads the
    single file by path rather than relying on package imports. Importing
    registers nothing; it only makes `_engine_path()` and `CONTAINMENT`
    available as the single source of truth for this diagnostic.
    """
    spec = importlib.util.spec_from_file_location(
        "web_safety_adapter_dormant", _ADAPTER_INIT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot build import spec for {_ADAPTER_INIT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def default_engine_candidate() -> Path:
    """The in-tree build output the adapter would use when no override is set.

    Must reproduce `_engine_path()` (`__init__.py:161-162`) exactly:
    `__file__` -> parent.parent.parent -> engine/target/release/web-safety-engine.
    Because doctor.py lives beside `__init__.py` in `<repo>/adapters/hermes/`,
    the same parent.parent.parent walk yields the repo root.
    """
    return _HERE.parent.parent / "engine" / "target" / "release" / "web-safety-engine"


def _run(cmd: list[str], stdin_data: Optional[bytes] = None) -> dict[str, Any]:
    """Run one probe and return {rc, stdout, stderr, timeout, ran}."""
    result: dict[str, Any] = {"ran": False, "rc": None, "stdout": "", "stderr": ""}
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=_deadline(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["timeout"] = True
        return result
    except OSError as e:
        result["error"] = str(e)
        return result
    result["ran"] = True
    result["rc"] = proc.returncode
    result["stdout"] = proc.stdout.decode("utf-8", "replace")
    result["stderr"] = proc.stderr.decode("utf-8", "replace")
    return result


def probe_info(path: Path) -> dict[str, Any]:
    """Run `info`; return {ok, schema_version, version, reason} on success."""
    out = _run([str(path), "info"])
    if not out.get("ran"):
        return {"ok": False, "reason": f"could not execute: {out.get('error', '?')}"}
    if out.get("timeout"):
        return {"ok": False, "reason": f"timed out after {_deadline():g}s"}
    if out["rc"] != 0:
        return {
            "ok": False,
            "reason": f"exit {out['rc']}: {out['stderr'].strip() or out['stdout'].strip()[:200]}",
        }
    try:
        data = json.loads(out["stdout"])
    except ValueError as e:
        return {"ok": False, "reason": f"`info` stdout is not JSON: {e}"}
    if not isinstance(data, dict):
        return {"ok": False, "reason": "`info` did not return a JSON object"}
    return {
        "ok": True,
        "schema_version": data.get("schema_version"),
        "version": data.get("version"),
    }


def probe_scan(path: Path) -> dict[str, Any]:
    """Run one benign scan through the host the adapter speaks (hermes,
    post-tool) and check the response is one the adapter would accept.

    `_scan()` (`__init__.py:225-250`) accepts exactly two post-tool verdicts:
    a JSON `str` (the replacement, i.e. unchanged output) or JSON `null`
    (unchanged). Anything else — a dict, a number, malformed JSON, non-zero
    exit, timeout — is contained. So a healthy probe returns a parseable
    `str` or `null`.
    """
    envelope = json.dumps({"tool_name": "web_search", "result": "benign probe: the sky is blue"})
    out = _run([str(path), "scan", "--host", "hermes", "--event", "post-tool"], envelope.encode())
    if not out.get("ran"):
        return {"ok": False, "reason": f"could not execute: {out.get('error', '?')}"}
    if out.get("timeout"):
        return {"ok": False, "reason": f"timed out after {_deadline():g}s"}
    if out["rc"] != 0:
        return {"ok": False, "reason": f"exit {out['rc']}: {out['stderr'].strip() or out['stdout'].strip()[:200]}"}
    try:
        verdict = json.loads(out["stdout"])
    except ValueError as e:
        return {"ok": False, "reason": f"verify response is not JSON: {e}"}
    if not (verdict is None or isinstance(verdict, str)):
        return {"ok": False, "reason": f"unexpected verify shape ({type(verdict).__name__}); adapter would contain"}
    return {"ok": True, "verdict": verdict}


def main() -> int:
    lines: list[str] = []
    add = lines.append
    add("web-safety Hermes adapter — diagnostic")
    add("=" * 52)
    add(f"adapter module : {_ADAPTER_INIT}")
    add("status         : DORMANT (this checkout registers nothing)")

    # --- canonical resolution -------------------------------------------------
    try:
        adapter = _load_adapter()
    except Exception as e:  # pragma: no cover - defensive: the module is ours
        add("")
        add(f"ERROR: cannot load the adapter module to reproduce its resolution: {e}")
        add("The adapter and this doctor must live together in adapters/hermes/.")
        print("\n".join(lines))
        return 1

    override = os.environ.get("WEB_SAFETY_ENGINE")
    adapter_resolved = adapter._engine_path()
    default_candidate = default_engine_candidate()
    # Bound by the first probe block below; initialized so the M5 check at the
    # bottom can read it even if the static analysis cannot prove it was set.
    info: dict[str, Any] = {"ok": False}

    add(f"override       : WEB_SAFETY_ENGINE={'set' if override else 'unset'}")
    if override:
        add(f"  -> {override}")
    add(f"it would use   : {adapter_resolved or 'NOTHING (fail-closed)'}")
    add("")

    # --- resolve order (M1-first), exactly as `_engine_path()` does ----------
    step_ok = True
    if override:
        candidate = Path(override)
        add(f"M1  override path present & executable?  {candidate}")
        if not candidate.is_file():
            add("      FAIL - WEB_SAFETY_ENGINE points at a file that does not exist")
            add("      FIX  : unset it to fall back to the in-tree build:\n")
            add("             unset WEB_SAFETY_ENGINE")
            add("             # or point it at a real engine and re-run this doctor")
            step_ok = False
        elif not os.access(candidate, os.X_OK):
            add("      FAIL - the override is a file but not executable")
            add(f"      FIX  : chmod +x {candidate}")
            add("             # or unset WEB_SAFETY_ENGINE to use the in-tree build")
            step_ok = False
        else:
            add("      PASS")
    else:
        add(f"M2  in-tree build present?  {default_candidate}")
        if not default_candidate.is_file():
            add("      FAIL - the engine has not been built for this checkout")
            add("      FIX  : build it from the pinned toolchain:\n")
            add("             cd engine && cargo build --release")
            step_ok = False
        else:
            add("      PASS")
            add("M3  in-tree build executable?")
            if not os.access(default_candidate, os.X_OK):
                add("      FAIL - present but the exec bit is off")
                add(f"      FIX  : chmod +x {default_candidate}")
                step_ok = False
            else:
                add("      PASS")
        candidate = default_candidate

    # --- runtime probes for a candidate we could actually run -----------------
    if step_ok:
        add("")
        add("M4  `info` runs and speaks JSON?")
        info = probe_info(candidate)
        if not info["ok"]:
            add(f"      FAIL - {info['reason']}")
            add("      FIX  : rebuild the engine from the pinned Cargo.lock:\n")
            add("             cd engine && cargo build --release --locked")
            step_ok = False
        else:
            add(f"      PASS  (schema_version={info['schema_version']}, version={info['version']})")

    if step_ok and info.get("ok"):
        add("")
        add(f"M5  schema_version matches the adapter contract?  (expect {EXPECTED_SCHEMA_VERSION})")
        if info["schema_version"] != EXPECTED_SCHEMA_VERSION:
            add(f"      FAIL - engine speaks schema {info['schema_version']}; adapter expects {EXPECTED_SCHEMA_VERSION}")
            add("      FIX  : rebuild from the pinned toolchain/Cargo.lock; a version")
            add("             bump must land in engine/src/contract.rs deliberately:\n")
            add("             cd engine && cargo build --release --locked")
            step_ok = False
        else:
            add("      PASS")

    if step_ok:
        add("")
        add("M4  benign probe scan returns a verdict the adapter accepts?")
        scan = probe_scan(candidate)
        if not scan["ok"]:
            add(f"      FAIL - {scan['reason']}")
            add("      FIX  : rebuild the engine from the pinned Cargo.lock:\n")
            add("             cd engine && cargo build --release --locked")
            step_ok = False
        else:
            add(f"      PASS  (verdict={scan['verdict']!r})")

    # --- verdict ---------------------------------------------------------------
    add("")
    if step_ok:
        add("RESULT : HEALTHY")
        add("FIX    : none needed. The adapter will scan web tools through:")
        add(f"         {candidate}")
        if override:
            add("")
            add("Note   : WEB_SAFETY_ENGINE is set; the in-tree build is currently")
            add("         ignored. Unset it if you want the default build instead.")
    else:
        add("RESULT : FAIL - the adapter is failing CLOSED because the engine cannot")
        add("         be used. This is an OPERATIONS issue, not a scan finding: every")
        add("         web tool result is being replaced by the containment string")
        add("         regardless of content. Run the FIX above, then re-run this")
        add("         doctor. If the scan *does* find a threat after a HEALTHY check,")
        add("         that containment is correct and is not an engine fault.")

    print("\n".join(lines))
    return 0 if step_ok else 1


if __name__ == "__main__":
    sys.exit(main())
