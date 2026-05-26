# Web safety scanner tests

Smoke harness for [scripts/web-safety-scanner.sh](../scripts/web-safety-scanner.sh). Each file in `payloads/` is fed to the scanner inside a synthetic `WebFetch` tool-result envelope and the detected severity is compared against the bucket encoded in the filename.

## Run

```bash
./tests/run-tests.sh
```

Exit code 0 = all pass. Exit code 1 = at least one failure (failed cases are listed). Exit code 2 = harness error (scanner missing, no payloads).

## Buckets

| Prefix | Expected outcome |
|---|---|
| `high-*` | Scanner emits `CRITICAL PROMPT INJECTION DETECTED [HIGH SEVERITY]` and halts |
| `med-*` | Scanner emits `PROMPT INJECTION WARNING [MEDIUM SEVERITY]` and pauses |
| `low-*` | Scanner emits `WEB CONTENT NOTE [LOW SEVERITY]` and continues |
| `legit-*` | No detection — either zero output or Layer-5 cleared |

## Adding a payload

Drop a `.txt` file under `payloads/` named with the right bucket prefix. The runner discovers it automatically on the next invocation.

## Why payloads live in this repo

These are public attack samples (the same patterns are documented in [docs/patterns.md](../docs/patterns.md) and dozens of jailbreak archives). They are required for regression coverage. If you install this plugin and Claude reads these files during routine work, the scanner will trigger on them — that's the intended behavior, not a bug. They are isolated under `tests/payloads/` so it's easy to add the directory to a downstream ignore list if needed.

## Isolation guarantees

Each test runs with a fresh `WEB_SAFETY_CONFIG_DIR` (so logs don't bleed across cases) and wipes `/tmp/web-safety-session-state` (so the 5-minute cross-tool escalation window doesn't poison later tests). `osascript` is stubbed via `PATH` so macOS notifications stay quiet during the run.
