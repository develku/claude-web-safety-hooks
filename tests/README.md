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

The cross-platform notification dispatcher has its own suite, [run-notify-tests.sh](run-notify-tests.sh), which stubs `uname` (to drive platform detection deterministically on any host) plus `notify-send`/`osascript`/sound players via `PATH`, so it exercises the macOS and Linux paths identically on both CI legs without firing a real notification.

Layer 7 multi-agent visibility has its own suite, [run-agent-tests.sh](run-agent-tests.sh): it injects `agent_id`/`session_id` into the scanner's stdin envelope to simulate subagent context (kill ledger row + egress arming + per-agent escalation scoping, including a two-scanners-in-parallel atomic-recount case), and drives `web-safety-agent-result.sh` / `web-safety-stop-gate.sh` directly with seeded ledger rows (join, freshness, session filters, one-shot and `stop_hook_active` contracts).

Layer 8 Bash-fetch scanning has its own suite, [run-bash-scan-tests.sh](run-bash-scan-tests.sh): it drives the routing gate [`web-safety-bash-scan.sh`](../scripts/web-safety-bash-scan.sh) with `{tool_name:"Bash", tool_input:{command}, tool_response}` envelopes. The core discriminator is that identical injection-bearing stdout HALTS when the producing command is fetch-shaped (`curl`/`wget`/`aria2c`/HTTPie/text-browsers) but is NEVER scanned when it is not (`cat`/`ls`/`grep`/`echo`) — proving the gate routes on command shape, not output content. It also asserts the `is_fetch_command` false-positive guards (substring `mycurl`, path component `~/.curlrc`, excluded `git pull`; path-qualified `/usr/bin/curl` and quoted `'curl'` still match), that the URL allowlist does not suppress the content scan, halt mode-independence, the subagent `[PENDING-KILLED]` ledger row + Layer-6 arming, and degenerate empty inputs.
