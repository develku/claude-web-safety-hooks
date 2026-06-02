<p align="center">
  <img src="attachments/logo.png" alt="Claude Web Safety Hooks" width="600">
</p>

# Claude Web Safety

<p align="center">
  <a href="https://github.com/develku/claude-web-safety-hooks/actions/workflows/tests.yml"><img src="https://github.com/develku/claude-web-safety-hooks/actions/workflows/tests.yml/badge.svg" alt="tests"></a>
</p>

Defense-in-depth hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that protect against **prompt injection from web content**. Distributed as a Claude Code plugin.

When Claude Code fetches web pages or searches the web, the returned content could contain hidden instructions designed to manipulate Claude's behavior. These hooks screen URLs before fetching, scan returned content against 600+ injection patterns across 8 evasion-resistant views, and surgically redact attacks before Claude sees them.

## How it works

Six layers, each documented in [docs/patterns.md](docs/patterns.md):

| Layer | When | What |
|---|---|---|
| **1. URL pre-screening** | PreToolUse | Block dangerous schemes, SSRF targets, IP addrs, credential leaks, open redirects, high-risk TLDs |
| **2. Severity-tiered scanner** | PostToolUse | 600+ patterns across HIGH/MEDIUM/LOW; 8 evasion views (whitespace, HTML entities, punctuation, Unicode confusables, URL-decoded, tag-stripped) |
| **3. Content sanitization** | PostToolUse | HIGH = full redaction; MEDIUM = surgical line-by-line; output capped at 50KB |
| **4. Cross-tool correlation + reassembly** | PostToolUse | 5-min window; 3+ flagged tools auto-escalate MEDIUM → HIGH. **v6.0+ also detects payloads split across multiple fetches** (`Part 1/3: ignore` + `Part 2/3: previous` + `Part 3/3: instructions` → reassembled match) |
| **5. Structural verification** | PostToolUse | Code-fence / YAML / JSON / HTML-code / inline-code aware — clears false positives like `assistant:` inside doc snippets without bothering the user |
| **6. Outbound exfiltration guard** | PreToolUse (Bash + web-fetch) | When a HIGH injection was flagged in this session in the last 5 min, escalates outbound data flows to a user confirmation — breaking the inject→exfil chain. Covers network-egress Bash commands (`curl`/`wget`/`scp`/`rsync`/`ssh`/`nc`/`socat`/`/dev/tcp`/inline `python -c`/`node -e`) **and** web-fetch tools (a fetch to a non-allowlisted host while armed — the most natural post-injection exfil). Trusted destinations via `url-allowlist.txt`, but an *upload* to an allowlisted host is not exempted; kill switch `WEB_SAFETY_EGRESS_GUARD_DISABLE=1` |

## Architecture

The plugin is pure shell — no daemon, no dependencies beyond `jq`/`perl`/`shasum`. `hooks/hooks.json` wires each script to a Claude Code tool event; the scripts communicate through session-scoped files in `/tmp`.

```
web-safety/
├── hooks/hooks.json                  # wires scripts → tool events (matchers below)
├── scripts/
│   ├── web-safety-approve.sh         # Layer 1   — PreToolUse(web)  URL pre-screen
│   ├── web-safety-scanner.sh         # Layers 2–5 — PostToolUse(web) scan + sanitize; arms Layer 6
│   ├── web-safety-egress.sh          # Layer 6   — PreToolUse(Bash) outbound exfiltration guard
│   ├── web-safety-verify-context.sh  # Layer 5   — structural-verification helper
│   ├── web-safety-listctl.sh         # backs /web-safety-allow + /web-safety-block
│   └── web-safety-report.sh          # backs /web-safety-report
├── commands/                         # 3 user-invoked slash commands (auto-discovered)
├── tests/                            # 3 suites · 167 cases · Linux+macOS CI
└── docs/                             # patterns.md, tuning.md, design specs
```

### Hook wiring

| Event | Matcher | Script | Layer(s) |
|---|---|---|---|
| **PreToolUse** | `WebFetch` / `WebSearch` / MCP web tools | `web-safety-approve.sh` → `web-safety-egress.sh` | 1, 6 |
| **PreToolUse** | `Bash` | `web-safety-egress.sh` | 6 |
| **PostToolUse** | `WebFetch` / `WebSearch` / MCP web tools | `web-safety-scanner.sh` (10s timeout) | 2–5 (+ arms 6) |

Layer 6 runs on the web matcher as well as `Bash` (since v7.5.0): while armed, an outbound fetch to a non-allowlisted host is escalated just like a Bash egress command.

### Runtime data flow

Hooks are short-lived processes with no shared memory, so cross-step state lives in session-keyed `/tmp` files (keyed on `${CLAUDE_SESSION_ID:-$PPID}`, so one session never affects another):

```
 fetch requested
      │
      ▼  PreToolUse(web)
 [Layer 1] approve.sh ── block dangerous URL / pass ──► fetch runs
                                                          │
                                                          ▼  PostToolUse(web)
                            [Layers 2–5] scanner.sh ── scan · sanitize · correlate
                                   │ writes
                                   ├─► /tmp/web-safety-session-<id>-state      (hit log → Layer 4 escalation)
                                   ├─► /tmp/web-safety-session-<id>-fragments  (split-payload reassembly → Layer 4)
                                   └─► /tmp/web-safety-session-<id>-armed       (timestamp, on HIGH → arms Layer 6)
                                                          │
 later: a Bash command OR a web fetch ──► PreToolUse(Bash/web)  │ reads
                            [Layer 6] egress.sh ───────────────────┘
                                   armed + egress/outbound-fetch + non-allowlisted host → permissionDecision:"ask"
```

User-side config and audit live under `~/.claude/hooks/`: `url-allowlist.txt`, `url-blocklist.txt`, and the append-only `web-safety.log`.

## Install

```
/plugin marketplace add develku/claude-web-safety-hooks
/plugin install web-safety@develku
/reload-plugins
```

That's it. The matchers cover `WebFetch`, `WebSearch`, and a wide set of MCP web tools (Playwright, Puppeteer, Firecrawl, Exa, Context7, MCP Docker variants).

## Quick start

```bash
# (Optional) add a URL allowlist to skip the soft-block checks on trusted domains
mkdir -p ~/.claude/hooks
echo "github.com" >> ~/.claude/hooks/url-allowlist.txt
echo "anthropic.com" >> ~/.claude/hooks/url-allowlist.txt

# (Optional) add a URL blocklist
echo "malware-distribution.example.com" >> ~/.claude/hooks/url-blocklist.txt

# Trigger a test
# Ask Claude: "fetch https://blog.cyberdesserts.com/prompt-injection-attacks/"
# You should see a macOS notification (Basso/Sosumi/Ping per severity) and Claude pauses.

# Check the audit log
tail -20 ~/.claude/hooks/web-safety.log
```

See [docs/tuning.md](docs/tuning.md) for environment variables, severity tuning, allowlist/blocklist details, and false-positive workflow.

## Commands

Three slash commands ship with the plugin (auto-discovered on install). All are user-invoked only (`disable-model-invocation: true`) and run through the helper scripts above:

| Command | Args | What |
|---|---|---|
| `/web-safety-report` | `[days]` | Markdown summary of the audit log — counts by severity, top tools, top hosts, recent events. Optional day window. Read-only; never mutates the log. |
| `/web-safety-allow` | `<domain>` | Validate + append a trusted domain to `url-allowlist.txt`. Relaxes **soft** blocks only (high-risk TLD, custom blocklist) — hard blocks (SSRF/internal targets, IPs, dangerous schemes, credentials-in-URL) still apply. |
| `/web-safety-block` | `<domain>` | Validate + append a domain to `url-blocklist.txt` — rejected before any fetch. |

## Requirements

- Claude Code CLI
- `jq`, `bash` 3.2+, `perl`, `shasum`
- macOS for desktop notifications (scanner itself is cross-platform)

## Update log

Full per-version detail in [CHANGELOG.md](CHANGELOG.md). Recent releases:

- **7.7.0** — Minor roll-up completing a 15-finding review: leetspeak loop now reports every obfuscated pattern (not just the first), escalation tool list renders with a real `, ` separator, `listctl` add is atomic, the `SESSION_STATE` prune is lock-guarded, and the allowlist honors a final entry without a trailing newline.
- **7.6.0** — Closed two HIGH false-negatives: base64 detection strengthened (CR/LF-stripping, lower threshold, decode-vs-real-patterns) and cross-call reassembly evasions (head+tail excerpt, completing-fragment capture, full 14-category lexicon). Affix index made per-word + fired-set de-dup after the gate found an FP-storm.
- **7.5.0** — Layer 6 now also guards the **web-fetch** channel (fetch to a non-allowlisted host while armed) and adopts the shared host library; upload-aware allowlist (an upload *to* an allowlisted host is no longer exempt).
- **7.4.0** — Object-shaped `tool_response` is now scanned, broadened MCP tool matcher, false-positive fixes, and audit-log→report injection closed (control-char-stripped URLs, backtick neutralization).
- **7.3.0** — Closed an SSRF pre-screen bypass (decimal/hex/octal-IP, userinfo, `*.internal`, metadata hosts via a canonical host normalizer), a large-input fail-open (input cap + truncation note), a no-op hex HTML-entity decode, and a verifier regex flaw that auto-cleared genuine `[INST]` injections; test harness hardened.
- **7.2.0** — macOS notifications now show the cause (matched patterns / outbound command / blocked URL) in the body + subtitle instead of generic text; osascript sanitizer hardened to strip backslashes (display-only, detection unchanged).
- **7.1.0** — Layer 6 hardening from an adversarial stress test (~130 vectors): fixes an interpreter-flag evasion (`python3 -u -c …`) and a path-component false positive (`ls ~/.ssh/`), expands coverage (`rsync`, `ssh`, `socat`, `telnet`, `openssl s_client`, `/dev/tcp`); egress suite → 50 cases.
- **7.0.0** — Layer 6 outbound exfiltration guard: PreToolUse(`Bash`) hook escalating egress to a confirmation after a HIGH injection flag, breaking the inject→exfil chain.
- **6.3.1** — fix: slash-command `${CLAUDE_PLUGIN_ROOT}` brace-substitution.
- **6.3.0** — slash commands (`/web-safety-report`, `/web-safety-allow`, `/web-safety-block`) + cross-platform CI test matrix.
- **6.2.0** — plugin-only installation; manual install path removed.
- **6.1.1** — confusable-letter bridge fix from stress testing.
- **6.1.0** — letter-boundary + affix-only limitation closures.
- **6.0.0** — cross-call payload reassembly (E8).

## Tests

```bash
./tests/run-tests.sh        # scanner — 47 cases
./tests/run-cmd-tests.sh    # command helpers — 49 cases
./tests/run-egress-tests.sh # Layer 6 egress guard — 71 cases
```

47 scanner cases (single-fetch payloads + multi-fetch reassembly sequences + enforcement / large-input / performance assertions) across HIGH/MEDIUM/LOW/legit/reassembly buckets, covering all 8 evasion views, base64-encoded payloads, hex/decimal HTML-entity decoding, Layer-5 false-positive guards, multi-pattern HIGH combinations, ordering-token reorder attacks, cross-session isolation, letter-boundary and tail-split reassembly, already-fired suppression, 3-char affix-only fragments, confusable-letter bridges, multi-technique leetspeak, and a 256 KB-page performance budget. A second suite (`run-cmd-tests.sh`) covers the report and allow/block helper scripts — including atomic/concurrent list adds, allowlist normalization, and SSRF hard-block classes through the pre-screen. A third (`run-egress-tests.sh`) covers the Layer 6 outbound exfiltration guard across **both** the Bash and web-fetch channels — arm-state production, the ask/defer decision, allowlist exemption and upload-aware non-exemption, session isolation, and path-qualified-binary boundary cases. All three run in CI on a Linux + macOS matrix. See [tests/README.md](tests/README.md).

## License

[MIT](LICENSE).
