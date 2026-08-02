# Tuning

How to customise the scanner without forking it.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `HIGH_SEVERITY_ACTION` | `stop` | `stop` halts Claude; `warn` issues a strong warning and lets Claude continue |
| `VERIFY_CONTEXT_ENABLED` | `true` | `false` disables Layer 5 (revert to v5.1 behaviour — every `MED_GENERIC_DELIMITERS` match pages the user) |
| `WEB_SAFETY_CONFIG_DIR` | `~/.claude/hooks` | Where the audit log, blocklist, and allowlist live. Persists across plugin updates |
| `CLAUDE_PLUGIN_ROOT` | (set by Claude Code) | Plugin install location — scripts auto-resolve sibling paths from here. Don't set manually |
| `CLAUDE_SESSION_ID` | `$PPID` fallback | Scopes `/tmp/web-safety-session-*` files per Claude session. Set automatically by recent Claude Code versions. Override only for testing (each unique value = isolated state). |
| `WEB_SAFETY_DEFAULT_ALLOWLIST_DISABLE` | `0` | `1` disables the plugin-shipped Layer-6 default allowlist (`scripts/web-safety-default-allowlist.txt`), falling back to user-file-only exemption. See "Layer 6" below. |
| `WEB_SAFETY_SUGGEST_THRESHOLD` | `3` | Number of armed-window asks to the **same** host before the guard appends a one-shot `/web-safety:allow <host>` hint to the confirmation. Never auto-adds. |
| `WEB_SAFETY_SEARCH_QUARANTINE_DISABLE` | `0` | `1` restores the pre-8.12.0 behaviour where a lone MEDIUM on a subagent's `WebSearch` result **kills** that subagent instead of quarantining the result. See "WebSearch quarantine" below. |

Example — disable Layer 5 for a single session:

```bash
export VERIFY_CONTEXT_ENABLED=false
claude
```

Example — relocate user state (e.g., shared across machines via iCloud Drive):

```bash
export WEB_SAFETY_CONFIG_DIR="$HOME/Library/Mobile Documents/com~apple~CloudDocs/claude-hooks"
```

## URL allowlist

`$WEB_SAFETY_CONFIG_DIR/url-allowlist.txt` — one domain per line. Comments start with `#`. Suffix-matched **with a label boundary**: `github.com` matches `github.com` and `api.github.com`, but **not** `raw.githubusercontent.com` (a different registrable suffix) or `*.github.io` — each registrable suffix must be listed separately.

```
# trusted internal docs + public read-only sources
github.com
anthropic.com
docs.python.org
# our wiki
wiki.example.internal
```

The allowlist short-circuits **soft blocks only** — high-risk TLD and the custom blocklist. Hard blocks (SSRF, dangerous URI schemes, IP addresses, credentials in URL, oversized URLs, excessive encoding, cross-host open redirects) still apply because those are security primitives, not heuristics.

Since v8.11.0 the open-redirect block is **host-aware**: a redirect-ish parameter (`?url=`, `?redirect=`, `?next=`, …) only hard-blocks when its target host is foreign to the request host. A target that is the request host itself, or a subdomain of it, is not a bounce and passes (`youtube.com/oembed?url=youtube.com/watch`). A *parent*-domain target still blocks.

## URL blocklist

`$WEB_SAFETY_CONFIG_DIR/url-blocklist.txt` — same format as the allowlist. Substring-matched against the full URL.

```
malware-distribution.example.com
known-injection-host.example.net
```

## URL content-trust list

`$WEB_SAFETY_CONFIG_DIR/url-content-trust.txt` — one domain per line, same comment/blank-line format as the allowlist, **suffix-matched** (`example.com` covers `docs.example.com`).

This is the answer to the most common false positive: a security article that *quotes* an attack string (`ignore previous instructions`, `<|im_start|>`) in prose, which pattern-matching cannot tell apart from a real attack. For a host on this list the scanner still **detects**, but **downgrades the action**:

- does **not** halt Claude,
- does **not** redact — the original content passes through, so you can actually read the quoted attack strings,
- still writes a `[TRUST-DOWNGRADE]` line to the audit log (visible in `/web-safety-report`),
- still **arms the Layer 6 exfiltration guard** as a backstop, and
- fires a non-blocking desktop notification when it lets would-be-redacted patterns through.

```
# security blogs I read for research — quoted attack strings are descriptive
blog.cyberdesserts.com
embracethered.com
```

**This is not the allowlist.** `url-allowlist.txt` only relaxes the *soft URL pre-blocks* (high-risk TLD + custom blocklist) and never touches the content scan; `url-content-trust.txt` only changes the *content-scan action* and never relaxes a URL block. **Hard URL blocks** (SSRF/internal targets, direct IPs, dangerous schemes, credentials-in-URL) always apply regardless of either list.

**Trade-off:** the safety you keep on a content-trusted source is the Layer 6 egress confirmation, not redaction — a content-trusted domain that is compromised will have its injection content passed through unredacted. Only add sources you genuinely curate, and audit `[TRUST-DOWNGRADE]` events periodically via `/web-safety-report`.

## Slash commands

The plugin ships four commands, auto-discovered when installed:

| Command | What it does |
|---|---|
| `/web-safety-report [days]` | Markdown summary of the audit log — counts by severity, top tools, top hosts, recent events. Optional `[days]` limits the window (e.g. `/web-safety-report 7`). Read-only; never mutates the log. |
| `/web-safety-allow <domain>` | Validate and append a domain to the allowlist above. Idempotent. |
| `/web-safety-block <domain>` | Validate and append a domain to the blocklist above. Idempotent. |
| `/web-safety-trust <domain>` | Validate and append a domain to the content-trust list above — downgrades the content scan (no halt, no redaction) for that source while keeping the audit log + Layer 6 backstop. Idempotent. |

`allow` / `block` / `trust` accept a bare domain or a full URL (reduced to its host) and reject anything that isn't a valid hostname — so a malformed or shell-metacharacter entry can never reach the files the hooks read. The underlying helpers (`scripts/web-safety-report.sh`, `scripts/web-safety-listctl.sh`) also run standalone if you prefer the CLI:

```bash
scripts/web-safety-report.sh 7
scripts/web-safety-listctl.sh allow github.com
scripts/web-safety-listctl.sh trust blog.cyberdesserts.com
```

## Adding patterns

Edit `scripts/web-safety-scanner.sh` and append to the relevant severity array. The arrays are grouped by attack class so the right home is usually obvious from the section comment.

```bash
HIGH_LLM_TOKENS=( ... "your new control token" )
MED_INSTRUCTION_OVERRIDE=( ... "your new override phrase" )
LOW_HTML_CSS=( ... "your new hiding selector" )
```

After adding, add a representative payload to `tests/payloads/<bucket>-<descriptive-name>.txt` and run `./tests/run-tests.sh` to confirm the classification matches.

## Adding MCP server coverage

Append to both `matcher` strings in `hooks/hooks.json`:

```json
"matcher": "...existing matchers...|mcp__yournewserver.*"
```

The PreToolUse and PostToolUse matchers should always be kept in sync — one without the other leaves a coverage hole.

## Notification rate limiting

Default: 5 seconds between scanner notifications (debounce), on every platform. Adjust `RATE_LIMIT_SECONDS` near the top of `scripts/web-safety-scanner.sh`. (The PreToolUse URL pre-block and exfiltration-guard notifications are not rate-limited — they fire only on a hard block / armed-egress event.)

## Audit log

`$WEB_SAFETY_CONFIG_DIR/web-safety.log`, append-only. Format examples:

```
[2026-03-23 14:30:01] [HIGH] tool=WebFetch url=https://evil.com patterns="<|im_start|>", "<|im_end|>"
[2026-03-23 14:30:01] [SANITIZE] severity=high hash=70c5ee93d298... lines=42 tool=WebFetch
[2026-03-23 14:31:15] [MEDIUM] tool=Exa patterns="ignore previous instructions"
[2026-03-23 14:32:00] [ESCALATED] session_hits=3 prior_tools=WebFetch,Exa patterns="you are now"
[2026-03-23 14:32:00] [PRE-BLOCK] url=data:text/html;base64,... reason=dangerous URI scheme
[2026-03-23 14:33:00] [CLEARED] tool=WebFetch url=https://github.com/... pattern="assistant: " reason="inside code_fence" hash=8360aceb695f
[2026-03-23 14:34:00] [SCANNER-ERROR] grep failed severity=MEDIUM view=collapsed exit=2 err="grep: ..."
[2026-03-23 14:35:00] [TRUST-DOWNGRADE] tool=WebFetch url=https://blog.example.com/... would_be=HIGH host=blog.example.com patterns="<|im_start|>"
```

Entry types:
- `[HIGH] / [MEDIUM] / [LOW] / [ESCALATED]` — the scanner detected something
- `[SANITIZE]` — content was rewritten; includes SHA-256 of the original for forensic chain-of-custody
- `[PRE-BLOCK]` — URL pre-screening rejected the URL before fetching
- `[CLEARED]` — Layer 5 verifier auto-cleared a false positive (does NOT count toward escalation)
- `[TRUST-DOWNGRADE]` — the host is on `url-content-trust.txt`, so a `would_be` HIGH/MEDIUM was passed through unredacted (not halted); Layer 6 was still armed. Does NOT count toward escalation. Audit these to confirm your trust list isn't masking a real attack.
- `[PENDING-KILLED]` — a detection halted a **subagent** (k=v: `epoch= session= agent= severity= tool= url= patterns=`). The kill itself is the containment; this row is what makes it visible — it is what `web-safety-agent-result.sh` joins against to explain the death to the orchestrator and what the Stop gate surfaces to you at turn end. Layer 6 was armed at write time.
- `[QUARANTINED]` — a lone MEDIUM on a **subagent's `WebSearch`** result (k=v: `epoch= session= agent= severity= tool= hash= lines= patterns=`). The whole result was withheld and the agent kept running — no kill, and deliberately **not** a `[PENDING-KILLED]` row, since Layer 7 would otherwise report a death that never happened. Layer 6 was **not** armed (nothing reached the model). Counts toward escalation as a `Q` strike, but cannot escalate on its own. See "WebSearch quarantine" below.
- `[SCANNER-ERROR]` — internal error (malformed pattern, system issue); the scanner fails-closed and surfaces a synthetic HIGH-severity hit so the user is alerted

## False-positive workflow

If the scanner pauses you on legitimate content:

1. Check the audit log — note the matched pattern.
2. **If the pattern is in `MED_GENERIC_DELIMITERS`** (`assistant:`, `human:`, `<system>`, `[INST]`, `system: you are`) — confirm Layer 5 is enabled (`VERIFY_CONTEXT_ENABLED=true`). If the content is inside a code fence / YAML string / JSON value / HTML code block but you're still being paused, the verifier may be missing a structural pattern — file an issue with a minimal reproducer.
3. **If it's a security article quoting attack strings in prose** (the most common irreducible false positive — pattern-matching can't tell description from execution) — add the host to the content-trust list: `/web-safety-trust <domain>`. The scanner then passes that source through unredacted (no halt) while keeping the audit log + Layer 6 backstop. See "URL content-trust list" above.
4. **If the URL host is consistently trusted for soft blocks** — add it to the allowlist (relaxes the soft URL pre-blocks only; does *not* suppress content-scan hits — use content-trust for those).
5. **If a specific pattern is over-firing** — open `scripts/web-safety-scanner.sh`, find the pattern in its severity array, and either remove it or move it to a lower-severity array. Add a `legit-*` payload to `tests/payloads/` capturing the false-positive context so regression tests guard against re-adding it.

## Cross-tool escalation + reassembly tuning

The scanner escalates MEDIUM → HIGH when 3+ calls trigger injection warnings in a 5-minute window. The constants are `SESSION_WINDOW=300` (seconds) and the check `if [ "$SESSION_HITS_NOW" -ge 3 ] && [ "$SESSION_REAL_HITS_NOW" -ge 1 ]` in the MEDIUM branch — since v8 the count is recomputed under the state-file lock at append time (the old script-start read raced under parallel subagents), and strikes are scoped **per agent** when the hook input carries `agent_id` (so independent fan-out agents don't pool their false positives into a fleet-wide ESCALATED; without `agent_id` the v7 whole-session scope applies). Tighten by lowering the threshold; loosen by raising the window. The E8 fragment store stays session-wide regardless — split-payload reassembly is cross-agent content evidence.

Since v8.12.0 the state file's rows carry a status letter — `H` (hit), `C` (auto-cleared false positive), `Q` (quarantined, see below) — and `Q` rows carry a content hash as a 5th field. Two counters come out of the same locked recount: `SESSION_HITS_NOW` is the strike total with `Q` rows **collapsed by hash**, and `SESSION_REAL_HITS_NOW` counts `H` rows only. Escalation requires the second to be ≥ 1, so a window containing nothing but quarantines never escalates — the 3-strike rule is a claim about repeated *model exposure*, and a quarantined result exposed the model to zero bytes. One genuine delivered hit re-arms the whole rule.

## WebSearch quarantine

A lone MEDIUM on a **subagent's** `WebSearch` result does not kill that subagent. The entire result is replaced with a neutral placeholder and the agent continues; the finding keeps its MEDIUM severity, its `[MEDIUM]` audit line, its correlation strike, and its desktop notification, and additionally logs a `[QUARANTINED]` row.

This exists because `WebSearch` is untunable by design. `TOOL_URL` is parsed from `.tool_input.url`, a WebSearch carries `.query`, and **both** `url-allowlist.txt` and `url-content-trust.txt` are host-keyed — so `host_is_content_trusted()` can never fire for a search and there is no per-source escape hatch. Every false positive there cost a subagent, which is why 20 of 27 recorded kills were WebSearch.

Unchanged on purpose: `WebFetch`, the main session (its halt is the one a human actually reads), and HIGH at any tool. Set `WEB_SAFETY_SEARCH_QUARANTINE_DISABLE=1` to restore the kill.

Note that capping the tier instead — treating a lone WebSearch MEDIUM as LOW — is **not** an equivalent relaxation and should not be attempted as a shortcut: the LOW branch emits no `toolResult` at all, so it would pass the suspect content through untouched *and* leave the agent running to act on it. In this scanner the severity tier is also the redaction switch.

Session state is stored at `/tmp/web-safety-session-${SESSION_ID}-state` (correlation; `/tmp/web-safety-session-${SESSION_ID}-agent-<agent_id>-state` inside subagents) and `/tmp/web-safety-session-${SESSION_ID}-fragments` (E8 reassembly excerpts). Both are scoped per Claude Code session via `CLAUDE_SESSION_ID` (or `PPID` fallback). Wipe manually for a clean slate:

```bash
rm -f /tmp/web-safety-session-*-state /tmp/web-safety-session-*-fragments
```

Reassembly (E8) constants near the top of the scanner:

| Constant | Default | Effect |
|---|---|---|
| `E8_MAX_FRAGMENTS` | 20 | FIFO cap on stored fragments per session |
| `E8_EXCERPT_SIZE` | 1500 | Max bytes per stored fragment (head of lowercased input) |
| `E8_TOTAL_CAP_KB` | 48 | Soft cap for total store size |
| `E8_ORDERING_REGEX` | `(part \d+( of \|/)\d+\|step \d+\|...)` | Pattern that activates label-sorted reassembly |

## Performance

Benchmarked on 50 KB pages, Apple Silicon:

| Component | Time | Token cost |
|---|---|---|
| URL pre-screening | < 1 ms | 0 |
| Content view generation (8 views) | ~3 ms | 0 |
| Batch pattern matching (`grep -Ff`) | ~10 ms | 0 |
| Structural context verification | ~2 ms | 0 |
| Cross-tool correlation | < 1 ms | 0 |
| Content sanitization | ~3 ms | 0 |
| **Total per web fetch** | **~19 ms** | **~80 tokens** (systemMessage only) |

No LLM calls. No API tokens beyond the `systemMessage` Claude reads from the hook response.

## Layer 6 — Outbound exfiltration guard

| Setting | Effect |
|---|---|
| `WEB_SAFETY_EGRESS_GUARD_DISABLE=1` | Kill switch — the guard defers unconditionally |
| Shipped default allowlist | `scripts/web-safety-default-allowlist.txt` — a small, conservative set of trusted egress destinations (`githubusercontent.com`, `arxiv.org`, `openreview.net`, `anthropic.com`, `openai.com`, `python.org`) checked **in addition to** your `url-allowlist.txt`, so armed-window research fetches to obviously-trusted hosts stop prompting out of the box. **Egress-guard only** — it does not affect the URL pre-screen (Layer 1). Membership is a security decision, not a reputation list: a host qualifies only if an attacker who controls a resource there cannot read back request query/path/body (finalized by cross-model DCA `20260705T195623`). Deliberately excludes `github.com`/`gitlab.com` (repo traffic analytics), `huggingface.co` (Spaces log requests), `readthedocs.io` (project-controlled subdomains) — add any yourself with `/web-safety:allow`. Disable the whole layer with `WEB_SAFETY_DEFAULT_ALLOWLIST_DISABLE=1`. |
| `url-allowlist.txt` (reused) | If every host extracted from an egress command suffix-matches an allowlist entry (default **or** user file), the command is exempt (no confirmation). A command with no extractable host (e.g. host hidden in a `python -c` variable) is treated as untrusted and still escalates. **Use full registrable domains** (`api.example.com`, `example.com`) — never a bare public suffix like `com` or `io`, which would suffix-match and exempt every host under it. |
| One-shot allowlist suggestion | After `WEB_SAFETY_SUGGEST_THRESHOLD` (default 3) asks to the **same** host in a session, the confirmation gains a one-line `/web-safety:allow <host>` hint. It **never** auto-adds — a single injected+approved fetch to an attacker host must never become permanently trusted, so the human always decides. |

- **Channels (v7.5+):** the guard runs on both the `Bash` matcher and the web-fetch matcher (`WebFetch`/`WebSearch`/MCP web tools). On the web channel, an armed outbound fetch to a non-allowlisted host is escalated; it fails closed if the destination field can't be parsed.
- **Upload-aware exemption (v7.5+):** the allowlist exempts *transfers to* a trusted host, but **not uploads** — a `curl`/`wget` carrying data (`-d`/`--data*`/`-F`/`-T`/`--upload-file`/`--json`/wget `--post-*`/`--body-*`) to an allowlisted host still escalates, because exfil to a trusted host is still exfil. `scp`/`rsync` transfers to an allowlisted host stay exempt.
- **Arming window:** 300s (matches the scanner's `SESSION_WINDOW`), keyed to a HIGH detection in the same session. Not independently configurable.
- **Posture:** soft-block — the guard returns `permissionDecision:"ask"`, surfacing a confirmation dialog; it never hard-denies. The injected instruction cannot self-approve egress; you decide.
- **Fail-open:** unlike the scanner (which fails closed), the egress guard fails *open* on internal error (missing `jq`, unparseable input, unreadable arm-state) so a guard bug cannot block every outbound command in a flagged session. The normal armed+egress decision is already safe (`ask`).
- **Known residual — redirects (v8.3+):** the guard screens the *initial* fetch URL only; a redirect **from** an allowlisted host to an attacker host is not re-screened (a `curl -L` / WebFetch follows it to a final host the PreToolUse hook never sees). The shipped default hosts are static/first-party without a known general open redirect, but post-redirect re-screening is a tracked follow-up. If you add a host with an open-redirect endpoint to your allowlist, you inherit this risk.

## Limitations

This is **not bulletproof**. Be aware:

- **Same context window** — even with `toolResult` redaction, the sanitized content and warning messages coexist in context. A sufficiently sophisticated attack might exploit the redaction markers themselves.
- **Pattern-based detection** — the scanner catches known patterns. Novel injection techniques not in the pattern database may bypass it.
- **Cross-tool correlation is count-based** — escalates when multiple tools are flagged but does not reassemble payloads split across tool calls.
- **Evasion views are additive** — each new normalisation view adds coverage but also increases the surface for false positives on security-focused content.
- **Invisible-character precision has residuals** — the emoji false-positive pass (v7.8.0) tightened the variation-selector (run ≥2), zero-width (ASCII-adjacency), and tag-char (exact subdivision-flag whitelist) predicates so legitimate emoji no longer trip them. Two notify-only smuggle residuals remain, tracked as View-4 normalizer TODOs: interleaved-carrier variation selectors, and zero-widths placed between two non-ASCII homoglyphs.
- **Not a substitute for human review** — the permission system (you approving tool calls) remains the strongest protection.
- **Desktop notifications cover macOS + Linux + Windows** — `web-safety-notify.sh` dispatches to macOS `osascript`, Linux `notify-send` (best-effort sound via `canberra-gtk-play`/`paplay`/`pw-play`), or a Windows WinRT toast via `powershell.exe` (Git Bash / WSL). On a headless/SSH/no-DBUS session, when no notifier is present, or on any other platform, the notification is a silent no-op while detection still runs. Detection never depends on the notifier.

This is one layer in a defense-in-depth strategy. It significantly raises the bar for injection attacks but does not eliminate the risk.
