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

`$WEB_SAFETY_CONFIG_DIR/url-allowlist.txt` — one domain per line. Comments start with `#`. Suffix-matched: `github.com` matches `api.github.com` and `raw.githubusercontent.com`.

```
# trusted internal docs + public read-only sources
github.com
anthropic.com
docs.python.org
# our wiki
wiki.example.internal
```

The allowlist short-circuits **soft blocks only** — high-risk TLD and the custom blocklist. Hard blocks (SSRF, dangerous URI schemes, IP addresses, credentials in URL, oversized URLs, excessive encoding, open redirects) still apply because those are security primitives, not heuristics.

## URL blocklist

`$WEB_SAFETY_CONFIG_DIR/url-blocklist.txt` — same format as the allowlist. Substring-matched against the full URL.

```
malware-distribution.example.com
known-injection-host.example.net
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

Default: 5 seconds between macOS notifications (debounce). Adjust `RATE_LIMIT_SECONDS` near the top of `scripts/web-safety-scanner.sh`.

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
```

Entry types:
- `[HIGH] / [MEDIUM] / [LOW] / [ESCALATED]` — the scanner detected something
- `[SANITIZE]` — content was rewritten; includes SHA-256 of the original for forensic chain-of-custody
- `[PRE-BLOCK]` — URL pre-screening rejected the URL before fetching
- `[CLEARED]` — Layer 5 verifier auto-cleared a false positive (does NOT count toward escalation)
- `[SCANNER-ERROR]` — internal error (malformed pattern, system issue); the scanner fails-closed and surfaces a synthetic HIGH-severity hit so the user is alerted

## False-positive workflow

If the scanner pauses you on legitimate content:

1. Check the audit log — note the matched pattern.
2. **If the pattern is in `MED_GENERIC_DELIMITERS`** (`assistant:`, `human:`, `<system>`, `[INST]`, `system: you are`) — confirm Layer 5 is enabled (`VERIFY_CONTEXT_ENABLED=true`). If the content is inside a code fence / YAML string / JSON value / HTML code block but you're still being paused, the verifier may be missing a structural pattern — file an issue with a minimal reproducer.
3. **If the URL host is consistently trusted** — add it to the allowlist (covers soft blocks only; doesn't suppress content-scan hits).
4. **If a specific pattern is over-firing** — open `scripts/web-safety-scanner.sh`, find the pattern in its severity array, and either remove it or move it to a lower-severity array. Add a `legit-*` payload to `tests/payloads/` capturing the false-positive context so regression tests guard against re-adding it.

## Cross-tool escalation + reassembly tuning

The scanner escalates MEDIUM → HIGH when 3+ tools trigger injection warnings in a 5-minute window. The constants are `SESSION_WINDOW=300` (seconds) and the check `if [ "$SESSION_HITS" -ge 2 ]` (current call makes it 3+). Tighten by lowering the threshold; loosen by raising the window.

Session state is stored at `/tmp/web-safety-session-${SESSION_ID}-state` (correlation) and `/tmp/web-safety-session-${SESSION_ID}-fragments` (E8 reassembly excerpts). Both are scoped per Claude Code session via `CLAUDE_SESSION_ID` (or `PPID` fallback). Wipe manually for a clean slate:

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

## Limitations

This is **not bulletproof**. Be aware:

- **Same context window** — even with `toolResult` redaction, the sanitized content and warning messages coexist in context. A sufficiently sophisticated attack might exploit the redaction markers themselves.
- **Pattern-based detection** — the scanner catches known patterns. Novel injection techniques not in the pattern database may bypass it.
- **Cross-tool correlation is count-based** — escalates when multiple tools are flagged but does not reassemble payloads split across tool calls.
- **Evasion views are additive** — each new normalisation view adds coverage but also increases the surface for false positives on security-focused content.
- **Not a substitute for human review** — the permission system (you approving tool calls) remains the strongest protection.
- **macOS-only notifications** — desktop notifications use `osascript`; the scanner works cross-platform without them.

This is one layer in a defense-in-depth strategy. It significantly raises the bar for injection attacks but does not eliminate the risk.
