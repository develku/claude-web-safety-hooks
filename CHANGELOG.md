# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [5.2.0] — 2026-05-26

Plugin packaging + portability + reliability pass after operator migrated to a new system.

### Added

- **Claude Code plugin packaging** — `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`. Installable via `/plugin marketplace add develku/claude-web-safety-hooks` → `/plugin install web-safety@develku`.
- **URL allowlist** — `~/.claude/hooks/url-allowlist.txt` short-circuits soft blocks (high-risk TLD, custom blocklist) for trusted domains. Hard blocks (SSRF, schemes, credentials) still apply.
- **Test harness** — `tests/run-tests.sh` runs 25 payloads (13 representative + 12 stress) across HIGH/MEDIUM/LOW/legit buckets and asserts the scanner's classification matches. Stress set covers all 8 evasion views, code-fence false-positive guards, and multi-pattern HIGH combinations.
- **`WEB_SAFETY_CONFIG_DIR`** env override — user-state (log, blocklist, allowlist) location, defaults to `~/.claude/hooks`.
- **`CLAUDE_PLUGIN_ROOT`** support — scripts auto-resolve sibling paths both in plugin install layout and legacy manual layout.
- **Documentation split** — `CHANGELOG.md`, `docs/patterns.md`, `docs/tuning.md` extracted from the previously 19K monolithic README.

### Fixed

- **Letter-spacing evasion (`i g n o r e p r e v i o u s i n s t r u c t i o n s`) was undetected since v5.1.** The whitespace-collapsed view (View 1) merged single-letter-then-space pairs but stopped after one pass — `i g n o r e` became `ig no re`, not `ignore`, so the MED pattern never matched. Replaced with a single regex that catches runs of 4+ single letters separated by spaces and squashes them in one pass while preserving multi-space word boundaries. **Found by the new stress test set** (`tests/payloads/med-evasion-whitespace.txt`) on first run — a year-old gap discovered the day the harness landed.
- **Layer 5 verifier silently failing when the plugin path contains spaces.** The scanner's `perl -e 'alarm 1; exec @ARGV'` invocation with a single-element `@ARGV` was going through `sh -c`, which word-split the path. Switched to the indirect-object form `exec { $ARGV[0] } @ARGV` which bypasses the shell. Caught by the new test harness on first run. **All users benefit**, not just plugin installs.
- **Silent grep failures in batch pattern matching.** A malformed pattern in the temporary pattern file would cause grep to exit non-zero, returning empty matches and silently dropping detections. Now wrapped in a fail-closed loop: exit > 1 logs `[SCANNER-ERROR]` and surfaces a synthetic HIGH-severity hit so the user is alerted instead of attacks slipping through.

### Changed

- **Scripts moved** from repo root to `scripts/`. `hooks.json` moved to `hooks/hooks.json` and now uses `${CLAUDE_PLUGIN_ROOT}/scripts/` paths with a top-level `description` field per plugin spec.
- **Hard-block / soft-block split in URL pre-screening.** Hard blocks (SSRF, schemes, IP, credentials, oversize, encoding) always apply. Soft blocks (high-risk TLD, custom blocklist) can be short-circuited by the new allowlist.
- **`LOG_FILE` and `BLOCKLIST` resolution** in both `web-safety-approve.sh` and `web-safety-scanner.sh` use `WEB_SAFETY_CONFIG_DIR` instead of hardcoded `$HOME/.claude/hooks/`.

## [4.2.0] — 2026-04-14

### Added

- **Structural context verification** for `MED_GENERIC_DELIMITERS` false positives (Layer 5).
- **`web-safety-verify-context.sh`** — standalone verifier with code fence, YAML, JSON, HTML, inline code detection.
- **Co-location guard** — denies auto-clearance when injection keywords appear on the same line as the matched delimiter.
- **`SESSION_STATE` schema upgrade** — `H` (hit) vs `C` (cleared) status; only genuine hits count toward cross-tool escalation.
- **`CLEARED` audit log entries** — pattern, reason, and content hash for forensic trail.
- **`VERIFY_CONTEXT_ENABLED`** env var — set to `false` for instant rollback to v5.1 behaviour.
- **8 evasion-resistant content views** — added Unicode whitespace, tag-stripped, and URL percent-decoded views (up from 5).

### Changed

- **macOS-compatible verifier timeout** — uses `perl -e 'alarm 1; exec @ARGV'` instead of `timeout` (not available on macOS by default).

## [5.1.0] — Earlier 2026

### Added

- **5 evasion-resistant content views** scanned in parallel: original lowercase, whitespace-collapsed (`i g n o r e` → `ignore`), HTML-entity decoded, punctuation-stripped (`i.g.n.o.r.e`), Unicode confusable normalised (Cyrillic / Greek / fullwidth → Latin).
- **Batch pattern matching** via `grep -Ff` temp files (~10x faster, 16 ms for 50 KB pages).
- **Content sanitization** with `toolResult` override (HIGH = full redact, MEDIUM = surgical).
- **Cross-tool correlation** with 5-minute sliding window + auto-escalation when 3+ tools flag in window.
- **URL pre-screening** in PreToolUse (SSRF, schemes, TLDs, redirects, blocklist).
- **Expanded tool coverage** — wildcard matchers for Exa, Firecrawl, MCP Docker tools, Context7.
- **Claude / Anthropic-specific tokens** — `<system-reminder>`, `<function_calls>`, `<invoke>`, `[HUMAN]`, `[ASSISTANT]`.
- **Forensic hashing** — SHA-256 of original content logged for incident response.

## [4.1.0] — Late 2025

### Added

- Matched content snippets in stop reason.
- Formatted stop reason display with tool name, URL, patterns.
- macOS desktop notifications with per-severity sounds (Basso / Sosumi / Ping).
- Audit log at `~/.claude/hooks/web-safety.log`.
- Rate-limited notifications (5-second debounce).
- Leetspeak normalisation and mixed-script homoglyph detection.

### Fixed

- Stop-behaviour correctness when HIGH severity triggers.
