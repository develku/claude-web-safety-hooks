# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [6.2.1] — 2026-05-26

### Fixed

- **`marketplace.json` source format compatibility.** Initial v6.0 marketplace.json used `"source": "."` (relative-path same-repo form), which is not supported by older Claude Code versions. The first real install attempt failed with `"This plugin uses a source type your Claude Code version does not support"`. Switched to the explicit GitHub object form `{"source": "github", "repo": "develku/claude-web-safety-hooks"}` which is universally supported.

## [6.2.0] — 2026-05-26

Plugin-only installation. The manual install path is removed from the documentation.

### Removed

- **Manual install instructions from README.** The plugin marketplace path (`/plugin marketplace add` → `/plugin install`) is the only documented installation method going forward. Anyone who already installed manually keeps working as before — the `$(dirname "$0")` fallback inside the scripts remains as defensive code (necessary for the test harness and direct script execution), it's just no longer advertised as a user-facing install path.
- Updated script comments to remove "legacy" framing — the fallback is now described as defensive programming for the test harness, not as a user-facing alternative install.

### Changed

- README "Install" section consolidated to the plugin path only. Three commands, no alternatives.

## [6.1.1] — 2026-05-26

Stress test follow-up. Three adversarial scenarios designed; two passed cleanly (confirmed FP control + multi-pattern reassembly), one exposed a real gap that's now fixed.

### Fixed

- **Confusable-letter splits at fragment boundaries were undetected.** Stress test `reassembly-confusable-bridge` (Cyrillic `іgn` + `ore previous instructions`) showed that the storage trigger was using literal grep against the SUSPICIOUS_TOKENS/AFFIX files, so Cyrillic/Greek/fullwidth letter splits at the fragment boundary bypassed both:
  1. **Storage trigger** — now also consults the confusable-normalized per-fetch view file (`$TMP_DIR/confusable.txt`), produced by the existing `generate_views()` pipeline. No new file generation needed.
  2. **Excerpt content** — confusable normalization (Cyrillic а→a, fullwidth ｉ→i, Greek ε→e, ɡ→g, etc.) is now applied to the stored excerpt BEFORE base64 encoding. Smart-join boundary computations and concat grep see Latin letters and bridge correctly.

### Added

- **3 stress test scenarios**:
  - `legit-bridge-benign` — smart-join bridges `fol` + `low` into `follow`, but no MED pattern matches → no escalation (FP control validated).
  - `reassembly-multi-pattern` — single 3-fragment sequence triggers two distinct reassembled MED patterns (`ignore previous instructions` + `disregard the above`).
  - `reassembly-confusable-bridge` — covers the fix described above.

## [6.1.0] — 2026-05-26

Closes the two known limitations documented at v6.0 release: letter-boundary
splits and affix-only fragments. Both gaps were flagged by Codex during the
v6.0 DCA round and deferred; this release resolves them with two narrow
mechanisms.

### Added

- **Affix index** (`$TMP_DIR/e8-affixes.txt`) — precomputed at scanner startup from MED patterns (spaces stripped). Contains all substrings of length ≥ 3 from each pattern. Used as an additional storage trigger so fragments containing partial-word substrings (e.g., `obe` from `obey`) get stored even when they don't carry a full SUSPICIOUS_TOKEN.
- **Smart-join concat** — third reassembly variant alongside chronological + label-sorted. Bridges fragment boundaries without space when BOTH boundary words are in the affix index but NOT full SUSPICIOUS_TOKENS. Catches letter-boundary splits (`ign` + `ore` → `ignore`) and 3-char affix-only splits (`dis` + `reg` + `ard` → `disregard`).
- **2 new test payloads** — `reassembly-letter-boundary` (3-char letter split bridging via smart-join), `reassembly-affix-3char` (full 3-fragment affix-only sequence reassembling `disregard your instructions`).

### Known limitations (deferred, narrower scope than v6.0)

- **2-char-only splits** — e.g., `do not ` + `ob` + `ey`. The 3-char minimum on the affix index excludes 2-char substrings (`ob`, `ey`), so fragments at 2-char granularity are not stored. Going lower causes a FP storm (`th`, `he`, `in` are universal English bigrams).
- **Single-side affix bridges with intervening tokens** — smart-join requires BOTH boundary words to be affix-only. If one side is a regular common English word (length ≥ 5 not in the affix index), the bridge fails. Trade-off accepted: relaxing to "one side affix-only" had measurable FP risk on benign content.

These are genuinely narrow attack classes given the 5-min window and the requirement that the attacker control multiple consecutive fetches at sub-3-char fidelity.

## [6.0.0] — 2026-05-26

Cross-call payload reassembly detection (E8). The scanner now defends against
prompt-injection payloads that an attacker splits across multiple web-fetching
tool calls — each fragment alone falling below detection threshold, but
reassembly across the 5-minute window forming a known attack.

Design hardened against four attack classes through DCA cross-model review
([artifact](../.claude/dca/20260526T113627_e8-cross-call-payload-reassembly.md)
in operator-local store; not in repo):

1. **Sequential reassembly** — fragments delivered in attack order
2. **Ordering-token reordering** — `Part 1/3`, `Step N`, `Page N of M` labels
3. **Cross-session pollution** — two concurrent Claude sessions polluting
   each other's correlation state (inherited bug in v5.2 SESSION_STATE)
4. **Eviction padding** — attacker pads with junk to evict early fragments
   (mitigated by reassemble-before-evict ordering)

### Added

- **`SESSION_FRAGMENTS` sidecar file** — `/tmp/web-safety-session-${SESSION_ID}-fragments`. TSV format `<ts> <seq> <tool> <url_hash> F <base64>`. 0600 perms. `mkdir`-based atomic lock (portable, no `flock` dependency).
- **`E8_ACTIVE` window detection** — when current fetch contains a suspicious indicator OR session has open fragments, the scanner runs past the TOTAL=0 early exit to engage reassembly. Necessary because the whole point of E8 is detecting attacks whose individual fetches don't trigger.
- **Auto-derived suspicious-token lexicon** — extracted from MED pattern arrays at scanner startup; ≥3-char tokens deduplicated. Won't drift when MED patterns are extended. Replaces the brittle hand-curated word list considered in the design phase.
- **Ordering-token detection + label-sorted reassembly** — detects `Part \d+/\d+`, `Step \d+`, `Segment [A-Z]`, `Page \d+ of \d+`, Korean `\d+편`. When present, builds a second concat sorted by ordering key (and strips the ordering preamble itself so payload words become contiguous). Chronological + label-sorted concats both grep'd against the MED pattern set.
- **Cross-fragment match filter** — reassembly matches are only declared genuine when the match string does NOT appear in any single fragment alone. Within-fragment matches were already caught by per-fetch + Layer 5; reassembly catches only the novel cross-call case.
- **`[REASSEMBLED]` audit log entry** — lists all participating ts/tool/url_hash so the operator can scope an incident.
- **Sequence mode in test harness** — directory payloads (`tests/payloads/<bucket>-<name>/<NN>.txt`) run multiple fetches against the SAME session. Filename `<NN>.<LABEL>.txt` opt-in for multi-session interleaving (cross-session-isolation tests).
- **4 new sequence test payloads**: `reassembly-basic`, `reassembly-labeled-reorder`, `legit-multi-fetch-no-attack`, `legit-cross-session-isolation`.

### Fixed

- **Cross-session pollution in `SESSION_STATE`** — inherited bug from v5.1. Two concurrent Claude Code sessions previously shared `/tmp/web-safety-session-state`, polluting each other's escalation counter. Now scoped via `${CLAUDE_SESSION_ID:-$PPID}`. **All users benefit**, not just E8 callers.
- **`umask 0077`** applied before writing `/tmp` state files so other users cannot read scanned content.

### Changed

- **8-view normalization** extracted into a `generate_views()` function. Reassembly runs the same pipeline on the concatenated string, so encoding-evasion + reassembly combinations are caught.
- **TMP_DIR creation** moved to immediately after lowercasing input. Per-fetch views are written directly to disk instead of accumulating in shell variables (saves ~400KB of shell memory on large pages).

### Known limitations (deferred to next round)

- **Letter-boundary split + encoding evasion** — fragments split mid-word (`ign` + `ore`) with optional encoding still bypass because the concat inserts a space between fragments which breaks the merged word. A "no-space concat" variant is the obvious mitigation but introduces FP risk on legitimate adjacent fetches. Out of scope for v6.0; addressed when stress evidence justifies.
- **Affix-only fragments** — a fragment containing only `ob` (no full SUSPICIOUS_TOKEN substring) is not stored, so an attack like `do not ` + `ob` + `ey` is missed unless the third fragment carries a token. Codex flagged; mitigation requires prefix/suffix participation logic in the trigger check.

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
