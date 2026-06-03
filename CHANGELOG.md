# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [7.7.0] — 2026-06-02

Minor roll-up (PR 5 of the staged review) — the `#15` cluster of small
correctness, portability, and concurrency items. This completes all 15 findings
from the full-codebase review. Each item was investigated and adversarially
verified (real vs. already-fixed vs. false-finding) before any change.

### Fixed (correctness)

- **Multi-technique leetspeak now fully reported.** The leetspeak loop exited on
  the *first* match, so a page combining several obfuscated payloads
  (`1gn0r3 pr3v10us 1nstruct10ns … byp455 54f3ty … j41lbr34k`) surfaced only one.
  The early `break` is removed; benign content already ran the full loop, so this
  only adds work on the rare attack path.
- **Escalation tool list renders correctly.** `SESSION_FLAGGED_TOOLS` joined with
  `tr '\n' ', '`, which collapses to `,` (POSIX `tr` ignores the extra char in the
  2-char set), so the cross-tool escalation message read `WebFetchExa`. It now
  joins with a real `, ` separator.

### Changed (concurrency / robustness)

- **`listctl` add is now atomic.** The check-then-append had a TOCTOU window
  (concurrent `listctl allow X` could duplicate an entry, violating the script's
  idempotency contract). It now rebuilds the list (deduped) into a same-filesystem
  temp file and renames it into place; the friendly "already in list" notice is
  preserved.
- **`SESSION_STATE` prune is lock-guarded.** The per-session hit-tracking file's
  read-modify-write prune now takes a `mkdir`-lock, mirroring the E8 fragment
  prune, so two concurrent same-session scanners can't clobber each other's
  rewrite. Fail-safe: if the lock is held the prune is skipped (the cutoff-filtered
  hit count is unaffected, so escalation stays correct).
- **Allowlist honors a final entry without a trailing newline.** `web-safety-approve.sh`
  used a bare `while read` loop that drops the last line when the file lacks a final
  newline; it now uses `|| [ -n "$domain" ]` (matching the shared lib's reader).

### Removed (dead code)

- Dead `VERIFIER_TIMEOUT=0.5` (the real verifier timeout is the `perl alarm`
  wrapper; the variable was unused and misleading).
- Dead `: > "${SESSION_FRAGMENTS}.tmp"` pre-truncate before the fragment append
  (nothing read that scratch file).

### Notes

- The escalation-count threshold (`SESSION_HITS >= 2` ⇒ "3+ tools") was **verified
  correct** (the current call is the 3rd) — flagged as a candidate, kept unchanged.
- `date +%s%N` for the E8 fragment sequence id is non-portable on BSD/macOS, but
  the field is write-only metadata never parsed back (a comment now documents this).
- Test-harness session cleanup switched to `rm -rf` so the per-session `.lock`
  directories are reclaimed.
- Suites: scanner 47, cmd 49, egress 71 — all green.

## [7.6.0] — 2026-06-02

Detection-recall hardening (PR 4 of the staged review): the two remaining HIGH
false-negative findings (#5 base64, #7 cross-call reassembly) plus the targeted
lexicon unification (#14 / #7c). These close the gaps where a determined attacker
could smuggle an injection past the scanner.

### Security (closed false negatives)

- **Base64 detection strengthened (#5).** The encoded-content check previously
  needed a single unbroken run of ≥50 base64 chars and decode-matched only against
  a 7-word English keyword list. It now: strips CR/LF before scanning (defeating
  line-wrapped blobs), lowers the run threshold to ≥16 chars, decodes up to 50
  candidate runs (was 5), and greps each decode against the **real** `high.pat` +
  `med.pat` pattern files (plus the keyword fallback) — so a base64-wrapped payload
  in any of the lexicon's languages is caught, not just English.
- **Cross-call reassembly evasions closed (#7).** Layer 8 (E8) buffers fetch
  excerpts and detects an injection split across several fetches. Three gaps closed:
  - **(#7a) excerpt now samples head *and* tail.** Head-only let an attacker prepend
    > `E8_EXCERPT_SIZE` bytes of benign filler to each fragment so the malicious tail
    was never buffered; the excerpt is now head ⅔ + tail ⅓.
  - **(#7b) the reassembly window captures completing fragments.** Once a fragment is
    buffered, a later fetch is now also buffered even if it carries no standalone
    indicator — otherwise the benign-looking *second half* of a split payload was
    never stored, so the halves never reached the ≥2 needed to reassemble.
  - **(#7c) the reassembly lexicon now covers all 14 MED categories.** It previously
    used a 6-array subset, so a payload reassembled from any of the other 8 pattern
    categories never opened the window.

### Changed (architecture, #14)

- **Single-source MED lexicon (`MED_ALL`).** The 14 medium-severity pattern arrays
  were expanded into the grep build, the casing maps, the E8 token/affix index, and
  the reassembly promotion map at **seven** separate sites — a drift hazard where a
  new pattern added in one place silently missed the others. They are now composed
  once into `MED_ALL` and every consumer reads that array.

### Security gate (two passes — found and fixed real regressions)

Reviewed pre-commit by the security gate. The first pass flagged that broadening
the reassembly lexicon (#7c) **amplified a latent false-positive**: the affix index
was built from space-*stripped* whole phrases, generating cross-word trigrams
(`epr`, `usi`, …) that matched ordinary prose and opened the E8 window on benign
content — which #7b then made re-run the reassembly pipeline (and potentially
re-fire) on every subsequent fetch. Both were fixed and re-verified CLOSED:

- **Per-word affix index.** Both affix-build pipelines now tokenize on spaces first,
  so affixes are substrings of individual MED *words* (the `obe`-from-`obey` design
  intent), not cross-word artifacts of whole phrases. The prose FP source is gone.
- **Fired-set de-dup (not eviction).** A reassembled pattern that already fired in a
  session is recorded in a per-session fired-set and suppressed on later fetches, so
  the same buffered halves can't re-emit the HIGH stop every fetch — while a
  *genuinely new* pattern completing on a later fetch still fires. Check + append
  share one lock (atomic), and lock failure degrades toward re-alerting, never
  toward silently dropping a detection.

### Known limitations (documented, by design)

- The E8 window still opens on benign content that contains a real injection-word
  substring (`system`, `ignore`, …). This is a cheap, consequence-free gate: it only
  triggers buffering + a bounded reassembly pass — it cannot itself raise a verdict,
  and the fired-set caps any reassembly to one fire.
- Base64 detection still does not cover the URL-safe alphabet (`-`/`_`) or
  space-separated (vs CR/LF-wrapped) runs — a known, narrower residual.

### Notes

- Suites: scanner 46, cmd 45, egress 71 — all green (256 KB benign page scans in
  ~3.4 s, well under the 8 s budget).

## [7.5.0] — 2026-06-02

Exfil-chain hardening (PR 3 of the staged review). Layer 6 (the inject→exfil
break) now also covers the **web-fetch** channel, and the egress guard adopts the
shared host library.

### Security

- **Web-fetch egress is now gated (#3a).** The exfiltration guard previously only
  saw Bash, so the most natural post-injection exfil — having the model fetch
  `attacker.com/?data=<secret>` — was ungated. The guard is now wired to the
  web-fetch PreToolUse matcher as well: while armed (≤5 min after a HIGH), an
  outbound fetch is escalated to ASK unless its host positively resolves to an
  allowlisted domain. **Fails closed** — a fetch tool whose destination is in a
  field we don't parse (`urls[]`, a search `.query`, …) ASKs rather than passing.
- **Upload-aware allowlist (#3c).** A curl/wget that UPLOADS data
  (`-d`/`--data*`/`-F`/`--form*`/`-T`/`--upload-file`/`--json`/`--url-query`/wget
  `--post-data`/`--post-file`/`--body-*`) to an allowlisted host is no longer
  exempted — exfil to a trusted host is still exfil. (scp/rsync *transfers* to an
  allowlisted host stay exempt: the user explicitly trusted that destination.)
- The egress guard now uses the shared `web-safety-lib.sh`
  (`normalize_host` / `host_in_list`) for host parsing + allowlist matching,
  ending the divergence with the URL pre-screen.

### Fixed (false positives, #11)

- **HTTPie detection by argument shape.** `HTTPIE_RE` previously matched any
  command containing the substring `https `; it now matches the `http`/`https`
  binary by its argument (an HTTP method, a URL/host, a `:port`, a scheme, or a
  flag), so `env http POST …`, backtick-wrapped httpie, etc. are still caught
  while a prose mention (`echo see https for details`) is not.
- **rsync only when remote.** `rsync` is treated as egress only with a remote spec
  (`host:path` / `user@host:path`); a purely local `rsync /tmp/a /tmp/b` no longer
  asks.

### Security gate

- Reviewed pre-commit by the cross-model gate (Codex + security-auditor). The
  first cut had residual exfil bypasses — non-`.url` MCP fetch fields, HTTPie via
  backtick/`env`, and missing curl/wget upload flags — each now closed and
  regression-tested; the re-verification pass confirmed all closed with no fresh
  bypass.

### Known limitations (documented, by design)

- The arm-state is a `/tmp` file; a multi-step injected sequence could `rm` it
  before exfil. The guard raises the bar (a single command can't both disarm and
  exfil — the PreToolUse check runs first) but is defense-in-depth, not a hard gate.
- A GET smuggling a secret in the query string to an **allowlisted** host stays
  exempt (the user positively trusted that destination).
- The HTTPie arg-shape match accepts a rare prose FP (`… https GET …`) → ASK, only
  while armed and only on a Bash command.

### Notes

- Suites: scanner 42, cmd 45, egress 71 — all green.

## [7.4.0] — 2026-06-02

Coverage, false-positive, and log-integrity fixes from the same full-codebase
review (PR 2 of a staged series).

### Security

- **Audit-log → report injection closed (#12).** Attacker-influenced URLs are
  control-char-stripped before being written to `web-safety.log` (a raw newline
  would otherwise forge log lines that the report later trusts), and
  `web-safety-report.sh` neutralizes backticks in logged content so a logged URL
  can no longer close the Markdown code fence and inject markdown into the
  "Most recent" section. Applies to both the pre-screen and scanner log writers.

### Fixed

- **Object-shaped `tool_response` was effectively unscanned (#9).** Real WebFetch
  / MCP tools return `tool_response` as an object, not a flat string; `jq -r`
  serialized it so JSON escaping could split injection patterns. The scanner now
  flattens an object/array response's string leaves to newline-joined text before
  scanning (string responses are unchanged).
- **`approve.sh` false positives (#10):** a blank / comment-only
  `url-blocklist.txt` no longer blocks **every** URL (BSD `grep -F -f` on an empty
  pattern set matches all lines — now filtered to real entries), and a WebSearch
  free-text `.query` is no longer run through the URL hard-blocks (a query merely
  mentioning "localhost" or a ".tk" domain was being blocked; its results are
  still scanned by the PostToolUse scanner).

### Changed

- **Broader MCP tool coverage (#8).** The hook matcher now also catches MCP tools
  by keyword (`fetch` / `search` / `scrape` / `crawl` / `browse` / `read_url` /
  `to_markdown` / `extract` / …) so a newly-added fetch/search MCP server is
  scanned without enumerating its exact tool slugs. Non-web MCP tools (e.g.
  `db__run_query`) are not matched.

### Notes

- Reviewed by a pre-commit security-auditor gate (no blocking findings). Two
  MEDIUM refinements were folded in: the object-flatten uses a **space** join (not
  newline) so a payload fragmented across sibling fields stays adjacent for the
  line-oriented matcher; and the report's markdown tables now strip `|` from
  tool/host cells (the fence fix alone left the tables open). Write-site URL log
  sanitization also strips DEL (0x7f), not just C0.
- Documented LOW residual: dropping the `.query` URL pre-screen means a
  hypothetical fetch tool that delivers its target URL in `.query` (no standard
  tool does) would skip SSRF pre-screening; its response is still scanned.
- Exfil-chain hardening (#3 — gating web-fetch egress, the egress guard adopting
  the shared `web-safety-lib.sh`) and egress false-positive tuning (#11) are
  deferred to a focused follow-up PR; they carry the egress guard's larger
  regression surface and warrant their own gate.
- Suites: scanner 42, cmd 45, egress 50 — all green.

## [7.3.0] — 2026-06-02

Security-critical hardening from a full-codebase review. This release closes the
highest-severity findings — an SSRF pre-screen bypass, a fail-open on large /
adversarial pages, a broken hex-entity normalization, and a verifier flaw that
auto-cleared genuine `[INST]` injection — and hardens the test suite so a
fail-open can no longer pass green. (Part 1 of a staged 3-PR review fix.)

### Security

- **SSRF pre-screen bypass closed** (`web-safety-approve.sh`). The "internal
  network" hard block was bypassable by alternate encodings of an internal host:
  decimal-integer IPs (`http://2130706433/` = 127.0.0.1), hex IPs
  (`http://0x7f000001/`), userinfo tricks (`http://allowed.com@127.0.0.1/`), and
  cloud-metadata hostnames (`metadata.google.internal`, any `*.internal`).
  Classification now runs **after canonical host normalization** — scheme,
  userinfo, and port stripped; integer/hex/octal IPv4 collapsed to dotted-quad —
  so every encoding of an internal target resolves to the same string before the
  block. New shared library `scripts/web-safety-lib.sh` is the single source of
  truth for host parsing/classification, used by both the URL pre-screen and the
  egress guard (previously divergent hand-rolled copies).
- **Hex HTML-entity evasion closed** (`web-safety-scanner.sh`). The "decoded"
  normalization view rewrote `&#x69;` to the literal text `\x69` and never
  produced the byte, so hex-entity-obfuscated injection
  (`&#x69;gnore previous instructions`) slipped past every grep view. Numeric
  entities — decimal **and** hex, any digit count — are now decoded via perl
  `chr`/`hex` (this also fixes the prior 2–3-digit-only / lookup-table limit on
  decimal entities).
- **Verifier no longer clears genuine `[INST]`/`[sys]` injection**
  (`web-safety-verify-context.sh`). Matched delimiter patterns were interpolated
  raw into `grep -E`, so bracket patterns became regex character classes and
  over-matched unrelated text — auto-clearing real Llama/Mistral
  instruction-delimiter injections as "structural false positives." Patterns are
  now regex-escaped before interpolation.

### Fixed

- **Fail-open on large / adversarial pages** (`web-safety-scanner.sh`).
  `tool_response` was unbounded; a large page (or adversarial padding) could push
  the scan past the 10 s PostToolUse timeout, at which point Claude Code kills the
  hook and the page reaches the model **unscanned**. The scanner now caps the
  scanned content at `MAX_SCAN_BYTES` (32 KB; override with
  `WEB_SAFETY_MAX_SCAN_BYTES`) and emits a LOW note when it truncates, so the
  unscanned tail is never silently trusted. The E8 reassembly indicator check is
  bounded to a 4 KB prefix (it only decides whether to store a ≤1.5 KB excerpt),
  and its greps drop a redundant `-i` (inputs and pattern files are already
  lowercased) — removing the dominant cost on adversarial input.

### Security gate

- This release was reviewed before commit by a cross-model gate (Codex +
  local security-auditor). It caught — and this release also fixes — a set of
  **residual SSRF bypasses** in the first cut of the normalizer: IPv4-mapped
  IPv6 (`[::ffff:127.0.0.1]`, `[::ffff:169.254.169.254]`), leading-whitespace /
  leading-newline / embedded-control-char URLs, backslash authority desync
  (`http://127.0.0.1\@allowed.com/`), single/double/triple percent-encoded hosts,
  octal-whole-integer hosts, and empty-authority (`http:///127.0.0.1/`). Each now
  has a regression test.

### Tests

- The harness no longer maps a scanner crash/non-zero exit to `clean` — a crash
  on a `legit-*` payload now fails loudly, so a fail-open regression is visible.
- Added an **enforcement-contract** assertion: a HIGH detection must emit
  `continue:false` + `toolResult` + `stopReason`, not merely a `systemMessage`.
- Added a production-size **perf regression test**, a **tail-injection** test
  (injection past the head cap must still be caught), an entity-overflow test,
  and SSRF / hex-entity / `[INST]`-verifier regression tests, plus an
  empty-array `set -u` guard.

### Known limitations (documented, by design)

- **Oversized-page middle gap.** Content over `MAX_SCAN_BYTES` is scanned as a
  head + tail slice; injection placed *only* in the omitted middle of such a page
  is detected as a LOW "content too large" note rather than blocked. This is the
  bounded-scan tradeoff that prevents the timeout-induced fail-open — the guard
  is defense-in-depth, not a sandbox. Raising `WEB_SAFETY_MAX_SCAN_BYTES` shrinks
  the gap at the cost of per-fetch latency.
- **`host_is_internal` + hex-grouped IPv4-mapped IPv6.** The internal-network
  classifier covers hex-grouped loopback (`::ffff:7f..`) and AWS metadata
  (`::ffff:a9fe`) but not hex-grouped private ranges; consumers must pair it with
  `host_is_bare_ip` (as the URL pre-screen does). The egress guard does not yet
  use the shared lib — that adoption (a later PR) must honor this contract.

## [7.2.0] — 2026-06-01

macOS notifications now show *what* triggered them. Previously every alert carried generic text ("Prompt injection detected! Content blocked.") and the cause lived only in the terminal `stopReason` and `web-safety.log` — and an osascript notification can't be clicked to reveal more (its owning app is just Script Editor). The cause is now in the notification itself, no click required.

### Changed

- **Notification body/subtitle now carry the cause** across all three sources:
  - Scanner HIGH / MEDIUM / ESCALATED / LOW — body lists the matched pattern names (`Patterns: tool_call_faking, llm_control_tokens`); subtitle shows the `TOOL_URL` (or, for the multi-tool escalation, the flagged-tool list).
  - Egress guard — body shows the actual outbound command that tripped the guard instead of a fixed sentence.
  - URL pre-screen block — subtitle shows the offending URL alongside the existing block reason.
- `send_notification` gained an optional 5th `subtitle` argument; existing calls without it render exactly as before.

### Security

- **Hardened the osascript sanitizer to strip backslashes as well as double quotes.** Both are AppleScript string-literal metacharacters; now that untrusted content (web-tool URLs, outbound commands) flows into the subtitle/body, a trailing `\` could have escaped the closing quote and enabled AppleScript injection. Verified neutralized against adversarial `"`/`\` input in all three scripts.

### Notes

- Detection behavior is unchanged — this is display-only; the cause data was already computed at each call site. All suites green (scanner 34, egress 50, cmd 9), and real notifications were fired to confirm rendering + sanitization.
- For alerts that linger long enough to read, set Script Editor's notification style to "Alert" in System Settings → Notifications. Full matched snippets + content hash remain in the terminal `stopReason` and `web-safety.log`.

## [7.1.0] — 2026-05-31

Layer 6 hardening from an adversarial stress test (~130 attack vectors across quoting/obfuscation, state/logic, allowlist, and unlisted-binary classes). The stress test confirmed zero quoting-evasion, zero logic/state, and zero allowlist bypasses — and surfaced one precision defect plus a set of low-false-positive coverage gaps.

### Fixed

- **`ONELINER_RE` flag-skip evasion.** The interpreter one-liner detector required `-c`/`-e` *immediately* after the interpreter, so a single benign flag (`python3 -u -c …`, `python3 -B -c …`, `perl -MLWP::Simple -e …`) slipped past it. Reworked into an inline-exec match that tolerates intervening flags, paired with a network-token match that may appear anywhere in the command (so perl's `-MLWP` module flag is now caught, not just `use LWP` in the code body).
- **Path-component false positive** (found by a focused pre-production stress pass). Adding `ssh` exposed a loose token boundary that admitted `.` and `/`, so common file operations (`ls ~/.ssh/`, `vim /etc/ssh/sshd_config`, `cat report.scp`, `ls nc.log`) spuriously asked. Boundaries now exclude path separators while still matching quoted (`'curl'`) and path-qualified (`/usr/bin/curl`) command forms.
- **Separate-argument interpreter flags.** The first flag-skip fix tolerated only single-token flags; a flag taking a separate-word argument (`python3 -W ignore -c …`, `perl -I /tmp -e …`, `python3 -X faulthandler -c …`) still evaded. The matcher now tolerates one argument word per flag — without over-matching a normal `pytest -k requests -c pytest.ini`.
- **Ruby `net/http` token.** The network-token set matched `net::http` but not the `require 'net/http'` path form; both are now recognized.

### Added

- **Expanded egress coverage** (low-false-positive vectors found in the stress test): `rsync`, `ssh` (remote-exec / reverse-tunnel), `socat`, `telnet`, `netcat`, `openssl s_client`, and pure-bash `/dev/tcp` & `/dev/udp` redirection (no external binary). `scp`/`sftp` were already covered; `rsync`/`ssh` close the obvious sibling gap. Bare `openssl` (local crypto: `enc`/`genrsa`/`dgst`) is deliberately *not* matched — only `s_client`.
- Regression tests for each new vector plus false-positive guards (`ssh-keygen`, `openssl genrsa`, a non-network `python -c`, `git commit` mentioning a net word, `telnetd`) plus a second round of guards (path-component FPs, separate-arg flags, `'curl'`/path-qualified preservation) — egress suite now 50 cases.
- Docs note: `url-allowlist.txt` entries must be full registrable domains, never a bare public suffix (which would exempt every host under it).

### Notes

- Out of scope by design (documented limitations, not regressions): token-split binary names (`c""url`), cloud-storage CLIs (`aws s3`/`gsutil`/`rclone`), `git push`, and DNS-tunnel exfil. These remain evadable; the guard is defense-in-depth, not a sandbox.

## [7.0.0] — 2026-05-31

New defense layer. The plugin detected injection in fetched content but did not stop the *next* step — a poisoned page telling Claude to read a secret and POST it out. Layer 6 closes that gap.

### Added

- **Layer 6 — Outbound exfiltration guard.** New PreToolUse(`Bash`) hook (`scripts/web-safety-egress.sh`) that breaks the inject→exfil chain: when a HIGH-severity prompt-injection was flagged in the session within the last 5 minutes, outbound network-egress commands (`curl`/`wget`/`scp`/`nc`/`aria2c`/HTTPie/text-browsers/inline `python -c`/`node -e` net one-liners — including path-qualified forms like `/usr/bin/curl`) are escalated to a user confirmation (`permissionDecision:"ask"`). The injected instruction cannot self-approve egress; a human decides.
- Trusted-destination exemption via the existing `url-allowlist.txt`. A command with no extractable host (e.g. host hidden in a `python -c` variable) is treated as untrusted and still escalates.
- Kill switch `WEB_SAFETY_EGRESS_GUARD_DISABLE=1`.
- New test suite `tests/run-egress-tests.sh` (23 cases: producer + consumer + allowlist exemption + session isolation + path-qualified + case-insensitive binary regressions), wired into the CI matrix.

### Changed

- The PostToolUse scanner now writes a per-session arm-state file (`/tmp/web-safety-session-<id>-armed`) on HIGH and ESCALATED detections, consumed by the new guard. No change to scanner detection behavior.

## [6.3.1] — 2026-05-30

First real invocation of the v6.3.0 commands exposed a substitution bug.

### Fixed

- **Slash commands referenced `$CLAUDE_PLUGIN_ROOT` without braces.** Claude Code substitutes the `${CLAUDE_PLUGIN_ROOT}` *braces* token textually before running an embedded `` !`…` `` command; the bare `$CLAUDE_PLUGIN_ROOT` form is passed through literally, so the `!`-exec shell expanded the unset variable to empty and the script path collapsed to `/scripts/web-safety-report.sh` (`No such file or directory`). Fixed all three commands to the braces form — matching the canonical pattern used by other installed plugins — quoted `"$ARGUMENTS"`, added `disable-model-invocation: true`, scoped `allowed-tools: Bash(bash:*)`, and removed the now-unnecessary natural-language fallback. The helper scripts themselves were correct and unchanged.

## [6.3.0] — 2026-05-30

Interactive surface + continuous integration. The plugin was hooks-only; this release adds user-facing slash commands and a cross-platform CI test matrix.

### Added

- **Slash commands** (`commands/`, auto-discovered on install):
  - `/web-safety-report [days]` — markdown summary of the audit log: counts by severity, top tools, top hosts, recent events. Optional `[days]` window. Read-only; never mutates the log.
  - `/web-safety-allow <domain>` — validate + append a domain to the URL allowlist.
  - `/web-safety-block <domain>` — validate + append a domain to the URL blocklist.
- **Helper scripts** backing the commands (also usable standalone):
  - `scripts/web-safety-report.sh` — log → markdown. GNU (`date -d`) and BSD (`date -v`) compatible.
  - `scripts/web-safety-listctl.sh` — strict hostname validation + normalization (a pasted URL is reduced to its host) + dedupe before writing the files the pre-screening hook reads, so a malformed or shell-metacharacter entry can never reach them.
- **CI** (`.github/workflows/tests.yml`) — runs the scanner suite + the new command-helper suite on a matrix of `ubuntu-latest` (GNU userland / bash 5) and `macos-latest` (BSD userland / bash 3.2), validating the "bash 3.2+ / cross-platform" claim. UTF-8 locale pinned per-OS to avoid the C/POSIX multibyte gotcha. Adds a tests badge to the README.
- **Command-helper tests** (`tests/run-cmd-tests.sh`) — 9 cases: domain validation/rejection (incl. shell-metachar input), URL→host normalization, dedupe, allow-vs-block routing, and report summarization against a synthetic log.

## [6.2.2] — 2026-05-26

### Fixed

- **`marketplace.json` source format** — both `"."` (v6.0–6.2) and `{"source": "github"}` (v6.2.1) failed install on Claude Code 2.1.150. Empirical inspection of three working community marketplaces (impeccable, openai-codex, anthropics' own claude-plugins-official) confirms the actually-supported formats are: bare relative-path string (`"./"`, `"./plugins/foo"`) and the `git-subdir` object. Switched to `"source": "./"` — the same form impeccable uses for a single-plugin-at-repo-root layout.

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

## [5.1.1] — 2026-04-14

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
