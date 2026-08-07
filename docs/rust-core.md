# Rust scanner core — architecture

The `engine/` crate is the shared low-latency scanner core. Since v9.0.0 it is
the **production scanner authority for Claude Code**: `hooks/hooks.json`
invokes `engine/target/release/web-safety-engine` on the PreToolUse and
PostToolUse hook sites (`--host claude --event pre-tool|post-tool`). The Bash
scanner in `scripts/` stays in-tree as the **frozen differential oracle** and
the operator's rollback path — deleting it would break every comparison suite,
and rewiring `hooks.json` back to the scripts is the rollback.

Current parity: **83/83 payloads agree, zero divergences in either direction**
(`tests/run-differential.sh`), plus **32 sequences / 73 steps, zero
divergences** on the state-sequence differential
(`tests/run-state-differential.sh`).

## Why a second implementation exists

The Bash scanner spends 1.7–7.8 seconds per scan because every stage is a
subprocess: 24 `grep -oFf` invocations across 8 normalized views, ~8 `perl -CSD`
codepoint passes, a base64 sweep with up to 50 `base64 -d` calls, and a
`sed`+`grep` leetspeak pass. That is most of Claude Code's 10-second PostToolUse
budget, and it is per fetch. The [Stage-1 architecture
decision](../CHANGELOG.md) chose one Rust CLI with thin runtime-native adapters;
[Stage 2](../CHANGELOG.md) validated it (VALIDATED: 603/603 corpus entries are
plain literals, 53 of 54 regexes compile unchanged, every latency gate met).

## Layering

```
        host envelope (JSON on stdin)
                  │
          ┌───────▼────────┐   the ONLY code that knows a runtime's field names
          │  hosts.rs      │   claude / codex / hermes → ScanRequest
          └───────┬────────┘
                  │  contract.rs — versioned, host-neutral
          ┌───────▼────────┐
          │  engine.rs     │   "what fired"
          │   normalize.rs │     the 8 evasion-resistant views
          │   corpus.rs    │     603 literals, generated from Bash
          └───────┬────────┘
                  │  Vec<Finding>, all disposition = Kept
          ┌───────▼────────┐
          │  policy.rs     │   "what survives"
          │   verify.rs    │     the deterministic context verifier
          └───────┬────────┘
                  │  ScanResponse — severity + decision + every finding
          ┌───────▼────────┐
          │  hosts.rs      │   ScanResponse → that host's response schema
          └────────────────┘
```

The engine/policy split is deliberate: a differential divergence can always be
localised to one side of it. `engine.rs` never suppresses; `policy.rs` never
matches.

### Bash → Rust map

| Bash | Rust |
|---|---|
| the `HIGH_*` / `MED_*` / `LOW_*` arrays | `corpus.rs` ← generated `corpus/patterns.json` |
| `generate_views()` | `normalize.rs` |
| `run_batch_grep` + the `perl -CSD` / base64 / leetspeak passes | `engine.rs` |
| `web-safety-verify-context.sh` | `verify.rs` |
| the v8.4+ context gate, Layer 5, the emit chain | `policy.rs` |
| the hook's `jq` input/output expressions | `hosts.rs` |
| `record_session_hit`, the E8 sidecar, `arm_egress_guard`, `record_agent_kill`, the toast dedup | `state/` — see [state.md](./state.md) |

## One corpus, one source of truth

`engine/corpus/patterns.json` is a **generated artifact**.
`engine/tools/extract-corpus.sh` slices the arrays straight out of
`scripts/web-safety-scanner.sh` (and `INJECTION_KEYWORDS` out of
`scripts/web-safety-verify-context.sh`), and the Rust core `include_str!`s the
result. There is no hand-maintained second copy.

Drift is enforced rather than intended: `corpus::tests::corpus_matches_bash_source`
re-runs the extractor and fails if the checked-in artifact differs. A pattern
added to Bash without regenerating is a red test, not a silent coverage hole.

Because that drift check runs the extractor on every `cargo test`, the extractor
must **read** the scanner, never **run** it. Block reading is
`engine/tools/corpus-parse.awk`, a strict data parser for one grammar —
`NAME=(`, indented `"literal"` lines with `\"` and `\\` as the only escapes,
`)` — that rejects unquoted entries, unsupported escapes, two entries on a line,
trailing content, `$`/backtick substitutions, unterminated blocks, and duplicate
declarations. Nothing in a corpus source can expand or execute; the earlier
`eval`-based reader would run a `$(...)` in any array on every developer's and
CI's `cargo test`. `engine/tests/corpus_extractor.rs` proves this with sentinel
fixtures and exercises the parser against temporary sources rather than only the
production paths.

```
high     87 patterns across  3 arrays
medium  495 patterns across 14 arrays
low      21 patterns across  3 arrays
        603 engine literals   (+ 7 leetspeak, 11 gate registry, 12 injection keywords)
```

## The one regex rewrite

Rust's `regex` is a finite automaton: linear time, no backreferences, no
look-around. Exactly one production pattern needed a rewrite —
`web-safety-scanner.sh:392`, the view-1 collapse:

```perl
s{(?<![a-z])([a-z](?: [a-z]){3,})(?![a-z])}{...}ge
```

Both assertions are single-codepoint class tests, so `normalize::collapsed` is a
deterministic forward scan that reproduces perl's behaviour including the
one-step backtrack when the greedy run ends immediately before another letter
(`collapsed("a b c d ef") == "abcd ef"`).

**No backtracking engine was introduced anywhere.** `engine::tests::adversarial_input_stays_bounded`
holds the line: 180 KB of the shapes that hang a backtracking matcher, asserted
to complete in bounded time.

## Fidelity over elegance

Where Bash's tool is deliberately *not* Unicode-aware or deliberately
line-scoped, the port reproduces that exactly — quietly widening a view would
make the differential report agreement it has not earned.

- View 0 lowercases **ASCII only**, because `tr` in the C locale does.
- View 5 squeezes **plain spaces only** (`tr -s ' '`), unlike view 1's
  `tr -s '[:space:]'`.
- View 6 is **line-scoped**, because `sed 's/<[^>]*>//g'` cannot match across a
  newline — so a lone `<` never swallows the document.
- View 7 decodes on **bytes** and converts lossily, because perl produces a raw
  byte stream that production greps directly.

## Suppression layers

Each gate is KEEP-by-default; every uncertain case stays genuine. A cleared
finding is **retained** with its `disposition` and `reason` rather than deleted,
so an audit can see that suppression happened.

| Layer | Scope | Clears when |
|---|---|---|
| Context gate (v8.4+) | the 11 registry topic words, HIGH **and** MEDIUM | every occurrence is descriptive prose, per the directive verifier |
| Control-token gate (v8.8) | `HIGH_LLM_TOKENS` | every occurrence sits in an **inline** quote or a string VALUE |
| Layer 5 (v4.2) | `MED_GENERIC_DELIMITERS`, only when no HIGH survives | the first occurrence is structurally enclosed |
| Emit reclassification (v8.9/v8.11) | LOW notes | the LOW set is *only* notes (truncation caveat, topic labels) |

Two non-obvious rules the port preserves:

- The context gate runs **before** the tier verdict, which is the only reason it
  reaches HIGH `exfiltrate`; Layer 5 is gated on `HIGH == 0` and never sees it.
- The control-token gate refuses to clear a token alone on a fenced line. That
  shape is "enclosed" but still a functioning template boundary — the
  fence-to-evade class — and its imperative body may dodge every MEDIUM pattern.

## Contract

`contract.rs` is versioned (`schema_version`, currently `1`). Additive
`Option`-typed fields do not need a bump; changing the meaning of an existing
field does. A `schema_version` the build does not speak is a
`ContractError`, never a silent allow.

Fail-closed at the boundary: a malformed envelope exits `2` **and** writes the
host's containment response to stdout, so a caller that ignores the exit code
still gets containment rather than silence.

`hosts::to_request` returns `Result`. It substitutes nothing: a missing
`tool_name`, a missing output field, or an output field that cannot carry tool
output (`null`, a number, a boolean) is a contract error rather than the
`"unknown"` / empty content it used to become — which turned an envelope the
adapter could not read into a clean verdict. An **explicitly** empty output
(`""`, `[]`, `{}`) is a real result and still scans.

Codex is no longer provisional: its mapping is read off the
`post-tool-use.command.input` JSON Schema embedded in a local Codex CLI 0.144.1
binary (frozen under `engine/tests/fixtures/codex-0.144.1/schema/`), and that
schema is `additionalProperties: false` with THIRTEEN declared properties, of
which eleven are REQUIRED. So the posture is unchanged but the reason is
stronger: a missing required field, a `hook_event_name` other than
`PostToolUse`, or a `permission_mode` outside the host's closed enum is a
contract error rather than a scan under a contract nobody validated.
`transcript_path` is required by the host, type-checked, and never read — it
points at hostile conversation metadata.

`additionalProperties: false` is a claim about the WHOLE document, and a mapping
that only enumerates what it READS cannot make it — an unknown key is silently
discarded and the scan proceeds under a contract that has changed. So the
allowed key set is enumerated exactly and anything outside it is a contract
error, even when the tool output is clean.

The same applies to the two OPTIONAL properties. Optional is a statement about
presence, not about type: `agent_id` and `agent_type` are both typed `string`,
so a wrong-typed or explicitly null one is a contract error rather than a field
dropped to absent. That distinction is load-bearing for `agent_id`, because
absent is a DIFFERENT and weaker correlation scope than present — silently
widening it is the failure mode. `agent_type` is a class label with no identity
meaning; it is never read as one, and never backfilled into `agent_id`.

Hermes stays provisional and therefore strictest by assumption: its accepted
field names are an enumerated list, and running off the end of it is an error,
not a fallback.

### Two limits, not one

| Control | Bounds | Default | Lifted by |
|---|---|---|---|
| `--max-scan-bytes` | how much content is **scanned** | 65536 | `--no-cap` |
| `--max-envelope-bytes` | how much stdin is **allocated** | 1048576 (ceiling 67108864) | nothing |

The envelope limit is a resource control, enforced while reading stdin and
*before* JSON parsing, so an oversize envelope is rejected without ever being
buffered or expanded into a `Value` tree. `--no-cap` widens what is scanned and
deliberately does not lift it. Flattening object/array output appends into one
budgeted buffer rather than cloning every leaf into a `Vec<String>` and
allocating the join on top; recursion stays bounded because `serde_json`'s
parser enforces its own depth limit. The default leaves roughly 4x headroom over
the approved 256 KB benchmark envelope.

A response that cannot be written or flushed exits `74` (`EX_IOERR`) instead of
`0`: a verdict — above all a containment verdict — that never reached stdout
must not be reported as a completed scan.

### Task identity

`ScanRequest.task_id` is the host's task/execution dimension — Claude's
`prompt_id` (v2.1.196+). It is additive and `Option`-typed, so it needs no
version bump, and it feeds the state scope key's `task` slot directly.

Absent is a real value with its own bucket; nothing is ever backfilled from the
session id. When the host reports a task id **and** `--state-task` supplies a
different one, that is a `ContractError` rather than a precedence question: the
two disagree about which execution the call belongs to, and choosing either
would file it under a scope its own runtime does not recognise. Agreeing values
are fine, and the override still exists for a runtime that exposes no task field
(Hermes reads none, because no field name is certified for it yet). Codex
reports `turn_id`, which its own schema documents as the active turn id, and
that is the task scope.

## Sanitization

`sanitize.rs` owns what the model reads *after* something fires — the contract
Bash implements in `sanitize_content()` and `emit_search_quarantine()`. It is in
the shared core, not in an adapter, so all three runtimes withhold and redact
identically.

| Tier | Plan |
|---|---|
| clean / INFO / LOW / trust-downgrade | none — the original result is delivered untouched, and no digest is computed |
| MEDIUM | `redact` — line-oriented surgical redaction, one shared 50 KB cap |
| HIGH, escalation, quarantine, enforced state failure | `withhold` — the whole result, replaced by a bounded static receipt |

The receipt carries a line count, a 12-hex digest prefix and a finding count. It
never carries a matched literal — and it carries **no tool label and no URL at
all**.

Both used to be there, each behind a syntactic check: an `[A-Za-z0-9_-]`
allowlist for the label, an origin parse for the URL. Both checks answered the
wrong question.

* `ignore_previous_instructions` is wholly inside that allowlist, and it is a
  complete instruction phrase. Separating words with `_` or `-` costs an
  attacker nothing. Character safety is not semantic prompt safety.
* `ignore-previous-instructions.example` is a syntactically valid DNS hostname,
  and so is a punycode label, a tracking identifier, or an internal subdomain
  leaked out of a private URL. Parsing a URL down to its origin does not make
  the origin safe to show a model.

So both are **omitted, not filtered**. Not hashed, not shortened to a
registrable domain, not replaced by a partial label — every one of those emits a
derivative of an attacker-chosen string, which is still attacker-chosen. Fixed
text plus the two non-instructional forensic identifiers is enough: the model
needs neither value to obey the receipt.

The same omission applies to every other model-facing string on every host —
`systemMessage`, `stopReason`, `additionalContext`, the Codex `reason`, and the
Hermes annotation and replacement body all come from a summary that is now
`web-safety: <SEVERITY> (<n> finding(s))` and nothing more. `tool_name` survives
inside the encoder only as the SHAPE selector that picks a replacement schema;
it never reaches the document.

The operator loses nothing: the raw envelope, with the tool name and the full
URL, still reaches the `--emit report` channel, which is operator-invoked and is
never returned to a host.

`engine/tests/envelope_provenance.rs` holds the whole-document property — every
host encoder, every containment tier, zero occurrences of the supplied label,
hostname, path, query, fragment or identifier.

### Three deliberate tightenings over Bash

Every one of these is a case where Bash delivers content and the Rust core does
not. `tests/run-sanitizer-differential.sh` counts them: **83 payloads, 72
identical decisions, 11 tightenings, 0 weakenings, 0 leaks** — and the 11 are all
the first rule below.

1. **A MEDIUM only a normalized view can see withholds everything.** Bash
   redacts by `grep -F`-ing each matched literal against the raw line, so a
   finding that exists only in a decoded, collapsed or confusable-folded view
   matches no line at all — and Bash then passes the attack line through
   unredacted. Here an unmappable MEDIUM escalates to a full withhold. The 11
   differential tightenings are exactly the `med-evasion-*` family plus
   `med-line-split` and `evasion-survives-suppression`.
2. **No matched literal ever reaches the model.** Bash writes
   `[REDACTED: matched '<pattern>']` into the sanitized body and lists matched
   patterns in its `systemMessage` and `stopReason`; the pattern IS
   attacker-chosen text. Nothing the Rust core emits contains it — the marker is
   the fixed `[REDACTED: line matched an injection pattern]`, and the operator's
   log keeps the detail.
3. **The 50 KB cap is a cap.** Bash checks the cap *before* appending and then
   appends the whole line, so one 200 KB line sails 150 KB past it. Here a line
   that will not fit is truncated on a character boundary and the pass stops.

The digest is taken over the scanned content exactly; Bash's is taken over the
content plus the newline `echo` adds, so the two hashes differ by that byte and
the differential compares decisions and line accounting rather than digests.

## Claude Code 2.1.220 response encoding

The Claude branch of `hosts::encode_response` targets the **current** hook
schema, verified against both the official reference and a live 2.1.220 capture
(`engine/tests/fixtures/claude-2.1.220/`). What the host actually offers a
`PostToolUse` hook, and what each lever is worth:

| Lever | Worth |
|---|---|
| `hookSpecificOutput.updatedToolOutput` | the only way to change what the model reads — and it must match the tool's output shape, or it is **silently ignored** |
| `decision: "block"` | stops the agentic loop; does **not** withhold the result |
| `continue: false` + `stopReason` | stops the turn outright; needs no knowledge of the shape |
| exit `2` | shows stderr to the model; cannot replace anything |

So the encoder replaces when it knows the shape and stops when it does not, and
it never emits a replacement that might be ignored. `decision: "block"` is not
used at all: relying on it was the Stage-4 mistake this stage replaces.

| Outcome | Document |
|---|---|
| allow | `{}` |
| note | `systemMessage` only; the original result stands |
| MEDIUM | `updatedToolOutput` (redacted) + `continue:false` + bounded `stopReason` |
| HIGH / escalation | `updatedToolOutput` (withheld) + `continue:false` + bounded `stopReason` |
| quarantine | `updatedToolOutput` (withheld) + `systemMessage`; **no** stop — the agent keeps working |
| enforced state failure | shape-preserving withheld output + stop |
| unknown shape, any containment tier | stop only, no replacement |

### Shapes are recognised by EXACT key set

Shapes are recognised by tool name *and* structure, and the structure match is
exact: the same keys the live capture emitted, the same JSON types, no more and
no less — recursively, including a `WebSearch` result's nested `content`
entries. A `WebFetch` result that is not the observed object — a bare string,
for instance, which 2.1.220 was never seen to return — is unknown; so is one
carrying an extra key a future version adds. Unknown fails closed. For a
quarantine that means a deliberate escalation from "the agent survives" to "the
turn stops".

Exactness is the point. A subset check ("does it have `result` and `code`?")
recognises a shape whose *other* leaves were never inspected, and the encoder
then clones the hostile object and patches the leaves it did look at. That is
how a HIGH planted in `codeText` survived into a result the same document
claimed had been withheld.

### A withheld replacement is BUILT, never cloned

For any full-withhold outcome the replacement is constructed from constants.
The only thing taken from the original is its *structure* — which keys, how many
array elements, which element is a string — because a replacement whose shape
the host rejects is silently ignored, and an ignored containment is none.

Every string leaf in it is one of exactly four things: the bounded forensic
receipt, a fixed discriminator the host's own validator requires (`"text"`), the
non-routable placeholder `https://withheld.invalid/` for a URL-typed field, or
the fixed token `[withheld by web-safety]`. Numeric timing, status and count
fields become fixed safe values. No string is carried over because it "looked
like metadata".

Structure is preserved rather than reduced — a `WebSearch` `results` array comes
back with the same length and the same per-element kinds, its nested objects
rebuilt slot-for-slot — since reducing it is what an unpublished host validator
is most likely to reject. The corollary is that a `results` array with no string
element has nowhere to put the receipt, and that too fails closed.

### The leak check covers the whole document

Every containment document is checked before it leaves, against **every kept
finding's literal at every severity** — not only the MEDIUM ones a redaction
pass was driven by. That distinction is the bug: a HIGH plans a withhold and
therefore has no MEDIUM patterns, so the old check ran against an empty set and
answered "nothing survived" without looking.

The check runs over two views, and over the whole native document —
`updatedToolOutput` recursively, `additionalContext`, `systemMessage`,
`stopReason`:

* **per leaf**, which catches the ordinary case; and
* over the **space-joined flattened view**, the same one `to_request` builds,
  which catches a payload split across sibling JSON leaves — adjacent only once
  the document is joined, and invisible to line-oriented redaction.

The escalation ladder is: surgical redaction → full withhold → replacement-free
stop → a `hard_stop()` document with no variable parts at all. For a MEDIUM this
is also the mapping proof, stated as an outcome instead of an analysis: a
literal that lived only in a metadata leaf, a discriminator, a URL or a split
representation is still present in the surgical candidate, so the candidate is
discarded and the whole result withheld.

`engine/tests/claude_conformance.rs` asserts this as a property, not a
worked example: a unique hostile sentinel is placed in **each string leaf of
each captured fixture in turn — 66 leaf/case combinations** — and for every one
the sentinel must appear zero times in the complete serialized hook output.

Those sentinels are markup-bearing, which is what made them visible to a
character check in the first place. `engine/tests/envelope_provenance.rs`
covers the complementary class — probes that are deliberately allowlist-CLEAN,
a bare identifier and a bare hostname — across **all three host encoders and all
five containment tiers** (HIGH, MEDIUM/Ask, quarantine, Note, typed state
containment), asserting zero occurrences of the supplied label, hostname, path,
query, fragment or identifier in the complete serialized response. **422 encoded
documents** over 13 tests; each test reports its own share under `--nocapture`,
so a matrix that quietly shrinks is visible rather than silently passing. It
also pins the other direction: the digest prefix and the bounded counts must
still arrive, so omission is never achieved by emitting nothing.

## Running it

```bash
cd engine
cargo test                                    # 446 tests
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release                         # target/release/web-safety-engine

echo '{"tool_name":"WebFetch","tool_response":"hello"}' \
  | target/release/web-safety-engine scan --host claude --emit report
target/release/web-safety-engine info
```

```bash
tests/run-differential.sh                                   # Bash vs Rust, 83 payloads
tests/run-differential.sh --cases-only --max-scan-bytes 1024  # truncation-note parity
tests/run-state-differential.sh                             # Bash vs Rust, 32 sequences
tests/run-sanitizer-differential.sh                         # Bash vs Rust, 83 sanitizations
tests/run-claude-conformance.sh                             # dormant adapter, 51 host cases
engine/tools/bench.pl --samples 40                          # cold-start latency gates
engine/tools/bench.pl --samples 40 --state                  # …with the state layer on
```

## State

Persistent correlation and containment state lives in `src/state/` and is
documented separately in **[state.md](./state.md)**: a bundled SQLite store with
WAL and short `BEGIN IMMEDIATE` transactions, a versioned schema, `off` /
`report` / `enforce` modes (default `off`), and typed failure semantics that
never degrade into a silently-stateless run.

Three properties of that layer are load-bearing enough to repeat here:

* the scope key is **runtime + namespace + session + task + agent**, session and
  namespace are mandatory outside `off`, and nothing is ever substituted for a
  missing identity — an unidentifiable call is refused *before* the store is
  opened, so it cannot land in a bucket shared with unrelated calls;
* the state root is validated component by component against symlink, ownership,
  permission and link-count redirection, and the object SQLite opened is
  re-checked afterwards. The residual same-UID active-mutation limitation is
  stated in [state.md](./state.md) and production cutover stays blocked on the
  containment gate that closes it;
* a database whose key shape this build cannot interpret is refused, never read
  on a best-effort basis.

Since v9.0.0 the Claude hook sites run it in **report mode**
(`--state-mode report --state-dir ~/.claude/hooks/engine-state`): transitions
apply — arming, strikes, the kill ledger — and a state failure is reported
rather than contained, which is the same fail-open posture the Bash `/tmp`
arm-files had. `enforce` stays un-wired pending the containment gate below.

## Codex containment is a block, never a rewrite

Codex 0.144.1 PARSES `updatedMCPToolOutput` and `suppressOutput` and then
refuses to honour either: the runtime answers with "PostToolUse hook returned
unsupported …", fails the hook, and processes the ORIGINAL tool output. So this
host has no supported way to hand the model a sanitized copy of a result, and a
document carrying one of those keys is worse than no document at all.

What it does have is `decision: "block"` — the only value its `BlockDecisionWire`
accepts — which replaces the model-visible result with the hook's `reason` and,
in code mode, rejects the nested tool promise so the original never reaches the
script. A MEDIUM is therefore delivered as a block WITHOUT a stop (result
replaced, turn survives) rather than as the surgical redaction the Claude
encoder can perform. That is a host capability difference, not a policy
difference: `sanitize.rs` plans the same replacement for both, and the Codex
encoder simply cannot deliver the redacted variant.

`agent_id` is OPTIONAL in the Codex envelope, so absence is indistinguishable
from a subagent that did not report. A stateful Codex call without one is a
typed identity failure rather than a shared correlation bucket — the MAC-21
rule, applied to a host whose identity contract cannot prove isolation.

## Out of scope for this stage

Production hook wiring and any default cutover, the final Hermes adapter
conformance, PyO3, Docker/iron-proxy configuration, and release packaging. The
Hermes envelope shape in `hosts.rs` is still provisional and needs conformance
tests against the real schema before it ships.
