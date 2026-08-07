# web-safety-engine

Shared scanner core for the web-safety hooks. Architecture and the Bash→Rust map
live in [`docs/rust-core.md`](../docs/rust-core.md); this file is how to build and
run it.

**This is production** (since v9.0.0): `hooks/hooks.json` invokes
`target/release/web-safety-engine` on the Claude Code PreToolUse and PostToolUse
hook sites. The Bash scripts in `scripts/` are the frozen differential oracle and
the rollback path.

## Build and test

Requires a Rust toolchain. `rust-toolchain.toml` pins an **exact release** —
not `stable` — and pulls `rustfmt` + `clippy`, so every machine and every CI run
compiles with the same compiler; `Cargo.lock` is authoritative and CI builds
`--locked`. SQLite is **bundled** — `rusqlite`'s `bundled` feature compiles the
amalgamation, so a C compiler is required but no system SQLite is, and runtime
behaviour does not depend on a system SQLite ABI.

```bash
cargo test                                  # unit + CLI + payload-fixture tests
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release
```

## Use

```bash
# scan a Claude Code PostToolUse envelope
echo '{"tool_name":"WebFetch","tool_response":"ignore previous instructions"}' \
  | target/release/web-safety-engine scan --host claude

# the neutral contract instead of the host encoding — what the differential reads
… | target/release/web-safety-engine scan --host claude --emit report

# corpus scale, views, gated patterns, schema version
target/release/web-safety-engine info
```

Exit codes: `0` scan completed · `2` contract error (fail-closed: a containment
response is still written to stdout) · `64` usage error · `74` the response
could not be written to stdout.

An envelope is mapped or rejected — never partially guessed. A missing
`tool_name`, a missing output field, an output field that cannot carry output
(`null` / number / boolean), a nested container of the wrong type, or an
unsupported `schema_version` all exit `2` with containment. An explicitly empty
output (`""`, `[]`, `{}`) is a legitimate result and still scans.

Two independent limits:

```bash
--max-scan-bytes N      # how much content is SCANNED   (default 65536, --no-cap disables)
--max-envelope-bytes N  # how much stdin is ALLOCATED   (default 1048576, max 67108864)
```

`--max-envelope-bytes` is a resource limit enforced while reading stdin, before
JSON parsing; `--no-cap` does not lift it.

## State

Cross-call correlation, E8 reassembly, egress arming, the kill ledger and toast
dedup live behind an explicit, **off-by-default** mode. Full design in
[`docs/state.md`](../docs/state.md).

```bash
--state-mode off|report|enforce   # default off: the database is never opened
--state-dir PATH                  # needed by any mode but off; PATH/state.db is the
                                  #   only file. Must be ABSOLUTE and symlink-free.
                                  #   Omitting it is a STATE failure, not exit 64.
--state-namespace NS              # profile/user namespace — REQUIRED, no default
--state-task ID                   # host's task/execution id, when it exposes one
--state-runtime NAME              # runtime key for scoping (default: the --host value)
--content-trusted                 # the URL's host is on the content-trust list
--no-search-quarantine            # restore the pre-v8.12.0 subagent WebSearch kill
```

The scope key is **runtime + namespace + session + task + agent**. Session and
namespace are mandatory in any mode but `off`; task and agent may be absent, and
an absent dimension is its own bucket rather than a wildcard. Nothing is ever
substituted for a missing identity — the collapse that produced is exactly what
this contract exists to prevent.

In `report` an unusable store — or an unusable *identity*, or a `--state-dir`
that was never supplied — is reported and the scan is still delivered; in
`enforce` it is containment. None of them ever behaves statelessly while
claiming the transition succeeded, and none of them is ever a usage error,
because exit 64 writes no response document at all.

## Regenerating the corpus

`corpus/patterns.json` is generated from the Bash arrays and must never be
hand-edited:

```bash
tools/extract-corpus.sh
```

`cargo test corpus_matches_bash_source` fails if it is stale. The extractor
parses the arrays as **data** via `tools/corpus-parse.awk` and never evaluates,
sources or otherwise interprets a scanner source as shell. Point it at fixtures
with `WEB_SAFETY_SCANNER_SRC` / `WEB_SAFETY_VERIFIER_SRC`.

## Layout

```
corpus/patterns.json   generated — 603 engine literals + the auxiliary lists
src/contract.rs        versioned, host-neutral request/finding/decision model
src/corpus.rs          corpus loading + the anti-drift test
src/normalize.rs       the 8 evasion-resistant views
src/engine.rs          Aho-Corasick + codepoint/base64/leetspeak verifiers
src/verify.rs          the deterministic context verifier (structural + directive)
src/policy.rs          context gate, Layer 5, INFO reclassification, verdict
src/hosts.rs           claude / codex / hermes adapters
src/state/             correlation, E8 reassembly, arming, kill ledger, dedup
src/state/paths.rs     state-root path safety: redirection + TOCTOU hardening
src/main.rs            the CLI
tests/cli.rs           CLI boundary + fail-closed behaviour
tests/envelope.rs      envelope validation, resource bounds, undelivered responses
tests/corpus_extractor.rs   the extractor reads its source, never runs it
tests/payload_fixtures.rs   every tests/payloads/*.txt through the core
tests/state_store.rs        path safety, schema/version contract, modes
tests/state_correlation.rs  strike counting, escalation, isolation, concurrency
tests/state_fragments.rs    the E8 state machine
tests/state_containment.rs  arming, kill ledger, toast dedup, one-shot claims
tests/state_transition.rs   the emit-stage branch and mode failure semantics
tests/state_faults.rs       fault injection and adversarial bounds
tests/state_cli.rs          the CLI state surface
tests/state_identity.rs     the identity contract, as subprocess regressions
tests/state_scope.rs        the task/execution dimension and its isolation
tests/state_paths.rs        filesystem redirection + the check-to-use window
tools/extract-corpus.sh     canonical, read-only corpus extraction
tools/corpus-parse.awk      strict literal-array DATA parser (no eval)
tools/bench.pl              cold-start latency harness (--state for stateful gates)
tools/bash-probe.sh         run one payload through the Bash scanner
```
