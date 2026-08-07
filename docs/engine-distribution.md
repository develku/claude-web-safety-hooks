# Engine distribution decision

**Status:** DECIDED · **Owner:** Kuvis/coding · **Date:** 2026-08-07
**Scope:** how the shared Rust `web-safety-engine` gets to the Hermes adapter, and how the
fail-closed grey-out stays diagnosable. Applies to the dormant Stage 5C adapter in
`adapters/hermes/` and the engine source in `engine/`. This is a *staged* decision — local
commit only, nothing enabled or pushed.

---

## The problem being solved (R3)

Stage-1 audit **R3 (MED)** called out: *hardcoded engine path + fail-closed grey-out, no
doctor.* Concretely:

- The adapter locates the engine deterministically (`adapters/hermes/__init__.py:95-110`):
  `WEB_SAFETY_ENGINE` override first, else `<repo>/engine/target/release/web-safety-engine`.
- When that binary is missing, not executable, times out, or returns anything the host
  would discard, the adapter **withholds the tool result** and returns the single fixed
  `CONTAINMENT` string (`__init__.py:65-69`).

The consequence: an operator who enables the plugin and then sees every tool result replaced
by the containment string cannot tell **why**. Is the engine genuinely flagging malicious
content (a scan hit — keep it contained), or is the engine simply absent/misconfigured so
every call fails closed (an ops bug)? The two demand opposite responses, and today the only
visible signal is identical for both.

The decision below is about making that failure **diagnosable without weakening the
grey-out itself** — because the grey-out string must stay uniform (see "A constraint that
rules out one naive fix" below).

---

## The three options

### 1. Build-in-tree (source ships; built at enable/install time)

The Rust source lives in `engine/` (already true post-R1). The operator builds it with the
pinned toolchain (`rust-toolchain.toml` pins **exact** `1.97.1`; `Cargo.lock` authoritative;
CI builds `--locked`). The adapter points at the deterministic build output.

### 2. Prebuilt binary (compiled artifact shipped/committed)

A `web-safety-engine` binary is committed to the repo (or attached to an install) so an
operator need not compile.

### 3. `WEB_SAFETY_ENGINE` env override (operator points the adapter at an explicit path)

Already implemented and checked **first** in `_engine_path()`. The operator names the byte
path of whatever engine they want.

These are **not** mutually exclusive — 3 already coexists with 1 as an escape hatch. The
decision is which is the *primary distribution mechanism* and what each contributes to
diagnosability.

---

## Decision

**Primary: build-in-tree.** The engine distributes as versioned source, built at
enable/install time from the pinned toolchain. The deterministic default path is
`<repo>/engine/target/release/web-safety-engine`.

**Retained escape hatch: `WEB_SAFETY_ENGINE`.** Keep it, checked first, as the documented
operator override for a custom build, a staged rollout, or the test harness (the smoke test
already uses it). It is an override of the default, not a replacement for it.

**Rejected for this phase: prebuilt binary.**

---

## Implementation status (R3)

**Mechanism: IMPLEMENTED + VERIFIED, staged/dormant — local commit only, no enable, no push.**

The build-in-tree mechanism is not new code to write; it is the resolve order
already present in `adapters/hermes/__init__.py::_engine_path()`, which this stage
confirms is the distributed mechanism and verifies against the real in-tree build:

- **Resolve order = exactly as specified** (`adapters/hermes/__init__.py:150-165`):
  `WEB_SAFETY_ENGINE` override first; else the deterministic in-tree default
  `<repo>/engine/target/release/web-safety-engine`; PATH is never searched.
- **Verified against the real build** (toolchain `1.97.1` matches the pinned
  `rust-toolchain.toml`; binary present and executable):
  - no override ⇒ resolves to the in-tree build path (exists + `X_OK`) ✓
  - bogus override ⇒ returns `None` → `CONTAINMENT` (fail-closed, M1) ✓
  - valid override ⇒ prefer the operator path ✓
  - engine `info` healthy (`schema_version:1`, `version:0.1.0`) ✓
- **Grey-out stays uniform.** `_scan()` returns the single fixed `CONTAINMENT` string
  (never `None`) on every failure; the string never says *why*. Diagnosability is
  out-of-band by construction — an out-of-band doctor reproduces `_engine_path()`
  and probes the resolved binary across the M1–M5 table below.

---

## Why build-in-tree

### Diagnosability — the decisive axis

The grey-out becomes diagnosable because **the engine location is a pure, reproducible
function of the repo** (`__file__` → `parent.parent.parent / engine / target / release /
web-safety-engine`). A doctor diagnostic can therefore enumerate, in resolve order, every
failure mode the adapter can hit and pair each with an actionable remediation:

| # | Resolution step | Grey-out cause | Doctor can see | Actionable fix |
|---|---|---|---|---|
| M1 | `WEB_SAFETY_ENGINE` set | override set but not executable/missing | path is set; `os.path.isfile`/`os.access` fail | unset it, or fix the path |
| M2 | default path | engine **not built** | expected file absent | `cd engine && cargo build --release` |
| M3 | default path | built but not `+x` | file present, exec bit off | `chmod +x engine/target/release/web-safety-engine` |
| M4 | default path | built but contract/broken at runtime | `info` runs, a probe `scan` fails / non-zero / timeout / malformed stdout | rebuild from pinned `Cargo.lock` |
| M5 | default path | wrong toolchain drift | `info` schema_version ≠ adapter contract | rebuild pinned; bump `rust-toolchain.toml` deliberately |

Every row is a **deterministic, independently checkable fact** because the expected path and
the expected behavior of a correct build are both fixed by the repo. The doctor reproduces
the identical path the adapter will use and tests the exact binary — no guessing about
where the engine "ought" to be.

### Maintainability

- **Version-locked builds.** Exact toolchain + authoritative `Cargo.lock` ⇒ the same source
  compiles to the same binary on every machine. No silent drift between the adapter's
  expected contract and the engine it calls.
- **One command to (re)build** (`cargo build --release`). A broken engine is repaired, not
  replaced.
- **No platform matrix during the dormant phase.** Prebuilt artifacts would need per-OS/arch
  binaries and a release pipeline we are explicitly not standing up yet.

### Staying staged/dormant

- **Keeps binaries out of git**, consistent with the repo's own hygiene: `.gitignore`
  ignores `engine/target/` with the note *"a plain `git add -A` after a build cannot publish
  binaries"* (`.gitignore:19-23`). Committing a binary would directly contradict this and
  risk the exact 1.9 MB near-publication incident `82dfb1d` fixed.
- **No CI/push required.** Everything ships as source in a local commit. A binary is a
  *release-time* decision for a later, operator-approved phase, not a dormant-stage one.
- **No supply-chain surface.** A committed binary is an opaque blob with no diff, no
  provenance, and no rebuild path — exactly the audit liability R3 exists to avoid.

---

## Why not prebuilt binary

1. **Harms diagnosability.** With a blob, there is no reproducible expected path, no `cargo
   build` remediation, and cross-machine/arch mismatches (e.g. `EXEC format error`) surface
   as opaque grey-outs with no rebuild recovery. Every diagnosability row in the table above
   depends on "we can rebuild the exact engine from pinned source."
2. **Harms maintainability.** Binary/adaptor version skew is silent; the project's whole
   reliability story is pinned builds, which a blob throws away.
3. **Violates the dormant constraint.** Binaries in git contradict the explicit
   `.gitignore` stance and are a release-time artifact.

---

## A constraint that rules out one naive fix

It is tempting to make the containment string *say why* ("engine missing" vs "threat
found"). **Do not.** The grey-out string is deliberately uniform and self-describing only as
a fixed non-quoting notice (`__init__.py:55-69`): it never quotes or summarizes the content
it stands in for, so it is safe on every path. Making it conditional would let a caller
distinguish "scanned and clean-but-withheld" from "not scanned" — a **fail-open leak** that
informs an attacker whether they were filtered. Diagnosability therefore lives in an
**out-of-band doctor**, never in the returned string. Build-in-tree is what makes that doctor
complete and deterministic.

---

## Handoff to dependent work

- **`t_bdd8cb62` (implement distribution):** keep resolve order — `WEB_SAFETY_ENGINE` first,
  then the deterministic in-tree default; never PATH search (`__init__.py:95-110` already
  correct). No change required to the resolve order; the mechanism is already build-in-tree
  + override. Implementation work = documentation + any hardening, not a new mechanism.
- **`t_6a609b27` (doctor diagnostic):** implement the M1–M5 table above as a local command
  that reproduces `_engine_path()` exactly, probes the resolved binary (`info` + a benign
  probe scan), and prints the actionable remediation for each failure. Output must be
  actionable (a shell command the operator can run), never a bare "engine missing."

---

## Rollback

This is a **documentation decision** — no hook config, no runtime, no `~/.hermes` tree
touched. Deleting `docs/engine-distribution.md` returns the repo to pre-decision state; no
runtime plugin config exists to undo.
