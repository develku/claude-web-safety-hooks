# Correlation and containment state — architecture

Stage 3 shipped a **stateless** scanner: one envelope in, one verdict out. Four
of the Bash scanner's protections cannot be expressed that way, because they are
statements about a *sequence* of calls rather than about one page:

| Bash | Rust |
|---|---|
| `record_session_hit` + the 3-strike escalation | `state::correlation` |
| the E8 fragment sidecar and its reassembly pass | `state::fragments` |
| `arm_egress_guard` / the Layer 6 armed window | `state::arm` |
| `record_agent_kill`'s `[PENDING-KILLED]` rows | `state::ledger` |
| the `{severity + content-hash}` toast dedup | `state::notify` |
| the emit-stage branch that drives all of the above | `state::event` |

**Since v9.0.0 the Claude hook sites run this layer in `report` mode**
(`hooks/hooks.json` passes `--state-mode report --state-dir
~/.claude/hooks/engine-state --state-namespace default`): transitions apply and
a state failure is reported, never contained — the same fail-open posture as
the Bash `/tmp` arm-files it replaces. The CLI default stays `off`, `enforce`
stays un-wired (see the containment gate below), and the Bash scripts remain
the frozen differential oracle and the rollback path.

## Modes

| Mode | Database | What a state failure means |
|---|---|---|
| `off` (default) | never opened, created or read | n/a — nothing runs |
| `report` | used | the scan is still delivered; `state.applied=false` and `state.error` is set. It never claims a failed transition succeeded. |
| `enforce` | used | typed containment: the response becomes HIGH / `block` with `state.containment=true` |

`enforce` contains rather than degrading because a call whose correlation state
is unreadable *cannot know it is not the third strike*, and reporting the weaker
verdict would be a fail-open.

```bash
web-safety-engine scan --host claude --emit report \
  --state-mode report --state-dir /Users/me/.claude/hooks/state \
  --state-namespace profile-a [--state-task task-17]
```

`--state-dir` is needed by any mode but `off`, and must be an **absolute,
symlink-free** path (see "Filesystem safety"). Omitting it is a **state
failure**, handled exactly like an unusable store: `report` delivers the scan
with `state.applied=false` and an error naming the missing state directory,
`enforce` contains, and neither exits 64 — see "Failure and containment
behaviour" below.
`--state-namespace` is likewise required and has **no default**. `--state-task` carries the host's task /
execution id when it exposes one. `--state-runtime` overrides the runtime key
(default: the `--host` value). `--content-trusted` and `--no-search-quarantine`
mirror the operator switches the Bash scanner reads from `url-content-trust.txt`
and `WEB_SAFETY_SEARCH_QUARANTINE_DISABLE`.

## The scope key

Every key carries **runtime + namespace + session + task**, plus the **agent**
where an agent-level distinction exists:

| State | Scope | Why |
|---|---|---|
| strikes (`hits`) | runtime + namespace + session + task + **agent** | a parallel fan-out's false-positive noise must not mass-escalate the fleet; the main session is its own bucket (`agent_id = ''`) |
| E8 fragments, fired patterns | runtime + namespace + session + task | split-payload evidence is *content* evidence: a fan-out that hands one half to each of two subagents is the attack, so reassembly is cross-agent **inside one task** and never leaves it |
| armed window | runtime + namespace + session + task | a subagent's HIGH must arm the window its parent's outbound calls are checked against |
| kill ledger | runtime + namespace + session + task + **agent** | the row exists to attribute one specific agent's death |
| notification dedup | runtime + namespace + session + task | collapsing a burst *across sibling subagents* is the entire purpose |
| one-time claims | runtime + namespace + session + task | approvals are an execution fact |

**There is no cross-task state.** Two tasks running under one long-lived session
share nothing: not strikes, fragments, the armed window, the ledger, dedup or
one-shot claims. That is the default safe direction, and it is a property of the
`UNIQUE` constraints on both scope tables rather than of any calling convention.
Any future exception has to be added to this table before it is added to code.

### Absent dimensions are buckets, not wildcards

Task and agent are the two dimensions a host may legitimately leave out. Both
are stored as `''` when absent — and `''` is a *scope of its own*. A host that
reports no task shares state only with other calls the same host reported the
same way; it never joins, or matches, a named task. A host that exposes only a
session id is at exactly Bash's granularity, which is a supported deployment.

What is **not** supported is inventing the value. A task id is never derived
from the session id, from the pid, or from anything else, because a derived
identifier is indistinguishable from a real one to every layer above it.

### Session and namespace are mandatory

Session identity and namespace are **required in every mode but `off`**. There
is no default namespace and no synthetic session:

* a missing or empty `session_id` is `StateError::InvalidIdentity`;
* a missing or empty namespace is the same;
* the failure is produced **before the store is opened** — the database is not
  created, no table is read, and nothing is written. A call that cannot be
  identified leaves no trace, because there is no shared bucket for it to leave
  a trace in.

This is the fix for the collapse MAC-21 found: every call without a session id
used to land in one literal `no-session` bucket, so three unrelated calls
accumulated one another's strikes and the third escalated to HIGH.

An identity failure is a **state** failure, never a usage error. `report` keeps
the stateless verdict and sets `state.error` with `applied=false`; `enforce`
returns HIGH / `block` with `containment=true`. Exiting 64 would write no
document at all, and a host that reads "no document" as "allow" would turn the
strictest mode into the only fail-open in the CLI.

### Untrusted identity

Session ids, task ids, agent ids and namespaces come from the harness and are
attacker-influenceable.

* They **never** reach a path. The database path is fixed: `<state-dir>/state.db`.
* They **never** reach SQL text. Every value is a bound parameter.
* They are **validated, not rewritten.** Bash strips a session id to
  `[A-Za-z0-9_-]` and truncates at 64, which silently maps two distinct sessions
  onto one bucket. Here an id outside the contract — empty, longer than the
  bound, `.`/`..`, or carrying `/`, `\`, whitespace or a control code — is
  `StateError::InvalidIdentity`. Collapsing unrelated executions into a shared
  bucket is exactly the failure this layer exists to prevent, so it is refused
  rather than papered over.

**Residual, stated plainly:** a runtime that can vary the task id it reports can
fragment its own correlation state and never reach three strikes. Task id is
trusted exactly as far as session id is — it comes from the adapter, not from
scanned page content — so this is a property of a compromised *adapter*, not of
a hostile page. An adapter must report the host's real execution id or none.

Metadata is the opposite: tool names, URLs and detector labels are
control-stripped and length-bounded rather than refused, because a detector
label legitimately contains arbitrary matched text and losing the audit row
would be worse than storing a truncated one.

## Schema

`PRAGMA user_version` carries `STATE_SCHEMA_VERSION` (currently **2**).

```
scopes(id, runtime, namespace, session_id, task_id, agent_id)  UNIQUE(all five)
session_scopes(id, runtime, namespace, session_id, task_id)    UNIQUE(all four)
hits(id, scope_id→scopes, ts, tool, url, status, content_hash)
fragments(id, session_scope_id→session_scopes, ts, seq, tool, url_hash, excerpt)
fired_patterns(session_scope_id, pattern, ts)                 PK(scope, pattern)
armed(session_scope_id, armed_at)                             PK(scope)
kill_ledger(id, scope_id→scopes, ts, severity, tool, host, detail, consumed_at)
notify_dedup(session_scope_id, severity, content_hash, last_ts)  PK(all but ts)
one_time(session_scope_id, kind, key, created_at, consumed_at)   PK(scope,kind,key)
```

`hits.status` is `H` (delivered), `C` (Layer-5 cleared) or `Q` (quarantined).
`content_hash` is set only on `Q` rows, and may still be NULL there — see
"counting" below.

### Migration contract

Three constants define it: `STATE_SCHEMA_VERSION` (what this build writes),
`MIN_READABLE_SCHEMA_VERSION` (the oldest key shape it can still interpret), and
the `user_version` it finds on disk.

| `user_version` | Outcome |
|---|---|
| `0` (empty file) | this build owns it — create the current schema |
| `1` (below `MIN_READABLE`) | `StateError::IncompatibleSchema` — refused, never migrated |
| `MIN_READABLE ..= STATE_SCHEMA_VERSION` | readable; migrate forward in one transaction |
| `> STATE_SCHEMA_VERSION` | `StateError::UnsupportedSchema` — written by a newer build |

**Why v1 is refused rather than migrated.** v1's scope tables have no `task_id`
column. Adding one and defaulting it would assert that every existing row belongs
to the task-absent bucket — a claim its writer never made, and one that would
silently merge rows the current key shape says are distinct. Because Stage 4 is
unreleased, no v1 database exists outside a developer's scratch directory, so
refusing costs one `rm -rf` and buys the guarantee that **no database is ever
read under keys that do not mean what they meant when it was written**. The
error message names the state root and says exactly that.

The same rule is what will govern the next key-shape change: bump both
`STATE_SCHEMA_VERSION` and `MIN_READABLE_SCHEMA_VERSION` when the meaning of a
key changes, and bump only `STATE_SCHEMA_VERSION` when the change is additive
and old rows remain interpretable.

Mechanics, unchanged: migrations run inside `BEGIN IMMEDIATE` and re-read
`user_version` **inside** the lock, so two processes racing to migrate cannot
both apply it; a migration that fails rolls back, so there is no half-applied
state for the next run to mistake for complete.

## TTLs

| State | TTL | Boundary | Bash source |
|---|---|---|---|
| strikes | 300 s | **inclusive** (`ts >= now - 300`) | `SESSION_WINDOW` |
| fragments, fired patterns | 300 s | inclusive | `SESSION_WINDOW` |
| armed window | 300 s | inclusive (`NOW - ARMED_AT <= WINDOW`) | `WINDOW` in `web-safety-egress.sh` |
| notification dedup | 300 s | **exclusive** (`now - last < 300`) | `NOTIFY_DEDUP_WINDOW` |
| kill ledger, one-time | 900 s | inclusive | the freshness window in `web-safety-agent-result.sh` |

The dedup boundary really is exclusive while the others are inclusive: Bash
writes `-lt` there and `>=` everywhere else. Both are reproduced; a test pins
each.

## Counting, exactly

`record_hit` appends one row and recounts the window **inside the same
transaction**. Two counters come back:

* `strikes` — `H` rows one per row, plus `COUNT(DISTINCT content_hash)` over
  hashed `Q` rows, plus one for each hashless `Q` row. Quarantine rows collapse
  by content hash because a subagent re-running an identical query gets
  byte-identical results, and that retry loop must not manufacture strikes. A
  `Q` row that somehow lost its hash counts **once** — fail toward counting,
  never toward vanishing.
* `real_strikes` — `H` rows only.

Escalation requires `strikes >= 3 && real_strikes >= 1`. The second clause is
what stops a pure-quarantine fan-out from escalating: the 3-strike rule measures
*model exposure*, and a fully-replaced result exposed the model to zero bytes.

`C` rows count for nothing, in either counter.

## Transaction boundaries

`BEGIN IMMEDIATE` on every write, so two writers contend at BEGIN rather than at
the first write — which is what makes "append and recount" one critical section
instead of a read-modify-write race. Before v8 the Bash count was taken once at
script start, so N parallel scanners all read the same pre-append total and none
of them ever reached the third strike.

The E8 step is deliberately **three short transactions**, not one long one:

1. store gate + fragment append + expiry prune;
2. *(no lock held)* build the three concatenations, run the eight views, match,
   and drop anything a single fragment already contains;
3. fired-set filter + append, atomically — `INSERT OR IGNORE` on the primary key
   *is* the check, so two concurrent scanners cannot both claim a first firing.

Holding the write lock across step 2 would turn every other scanner's lock wait
into a function of this one's matching cost. Bash locks the same two windows,
for the same reason.

## Failure and containment behaviour

| Condition | Typed as |
|---|---|
| any path redirection or unsafe component (below) | `UnsafePath` |
| corrupt / not-a-database, read-only, otherwise unopenable | `Unusable` |
| lock not acquired inside `busy_timeout_ms` | `Busy` |
| `user_version` newer than this build | `UnsupportedSchema` |
| `user_version` older than `MIN_READABLE_SCHEMA_VERSION` | `IncompatibleSchema` |
| identity outside the contract, including missing session or namespace | `InvalidIdentity` |
| bad mode, missing state dir, lock budget past the ceiling | `Config` |

There is deliberately **no** variant meaning "carried on statelessly and it was
fine". An unclassified SQLite failure maps to `Unusable`, which `enforce` turns
into containment.

Every row above reaches the caller the same way: as a `state` block on a valid
host/report document, exit 0. **None of them is a usage error**, including a
`--state-dir` that was never supplied. Exit 64 writes no document at all, and a
host wrapper that reads an absent response as *allow* would then fail open in
`enforce` — the one mode whose entire job is to fail closed. Usage errors are
reserved for invocations with no scan to fail closed into: an unknown option, a
missing option value, an unparseable `--state-mode` name, an unknown or missing
`--host`.

## Filesystem safety

The threat is a process running as the **same UID** that wants the state layer
to read or write somewhere else: a symlinked root, a symlinked parent component,
a symlinked or hardlinked database, a redirected WAL sidecar, or an object
swapped in between the check and the open. SQLite's public API takes a
*pathname*, not a descriptor, so every guarantee here is built out of two things:
refusing every redirection already in place before the name is handed over, and
*detecting* one that lands in the window.

`engine/src/state/paths.rs` runs this order on every open:

1. the root must be **absolute** and free of `.` / `..`. A relative root is
   resolved against a working directory this process does not own;
2. every existing component from `/` down to the root's parent is `lstat`ed and
   must be: not a symlink, a directory, owned by this uid or by root, and not
   group/world-writable **unless** it carries the sticky bit (the `/tmp` shape,
   where only an entry's owner may rename it);
3. every missing component is created one at a time with mode `0700` **in the
   `mkdir` call itself** — never `0777`-then-chmod, which leaves a window;
4. the controlled root is held to the stricter rule: owned by this uid and not
   group/world-writable, sticky bit or not;
5. the database is `lstat`ed (regular file, **link count 1**, our uid, not
   group/world-writable), then opened *by us* with `O_NOFOLLOW | O_CLOEXEC` and
   mode `0600`, and `fstat`ed **through that descriptor**, so the identity that
   gets recorded is the object actually opened rather than the name asked for;
6. any existing `-wal` / `-shm` sidecar is held to the same rule before SQLite
   may create or reuse one;
7. SQLite opens with **`SQLITE_OPEN_NOFOLLOW`**;
8. afterwards the database name is `lstat`ed again and compared field for field
   — device, inode, uid, link count, file type — against the recorded identity,
   and the sidecars are re-validated and tightened to `0600`. Any difference is
   `UnsafePath`, never a warning.

Note that step 1 makes a symlink-free root a **contract**, not a convenience:
`/var/folders/...` on macOS resolves through the `/var` symlink and is refused.
Pass the resolved path (`cd "$dir" && pwd -P`, `Cwd::realpath`,
`std::fs::canonicalize`). The test harnesses and `tools/bench.pl` do exactly
that.

### Residual limitation — stated, not papered over

**A same-UID process that can rename the state root's parent directories, or the
SQLite sidecars, *continuously* is not defeated by a pathname-based SQLite VFS.**
Step 8 detects a swap after the fact, which is enough to refuse the transition
and is why every detection is a typed error — but a sufficiently persistent
attacker can keep losing that race and retrying. Closing it needs a
descriptor-based custom VFS or a privileged broker; neither is in this stage, and
no claim is made here that the window is closed.

What follows from that, and is binding:

* every static and detectable redirection is refused in code (above);
* a detected race fails **safe** — `UnsafePath`, which `enforce` turns into
  containment;
* the future containment stage must make the state root inaccessible to
  untrusted tool processes;
* **`enforce`-mode cutover stays blocked on that containment gate.** The wired
  `report` mode never turns a state failure into containment, so it carries no
  new fail-closed risk over the Bash `/tmp` files it replaces — but promoting
  the wiring to `enforce` without the containment stage would.

### Storage permissions

On Unix the state root and every component this layer creates are `0700`, and
the database and its sidecars `0600`, set at **creation** and verified after.
An existing directory's mode is not loosened — it may be intentionally tighter —
but a mode that is *too loose* is a refusal rather than a silent chmod.

**Platform limitation:** on non-Unix targets there are no mode bits and no uid
to check, so only the structural checks (absolute, no `..`, not a symlink, not a
directory where a file belongs) apply. Anyone deploying there should place the
state root inside an already-restricted profile directory.

## Bounded growth

* Expired rows are deleted per scope inside the same transaction that appends,
  so a hot session trims itself rather than waiting for a sweep.
* `prune()` deletes every expired row across all tables, drops scopes that no
  longer own anything, and then **checkpoints the WAL with `TRUNCATE`**. Without
  the checkpoint the WAL keeps its high-water mark and a long adversarial
  sequence leaves megabytes behind for rows that were pruned seconds earlier —
  measured at 4.3 MB before the fix. `journal_size_limit=1048576` keeps it
  truncated between checkpoints.
* Fragments are capped at 20 per session, pruned **after** the reassembly check,
  so an attacker cannot evict the incriminating half by padding the window in
  the same call.
* Excerpts are capped at 1500 bytes (head 2/3 + tail 1/3), UTF-8-safe, already
  lowercased and confusable-folded. No raw response body is ever persisted.

Measured, one process per call:

| Sequence | Calls | On disk | rows (hits/frags/scopes) |
|---|---|---|---|
| benign, one session | 100 | 88 KB | 0 / 20 / 1 |
| MEDIUM, one session | 100 | 144 KB | 100 / 20 / 1 |
| MEDIUM, 20-session fan-out | 200 | 172 KB | 200 / 200 / 20 |
| adversarial, 50-session | 200 | 180 KB | 200 / 200 / 50 |

## Latency

`engine/tools/bench.pl --state` measures a **fresh process per sample**, which
is what a hook actually pays.

| Gate | Target | Stateless | Stateful |
|---|---|---|---|
| cold CLI p95 @ 50 KB | ≤ 50 ms | 10.00 ms | 23.44 ms |
| cold CLI p95 @ 256 KB | ≤ 100 ms | 11.02 ms | 24.87 ms |
| hard per-call ceiling (max) | ≤ 500 ms | 11.41 ms | 25.32 ms |

The stateful delta is roughly 13 ms: opening the database, the migration check,
and four to six short transactions.

Concurrency, measured in `engine/tests/state_correlation.rs`:

* 50 simultaneous writers on one scope each observe a **distinct** running
  total — no strike is lost — with the documented maximum lock budget;
* a realistic 8-way subagent fan-out on the **production** 250 ms budget
  completes every call inside the 500 ms ceiling;
* a lock held past the budget produces `StateError::Busy` in well under
  500 ms rather than waiting the hook out.

## Known divergence from Bash

One, and it is a consequence of an architecture invariant rather than an
accident:

| What | Bash | Here | Why |
|---|---|---|---|
| notification dedup key | the FILE `/tmp/web-safety-scanner-notify-<severity>-<hash>` — **global across sessions** | runtime + namespace + **session + task** + severity + hash | the stage's invariant requires every state key to carry runtime, namespace, session and task. Agent is deliberately excluded on both sides, since collapsing a fan-out across sibling subagents is the point. |

Observable difference: two **concurrent, distinct** sessions (or two tasks under
one session) scanning byte-identical content toast once under Bash and once per
scope here. It affects notification intent only — never a scan decision, an audit
row, a sanitization, a kill, or an arm. It is **not** silently blessed: it is
recorded here and flagged for Kuvis in the stage report.

An earlier draft of this stage carried a second asymmetry here: a missing
`--state-dir` exited 64 while a missing namespace or session failed closed
through the host encoding. That was a fail-open shape — exit 64 writes no
document, and a host wrapper reading an absent response as *allow* would have
been handed the weakest outcome in the strictest mode — and it is **gone**.
Configuration and identity now fail through the one typed state path: `report`
delivers the scan with `state.applied=false` and an error naming the missing
state directory, `enforce` contains, both at exit 0. Pinned by
`engine/tests/state_cli.rs`.

`tests/run-state-differential.sh` reports **zero** divergences across its
corpus, which does not exercise two concurrent distinct sessions on identical
content (both implementations are single-session-at-a-time there).

## What a future adapter consumes

The APIs are runtime-neutral. No adapter is wired in this stage.

| Adapter | API |
|---|---|
| a PostToolUse content scanner | `StateLayer::apply(&ctx, &StateEvent)` → `StateReport` |
| the egress guard (Layer 6) | `StateStore::armed(&ctx)` → `Option<ArmState>` |
| the Agent-result hook (Layer 7) | `StateStore::consume_kills(&ctx)` → one-shot rows; `summarize_kills` for the model-facing sentence |
| the Stop gate | `StateStore::pending_kills(&ctx)` (read-only) |
| a future explicit-approval flow | `StateStore::claim_once(&ctx, kind, key)` |
| a maintenance sweep | `StateStore::prune()` |

`summarize_kills` relays **severity via tool (host)** and nothing else. The
`detail` column holds detector labels, which are the attacker's matched text;
putting it in front of a model would re-deliver the injection the kill just
prevented.

## Out of scope for this stage

No hook wiring, no default switch, no Claude/Codex/Hermes final adapter, no
PyO3, no Docker/iron-proxy, no packaging or release. `web-safety-egress.sh`,
`web-safety-agent-result.sh` and `web-safety-stop-gate.sh` are untouched and
still read their own `/tmp` and audit-log state.
