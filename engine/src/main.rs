//! `web-safety-engine` — the shared scanner CLI.
//!
//! Reads one host envelope on stdin, writes that host's response schema on
//! stdout. Not wired into any hook yet: Bash remains the production runtime and
//! the rollback path for this stage. The binary exists so the differential
//! runner can compare the two on identical input.
//!
//! ```text
//! web-safety-engine scan --host claude|codex|hermes
//!                        [--event pre-tool|post-tool]
//!                        [--emit host|report] [--max-scan-bytes N | --no-cap]
//!                        [--max-envelope-bytes N]
//!                        [--state-mode off|report|enforce] [--state-dir PATH]
//!                        [--state-namespace NS] [--state-task ID]
//!                        [--content-trusted] [--no-search-quarantine]
//! web-safety-engine info
//! web-safety-engine --version
//! ```
//!
//! Exit codes: `0` scan completed, `2` contract error (fail-closed), `64` usage,
//! `74` the response could not be written.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use web_safety_engine::contract::{
    ContractError, Decision, ScanRequest, ScanResponse, Severity, SCHEMA_VERSION,
};
use web_safety_engine::engine::{Config, Engine, DEFAULT_MAX_SCAN_BYTES};
use web_safety_engine::hosts::{
    encode_response, encode_response_at, original_output, to_request_at, Event, Host,
    DEFAULT_MAX_ENVELOPE_BYTES, MAX_ENVELOPE_BYTES_CEILING,
};
use web_safety_engine::normalize::VIEW_NAMES;
use web_safety_engine::policy::Scanner;
use web_safety_engine::state::{
    StateConfig, StateContext, StateError, StateEvent, StateLayer, StateMode, StateReport,
    StateStore, STATE_CONTEXT_VERSION, STATE_SCHEMA_VERSION, STATE_SCOPE_KEYS,
};
use web_safety_engine::{egress, urlscreen};

const EXIT_CONTRACT_ERROR: u8 = 2;
const EXIT_USAGE: u8 = 64;
/// `EX_IOERR` from sysexits(3) — the verdict was reached but never delivered.
const EXIT_IO_ERROR: u8 = 74;

const USAGE: &str = "\
web-safety-engine — shared scanner core for the web-safety hooks

USAGE:
  web-safety-engine scan --host <claude|codex|hermes> [OPTIONS]   scan stdin
  web-safety-engine info                                          corpus + build info
  web-safety-engine --version

OPTIONS:
  --event <pre-tool|post-tool>
                             which interception point produced this envelope
                             (default: post-tool). A pre-tool envelope carries
                             the intent (tool name + args) and no result, and
                             its response permits or refuses the call rather
                             than replacing anything. Layers 1 and 6 are not
                             ported to Rust yet, so pre-tool currently REFUSES
                             every call — it cannot approve.
  --emit <host|report>       response encoding (default: host)
  --max-scan-bytes <N>       scan cap in bytes (default: 65536)
  --no-cap                   scan the whole input
  --max-envelope-bytes <N>   hard limit on the envelope read from stdin
                             (default: 1048576, max: 67108864). A RESOURCE
                             limit: --no-cap does not lift it.

STATE (default: off — Bash remains the production correlation authority):
  --state-mode <off|report|enforce>
                             off      never opens the database
                             report   applies transitions; a state failure is
                                      reported, the scan is still delivered
                             enforce  a state failure is containment
  --state-dir <PATH>         controlled state root; <PATH>/state.db is the only
                             file opened. Must be an absolute, symlink-free
                             path. Needed by any mode but off — and omitting it
                             is a STATE failure, not a usage error: report
                             delivers the scan with state.applied=false, enforce
                             contains. Neither exits 64, because an empty stdout
                             reads as 'allow' on every host.
  --state-namespace <NS>     profile/user namespace. REQUIRED in any mode but
                             off — there is no default, because a shared
                             default would merge unrelated profiles.
  --state-task <ID>          adapter-supplied task/execution id, when the host
                             exposes one. Omit it if the host does not; it is
                             never invented from the session id.
  --state-runtime <NAME>     runtime key for state scoping (default: --host)
  --content-trusted          the URL's host is on the operator's content-trust
                             list: downgrade instead of halting
  --no-search-quarantine     restore the pre-v8.12.0 subagent WebSearch kill

EXIT CODES:
  0   scan completed
  2   contract error — the envelope could not be understood (fail-closed)
  64  usage error
  74  the response could not be written to stdout";

enum Failure {
    Usage(String),
    Contract {
        err: ContractError,
        host: Option<Host>,
    },
    /// stdout could not be written or flushed. The verdict never reached the
    /// caller, so reporting success would be a lie — including, and especially,
    /// when the undelivered verdict was containment.
    Io(std::io::Error),
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(msg)) => {
            eprintln!("{msg}\n\n{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
        Err(Failure::Io(e)) => {
            eprintln!("web-safety-engine: cannot write the response: {e}");
            ExitCode::from(EXIT_IO_ERROR)
        }
        // Fail-closed: a caller that ignores the exit code still receives
        // containment on stdout rather than an empty (= allow) response.
        Err(Failure::Contract { err, host }) => {
            eprintln!("web-safety-engine: {err}");
            if let Some(host) = host {
                if let Err(e) = emit(&encode_response(host, "unknown", &containment(), None)) {
                    eprintln!("web-safety-engine: containment response not delivered: {e}");
                }
            }
            ExitCode::from(EXIT_CONTRACT_ERROR)
        }
    }
}

/// The pre-call verdict: Layer 1 (URL pre-screening) then Layer 6 (egress).
///
/// Order matches the hooks' own: the URL screen is a PRIMARY control that runs
/// on every call, and the egress guard is a SECONDARY one that only speaks
/// inside an armed window. A Layer 1 block therefore wins outright, and Layer 6
/// is consulted only for calls Layer 1 was willing to let through.
fn precall_decision(
    config_dir: &Option<PathBuf>,
    state: &StateArgs,
    host: Host,
    request: &ScanRequest,
) -> ScanResponse {
    let (allowlist, blocklist) = load_lists(config_dir);

    // --- Layer 1 ---
    if let Some(url) = request.url.as_deref() {
        if let urlscreen::Screen::Block(_) = urlscreen::screen(url, &allowlist, &blocklist) {
            // The reason is deliberately NOT carried into the response. It names
            // the offending URL's shape and lands in prose the model reads; the
            // hooks log it instead, and the model is told only that the call was
            // refused.
            return precall_refusal();
        }
    }

    // --- Layer 6 ---
    //
    // `armed` is READ from the engine's own state, never re-derived here. It is
    // false whenever state is off or unreadable, which matches the Bash guard:
    // this is a secondary layer over an already-armed session, and it defers in
    // every case it cannot positively establish.
    let armed = precall_armed(state, host, request);
    let call = egress::Call {
        tool_name: &request.tool_name,
        command: request.command.as_deref().unwrap_or(""),
        url: request.url.as_deref().unwrap_or(""),
        armed,
    };
    if egress::decide(&call, &allowlist).is_guard() {
        return precall_refusal();
    }

    precall_allow()
}

/// Refuse the call. HIGH/Block so every host encoder treats it as containment.
fn precall_refusal() -> ScanResponse {
    ScanResponse {
        decision: Decision::Block,
        ..containment()
    }
}

/// Let the call proceed. Not a statement that it is safe — only that neither
/// pre-call layer found a reason to stop it.
fn precall_allow() -> ScanResponse {
    ScanResponse {
        severity: Severity::Info,
        decision: Decision::Allow,
        ..containment()
    }
}

/// Is the egress window open for this call's session?
///
/// Any failure reads as NOT armed. That is the Bash guard's own posture — it
/// `exit 0`s on a missing, unreadable or garbage arm file — and it is safe
/// because Layer 6 only ever ADDS a refusal on top of Layers 1-5.
fn precall_armed(args: &StateArgs, host: Host, request: &ScanRequest) -> bool {
    if args.mode == StateMode::Off {
        return false;
    }
    let Ok(ctx) = state_identity(args, host, request) else {
        return false;
    };
    // `open` yields None in off mode; both that and an error mean not armed.
    let Ok(Some(store)) = StateStore::open(StateConfig {
        mode: args.mode,
        dir: args.dir.clone().unwrap_or_default(),
        ..StateConfig::default()
    }) else {
        return false;
    };
    matches!(store.armed(&ctx), Ok(Some(_)))
}

/// Read the operator's URL allowlist and blocklist.
///
/// Missing files are empty lists, not an error: an operator who has never
/// curated a list still gets every hard block, which is the same thing the
/// hooks do.
fn load_lists(config_dir: &Option<PathBuf>) -> (Vec<String>, Vec<String>) {
    let Some(dir) = config_dir else {
        return (Vec::new(), Vec::new());
    };
    let read = |name: &str| -> Vec<String> {
        std::fs::read_to_string(dir.join(name))
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    };
    (read("url-allowlist.txt"), read("url-blocklist.txt"))
}

fn containment() -> ScanResponse {
    ScanResponse {
        schema_version: SCHEMA_VERSION,
        severity: Severity::High,
        decision: Decision::Block,
        findings: vec![],
        truncated: false,
        scanned_bytes: 0,
        elapsed_us: 0,
        state: None,
        // No content was ever read, so there is nothing to plan a replacement
        // over. The Claude encoder turns this into a stop, which is containment
        // that needs no knowledge of the tool's output shape.
        replacement: None,
    }
}

fn run() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") => scan(&args[1..]),
        Some("info") => info(),
        Some("--version" | "-V") => {
            println!("web-safety-engine {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(Failure::Usage(format!("unknown command: {other}"))),
        None => Err(Failure::Usage("no command given".into())),
    }
}

/// Read at most `limit` bytes of envelope from stdin.
///
/// The limit is enforced *while reading*, before any JSON parsing, so an
/// oversize envelope can never be buffered — let alone parsed into a `Value`
/// tree several times its own size — on the way to being rejected. One byte
/// beyond the limit is read so that "exactly at the limit" and "over it" are
/// distinguishable without buffering the remainder.
fn read_envelope(limit: usize) -> Result<String, ContractError> {
    let mut buf: Vec<u8> = Vec::new();
    let probe = u64::try_from(limit)
        .map_err(|_| ContractError::MalformedEnvelope("envelope limit is out of range".into()))?
        .saturating_add(1);
    std::io::stdin()
        .lock()
        .take(probe)
        .read_to_end(&mut buf)
        .map_err(|e| ContractError::MalformedEnvelope(format!("cannot read stdin: {e}")))?;

    if buf.len() > limit {
        return Err(ContractError::MalformedEnvelope(format!(
            "envelope exceeds the {limit}-byte limit"
        )));
    }
    String::from_utf8(buf)
        .map_err(|e| ContractError::MalformedEnvelope(format!("stdin is not UTF-8: {e}")))
}

/// The state-related half of `scan`'s argument list, kept together so the
/// option loop stays readable and so "state is off unless asked for" is one
/// visible default rather than three.
struct StateArgs {
    mode: StateMode,
    /// `None` means the operator supplied no `--state-dir`. In any mode but
    /// `off` that is a *configuration* failure carried through the state layer
    /// — `StateStore::open` refuses an empty root with a typed
    /// `StateError::Config` before it creates anything — never a usage error.
    dir: Option<PathBuf>,
    /// `None` means the operator did not supply one. It is deliberately NOT
    /// defaulted here: a default namespace is a shared bucket, and the whole
    /// point of the namespace is that two profiles never share one.
    namespace: Option<String>,
    /// `None` means the host exposes no task/execution id — a legitimate shape,
    /// and its own scope.
    task: Option<String>,
    runtime: Option<String>,
    content_trusted: bool,
    quarantine_enabled: bool,
}

impl Default for StateArgs {
    fn default() -> StateArgs {
        StateArgs {
            mode: StateMode::Off,
            dir: None,
            namespace: None,
            task: None,
            runtime: None,
            content_trusted: false,
            quarantine_enabled: true,
        }
    }
}

fn scan(args: &[String]) -> Result<(), Failure> {
    let mut host: Option<Host> = None;
    let mut event = Event::PostTool;
    let mut args_config_dir: Option<PathBuf> = None;
    let mut emit_report = false;
    let mut config = Config::default();
    let mut max_envelope_bytes = DEFAULT_MAX_ENVELOPE_BYTES;
    let mut state = StateArgs::default();

    let mut i = 0;
    while i < args.len() {
        let value = args
            .get(i + 1)
            .ok_or_else(|| Failure::Usage(format!("{} needs a value", args[i])));
        match args[i].as_str() {
            "--host" => {
                // An unknown host is a USAGE error, not a scan outcome: there is
                // no response schema to fail closed into.
                host = Some(Host::parse(value?).map_err(|e| Failure::Usage(e.to_string()))?);
                i += 2;
            }
            "--config-dir" => {
                // Where url-allowlist.txt / url-blocklist.txt live. Absent means
                // no lists, which costs only the soft blocks.
                args_config_dir = Some(PathBuf::from(value?));
                i += 2;
            }
            "--event" => {
                // Same reasoning as `--host`: an unknown event has no response
                // schema to fail closed into, so it is a usage error.
                event = Event::parse(value?).map_err(|e| Failure::Usage(e.to_string()))?;
                i += 2;
            }
            "--emit" => {
                emit_report = match value?.as_str() {
                    "report" => true,
                    "host" => false,
                    other => return Err(Failure::Usage(format!("unknown --emit value: {other}"))),
                };
                i += 2;
            }
            "--max-scan-bytes" => {
                config.max_scan_bytes = Some(
                    value?
                        .parse::<usize>()
                        .map_err(|_| Failure::Usage("--max-scan-bytes needs a number".into()))?,
                );
                i += 2;
            }
            "--no-cap" => {
                // Widens what is SCANNED. `max_envelope_bytes` is untouched on
                // purpose: the resource limit is not the scan cap.
                config.max_scan_bytes = None;
                i += 1;
            }
            "--max-envelope-bytes" => {
                let n = value?
                    .parse::<usize>()
                    .map_err(|_| Failure::Usage("--max-envelope-bytes needs a number".into()))?;
                if n == 0 || n > MAX_ENVELOPE_BYTES_CEILING {
                    return Err(Failure::Usage(format!(
                        "--max-envelope-bytes must be 1..={MAX_ENVELOPE_BYTES_CEILING}"
                    )));
                }
                max_envelope_bytes = n;
                i += 2;
            }
            "--state-mode" => {
                state.mode = StateMode::parse(value?).map_err(|e| Failure::Usage(e.to_string()))?;
                i += 2;
            }
            "--state-dir" => {
                state.dir = Some(PathBuf::from(value?));
                i += 2;
            }
            "--state-namespace" => {
                state.namespace = Some(value?.clone());
                i += 2;
            }
            "--state-task" => {
                state.task = Some(value?.clone());
                i += 2;
            }
            "--state-runtime" => {
                state.runtime = Some(value?.clone());
                i += 2;
            }
            "--content-trusted" => {
                state.content_trusted = true;
                i += 1;
            }
            "--no-search-quarantine" => {
                state.quarantine_enabled = false;
                i += 1;
            }
            other => return Err(Failure::Usage(format!("unknown option: {other}"))),
        }
    }

    // A missing `--state-dir` is deliberately NOT checked here. It is state
    // *configuration*, and `StateStore::open` already refuses an empty root with
    // a typed `StateError::Config` before it creates anything — so it fails
    // closed through the same path as every other unusable store. Rejecting it
    // as a usage error would exit 64 with an empty stdout, and a host wrapper
    // that reads "no response" as "allow" would then fail OPEN in `enforce`,
    // the one mode whose entire job is to fail closed (MAC-24).
    let host = host.ok_or_else(|| Failure::Usage("scan needs --host".into()))?;
    let contract = |err: ContractError| Failure::Contract {
        err,
        host: Some(host),
    };
    let fail = |why: String| contract(ContractError::MalformedEnvelope(why));

    let raw = read_envelope(max_envelope_bytes).map_err(contract)?;
    if raw.trim().is_empty() {
        return Err(fail("empty stdin".into()));
    }

    // `serde_json`'s parser enforces its own recursion limit, so a pathologically
    // nested envelope is a parse error here rather than a stack overflow in the
    // adapter's flattening pass.
    let env: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| fail(format!("stdin is not JSON: {e}")))?;

    let mut request = to_request_at(host, event, &env, max_envelope_bytes).map_err(contract)?;
    resolve_task_id(&mut request, state.task.as_deref()).map_err(contract)?;

    let response = match event {
        Event::PostTool => {
            let mut r = Scanner::new(config).scan(&request.content);
            apply_state(&state, host, &request, &mut r);
            // Planned AFTER state, so an escalation or a quarantine is the
            // outcome the replacement is built for — not the stateless verdict
            // it started from.
            r.replacement = web_safety_engine::sanitize::plan(&request, &r);
            r
        }
        // Layers 1 and 6, the two controls that run BEFORE a tool does. The
        // content scanner is deliberately not consulted: `request.content` is
        // empty on this event, so it would find nothing and permit everything.
        Event::PreTool => precall_decision(&args_config_dir, &state, host, &request),
    };

    if emit_report {
        // Serialize the struct directly rather than via `to_value`: serde_json's
        // Value is a sorted map, which would bury `severity` behind the findings
        // array and make a naive top-level field read pick a finding's severity.
        write_json(&response).map_err(Failure::Io)?;
    } else {
        emit(&encode_response_at(
            host,
            event,
            &request.tool_name,
            &response,
            // A pre-call envelope carries no result, so there is nothing to
            // build a shape-preserving replacement from — and nothing to
            // replace. Passing the post-call lookup here would read a field
            // this event does not have.
            match event {
                Event::PostTool => original_output(host, &env),
                Event::PreTool => None,
            },
        ))
        .map_err(Failure::Io)?;
    }
    Ok(())
}

/// Settle the task/execution dimension from the host envelope and the optional
/// `--state-task` override.
///
/// One unambiguous rule, and it is refusal rather than precedence: if the host
/// reported a task id AND the adapter passed a different one, the two disagree
/// about which execution this call belongs to, and picking either would silently
/// file the call under a scope its own runtime does not recognise. That is a
/// contract error — fail closed — not something to resolve by ordering.
///
/// The override still exists for a runtime that exposes no task field of its
/// own; agreeing values are, of course, fine.
fn resolve_task_id(request: &mut ScanRequest, cli: Option<&str>) -> Result<(), ContractError> {
    match (request.task_id.as_deref(), cli) {
        (Some(host), Some(cli)) if host != cli => Err(ContractError::MalformedEnvelope(format!(
            "the host reported task {host:?} but --state-task said {cli:?}; \
             refusing to guess which execution this call belongs to"
        ))),
        (None, Some(cli)) => {
            request.task_id = Some(cli.to_string());
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Assemble the state identity from what the host actually reported.
///
/// Nothing here substitutes, truncates or invents. A field the host did not
/// supply arrives as `""` and is refused by [`StateContext::validate`], which is
/// the whole fix for MAC-21's Critical finding: the previous code mapped a
/// missing `session_id` onto the literal `no-session`, so every sessionless call
/// on the machine landed in one bucket, accumulated one another's strikes, and
/// escalated the third to HIGH.
fn state_identity(
    args: &StateArgs,
    host: Host,
    request: &ScanRequest,
) -> Result<StateContext, StateError> {
    let mut ctx = StateContext::new(
        args.runtime.as_deref().unwrap_or(host.name()),
        args.namespace.as_deref().unwrap_or(""),
        request.session_id.as_deref().unwrap_or(""),
    );
    // Already reconciled with `--state-task` by `resolve_task_id`, which refuses
    // the contradictory case outright, so there is exactly one task id by here.
    ctx.task_id = request.task_id.clone();
    ctx.agent_id = request.agent_id.clone();
    ctx.tool_name = request.tool_name.clone();
    ctx.url = request.url.clone();
    ctx.permission_mode = request.permission_mode.clone();
    ctx.validate()?;
    Ok(ctx)
}

/// Run the state transition, if any, and fold its result back into the
/// response.
///
/// Three ways this changes the delivered verdict, all deliberate:
///
/// * a modelled promotion — E8 reassembly or the 3-strike escalation turns an
///   individually-clean fetch into containment;
/// * `enforce` containment — the store was unusable, so the call cannot know
///   it is *not* the third strike and must not report the weaker verdict;
/// * an identity the runtime never supplied — same containment, and reached
///   **before** the store is opened, so a call with no session leaves no trace
///   in a shared bucket because there is no shared bucket to leave it in.
///
/// In `off` mode this returns before touching anything and the response is
/// byte-identical to the Stage-3 document.
fn apply_state(args: &StateArgs, host: Host, request: &ScanRequest, response: &mut ScanResponse) {
    if args.mode == StateMode::Off {
        return;
    }

    let event = StateEvent {
        response,
        content: &request.content,
        content_trusted: args.content_trusted,
        quarantine_enabled: args.quarantine_enabled,
    };

    // Codex 0.144.1 exposes `agent_id` as an OPTIONAL PostToolUse field (its
    // own `post-tool-use.command.input` schema lists it outside `required`), so
    // an envelope without one is indistinguishable from a subagent that simply
    // did not report. Correlating those calls together would merge unrelated
    // agents into one bucket — the exact MAC-21 failure the scope key exists to
    // prevent — and no isolated 0.144.1 run has yet proven the field is always
    // present for a subagent. Until it is, a stateful Codex call with no agent
    // id is a typed identity failure: `report` says so and still delivers the
    // scan, `enforce` contains. Neither correlates.
    if host == Host::Codex && request.agent_id.is_none() {
        fold_state(
            response,
            StateLayer::rejected(
                args.mode,
                &event,
                &StateError::InvalidIdentity {
                    field: "agent_id".into(),
                    why: "codex 0.144.1 does not guarantee an agent identifier on PostToolUse, \
                          so cross-agent correlation cannot be proven safe"
                        .into(),
                },
            ),
        );
        return;
    }

    // Identity is settled before storage. An identity failure — and, since
    // MAC-24, a missing state directory — is a STATE failure, never a usage
    // error: exit 64 writes no document, and a host that reads "no document" as
    // "allow" would turn the strictest mode into the only fail-open in the CLI.
    let report = match state_identity(args, host, request) {
        Ok(ctx) => {
            let layer = StateLayer::open(StateConfig {
                mode: args.mode,
                dir: args.dir.clone().unwrap_or_default(),
                ..StateConfig::default()
            });
            layer.apply(&ctx, &event)
        }
        Err(e) => StateLayer::rejected(args.mode, &event, &e),
    };

    fold_state(response, report);
}

/// Apply the modelled verdict, then hand the report to the caller. Split out so
/// the mutable borrow of `response` starts only after every read of it is done.
fn fold_state(response: &mut ScanResponse, report: StateReport) {
    let (severity, decision) = verdict_for(&report);
    response.severity = severity;
    response.decision = decision;
    response.state = Some(report);
}

/// The severity/decision pair a modelled outcome delivers.
fn verdict_for(report: &web_safety_engine::state::StateReport) -> (Severity, Decision) {
    use web_safety_engine::state::Outcome;
    match report.outcome {
        Outcome::High | Outcome::Escalated => (Severity::High, Decision::Block),
        // A quarantine is MEDIUM-tier containment: the result is replaced, but
        // the agent survives, so it is not a Block.
        Outcome::Medium | Outcome::Quarantine => (Severity::Medium, Decision::Ask),
        // The downgrade deliberately does not halt: content passes through
        // unredacted and the armed egress guard is the backstop.
        Outcome::TrustDowngrade => (Severity::Low, Decision::Note),
        Outcome::Low => (Severity::Low, Decision::Note),
        Outcome::Note => (Severity::Info, Decision::Note),
        Outcome::Clean => (Severity::Info, Decision::Allow),
    }
}

fn info() -> Result<(), Failure> {
    let engine = Engine::new(Config::default());
    let c = engine.corpus();
    emit(&serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "default_max_scan_bytes": DEFAULT_MAX_SCAN_BYTES,
        "state_schema_version": STATE_SCHEMA_VERSION,
        "state_context_version": STATE_CONTEXT_VERSION,
        "state_scope_keys": STATE_SCOPE_KEYS,
        "state_modes": ["off", "report", "enforce"],
        "default_state_mode": StateMode::default().as_str(),
        "default_max_envelope_bytes": DEFAULT_MAX_ENVELOPE_BYTES,
        "max_envelope_bytes_ceiling": MAX_ENVELOPE_BYTES_CEILING,
        "patterns": {
            "high": c.high.len(),
            "medium": c.medium.len(),
            "low": c.low.len(),
            "total": c.high.len() + c.medium.len() + c.low.len(),
        },
        "views": VIEW_NAMES,
        "context_gated": c.context_gate.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
    }))
    .map_err(Failure::Io)
}

fn emit(v: &serde_json::Value) -> std::io::Result<()> {
    write_json(v)
}

/// Write one JSON document and a newline, then FLUSH.
///
/// The flush is the point: `to_writer` only fills `stdout`'s buffer, and the
/// implicit flush at process exit discards its error. Without an explicit,
/// checked flush a containment response that never left the buffer would still
/// exit 0 — a fail-open hiding behind a successful-looking scan.
fn write_json<T: serde::Serialize + ?Sized>(v: &T) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, v)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}
