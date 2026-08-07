//! `web-safety-engine` — the shared scanner CLI.
//!
//! Reads one host envelope on stdin, writes that host's response schema on
//! stdout. This binary is what `hooks/hooks.json` invokes — the production
//! scanner authority. The Bash scripts stay in-tree as the frozen differential
//! oracle and the operator's rollback path.
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
    ContractError, Decision, Disposition, Finding, ScanRequest, ScanResponse, Severity,
    SCHEMA_VERSION,
};
use web_safety_engine::engine::{Config, Engine, DEFAULT_MAX_SCAN_BYTES};
use web_safety_engine::hosts::{
    encode_pre_tool_response, encode_response, encode_response_at, original_output, to_request_at,
    Event, Host, DEFAULT_MAX_ENVELOPE_BYTES, MAX_ENVELOPE_BYTES_CEILING, PRECALL_EGRESS_BASH_RULE,
    PRECALL_EGRESS_FETCH_RULE, PRECALL_URLSCREEN_RULE,
};
use web_safety_engine::normalize::VIEW_NAMES;
use web_safety_engine::oplog::{self, Oplog};
use web_safety_engine::policy::Scanner;
use web_safety_engine::state::{
    Outcome, StateConfig, StateContext, StateError, StateEvent, StateLayer, StateMode, StateReport,
    StateStore, DEFAULT_NOTIFY_WINDOW_SECS, STATE_CONTEXT_VERSION, STATE_SCHEMA_VERSION,
    STATE_SCOPE_KEYS,
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
                             than replacing anything (Layers 1 and 6).
  --config-dir <PATH>        operator config: url-allowlist.txt,
                             url-blocklist.txt, and the default audit-log
                             location. Absent means no lists and no log; the
                             WEB_SAFETY_CONFIG_DIR env var is honoured as a
                             fallback, matching the shell hooks.
  --default-allowlist <PATH> the plugin-shipped egress allowlist, layered under
                             the operator's for the Layer 6 exemption only.
                             WEB_SAFETY_DEFAULT_ALLOWLIST_DISABLE=1 ignores it.
  --audit-log <PATH>         operator audit log (default:
                             <config-dir>/web-safety.log when --config-dir is
                             given, else disabled)
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
    default_allowlist: &Option<PathBuf>,
    state: &StateArgs,
    host: Host,
    request: &ScanRequest,
    log: &Oplog,
) -> ScanResponse {
    let (allowlist, blocklist) = load_lists(config_dir);
    let session = request.session_id.as_deref().unwrap_or("");

    // --- Layer 1 ---
    //
    // The USER allowlist only: the production pre-screen never consults the
    // plugin-shipped default list — that list exists to quiet the armed egress
    // guard, not to widen what the screen's soft blocks permit.
    //
    // The screen's reason travels on the response as a finding so the host
    // encoder can say what the production hook says (`Pre-screening blocked:
    // <reason>`). The vocabulary is the screen's own fixed strings — nothing
    // derived from page content.
    if let Some(url) = request.url.as_deref() {
        if let urlscreen::Screen::Block(reason) = urlscreen::screen(url, &allowlist, &blocklist) {
            log.pre_block(url, &reason);
            return precall_refusal(reason);
        }
    }

    // --- Layer 6 ---
    //
    // Kill switch first, the same env lever the Bash guard honours. It disables
    // the GUARD only; the Layer 1 screen above is a separate hook in production
    // and stays live here too.
    if std::env::var("WEB_SAFETY_EGRESS_GUARD_DISABLE").as_deref() == Ok("1") {
        return precall_allow();
    }

    // `armed` is READ from the engine's own state, never re-derived here. It is
    // false whenever state is off or unreadable, which matches the Bash guard:
    // this is a secondary layer over an already-armed session, and it defers in
    // every case it cannot positively establish.
    let armed = precall_armed(state, host, request, log);

    // The armed-window WebSearch downgrade is logged, never prompted — the
    // query goes to the configured provider, not an attacker-chosen host.
    // `decide` below returns `Defer` for it; the audit row is the Bash guard's
    // observable side of that decision, kept here.
    if armed && request.tool_name == "WebSearch" && request.command.is_none() {
        log.egress_search_downgrade(session, request.query.as_deref().unwrap_or(""));
    }

    // The guard's exemption list is the plugin-shipped default allowlist
    // layered UNDER the operator's file — `host_in_any_list` in the shell.
    // Disable the default layer with the same env var the hook documents.
    let mut egress_lists = allowlist;
    if std::env::var("WEB_SAFETY_DEFAULT_ALLOWLIST_DISABLE").as_deref() != Ok("1") {
        if let Some(path) = default_allowlist {
            if let Ok(s) = std::fs::read_to_string(path) {
                egress_lists.extend(s.lines().map(str::to_string));
            }
        }
    }

    // The guard reads the WIDER url the host's egress hook reads
    // (`egress_url`), falling back to the screen's — on most hosts they are
    // the same field.
    let guard_url = request
        .egress_url
        .as_deref()
        .or(request.url.as_deref())
        .unwrap_or("");
    let command = request.command.as_deref().unwrap_or("");
    let call = egress::Call {
        tool_name: &request.tool_name,
        command,
        url: guard_url,
        armed,
    };
    match egress::decide(&call, &egress_lists) {
        egress::Egress::Defer => precall_allow(),
        egress::Egress::GuardFetch => {
            log.egress_ask_fetch(session, &request.tool_name, Some(guard_url));
            precall_guard(PRECALL_EGRESS_FETCH_RULE)
        }
        egress::Egress::GuardBash => {
            log.egress_ask_bash(session, command);
            precall_guard(PRECALL_EGRESS_BASH_RULE)
        }
    }
}

/// One pre-call finding: the audit-trail carrier for WHICH control refused and
/// why. `matched` is engine vocabulary, never page content.
fn precall_finding(rule_id: &str, severity: Severity, matched: String) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        severity,
        matched,
        view: "raw".into(),
        disposition: Disposition::Kept,
        reason: None,
    }
}

/// Layer 1 refusal. HIGH/Block so every host encoder treats it as containment.
fn precall_refusal(reason: String) -> ScanResponse {
    ScanResponse {
        decision: Decision::Block,
        findings: vec![precall_finding(
            PRECALL_URLSCREEN_RULE,
            Severity::High,
            reason,
        )],
        ..containment()
    }
}

/// Layer 6 escalation. MEDIUM/Ask — operator confirmation, which each host
/// encoder renders in its own enforcement shape (and escalates to a hard block
/// where the host would discard an ask).
fn precall_guard(rule_id: &str) -> ScanResponse {
    ScanResponse {
        severity: Severity::Medium,
        decision: Decision::Ask,
        findings: vec![precall_finding(
            rule_id,
            Severity::Medium,
            "armed egress".into(),
        )],
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
fn precall_armed(args: &StateArgs, host: Host, request: &ScanRequest, log: &Oplog) -> bool {
    if args.mode == StateMode::Off {
        return false;
    }
    let session = request.session_id.as_deref().unwrap_or("");
    let mode = args.mode.as_str();
    // Every failure below still returns "not armed" — that is the guard's
    // documented posture — but it no longer does so SILENTLY. An unusable store
    // means Layer 6 cannot fire for the rest of the session, and an operator
    // who cannot see that has no way to tell a quiet guard from a dead one.
    let ctx = match state_identity(args, host, request) {
        Ok(ctx) => ctx,
        Err(e) => {
            log.state_error(session, mode, &e.to_string());
            return false;
        }
    };
    let store = match StateStore::open(StateConfig {
        mode: args.mode,
        dir: args.dir.clone().unwrap_or_default(),
        ..args.store_config()
    }) {
        Ok(Some(store)) => store,
        // `None` is `off` mode, which returned above; reaching it here is not
        // a failure and has nothing to report.
        Ok(None) => return false,
        Err(e) => {
            log.state_error(session, mode, &e.to_string());
            return false;
        }
    };
    match store.armed(&ctx) {
        Ok(window) => window.is_some(),
        Err(e) => {
            log.state_error(session, mode, &e.to_string());
            false
        }
    }
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
    (
        read_list(dir, "url-allowlist.txt"),
        read_list(dir, "url-blocklist.txt"),
    )
}

fn read_list(dir: &std::path::Path, name: &str) -> Vec<String> {
    std::fs::read_to_string(dir.join(name))
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Is this call's source on the operator's content-trust list?
///
/// The port of `web-safety-scanner.sh`'s `host_is_content_trusted`, and the
/// whole of what `/web-safety-trust` buys: a trusted source keeps being
/// SCANNED, but a finding downgrades instead of halting or redacting, so an
/// operator can read a security article that quotes attack strings without the
/// scanner deleting the page they fetched. The armed egress guard stays as the
/// backstop.
///
/// Fail-safe in every uncertain case, exactly as the shell is: no config dir,
/// no URL, or an authority that will not resolve means NOT trusted, and the
/// ordinary protective path runs.
fn content_trusted(config_dir: &Option<PathBuf>, request: &ScanRequest) -> bool {
    let Some(dir) = config_dir else { return false };
    let Some(url) = request.url.as_deref().filter(|u| !u.is_empty()) else {
        return false;
    };
    let host = urlscreen::normalize_host(url);
    if host.is_empty() || host == urlscreen::INVALID_AUTHORITY {
        return false;
    }
    urlscreen::host_in_list(&host, &read_list(dir, "url-content-trust.txt"))
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

impl StateArgs {
    /// The store configuration every call site shares — so a tunable set for
    /// the post-call transition is the same one the pre-call arm READ uses.
    /// They diverged once already, and a window that differs between the writer
    /// and the reader is an arm that expires at a time nobody chose.
    fn store_config(&self) -> StateConfig {
        StateConfig {
            mode: self.mode,
            dir: self.dir.clone().unwrap_or_default(),
            // `WEB_SAFETY_NOTIFY_DEDUP_WINDOW` in `web-safety-scanner.sh`.
            // Honoured here because the operator's documented switch has to
            // keep working now that this engine, not the shell, owns dedup.
            notify_window_secs: env_secs("WEB_SAFETY_NOTIFY_DEDUP_WINDOW")
                .unwrap_or(DEFAULT_NOTIFY_WINDOW_SECS),
            ..StateConfig::default()
        }
    }
}

/// A positive whole number of seconds from the environment, or `None`.
///
/// A malformed value is `None` rather than an error: the shell hooks treat a
/// junk tunable the same way — fall back to the default and keep scanning —
/// and refusing to scan because an env var has a typo would be a worse failure
/// than ignoring it.
fn env_secs(key: &str) -> Option<i64> {
    std::env::var(key)
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
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
    let mut default_allowlist: Option<PathBuf> = None;
    let mut audit_log: Option<PathBuf> = None;
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
            "--default-allowlist" => {
                // The plugin-shipped egress allowlist, layered UNDER the
                // operator's file for the Layer 6 exemption only — the URL
                // pre-screen never reads it.
                default_allowlist = Some(PathBuf::from(value?));
                i += 2;
            }
            "--audit-log" => {
                // The operator audit log. Defaults to
                // `<config-dir>/web-safety.log` when a config dir is given —
                // the hooks' own location — and to no logging otherwise.
                audit_log = Some(PathBuf::from(value?));
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
    // The operator's documented env switches, applied AFTER the flags so an
    // explicit flag always wins. These are honoured because the shell hooks
    // honoured them and the operator's documentation still promises them — a
    // switch that silently stopped working is a control the operator thinks
    // they have and does not.
    if std::env::var("WEB_SAFETY_SEARCH_QUARANTINE_DISABLE").as_deref() == Ok("1") {
        state.quarantine_enabled = false;
    }
    if let Some(n) = std::env::var("WEB_SAFETY_MAX_SCAN_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        // Only when no explicit cap flag was given: `--no-cap` sets `None`, and
        // an env var must not silently re-impose a cap the caller removed.
        if config.max_scan_bytes == Some(DEFAULT_MAX_SCAN_BYTES) {
            config.max_scan_bytes = Some(n);
        }
    }

    let host = host.ok_or_else(|| Failure::Usage("scan needs --host".into()))?;
    let contract = |err: ContractError| Failure::Contract {
        err,
        host: Some(host),
    };
    let fail = |why: String| contract(ContractError::MalformedEnvelope(why));

    // The hooks' own config-dir resolution: the flag, else the env override the
    // shell scripts document. There is deliberately NO `$HOME` default here —
    // a bare `scan` invocation must stay deterministic (no lists, no log), and
    // the production wiring passes the directory explicitly.
    let args_config_dir =
        args_config_dir.or_else(|| std::env::var_os("WEB_SAFETY_CONFIG_DIR").map(PathBuf::from));

    // The audit log the Bash hooks share. Its rows are consumed by the Layer 7
    // scripts and /web-safety:report, so the engine keeps writing them.
    let log = match audit_log.or_else(|| args_config_dir.as_deref().map(oplog::default_log)) {
        Some(p) => Oplog::at(p),
        None => Oplog::disabled(),
    };

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

    // The operator's per-source downgrade list. `--content-trusted` stays an
    // explicit override for an adapter that resolves trust itself (Hermes
    // does); when it is not set, the list is consulted here so the shipped
    // `/web-safety-trust` command keeps working under the engine.
    if !state.content_trusted {
        state.content_trusted = content_trusted(&args_config_dir, &request);
    }

    let response = match event {
        Event::PostTool => {
            if routed_out_by_layer8_gate(host, &request) {
                // `web-safety-bash-scan.sh`'s exit-0 path: a Bash result whose
                // command is not fetch-shaped is never scanned, never touches
                // state, and the hook says nothing. The gate is what keeps
                // routine `cat`/`ls`/`grep` output away from a halting scanner.
                precall_allow()
            } else {
                let mut r = Scanner::new(config).scan(&request.content);
                apply_state(&state, host, &request, &mut r, &log);
                // Planned AFTER state, so an escalation or a quarantine is the
                // outcome the replacement is built for — not the stateless
                // verdict it started from.
                r.replacement = web_safety_engine::sanitize::plan(&request, &r);
                // The audit rows the Bash scanner wrote, in its order: the
                // detection line `/web-safety-report` counts by severity, then
                // — BEFORE the halt is delivered — the `[PENDING-KILLED]` row
                // the Layer 7 consumers join (`record_agent_kill`'s ordering).
                write_detection_row(&log, &request, &r);
                write_kill_row(&log, &request, &r);
                r
            }
        }
        // Layers 1 and 6, the two controls that run BEFORE a tool does. The
        // content scanner is deliberately not consulted: `request.content` is
        // empty on this event, so it would find nothing and permit everything.
        Event::PreTool => precall_decision(
            &args_config_dir,
            &default_allowlist,
            &state,
            host,
            &request,
            &log,
        ),
    };

    if emit_report {
        // Serialize the struct directly rather than via `to_value`: serde_json's
        // Value is a sorted map, which would bury `severity` behind the findings
        // array and make a naive top-level field read pick a finding's severity.
        write_json(&response).map_err(Failure::Io)?;
    } else {
        let doc = match event {
            Event::PostTool => encode_response_at(
                host,
                event,
                &request.tool_name,
                &response,
                original_output(host, &env),
            ),
            // A pre-call envelope carries no result to replace; its encoder
            // permits or refuses, and needs the permission mode because some
            // hosts discard an "ask" in some modes.
            Event::PreTool => encode_pre_tool_response(
                host,
                &request.tool_name,
                &response,
                request.permission_mode.as_deref(),
            ),
        };
        emit(&doc).map_err(Failure::Io)?;
    }
    Ok(())
}

/// The Layer 8 routing gate, host-scoped to where it is production behavior:
/// Claude's Bash PostToolUse hook (`web-safety-bash-scan.sh`) scans a result
/// only when the command that produced it is fetch-shaped. Other hosts route in
/// their own adapters (Hermes forwards every terminal envelope deliberately).
fn routed_out_by_layer8_gate(host: Host, request: &ScanRequest) -> bool {
    host == Host::Claude
        && request.tool_name == "Bash"
        && !request
            .command
            .as_deref()
            .is_some_and(egress::is_fetch_command)
}

/// KEPT finding labels, HIGH first then MEDIUM — `labels_for`'s order, the
/// text the shell put in its `patterns=` fields. Operator-facing only.
fn kept_labels(response: &ScanResponse) -> String {
    let mut labels: Vec<&str> = response
        .findings
        .iter()
        .filter(|f| f.counts_toward_verdict() && f.severity == Severity::High)
        .map(|f| f.matched.as_str())
        .collect();
    labels.extend(
        response
            .findings
            .iter()
            .filter(|f| f.counts_toward_verdict() && f.severity == Severity::Medium)
            .map(|f| f.matched.as_str()),
    );
    labels.join(", ")
}

/// Append the `[<SEVERITY>]` detection row (`log_detection` in the shell) for
/// any verdict the scanner had something to say about. A clean scan writes
/// nothing, exactly as the shell wrote nothing.
fn write_detection_row(log: &Oplog, request: &ScanRequest, response: &ScanResponse) {
    if response.decision == Decision::Allow {
        return;
    }
    log.detection(
        response.severity.as_str(),
        &request.tool_name,
        request.url.as_deref(),
        &kept_labels(response),
    );
}

/// Append the `[PENDING-KILLED]` audit row when this scan just ledgered a
/// subagent kill. The ROW is the carrier the Bash Layer 7 consumers
/// (`web-safety-agent-result.sh`, `web-safety-stop-gate.sh`) join on; the
/// ledger row in the state store is the engine's own durable record.
fn write_kill_row(log: &Oplog, request: &ScanRequest, response: &ScanResponse) {
    let Some(state) = &response.state else { return };
    if !state.ledgered {
        return;
    }
    // The same outcome→severity vocabulary `record_kill` was fed.
    let severity = match state.outcome {
        Outcome::High => "HIGH",
        Outcome::Escalated => "ESCALATED",
        Outcome::Medium => "MEDIUM",
        _ => return,
    };
    log.pending_killed(
        oplog::epoch_now(),
        request.session_id.as_deref().unwrap_or(""),
        request.agent_id.as_deref().unwrap_or(""),
        severity,
        &request.tool_name,
        request.url.as_deref(),
        // The consumers never copy `patterns` into model-facing text.
        &kept_labels(response),
    );
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
fn apply_state(
    args: &StateArgs,
    host: Host,
    request: &ScanRequest,
    response: &mut ScanResponse,
    log: &Oplog,
) {
    apply_state_transition(args, host, request, response);

    // One place, every path. A transition that did not reach the store leaves
    // the session with no arming, no strike history and no kill ledger — in
    // `report` mode the scan is still delivered, so this row is the ONLY
    // signal that the stateful half of the defense is not running.
    if let Some(state) = &response.state {
        if !state.applied {
            log.state_error(
                request.session_id.as_deref().unwrap_or(""),
                state.mode.as_str(),
                state
                    .error
                    .as_deref()
                    .unwrap_or("the state transition did not reach the store"),
            );
        }
    }
}

fn apply_state_transition(
    args: &StateArgs,
    host: Host,
    request: &ScanRequest,
    response: &mut ScanResponse,
) {
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
            let layer = StateLayer::open(args.store_config());
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
