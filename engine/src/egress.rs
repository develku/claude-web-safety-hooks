//! Layer 6 — the outbound exfiltration guard's DECISION, ported from
//! `scripts/web-safety-egress.sh`.
//!
//! Scope boundary, deliberately: this module ports the decision and nothing
//! else. The shell hook also logs, fires a rate-limited desktop toast, keeps a
//! per-host ask tally to suggest allowlisting, and picks between two response
//! shapes by permission mode. Those are the HOST's concerns — the engine already
//! owns notification dedup in `state`, and the response shape belongs to
//! `hosts::encode_*`. Porting them here would be the second copy of a fact.
//!
//! What the guard is: when a HIGH-severity injection was flagged in this session
//! within the arming window, outbound activity is escalated. It breaks the
//! inject→exfil chain, because an injected instruction cannot self-approve
//! egress. Two channels — a web-fetch to a non-allowlisted host, and a Bash
//! command that puts bytes on the network.
//!
//! It **defers** in every non-triggering case. That is not fail-open sloppiness:
//! Layer 6 is a secondary layer gated on an already-armed session, and the
//! primary controls (Layers 1-5) run regardless.

use crate::urlscreen::{host_in_list, normalize_host, INVALID_AUTHORITY};
use regex::Regex;
use std::sync::OnceLock;

/// Which channel escalated, or that nothing did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    /// Nothing to escalate. The overwhelming majority of calls.
    Defer,
    /// A fetch to a destination that could not be proven allowlisted.
    GuardFetch,
    /// A Bash command that puts bytes on the network.
    GuardBash,
}

impl Egress {
    pub fn is_guard(&self) -> bool {
        !matches!(self, Egress::Defer)
    }
}

/// One call's worth of input, in the engine's vocabulary rather than the hook's.
pub struct Call<'a> {
    pub tool_name: &'a str,
    pub command: &'a str,
    pub url: &'a str,
    /// The arming window is open. Read from state, never re-derived here — the
    /// engine owns the arm store and a second opinion about "armed" is exactly
    /// the divergence this split is meant to avoid.
    pub armed: bool,
}

fn re(src: &str) -> Regex {
    Regex::new(src).expect("a static pattern compiles")
}

macro_rules! lazy_re {
    ($name:ident, $src:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| re($src))
        }
    };
}

// The pattern set, verbatim from the hook. Boundaries exclude path chars `.`
// and `/` so `~/.ssh/` and `report.scp` are not command matches, while quotes,
// separators and a leading `/` still are.
lazy_re!(
    re_egress,
    r"(?i)(^|[^a-zA-Z0-9_.])(curl|wget|ncat|netcat|nc|scp|sftp|ssh|aria2c|ftp|lynx|links|w3m|socat|telnet)([^a-zA-Z0-9_./-]|$)"
);
lazy_re!(
    re_httpie,
    r"(?i)(^|[^a-zA-Z0-9_.])https?[[:space:]]+(get|post|put|delete|head|patch|options|localhost|[a-z0-9_-]+\.[a-z]|[0-9]{1,3}\.[0-9]|:[0-9]|https?://|-)"
);
lazy_re!(
    re_oneliner,
    r"(?i)(python3?|node|ruby|perl)([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+-(c|e)([[:space:]]|$)"
);
lazy_re!(
    re_net_token,
    r"(?i)(urllib|requests|socket|http\.client|httplib|fetch\(|net[:/]{1,2}http|lwp|open-uri)"
);
lazy_re!(
    re_openssl,
    r"(?i)(^|[^a-zA-Z0-9_.])openssl[[:space:]]+s_client"
);
// Case-SENSITIVE in the hook (`grep -qE`, no -i), and kept that way.
lazy_re!(re_devnet, r"/dev/(tcp|udp)/");
lazy_re!(
    re_rsync_remote,
    r"(?i)(^|[^a-zA-Z0-9_.])rsync([[:space:]]).*[A-Za-z0-9._-]:"
);
lazy_re!(
    re_dns,
    r"(?i)(^|[^a-zA-Z0-9_.])(dig|nslookup|drill|kdig)([^a-zA-Z0-9_./-]|$)"
);
lazy_re!(
    re_git_push,
    r"(?i)(^|[^a-zA-Z0-9_.])git([[:space:]]+-{1,2}[A-Za-z][^[:space:]]*([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+push([[:space:]]|$)"
);
lazy_re!(
    re_upload,
    r"(^|[[:space:]])(-d[^[:space:]]*|--data[a-z-]*|-F[^[:space:]]*|--form(-string)?|-T[^[:space:]]*|--upload-file|--json|--url-query|--post-data|--post-file|--body-data|--body-file)([[:space:]]|=|$)"
);
lazy_re!(
    re_url_in_cmd,
    r"[a-zA-Z][a-zA-Z0-9+.-]*://[^[:space:]\x22]+"
);
lazy_re!(re_at_host, r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+");

/// Does this command put bytes on the network?
pub fn is_egress_command(cmd: &str) -> bool {
    if re_egress().is_match(cmd)
        || re_dns().is_match(cmd)
        || re_git_push().is_match(cmd)
        || re_httpie().is_match(cmd)
        || re_openssl().is_match(cmd)
        || re_devnet().is_match(cmd)
        || re_rsync_remote().is_match(cmd)
    {
        return true;
    }
    // An interpreter one-liner counts only when it ALSO names a network API —
    // `python -c "print(1)"` is not egress.
    re_oneliner().is_match(cmd) && re_net_token().is_match(cmd)
}

/// Candidate destination hosts in a command: `scheme://host…` and `user@host`.
/// Lowercased, deduplicated, sorted — mirroring the hook's `sort -u`.
pub fn command_hosts(cmd: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in re_url_in_cmd().find_iter(cmd) {
        let s = m.as_str();
        let after_scheme = match s.find("://") {
            Some(i) => &s[i + 3..],
            None => s,
        };
        // Strip userinfo, then cut at the first `:` or `/`.
        let no_userinfo = match after_scheme.find('@') {
            Some(i) if !after_scheme[..i].contains('/') => &after_scheme[i + 1..],
            _ => after_scheme,
        };
        let host: String = no_userinfo
            .chars()
            .take_while(|c| *c != ':' && *c != '/')
            .collect();
        push_host(&mut out, &host);
    }
    for m in re_at_host().find_iter(cmd) {
        if let Some(i) = m.as_str().find('@') {
            push_host(&mut out, &m.as_str()[i + 1..]);
        }
    }
    out.sort();
    out.dedup();
    out
}

fn push_host(out: &mut Vec<String>, h: &str) {
    let h = h.to_lowercase();
    // The hook keeps only lines containing an alphanumeric.
    if h.chars().any(|c| c.is_ascii_alphanumeric()) {
        out.push(h);
    }
}

/// Uploading data is not exempted even to an allowlisted host — exfil to a
/// trusted destination is still exfil.
pub fn has_upload(cmd: &str) -> bool {
    re_upload().is_match(cmd)
}

/// The guard's decision.
///
/// `allowlists` are the concatenated entries of the plugin-shipped default list
/// and the operator's `url-allowlist.txt`; a match in EITHER exempts the host,
/// which is what the hook's `host_in_any_list` does.
pub fn decide(call: &Call, allowlists: &[String]) -> Egress {
    // Step 1 — armed and fresh, or nothing to do.
    if !call.armed {
        return Egress::Defer;
    }

    // --- web-fetch channel ---
    //
    // Fail-CLOSED: any non-Bash tool escalates unless a destination host is
    // POSITIVELY resolved AND allowlisted. That deliberately covers tools whose
    // target sits in a field this mapping does not parse.
    if call.tool_name != "Bash" && call.command.is_empty() {
        // WebSearch has no attacker-chosen destination — its query goes to the
        // configured provider, not an arbitrary endpoint — so it is not the
        // arbitrary-host exfil vector this channel guards. EXACT name match
        // only: WebFetch and MCP fetch/search tools stay fail-closed.
        if call.tool_name == "WebSearch" {
            return Egress::Defer;
        }
        if !call.url.is_empty() {
            let host = normalize_host(call.url);
            if !host.is_empty() && host != INVALID_AUTHORITY && host_in_list(&host, allowlists) {
                return Egress::Defer;
            }
        }
        return Egress::GuardFetch;
    }

    // --- Bash channel ---
    if call.command.is_empty() {
        return Egress::Defer;
    }
    if !is_egress_command(call.command) {
        return Egress::Defer;
    }

    // Exempt only when at least one host was found, none of them is unknown to
    // the allowlists, and the command is not uploading.
    let hosts = command_hosts(call.command);
    if !hosts.is_empty()
        && !has_upload(call.command)
        && hosts.iter().all(|h| host_in_list(h, allowlists))
    {
        return Egress::Defer;
    }

    Egress::GuardBash
}
