//! Layer 1 — URL pre-screening, ported from `scripts/web-safety-approve.sh` and
//! its shared helpers in `scripts/web-safety-lib.sh`.
//!
//! This is a PORT, not a redesign. Bash remains the authority for as long as it
//! is the thing wired into `hooks/hooks.json`, so where the shell does something
//! surprising this module reproduces the surprise and documents it rather than
//! improving on it. A "fix" here would show up as a differential failure and,
//! worse, as two controls that disagree about the same URL.
//!
//! Order matters and is the shell's:
//!
//! 1. hard blocks — security primitives, the allowlist cannot override them;
//! 2. allowlist — equals-or-subdomain suffix match, short-circuits what follows;
//! 3. soft blocks — heuristics the allowlist is allowed to overrule.
//!
//! The normalizer aims at the host a WHATWG/curl-style client would actually
//! connect to, because parser disagreement between the checker and the fetcher
//! is the classic SSRF bypass. It is deliberately fail-toward-block: an
//! ambiguous or hostile authority becomes [`INVALID_AUTHORITY`], which
//! [`host_is_internal`] treats as internal.

use regex::Regex;
use std::sync::OnceLock;

/// The parser-desync sentinel. Not a host: a marker that the authority could not
/// be resolved to one interpretation, which [`host_is_internal`] blocks.
pub const INVALID_AUTHORITY: &str = "ws-invalid-authority";

/// The outcome of a pre-screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// Nothing matched. NOT a statement that the URL is safe — only that Layer 1
    /// found no reason to refuse it.
    Allow,
    /// Refuse, with the shell's own reason string so the two implementations can
    /// be compared on the reason and not merely on the verdict.
    Block(String),
}

impl Screen {
    pub fn is_block(&self) -> bool {
        matches!(self, Screen::Block(_))
    }
    pub fn reason(&self) -> Option<&str> {
        match self {
            Screen::Block(r) => Some(r),
            Screen::Allow => None,
        }
    }
}

// --- character classes -------------------------------------------------------

/// Control characters the shell rejects ANYWHERE in the raw URL: `[\t\n\r\f\v]`.
/// They signal request-splitting / parser desync and are never valid in a URL.
const CONTROLS: [char; 5] = ['\t', '\n', '\r', '\u{0c}', '\u{0b}'];

/// Leading whitespace the fetcher would strip, so the byte-0-anchored scheme and
/// SSRF checks must strip it too — otherwise a leading NBSP slips the entire
/// classification. Mirrors the shell's perl character class exactly, ASCII and
/// Unicode both, because `[[:space:]]` in the C locale is ASCII-only.
fn is_leading_ws(c: char) -> bool {
    matches!(
        c,
        '\u{09}'
            | '\u{0a}'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{0d}'
            | '\u{20}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200B}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

// --- helpers ported from web-safety-lib.sh -----------------------------------

/// Decode `%XX` sequences. One pass; the caller iterates to a fixed point.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let (h, l) = (hexval(b[i + 1]), hexval(b[i + 2]));
            if let (Some(h), Some(l)) = (h, l) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    // Lossy on purpose: the shell's perl decode emits bytes, and a decoded
    // sequence that is not valid UTF-8 is hostile input, not text to preserve.
    String::from_utf8_lossy(&out).into_owned()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Collapse an integer-encoded IPv4 to canonical dotted-quad, inet_aton style.
///
/// Covers whole decimal (`2130706433`), hex (`0x7f000001`), octal (`017700000001`)
/// and dotted forms whose labels are any of those (`0177.0.0.1`). A non-IP host
/// passes through untouched.
pub fn ipv4_canonical(h: &str) -> String {
    // Whole integer: hex (0x..), octal (leading 0), or decimal.
    if is_whole_integer_form(h) {
        let n = if let Some(hex) = h.strip_prefix("0x").or_else(|| h.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else if h.starts_with('0') && h.len() > 1 {
            u64::from_str_radix(&h[1..], 8).ok()
        } else {
            h.parse::<u64>().ok()
        };
        if let Some(n) = n {
            if n <= 4_294_967_295 {
                return format!(
                    "{}.{}.{}.{}",
                    (n >> 24) & 255,
                    (n >> 16) & 255,
                    (n >> 8) & 255,
                    n & 255
                );
            }
        }
        return h.to_string();
    }

    // Dotted form whose labels may be octal / hex / decimal.
    if h.contains('.')
        && h.chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == 'x')
    {
        let parts: Vec<&str> = h.split('.').collect();
        if (2..=4).contains(&parts.len())
            && parts.iter().all(|p| {
                (p.starts_with("0x")
                    && p.len() > 2
                    && p[2..].chars().all(|c| c.is_ascii_hexdigit()))
                    || (!p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            })
        {
            let octets: Vec<String> = parts
                .iter()
                .map(|p| {
                    let v = if let Some(x) = p.strip_prefix("0x") {
                        u64::from_str_radix(x, 16).unwrap_or(0)
                    } else if p.len() > 1
                        && p.starts_with('0')
                        && p[1..].bytes().all(|b| (b'0'..=b'7').contains(&b))
                    {
                        u64::from_str_radix(&p[1..], 8).unwrap_or(0)
                    } else {
                        p.parse::<u64>().unwrap_or(0)
                    };
                    v.to_string()
                })
                .collect();
            return octets.join(".");
        }
    }
    h.to_string()
}

fn is_whole_integer_form(h: &str) -> bool {
    if let Some(x) = h.strip_prefix("0x") {
        return !x.is_empty() && x.chars().all(|c| c.is_ascii_hexdigit());
    }
    if h == "0" {
        return true;
    }
    if let Some(rest) = h.strip_prefix('0') {
        return !rest.is_empty() && rest.bytes().all(|b| (b'0'..=b'7').contains(&b));
    }
    !h.is_empty()
        && h.starts_with(|c: char| c.is_ascii_digit() && c != '0')
        && h.chars().all(|c| c.is_ascii_digit())
}

/// The canonical lowercased bare host, or [`INVALID_AUTHORITY`].
pub fn normalize_host(raw: &str) -> String {
    if raw.chars().any(|c| matches!(c, '\r' | '\n' | '\t')) {
        return INVALID_AUTHORITY.to_string();
    }
    // Strip scheme (no-op when absent).
    let mut host = match raw.find("://") {
        Some(i) => raw[i + 3..].to_string(),
        None => raw.to_string(),
    };
    // WHATWG: a backslash is equivalent to a slash inside the authority. Done
    // BEFORE the path strip so `127.0.0.1\@evil.com` cannot hide the real host.
    host = host.replace('\\', "/");
    host = host.split('/').next().unwrap_or("").to_string();
    host = host.split('?').next().unwrap_or("").to_string();
    host = host.split('#').next().unwrap_or("").to_string();
    // Userinfo: greedy to the LAST '@', matching the shell's `${host##*@}`.
    if let Some(i) = host.rfind('@') {
        host = host[i + 1..].to_string();
    }
    // A bracketed IPv6 literal keeps its brackets and colons; anything else
    // loses its port.
    if !(host.starts_with('[') && host.contains(']')) {
        if let Some(i) = host.find(':') {
            host = host[..i].to_string();
        }
    }
    // Percent-decode to a fixed point, at most 3 passes. A double-encoded host
    // would otherwise be classified in its encoded form while a multi-decoding
    // fetcher reaches the internal target.
    let mut prev = String::new();
    let mut i = 0;
    while host != prev && i < 3 {
        prev = host.clone();
        host = percent_decode(&host);
        i += 1;
    }
    // A separator or control re-introduced by decoding, or any residual %XX
    // (legitimate hosts never contain '%'), is hostile.
    if host
        .chars()
        .any(|c| matches!(c, '/' | '@' | '\\' | '\r' | '\n' | '\t'))
        || residual_percent(&host)
    {
        return INVALID_AUTHORITY.to_string();
    }
    ipv4_canonical(&host.to_lowercase())
}

fn residual_percent(h: &str) -> bool {
    let b = h.as_bytes();
    (0..b.len()).any(|i| {
        b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
    })
}

/// Loopback / private / link-local / cloud-metadata targets that must never be
/// fetched. The allowlist cannot override this.
///
/// CONSUMER CONTRACT (inherited from the shell): for IP-literal hosts this must
/// be paired with [`host_is_bare_ip`]. Hex-grouped IPv4-mapped IPv6 is
/// classified here only for loopback (`::ffff:7f..`) and AWS metadata
/// (`::ffff:a9fe`); a hex-grouped PRIVATE range is caught by the bare-IP rule.
pub fn host_is_internal(h: &str) -> bool {
    if h == INVALID_AUTHORITY {
        return true;
    }
    // IPv4-mapped / IPv4-compatible IPv6 → reclassify the embedded dotted IPv4.
    if h.contains(':') && h.matches('.').count() >= 3 {
        let inner = h.trim_start_matches('[').trim_end_matches(']');
        if let Some(tail) = inner.rsplit(':').next() {
            if tail.matches('.').count() == 3 && host_is_internal(&ipv4_canonical(tail)) {
                return true;
            }
        }
    }
    let lower = h.to_lowercase();
    // Hex-grouped IPv4-mapped loopback (7f00:…) / AWS metadata (a9fe:a9fe).
    if lower.contains(":ffff:a9fe") || lower.starts_with("[::ffff:a9fe") {
        return true;
    }
    if let Some(i) = lower.find(":ffff:7f") {
        // `*:ffff:7f[0-9a-f][0-9a-f]:*` or a bracketed `[*:ffff:7f*`
        let rest = &lower[i + ":ffff:7f".len()..];
        if lower.starts_with("[::ffff:7f")
            || (rest.len() >= 3
                && rest.as_bytes()[0].is_ascii_hexdigit()
                && rest.as_bytes()[1].is_ascii_hexdigit()
                && rest[2..].starts_with(':'))
        {
            return true;
        }
    }
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }
    if lower == "metadata" || lower.starts_with("metadata.") || lower.ends_with(".internal") {
        return true;
    }
    // IPv4 ranges — canonical dotted by now if it arrived as an integer form.
    for p in ["0.", "127.", "10.", "192.168.", "169.254."] {
        if lower.starts_with(p) {
            return true;
        }
    }
    if let Some(rest) = lower.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u32>() {
                // The shell's globs are literal: 172.16-19, 172.20-29, 172.30-31.
                if (16..=31).contains(&n) && rest.len() > second.len() {
                    return true;
                }
            }
        }
    }
    // IPv6 loopback / unique-local / link-local, bracketed or bare.
    if lower == "::1"
        || lower == "[::1]"
        || lower.starts_with("fe80:")
        || lower.starts_with("[fe80:")
    {
        return true;
    }
    if lower.starts_with("[fc") || lower.starts_with("[fd") {
        return true;
    }
    // `fc??:*` / `fd??:*` — exactly two characters between the prefix and the colon.
    for p in ["fc", "fd"] {
        if let Some(rest) = lower.strip_prefix(p) {
            let b = rest.as_bytes();
            if b.len() > 2 && b[2] == b':' {
                return true;
            }
        }
    }
    false
}

/// A bare IPv4 dotted-quad or an IPv6 literal — no domain name. Legitimate web
/// content uses domains, not raw IPs.
pub fn host_is_bare_ip(h: &str) -> bool {
    if (h.starts_with('[') && h.contains(':') && h.ends_with(']')) || h.matches(':').count() >= 2 {
        return true;
    }
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| (1..=3).contains(&p.len()) && p.chars().all(|c| c.is_ascii_digit()))
}

/// Equals-or-subdomain match against a list's entries. Comment-aware, blank-safe.
pub fn host_in_list(host: &str, entries: &[String]) -> bool {
    for raw in entries {
        let e = raw.trim();
        if e.is_empty() || e.starts_with('#') {
            continue;
        }
        // The shell strips ALL whitespace from the entry, not just the ends.
        let domain: String = e
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_lowercase();
        if domain.is_empty() {
            continue;
        }
        if host == domain || host.ends_with(&format!(".{domain}")) {
            return true;
        }
    }
    false
}

// --- the screen ---------------------------------------------------------------

fn re_scheme() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^(data:|file:|javascript:|blob:|ftp:)").unwrap())
}

fn re_credentials() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)https?://[^/]*:[^/]*@").unwrap())
}

fn re_redirect() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)[?&](redirect|url|next|goto|return|redir|dest|target|forward|continue|returnUrl)=https?://[^/?&#]*",
        )
        .unwrap()
    })
}

fn re_encoded() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)%[0-9a-f]{2}").unwrap())
}

fn re_risky_tld() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\.(tk|ml|ga|cf|gq|zip|mov|top|buzz|surf|click|link)\b").unwrap()
    })
}

/// Pre-screen one URL.
///
/// `allowlist` and `blocklist` are the files' lines, already read. Passing them
/// in rather than reading here keeps the policy pure and testable, and keeps the
/// engine's filesystem surface where the rest of its path handling lives.
pub fn screen(url: &str, allowlist: &[String], blocklist: &[String]) -> Screen {
    // The authority reads the URL through `URL=$(echo "$INPUT" | jq -r ...)`,
    // and command substitution strips every TRAILING newline before any rule
    // sees the value. So Bash structurally cannot observe a trailing `\n`, and a
    // port that does would block URLs the authority permits.
    //
    // Faithful rather than stricter, and safe: the stripped bytes are exactly
    // the ones the fetcher would never send. Leading and embedded controls are
    // untouched and still hard-blocked below — those are the request-splitting
    // shapes this rule exists for.
    let url = url.trim_end_matches('\n');

    if url.is_empty() {
        // The shell guards the whole block with `[ -n "$URL" ]`: a WebSearch
        // free-text query is not a URL and must not be run through these rules.
        return Screen::Allow;
    }

    // --- hard blocks (allowlist cannot override) ---
    if url.chars().any(|c| CONTROLS.contains(&c)) {
        return block("control characters in URL");
    }

    let url_c: &str = url.trim_start_matches(is_leading_ws);

    if re_scheme().is_match(url_c) {
        return block("dangerous URI scheme");
    }

    let lower_c = url_c.to_lowercase();
    if lower_c.starts_with("http://") || lower_c.starts_with("https://") {
        let h = normalize_host(url_c);
        if h.is_empty() {
            return block("malformed URL (empty host)");
        }
        if host_is_internal(&h) {
            return block("internal network (SSRF)");
        }
        if host_is_bare_ip(&h) {
            return block("direct IP address");
        }
    }

    // Byte length, matching the shell's `${#URL}` under a UTF-8 locale is char
    // count; both agree for the ASCII URLs this bound is about, and a
    // multi-byte URL that straddles the limit is contained either way.
    if url.chars().count() > 2048 {
        return block("URL exceeds 2048 chars");
    }

    if re_credentials().is_match(url) {
        return block("credentials in URL");
    }

    // Open redirect: only a FOREIGN target can bounce the fetcher off-origin, so
    // a same-host or subdomain target is not a finding. Deliberately asymmetric —
    // a PARENT-domain target stays foreign, because sibling-subdomain takeover is
    // a real bounce.
    let targets: Vec<&str> = re_redirect().find_iter(url).map(|m| m.as_str()).collect();
    if !targets.is_empty() {
        let req_host = normalize_host(url_c);
        if req_host.is_empty() || req_host == INVALID_AUTHORITY {
            return block("open redirect parameter");
        }
        for t in targets {
            let after_eq = match t.find('=') {
                Some(i) => &t[i + 1..],
                None => continue,
            };
            let redir_host = normalize_host(after_eq);
            let same = redir_host == req_host || redir_host.ends_with(&format!(".{req_host}"));
            if !same {
                return block("open redirect parameter");
            }
        }
    }

    let encoded = re_encoded().find_iter(url).count();
    if encoded > 10 {
        return block(&format!("excessive URL encoding ({encoded} sequences)"));
    }

    // --- allowlist short-circuit ---
    //
    // NOTE: this host is derived DIFFERENTLY from `normalize_host` above — the
    // shell uses a plain `sed` strip (scheme, then path, then port) with no
    // userinfo handling, no percent-decoding and no IPv4 canonicalization. The
    // divergence is preserved deliberately: changing it here would make the two
    // implementations disagree about which URLs are allowlisted, which is worse
    // than the quirk. Flagged in the MAC-51 notes as a Bash-side cleanup
    // candidate, to be changed in BOTH or neither.
    let allow_host = allowlist_host(url);
    let allowlisted = !allow_host.is_empty() && host_in_list(&allow_host, allowlist);

    // --- soft blocks (allowlist overrides) ---
    if !allowlisted {
        if re_risky_tld().is_match(url) {
            return block("high-risk TLD");
        }
        // Fixed-string, case-insensitive, against non-blank non-comment entries
        // only. An empty pattern set must match NOTHING: BSD `grep -F -f` with a
        // blank pattern file matches every line, which would block all fetches.
        let lower_url = url.to_lowercase();
        for raw in blocklist {
            let e = raw.trim();
            if e.is_empty() || e.starts_with('#') {
                continue;
            }
            if lower_url.contains(&e.to_lowercase()) {
                return block("domain in blocklist");
            }
        }
    }

    Screen::Allow
}

/// The shell's allowlist host derivation, quirks included. See the note at the
/// call site for why it is not `normalize_host`.
fn allowlist_host(url: &str) -> String {
    let mut h = url.to_string();
    for p in ["https://", "http://"] {
        if h.len() >= p.len() && h[..p.len()].eq_ignore_ascii_case(p) {
            h = h[p.len()..].to_string();
            break;
        }
    }
    h = h.split('/').next().unwrap_or("").to_string();
    h = h.split(':').next().unwrap_or("").to_string();
    h.to_lowercase()
}

fn block(reason: &str) -> Screen {
    Screen::Block(reason.to_string())
}
