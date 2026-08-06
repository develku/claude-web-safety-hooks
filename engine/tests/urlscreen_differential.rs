//! Layer 1 differential: the Rust port vs the Bash authority, same input.
//!
//! Bash is the authority for as long as it is what `hooks/hooks.json` runs, so
//! the question this suite answers is not "is the Rust screen correct?" but "do
//! the two agree?". A disagreement is a porting defect by definition, whichever
//! side looks more sensible — two controls that differ on the same URL is a
//! worse outcome than either behaviour alone.
//!
//! Both the verdict AND the reason are compared. A port that blocks the right
//! URLs for the wrong reasons would pass a verdict-only check and then diverge
//! the moment someone tunes a rule.
//!
//! Isolation: a throwaway `WEB_SAFETY_CONFIG_DIR`, and `osascript` shadowed on
//! PATH so a corpus of blocked URLs cannot fire real desktop notifications.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use web_safety_engine::urlscreen::{screen, Screen};

fn repo_root() -> PathBuf {
    // <repo>/engine/tests/.. /.. — the engine is a subdirectory of the checkout,
    // and the Bash authority lives beside it.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine has a parent")
        .to_path_buf()
}

fn approve_script() -> PathBuf {
    repo_root().join("scripts/web-safety-approve.sh")
}

/// A disposable environment PER TEST: a config dir the script may write logs
/// and lists into, and a PATH whose `osascript` does nothing.
///
/// Keyed by `tag`, not just by pid: cargo runs these tests in parallel threads
/// of ONE process, so a pid-only key gave every test the same directory and the
/// allowlist one wrote `url-allowlist.txt` under the corpus test's feet.
fn sandbox(tag: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("ws-l1-diff-{}-{tag}", std::process::id()));
    let cfg = base.join("cfg");
    let bin = base.join("bin");
    fs::create_dir_all(&cfg).expect("cfg dir");
    fs::create_dir_all(&bin).expect("bin dir");
    // Shadow the macOS notifier. Without this every blocked URL in the corpus
    // pops a real notification on the operator's desktop.
    for stub in [
        "osascript",
        "notify-send",
        "powershell.exe",
        "terminal-notifier",
    ] {
        let p = bin.join(stub);
        fs::write(&p, "#!/bin/sh\nexit 0\n").expect("stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
    }
    (cfg, bin)
}

/// Run the Bash authority and reduce its response to (blocked, reason).
fn bash_screen(url: &str, cfg: &Path, bin: &Path) -> (bool, String) {
    let envelope = serde_json::json!({
        "tool_name": "WebFetch",
        "tool_input": {"url": url},
    })
    .to_string();

    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut child = Command::new("bash")
        .arg(approve_script())
        .env("WEB_SAFETY_CONFIG_DIR", cfg)
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the bash authority spawns");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(envelope.as_bytes())
        .expect("write envelope");
    let out = child.wait_with_output().expect("bash runs");

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "bash stdout is not JSON ({e}) for {url:?}: {:?}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    let blocked = v["decision"] == "block";
    let reason = squeeze_ws(
        v["reason"]
            .as_str()
            .unwrap_or("")
            .trim_start_matches("Pre-screening blocked: "),
    );
    (blocked, if blocked { reason } else { String::new() })
}

/// Collapse runs of spaces — the ONLY normalization applied to either side.
///
/// It exists for one specific, platform-dependent Bash artifact: the
/// encoded-sequence count is interpolated straight from `wc -l`, and BSD `wc`
/// left-pads its number while GNU `wc` does not. So the authority's own reason
/// string is `"excessive URL encoding (      11 sequences)"` on macOS and
/// `"...(11 sequences)"` on Linux — stray whitespace in prose the model reads,
/// and a differential that would pass or fail depending on the runner's libc.
///
/// Reproducing the padding in Rust would make the port platform-dependent to
/// match a formatting bug. Normalizing the comparison keeps the differential
/// honest about the DECISION while refusing to enshrine the defect. Recorded as
/// a Bash-side finding on MAC-51 rather than silently absorbed.
fn squeeze_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        let is_space = c == ' ';
        if !(is_space && prev_space) {
            out.push(c);
        }
        prev_space = is_space;
    }
    // The padding sits between `(` and the number, so collapsing runs alone
    // still leaves `( 11` against `(11`.
    out.replace("( ", "(").replace(" )", ")")
}

/// Applied to BOTH sides, so the normalization can never quietly excuse a
/// difference on the Rust side that it would have caught on the Bash side.
fn rust_screen(url: &str) -> (bool, String) {
    match screen(url, &[], &[]) {
        Screen::Allow => (false, String::new()),
        Screen::Block(r) => (true, squeeze_ws(&r)),
    }
}

/// Every rule in `web-safety-approve.sh`, plus the encodings each one is meant
/// to survive. Kept as plain data so a new rule is a new row, not a new test.
const CORPUS: &[&str] = &[
    // -- clean --
    "https://example.com/",
    "https://example.com/path?a=1&b=2",
    "https://sub.domain.example.com/x",
    "http://example.com:8080/x",
    "https://example.com/%20space",
    // -- control characters --
    "https://exa\tmple.com/",
    "https://example.com/\n",
    "\nhttps://example.com/",
    "https://example.com/\r\n",
    // -- dangerous schemes, incl. leading-whitespace evasion --
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "blob:https://example.com/uuid",
    "ftp://example.com/x",
    "  data:text/html,x",
    "\u{00A0}javascript:alert(1)",
    "\u{FEFF}file:///etc/passwd",
    "\u{3000}data:text/plain,x",
    // -- SSRF / internal --
    "http://localhost/",
    "http://localhost:8080/admin",
    "http://foo.localhost/",
    "http://127.0.0.1/",
    "http://127.1.2.3/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://172.16.0.1/",
    "http://172.20.0.1/",
    "http://172.31.255.1/",
    "http://172.32.0.1/",
    "http://0.0.0.0/",
    "http://metadata.google.internal/",
    "http://metadata/",
    "http://anything.internal/",
    // -- SSRF via integer / hex / octal encodings --
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://0177.0.0.1/",
    "http://127.0.0.1.nip.io/",
    // -- SSRF via userinfo / backslash / percent encoding --
    "http://user@127.0.0.1/",
    "http://example.com@127.0.0.1/",
    "http://127.0.0.1\\@example.com/",
    "http://%31%32%37%2e%30%2e%30%2e%31/",
    "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/",
    // -- IPv6 --
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[fe80::1]/",
    "http://[fd00::1]/",
    // -- bare IP --
    "http://93.184.216.34/",
    "http://8.8.8.8/",
    // -- malformed authority --
    "http:///path",
    "http://",
    // -- credentials --
    "https://user:pass@example.com/",
    "https://u:p@sub.example.com/x",
    // -- open redirect --
    "https://example.com/?redirect=https://evil.com",
    "https://example.com/?url=https://evil.com/x",
    "https://example.com/?next=https://example.com/safe",
    "https://example.com/?next=https://sub.example.com/safe",
    "https://sub.example.com/?next=https://example.com/parent",
    "https://example.com/?goto=https://evil.com&format=json",
    "https://example.com/?redir=https://example.com&url=https://evil.com",
    "https://example.com/?target=http://example.com/a",
    // -- excessive encoding --
    "https://example.com/%41%42%43%44%45",
    "https://example.com/%41%42%43%44%45%46%47%48%49%4a%4b",
    "https://example.com/%41%42%43%44%45%46%47%48%49%4a%4b%4c%4d",
    // -- high-risk TLD --
    "https://evil.tk/",
    "https://foo.zip/x",
    "https://bar.click/y",
    "https://good.com/notatk",
    // -- oddities --
    "https://EXAMPLE.COM/",
    "HTTPS://EXAMPLE.COM/",
    "https://example.com",
    "//example.com/x",
    "example.com/x",
    "not a url at all",
    "",
];

#[test]
fn the_rust_screen_agrees_with_the_bash_authority_on_every_corpus_url() {
    let script = approve_script();
    assert!(
        script.is_file(),
        "the Bash authority is missing at {} — this suite compares against it, \
         and skipping the comparison would report agreement that was never checked",
        script.display()
    );

    let (cfg, bin) = sandbox("corpus");
    let mut mismatches: Vec<String> = Vec::new();

    for url in CORPUS {
        let (b_blocked, b_reason) = bash_screen(url, &cfg, &bin);
        let (r_blocked, r_reason) = rust_screen(url);
        if b_blocked != r_blocked || b_reason != r_reason {
            mismatches.push(format!(
                "  {url:?}\n      bash: blocked={b_blocked} reason={b_reason:?}\n      rust: blocked={r_blocked} reason={r_reason:?}"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} of {} URLs disagree:\n{}",
        mismatches.len(),
        CORPUS.len(),
        mismatches.join("\n")
    );
}

/// The allowlist is the one input the differential cannot exercise through the
/// corpus above, because the Bash side reads it from a file. Same file, both
/// sides, so the equals-or-subdomain rule and the comment/blank handling are
/// compared rather than assumed.
#[test]
fn the_allowlist_short_circuit_agrees_with_the_bash_authority() {
    let script = approve_script();
    assert!(script.is_file(), "the Bash authority is missing");

    let (cfg, bin) = sandbox("allowlist");
    let entries = "# a comment\n\n  example.tk  \nfoo.zip\n";
    fs::write(cfg.join("url-allowlist.txt"), entries).expect("allowlist");
    let list: Vec<String> = entries.lines().map(str::to_string).collect();

    // Each of these trips a SOFT block that the allowlist is allowed to overrule.
    for url in [
        "https://example.tk/",
        "https://sub.example.tk/x",
        "https://foo.zip/y",
        "https://other.tk/",
        "https://notexample.tk/",
    ] {
        let (b_blocked, b_reason) = bash_screen(url, &cfg, &bin);
        let (r_blocked, r_reason) = match screen(url, &list, &[]) {
            Screen::Allow => (false, String::new()),
            Screen::Block(r) => (true, squeeze_ws(&r)),
        };
        assert_eq!(
            (b_blocked, b_reason.as_str()),
            (r_blocked, r_reason.as_str()),
            "allowlist disagreement on {url:?}"
        );
    }
}

/// A hard block must survive an allowlist entry for the same host — that is what
/// separates a security primitive from a heuristic.
#[test]
fn the_allowlist_cannot_override_a_hard_block() {
    let script = approve_script();
    assert!(script.is_file(), "the Bash authority is missing");

    let (cfg, bin) = sandbox("hardblock");
    let entries = "localhost\n127.0.0.1\nexample.com\n";
    fs::write(cfg.join("url-allowlist.txt"), entries).expect("allowlist");
    let list: Vec<String> = entries.lines().map(str::to_string).collect();

    for url in [
        "http://localhost/",
        "http://127.0.0.1/",
        "https://user:pass@example.com/",
    ] {
        let (b_blocked, b_reason) = bash_screen(url, &cfg, &bin);
        let (r_blocked, r_reason) = match screen(url, &list, &[]) {
            Screen::Allow => (false, String::new()),
            Screen::Block(r) => (true, squeeze_ws(&r)),
        };
        assert!(b_blocked, "the authority stopped hard-blocking {url:?}");
        assert_eq!(
            (b_blocked, b_reason.as_str()),
            (r_blocked, r_reason.as_str()),
            "hard-block disagreement on {url:?}"
        );
    }
}
