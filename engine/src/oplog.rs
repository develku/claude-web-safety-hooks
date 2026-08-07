//! The operator audit log — the `web-safety.log` rows the Bash hooks write.
//!
//! When the engine is the wired production scanner, it must keep feeding the
//! log's three consumer classes or they silently die with the Bash writers:
//!
//! * `web-safety-agent-result.sh` and `web-safety-stop-gate.sh` join
//!   `[PENDING-KILLED]` rows to resolving Agent calls (Layer 7);
//! * `/web-safety:report` tabulates every `[A-Z-]+` tag;
//! * the operator reads it directly.
//!
//! The row FORMATS are therefore a contract, byte-compatible with the shell
//! writers (`web-safety-approve.sh`, `web-safety-egress.sh`,
//! `web-safety-scanner.sh`'s `record_agent_kill`), and the same log-injection
//! rules apply: every attacker-influenced value is control-stripped and
//! bounded before it becomes part of a line, because a raw newline would forge
//! rows the consumers then trust.
//!
//! Every write here is best-effort by design, mirroring the hooks' `2>/dev/null`
//! posture: the audit trail must never decide a verdict, so an unwritable log
//! changes nothing about the delivered response.

use std::io::Write;
use std::path::{Path, PathBuf};

/// A handle on the operator log. `None` inside means "no log configured" and
/// every write is a no-op — the deterministic default for tests and for a CLI
/// run without `--config-dir`.
pub struct Oplog {
    path: Option<PathBuf>,
}

impl Oplog {
    pub fn disabled() -> Oplog {
        Oplog { path: None }
    }

    pub fn at(path: PathBuf) -> Oplog {
        Oplog { path: Some(path) }
    }

    /// `[PRE-BLOCK]` — Layer 1 refused a URL before the fetch.
    /// Shell shape: `url=<url> reason=<reason>` (`web-safety-approve.sh`).
    pub fn pre_block(&self, url: &str, reason: &str) {
        self.write(&format!(
            "[PRE-BLOCK] url={} reason={}",
            clean(url, 256),
            reason
        ));
    }

    /// `[EGRESS-ASK-FETCH]` — the armed guard escalated a web fetch.
    /// Shell shape: `session=<id> tool=<name> url=<url|<unparsed>>`.
    pub fn egress_ask_fetch(&self, session: &str, tool: &str, url: Option<&str>) {
        let detail = format!(
            "tool={} url={}",
            tool,
            match url {
                Some(u) if !u.is_empty() => u,
                _ => "<unparsed>",
            }
        );
        self.write(&format!(
            "[EGRESS-ASK-FETCH] session={} {}",
            session_key(session),
            clean(&detail, 200)
        ));
    }

    /// `[EGRESS-ASK]` — the armed guard escalated an outbound Bash command.
    /// Shell shape: `session=<id> cmd="<command>"`.
    pub fn egress_ask_bash(&self, session: &str, command: &str) {
        self.write(&format!(
            "[EGRESS-ASK] session={} cmd=\"{}\"",
            session_key(session),
            clean(command, 200)
        ));
    }

    /// `[EGRESS-SEARCH-DOWNGRADE]` — armed-window WebSearch: logged, not
    /// prompted. Shell shape: `session=<id> query="<query>"`.
    pub fn egress_search_downgrade(&self, session: &str, query: &str) {
        self.write(&format!(
            "[EGRESS-SEARCH-DOWNGRADE] session={} query=\"{}\"",
            session_key(session),
            clean(query, 200)
        ));
    }

    /// `[<SEVERITY>]` — a detection verdict, `web-safety-scanner.sh`'s
    /// `log_detection`: `tool=<name>[ url=<url>] patterns=<labels>`. This is
    /// the row `/web-safety-report` counts by severity.
    pub fn detection(&self, severity: &str, tool: &str, url: Option<&str>, patterns: &str) {
        let url_part = match url {
            Some(u) if !u.is_empty() => format!(" url={}", clean(u, 256)),
            _ => String::new(),
        };
        self.write(&format!(
            "[{}] tool={}{} patterns={}",
            clean(severity, 16),
            clean(tool, 64),
            url_part,
            clean(patterns, 300)
        ));
    }

    /// `[PENDING-KILLED]` — a subagent is about to die on a containment
    /// verdict; make the death attributable BEFORE it happens. Shell shape
    /// (`record_agent_kill`): `epoch=<s> session=<id> agent=<id>
    /// severity=<SEV> tool=<name>[ url=<url>] patterns=[<labels>]`.
    ///
    /// The k=v fields are exactly what the two Layer 7 consumers parse, so
    /// their `grep`/`awk` joins keep working when this writer replaces the
    /// shell one.
    #[allow(clippy::too_many_arguments)]
    pub fn pending_killed(
        &self,
        epoch: u64,
        session: &str,
        agent: &str,
        severity: &str,
        tool: &str,
        url: Option<&str>,
        patterns: &str,
    ) {
        let agent = session_key(agent);
        if agent.is_empty() {
            // The shell writer requires an agent id — a main-session halt is
            // read live in its stopReason and writes no row.
            return;
        }
        let url_part = match url {
            Some(u) if !u.is_empty() => format!(" url={}", clean(u, 256)),
            _ => String::new(),
        };
        self.write(&format!(
            "[PENDING-KILLED] epoch={} session={} agent={} severity={} tool={}{} patterns=[{}]",
            epoch,
            session_key(session),
            agent,
            clean(severity, 16),
            clean(tool, 64),
            url_part,
            clean(patterns, 300)
        ));
    }

    fn write(&self, row: &str) {
        let Some(path) = &self.path else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        else {
            return;
        };
        let _ = writeln!(f, "[{}] {}", timestamp(), row);
    }
}

/// The default log location under a config dir — the shell hooks' own
/// `$CONFIG_DIR/web-safety.log`.
pub fn default_log(config_dir: &Path) -> PathBuf {
    config_dir.join("web-safety.log")
}

/// Strip C0 controls and DEL, bound the length — the hooks' uniform
/// `tr -d '\000-\037\177' | cut -c1-N` log-injection defense.
fn clean(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '\u{7f}')
        .take(max)
        .collect()
}

/// The join keys are whitelist-sanitized harder than free-text fields, exactly
/// as both writers and readers do: `tr -cd 'A-Za-z0-9_-' | cut -c1-64`.
fn session_key(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect()
}

/// `date '+%Y-%m-%d %H:%M:%S'` in local time, computed without a clock
/// dependency beyond std: seconds since the epoch, offset by the local zone as
/// libc reports it once per process.
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_local(now)
}

/// Epoch seconds for the `epoch=` field.
pub fn epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format epoch seconds as a local `YYYY-mm-dd HH:MM:SS`, using the TZ offset
/// the platform reports for *now*. The row's readers parse only the bracketed
/// tag and the k=v fields — the human-facing timestamp needs to be right, not
/// nanosecond-faithful across a DST boundary mid-second.
fn format_local(epoch: u64) -> String {
    let offset = local_offset_secs();
    let t = epoch as i64 + offset;
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// The local UTC offset in seconds, via libc's `localtime_r` — the same answer
/// `date` gives, with no new dependency.
fn local_offset_secs() -> i64 {
    #[cfg(unix)]
    {
        use std::os::raw::{c_char, c_int, c_long};
        #[repr(C)]
        struct Tm {
            tm_sec: c_int,
            tm_min: c_int,
            tm_hour: c_int,
            tm_mday: c_int,
            tm_mon: c_int,
            tm_year: c_int,
            tm_wday: c_int,
            tm_yday: c_int,
            tm_isdst: c_int,
            tm_gmtoff: c_long,
            tm_zone: *const c_char,
        }
        extern "C" {
            fn localtime_r(clock: *const i64, result: *mut Tm) -> *mut Tm;
        }
        let now = epoch_now() as i64;
        let mut tm = unsafe { std::mem::zeroed::<Tm>() };
        let ok = unsafe { localtime_r(&now, &mut tm) };
        if ok.is_null() {
            0
        } else {
            tm.tm_gmtoff as i64
        }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Howard Hinnant's `civil_from_days` — days since 1970-01-01 to (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_control_stripped_and_bounded_before_they_join_a_row() {
        let hostile = "evil\n[FORGED-ROW] session=x\r\ttail";
        let c = clean(hostile, 200);
        assert!(!c.contains('\n') && !c.contains('\r') && !c.contains('\t'));
        assert!(
            c.contains("[FORGED-ROW]"),
            "content survives, controls do not"
        );
        assert_eq!(clean(&"x".repeat(500), 200).len(), 200);
    }

    #[test]
    fn join_keys_admit_only_the_whitelisted_alphabet() {
        assert_eq!(session_key("abc-123_XYZ"), "abc-123_XYZ");
        assert_eq!(session_key("a b/c\\d=e"), "abcde");
        assert_eq!(session_key(&"a".repeat(100)).len(), 64);
    }

    #[test]
    fn a_disabled_log_writes_nothing_and_never_errors() {
        let log = Oplog::disabled();
        log.pre_block("https://x.test", "reason");
        log.pending_killed(0, "s", "a", "HIGH", "WebFetch", None, "p");
    }

    #[test]
    fn the_pending_killed_row_carries_every_field_its_consumers_parse() {
        let dir = std::env::temp_dir().join(format!("ws-oplog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = Oplog::at(dir.join("web-safety.log"));
        log.pending_killed(
            1700000000,
            "sess-1",
            "agent-9",
            "HIGH",
            "WebFetch",
            Some("https://evil.test/x?q=1"),
            "ignore_previous, im_start",
        );
        let text = std::fs::read_to_string(dir.join("web-safety.log")).expect("row written");
        for needle in [
            "[PENDING-KILLED]",
            "epoch=1700000000",
            "session=sess-1 ",
            "agent=agent-9 ",
            "severity=HIGH ",
            "tool=WebFetch ",
            "url=https://evil.test/x?q=1 ",
            "patterns=[ignore_previous, im_start]",
        ] {
            assert!(text.contains(needle), "{needle:?} missing from: {text}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kill_with_no_agent_writes_no_row_because_the_user_reads_it_live() {
        let dir = std::env::temp_dir().join(format!("ws-oplog-main-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = Oplog::at(dir.join("web-safety.log"));
        log.pending_killed(0, "sess-1", "", "HIGH", "WebFetch", None, "p");
        assert!(!dir.join("web-safety.log").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_timestamp_shape_matches_the_shell_writers() {
        let ts = format_local(1_700_000_000);
        // `YYYY-mm-dd HH:MM:SS` — 19 chars, separators in place.
        assert_eq!(ts.len(), 19, "{ts}");
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], " ");
        assert_eq!(&ts[13..14], ":");
    }

    #[test]
    fn civil_from_days_agrees_with_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }
}
