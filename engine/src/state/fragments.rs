//! E8 cross-call payload reassembly.
//!
//! The Bash implementation is a small state machine spread across three places
//! in `web-safety-scanner.sh` (the early-exit pre-check, the E8 block, and the
//! post-check prune). It is NOT "concatenate the last few pages and grep", and
//! flattening it into that would silently drop three of its four detections:
//!
//! 1. **The window opens** on a suspicious indicator in *this* fetch, on a
//!    prior strike in the window, or because a fragment is already stored.
//!    The third clause is what captures a benign-looking *completing half*.
//! 2. **The excerpt** is head + tail of the lowered content, confusable-folded,
//!    and bounded — head-only would let an attacker prepend filler until the
//!    payload fell off the end.
//! 3. **Three concatenations** are matched, not one: chronological,
//!    ordering-label-sorted (which defeats arrival order), and affix-bridged
//!    (which defeats a split *inside* a word, `ign` + `ore`).
//! 4. **Only cross-fragment matches count** — a pattern visible in any single
//!    fragment was already adjudicated by the per-fetch pipeline — and each one
//!    fires **once per session**, or a still-open window re-emits the same HIGH
//!    on every later fetch.
//!
//! Scope: the SESSION, across agents. A fan-out that hands one half of a
//! payload to each of two subagents is the attack this exists for. It never
//! crosses a session, task, profile or runtime.

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use regex::Regex;
use rusqlite::Transaction;
use std::collections::BTreeSet;
use std::collections::HashSet;

use super::store::{map_sql, StateStore};
use super::{sanitize_meta, StateContext, StateError};
use crate::corpus::Corpus;
use crate::normalize::{ascii_lower, Views};

const MAX_TOOL_CHARS: usize = 64;
/// The shortest fragment affix Bash indexes. Two characters would match every
/// English document ("th", "he", "in"); three is the FP floor it settled on.
const MIN_AFFIX: usize = 3;

/// The derived trigger lexicon plus the pattern automaton, built once and
/// shared across calls.
///
/// Everything here is *derived* from the MEDIUM corpus rather than
/// hand-curated: Bash learned that the hard way, when the grep used all 14
/// MEDIUM arrays but E8 used only 6, so reassembly attacks built from the other
/// 8 categories never opened the window at all.
pub struct E8Lexicon {
    /// Whole space-split tokens of length >= 3, non-alphanumerics removed.
    tokens: HashSet<String>,
    /// Every 3+ character substring of those tokens.
    affixes: HashSet<String>,
    /// One automaton over the affix set. It is a superset of the token set, so
    /// a single pass answers the whole indicator question.
    affix_ac: AhoCorasick,
    /// `part 1 of 3` / `step 2` / `segment b` / `page 1 of 5` / `1편`.
    ordering: Regex,
    /// The MEDIUM literals, for matching the reassembled concatenations.
    med_patterns: Vec<String>,
    med_ac: AhoCorasick,
}

impl Default for E8Lexicon {
    fn default() -> Self {
        Self::new()
    }
}

impl E8Lexicon {
    pub fn new() -> E8Lexicon {
        E8Lexicon::from_corpus(&Corpus::load())
    }

    pub fn from_corpus(corpus: &Corpus) -> E8Lexicon {
        let mut tokens: HashSet<String> = HashSet::new();
        for e in &corpus.medium {
            for word in e.pattern.split(' ') {
                let t: String = ascii_lower(word)
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect();
                if t.len() >= MIN_AFFIX {
                    tokens.insert(t);
                }
            }
        }

        let mut affixes: HashSet<String> = HashSet::new();
        for t in &tokens {
            let b = t.as_bytes();
            for len in MIN_AFFIX..=b.len() {
                for start in 0..=(b.len() - len) {
                    // Tokens are ASCII by construction, so byte slicing is safe.
                    affixes.insert(t[start..start + len].to_string());
                }
            }
        }

        let affix_list: Vec<&str> = affixes.iter().map(String::as_str).collect();
        let affix_ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build(&affix_list)
            .expect("affix automaton builds");

        let med_patterns: Vec<String> = corpus.medium.iter().map(|e| e.pattern.clone()).collect();
        let med_ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build(&med_patterns)
            .expect("medium automaton builds");

        E8Lexicon {
            tokens,
            affixes,
            affix_ac,
            ordering: Regex::new(
                r"(part [0-9]+( of |/)[0-9]+|step [0-9]+|segment [a-z]\b|page [0-9]+ of [0-9]+|[0-9]+편)",
            )
            .expect("ordering regex compiles"),
            med_patterns,
            med_ac,
        }
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub fn affix_count(&self) -> usize {
        self.affixes.len()
    }

    pub fn is_token(&self, s: &str) -> bool {
        self.tokens.contains(s)
    }

    pub fn is_affix(&self, s: &str) -> bool {
        self.affixes.contains(s)
    }

    /// Does this fetch look like part of a split payload?
    ///
    /// Bounded to `scan_bytes` on purpose. The stored excerpt is itself capped
    /// at 1500 bytes, so scanning further for the *decision* buys nothing — and
    /// an unbounded literal sweep over a long no-match line is exactly the
    /// adversarial-padding cost the Bash version had to defuse.
    pub fn has_indicator(&self, lowered: &str, confusable: &str, scan_bytes: usize) -> bool {
        let l = prefix(lowered, scan_bytes);
        if self.ordering.is_match(l) {
            return true;
        }
        if self.affix_ac.is_match(l) {
            return true;
        }
        let c = prefix(confusable, scan_bytes);
        !c.is_empty() && self.affix_ac.is_match(c)
    }

    /// Every MEDIUM literal occurring in `haystack`, de-duplicated.
    fn matches_in(&self, haystack: &str, out: &mut BTreeSet<String>) {
        for m in self.med_ac.find_iter(haystack) {
            out.insert(self.med_patterns[m.pattern().as_usize()].clone());
        }
    }
}

/// A `&str` prefix of at most `max` bytes, cut on a character boundary.
fn prefix(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The per-fetch inputs the state machine needs. Both are already normalized by
/// the caller so the state layer never re-derives (or diverges from) the views
/// the stateless scan used.
pub struct E8Input<'a> {
    /// `LOWER_OUTPUT` — the ASCII-lowercased scanned content.
    pub lowered: &'a str,
    /// The confusable-folded view of the same content.
    pub confusable: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub id: i64,
    pub ts: i64,
    pub tool: String,
    pub url_hash: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reassembly {
    /// Whether this fetch's excerpt was captured.
    pub stored: bool,
    /// Fragments inside the window after this call.
    pub fragment_count: u32,
    /// Cross-fragment matches firing for the FIRST time this session,
    /// lowercased exactly as the corpus stores them.
    pub new_matches: Vec<String>,
    /// `<ts>/<tool>/<url-hash>` per participating fragment, for the audit row.
    pub participating: Vec<String>,
}

impl StateStore {
    /// `[ -f "$SESSION_FRAGMENTS" ]` — is a reassembly window already open?
    pub fn e8_window_open(&self, ctx: &StateContext) -> Result<bool, StateError> {
        Ok(!self.e8_fragments(ctx)?.is_empty())
    }

    /// In-window fragments for this session, oldest first.
    pub fn e8_fragments(&self, ctx: &StateContext) -> Result<Vec<Fragment>, StateError> {
        ctx.validate()?;
        let cutoff = self.now() - self.config().window_secs;
        let tx = self.tx()?;
        let scope = StateStore::session_scope_id(&tx, ctx)?;
        let frags = read_fragments(&tx, scope, cutoff)?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(frags)
    }

    /// One fetch through the state machine: decide, store, reassemble, prune.
    ///
    /// Deliberately three short transactions rather than one long one. The
    /// concatenation and matching pass is CPU work over up to 20 * 1500 bytes;
    /// holding the write lock across it would turn every concurrent scanner's
    /// lock wait into a function of this one's matching cost. Bash locks the
    /// same two windows — the append, and the fired-set check-and-append — and
    /// for the same reason.
    pub fn e8_step(
        &self,
        ctx: &StateContext,
        lex: &E8Lexicon,
        input: E8Input<'_>,
        prior_hits: u32,
    ) -> Result<Reassembly, StateError> {
        ctx.validate()?;
        let cfg = self.config();
        let now = self.now();
        let cutoff = now - cfg.window_secs;

        // ── 1. store gate + append ──────────────────────────────────────────
        let (stored, frags) = {
            let tx = self.tx()?;
            let scope = StateStore::session_scope_id(&tx, ctx)?;
            let window_open = !read_fragments(&tx, scope, cutoff)?.is_empty();
            let should_store =
                lex.has_indicator(input.lowered, input.confusable, cfg.indicator_scan_bytes)
                    || prior_hits >= 1
                    || window_open;

            if should_store {
                let excerpt = build_excerpt(input.lowered, cfg.excerpt_bytes);
                tx.execute(
                    "INSERT INTO fragments (session_scope_id, ts, seq, tool, url_hash, excerpt)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    (
                        scope,
                        now,
                        // A per-fragment tiebreaker for same-second arrivals.
                        // `id` already orders them; `seq` exists so the audit row
                        // matches the Bash TSV shape.
                        now,
                        sanitize_meta(&ctx.tool_name, MAX_TOOL_CHARS),
                        super::hash::url_hash(ctx.url.as_deref().unwrap_or("no-url")),
                        &excerpt,
                    ),
                )
                .map_err(|e| map_sql(e, 0))?;
            }
            // Prune expired rows here rather than after the match: an expired
            // fragment must not be able to participate in this call's
            // reassembly, and reading them back only to filter would be the
            // same logic written twice.
            tx.execute(
                "DELETE FROM fragments WHERE session_scope_id = ?1 AND ts < ?2",
                (scope, cutoff),
            )
            .map_err(|e| map_sql(e, 0))?;
            let frags = read_fragments(&tx, scope, cutoff)?;
            tx.commit().map_err(|e| map_sql(e, 0))?;
            (should_store, frags)
        };

        let mut out = Reassembly {
            stored,
            fragment_count: frags.len() as u32,
            ..Reassembly::default()
        };
        // Bash attempts reassembly only when this fetch participated; a fetch
        // that stored nothing is not evidence of an in-progress split.
        if !stored || frags.len() < 2 {
            self.e8_prune_cap(ctx)?;
            return Ok(out);
        }

        // ── 2. match, outside any lock ──────────────────────────────────────
        let cross = cross_fragment_matches(lex, &frags);

        // ── 3. fired-set filter + append, atomically ────────────────────────
        if !cross.is_empty() {
            let tx = self.tx()?;
            let scope = StateStore::session_scope_id(&tx, ctx)?;
            let mut fresh = Vec::new();
            for m in &cross {
                // INSERT OR IGNORE on the primary key IS the check: the row
                // either did not exist (we own the first firing) or it did.
                // Splitting it into SELECT-then-INSERT would put two concurrent
                // scanners back in the TOCTOU that lets both fire.
                let n = tx
                    .execute(
                        "INSERT OR IGNORE INTO fired_patterns (session_scope_id, pattern, ts)
                         VALUES (?1, ?2, ?3)",
                        (scope, m, now),
                    )
                    .map_err(|e| map_sql(e, 0))?;
                if n == 1 {
                    fresh.push(m.clone());
                }
            }
            tx.commit().map_err(|e| map_sql(e, 0))?;

            if !fresh.is_empty() {
                out.participating = frags
                    .iter()
                    .map(|f| format!("{}/{}/{}", f.ts, f.tool, f.url_hash))
                    .collect();
                out.new_matches = fresh;
            }
        }

        self.e8_prune_cap(ctx)?;
        Ok(out)
    }

    /// Keep at most `max_fragments` rows, newest first — Bash's post-check
    /// `tail -n E8_MAX_FRAGMENTS`. Runs AFTER the reassembly check so an
    /// attacker cannot evict the incriminating half by padding the window with
    /// fresh fragments in the same call.
    fn e8_prune_cap(&self, ctx: &StateContext) -> Result<(), StateError> {
        let max = self.config().max_fragments as i64;
        let tx = self.tx()?;
        let scope = StateStore::session_scope_id(&tx, ctx)?;
        tx.execute(
            "DELETE FROM fragments
             WHERE session_scope_id = ?1
               AND id NOT IN (
                 SELECT id FROM fragments WHERE session_scope_id = ?1
                 ORDER BY ts DESC, id DESC LIMIT ?2
               )",
            (scope, max),
        )
        .map_err(|e| map_sql(e, 0))?;
        tx.commit().map_err(|e| map_sql(e, 0))?;
        Ok(())
    }
}

fn read_fragments(
    tx: &Transaction<'_>,
    scope: i64,
    cutoff: i64,
) -> Result<Vec<Fragment>, StateError> {
    let mut stmt = tx
        .prepare(
            "SELECT id, ts, tool, url_hash, excerpt FROM fragments
             WHERE session_scope_id = ?1 AND ts >= ?2
             ORDER BY ts, id",
        )
        .map_err(|e| map_sql(e, 0))?;
    let rows = stmt
        .query_map((scope, cutoff), |r| {
            Ok(Fragment {
                id: r.get(0)?,
                ts: r.get(1)?,
                tool: r.get(2)?,
                url_hash: r.get(3)?,
                excerpt: r.get(4)?,
            })
        })
        .map_err(|e| map_sql(e, 0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| map_sql(e, 0))?;
    Ok(rows)
}

/// Head + tail of the lowered content, confusable-folded, bounded.
///
/// Head-only sampling was a real bypass: prepend more than the excerpt size of
/// benign filler to every fragment and the malicious tail is never stored.
/// Content that already fits is taken whole — no head/tail duplication.
fn build_excerpt(lowered: &str, excerpt_bytes: usize) -> String {
    let slice = if lowered.len() > excerpt_bytes {
        let head = prefix(lowered, excerpt_bytes * 2 / 3);
        let tail = suffix(lowered, excerpt_bytes / 3);
        format!("{head}\n{tail}")
    } else {
        lowered.to_string()
    };
    fold_confusable_letters(&slice)
}

/// A `&str` suffix of at most `max` bytes, cut on a character boundary.
fn suffix(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// The E8 excerpt's own confusable fold.
///
/// Deliberately NOT [`crate::normalize::confusable`]: the production `sed`
/// chain in the E8 block maps letters only, and does not strip combining marks
/// or variation selectors the way view 4 does. Reusing view 4 here would fold
/// slightly more than Bash stores, and a stored excerpt that differs from
/// Bash's is a divergence in every later reassembly this session makes.
fn fold_confusable_letters(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        #[rustfmt::skip]
        let mapped = match c {
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y',
            'х' => 'x', 'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'ԁ' => 'd', 'ɡ' => 'g',
            'ɑ' => 'a', 'ε' => 'e', 'ο' => 'o', 'ν' => 'v', 'ι' => 'i', 'κ' => 'k',
            'τ' => 't', 'η' => 'n',
            'ａ'..='ｚ' => char::from_u32(c as u32 - 0xFF41 + 'a' as u32).unwrap_or(c),
            other => other,
        };
        out.push(mapped);
    }
    out
}

/// Match the three concatenations, then keep only what no single fragment holds.
fn cross_fragment_matches(lex: &E8Lexicon, frags: &[Fragment]) -> Vec<String> {
    let mut all: BTreeSet<String> = BTreeSet::new();
    for concat in [
        chronological(frags),
        label_sorted(frags),
        smart_joined(lex, frags),
    ] {
        // The same eight evasion-resistant views the per-fetch pipeline uses.
        // View 1 is load-bearing here specifically: it squeezes the whitespace
        // runs that the label-sorted concatenation leaves behind.
        for view in Views::build(&concat).views.iter() {
            lex.matches_in(view, &mut all);
        }
    }

    all.into_iter()
        .filter(|m| {
            // Already adjudicated by the per-fetch pipeline if any one fragment
            // carries it; only what appears *between* fragments is reassembly.
            !frags.iter().any(|f| f.excerpt.contains(m.as_str()))
        })
        .collect()
}

fn chronological(frags: &[Fragment]) -> String {
    let mut s = String::new();
    for f in frags {
        s.push(' ');
        s.push_str(&f.excerpt);
    }
    s
}

/// Ordering-label-aware: pull the numeric key out of each fragment, strip the
/// label preamble, and re-join in label order. Unlabeled fragments sort last
/// (Bash's `999999` sentinel) and keep their arrival order among themselves.
fn label_sorted(frags: &[Fragment]) -> String {
    let mut labeled: Vec<(u64, usize, String)> = frags
        .iter()
        .enumerate()
        .map(|(i, f)| (order_key(&f.excerpt), i, strip_order_preamble(&f.excerpt)))
        .collect();
    labeled.sort_by_key(|(k, i, _)| (*k, *i));
    let mut out = String::new();
    for (_, _, text) in labeled {
        out.push_str(&text);
        out.push(' ');
    }
    out
}

fn order_key(excerpt: &str) -> u64 {
    let re = Regex::new(r"(?i)(part|step|page) ([0-9]+)").expect("order key regex");
    re.captures(excerpt)
        .and_then(|c| c.get(2))
        .and_then(|m| m.as_str().parse::<u64>().ok())
        .unwrap_or(999_999)
}

fn strip_order_preamble(excerpt: &str) -> String {
    // Four `sed -E … //gi` passes, in the production order.
    let passes = [
        r"(?i)part[[:space:]]+[0-9]+([[:space:]]+of[[:space:]]+|/)[0-9]+[[:space:]]*:?",
        r"(?i)step[[:space:]]+[0-9]+[[:space:]]*:?",
        r"(?i)segment[[:space:]]+[a-z][[:space:]]*:?",
        r"(?i)page[[:space:]]+[0-9]+[[:space:]]+of[[:space:]]+[0-9]+[[:space:]]*:?",
    ];
    let mut s = excerpt.to_string();
    for p in passes {
        s = Regex::new(p)
            .expect("preamble regex compiles")
            .replace_all(&s, "")
            .into_owned();
    }
    s
}

/// The affix bridge. Join fragments with a space, EXCEPT where the previous
/// fragment's last word and this one's first word are both affixes and neither
/// is a whole token — the signature of a split inside a word rather than at a
/// legitimate boundary.
fn smart_joined(lex: &E8Lexicon, frags: &[Fragment]) -> String {
    let mut out = String::new();
    let mut prev_last: Option<String> = None;
    for (i, f) in frags.iter().enumerate() {
        let first = boundary_word(&f.excerpt, true);
        if i > 0 {
            let bridge = match (&prev_last, &first) {
                (Some(p), Some(c)) => {
                    lex.is_affix(p) && lex.is_affix(c) && !lex.is_token(p) && !lex.is_token(c)
                }
                _ => false,
            };
            if !bridge {
                out.push(' ');
            }
        }
        out.push_str(&f.excerpt);
        prev_last = boundary_word(&f.excerpt, false);
    }
    out
}

/// The first (or last) alphanumeric word, lowercased — Bash's
/// `tr -c '[:alnum:]' ' ' | awk '{print $1}'` / `'{print $NF}'`.
fn boundary_word(s: &str, first: bool) -> Option<String> {
    let mut words = s
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty());
    let w = if first {
        words.next()
    } else {
        words.next_back()
    };
    w.map(ascii_lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_excerpt_that_fits_is_stored_whole() {
        let e = build_excerpt("short content", 1500);
        assert_eq!(e, "short content");
    }

    #[test]
    fn an_oversized_excerpt_keeps_the_head_and_the_tail() {
        let raw = format!("HEAD{}TAIL", "x".repeat(4000));
        let e = build_excerpt(&ascii_lower(&raw), 300);
        assert!(e.starts_with("head"));
        assert!(e.ends_with("tail"));
        assert!(e.len() <= 301, "{} bytes", e.len());
    }

    #[test]
    fn the_excerpt_fold_maps_letters_without_stripping_combining_marks() {
        // Cyrillic о folds; a combining acute survives, unlike view 4.
        assert_eq!(fold_confusable_letters("оk"), "ok");
        assert_eq!(fold_confusable_letters("e\u{0301}"), "e\u{0301}");
        assert_eq!(fold_confusable_letters("ｉｄ"), "id");
    }

    #[test]
    fn the_order_key_falls_back_to_the_unlabeled_sentinel() {
        assert_eq!(order_key("part 2 of 3: previous"), 2);
        assert_eq!(order_key("step 7"), 7);
        assert_eq!(order_key("no marker here"), 999_999);
    }

    #[test]
    fn the_preamble_strip_removes_every_marker_shape() {
        assert_eq!(strip_order_preamble("part 1 of 3: ignore").trim(), "ignore");
        assert_eq!(strip_order_preamble("part 1/3:ignore").trim(), "ignore");
        assert_eq!(strip_order_preamble("step 2: ignore").trim(), "ignore");
        assert_eq!(strip_order_preamble("segment b: ignore").trim(), "ignore");
        assert_eq!(strip_order_preamble("page 1 of 5: ignore").trim(), "ignore");
    }

    #[test]
    fn boundary_words_are_the_first_and_last_alphanumeric_runs() {
        assert_eq!(boundary_word("  ign", true).as_deref(), Some("ign"));
        assert_eq!(
            boundary_word("hello, world!", false).as_deref(),
            Some("world")
        );
        assert_eq!(boundary_word("...", true), None);
    }

    #[test]
    fn prefix_and_suffix_never_split_a_code_point() {
        let s = "가나다라";
        assert!(prefix(s, 4).len() <= 4);
        assert!(suffix(s, 4).len() <= 4);
        // Both are valid &str, which is the assertion — an invalid cut would
        // have panicked on the slice.
        assert!(s.contains(prefix(s, 4)));
        assert!(s.contains(suffix(s, 4)));
    }
}
