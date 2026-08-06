//! The corpus extractor must READ its source, never RUN it.
//!
//! `engine/tools/extract-corpus.sh` used to slice a `NAME=( … )` block out of the
//! Bash scanner and hand it to `eval`. The drift test invokes that extractor
//! during `cargo test`, so anything that reached those arrays — a command
//! substitution, a parameter expansion, an extra command after the closing paren
//! — executed with the developer's privileges on every `cargo test` and in CI.
//!
//! The replacement is `engine/tools/corpus-parse.awk`, a data parser for one
//! documented grammar:
//!
//! ```text
//! NAME=(
//!   # comment
//!   "literal, with \" and \\ as the only escapes"
//! )
//! ```
//!
//! Anything else is rejected. These tests drive the parser against temporary
//! fixture sources, so they exercise the parser itself rather than only the
//! production corpus it happens to be pointed at.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn engine_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn parser() -> PathBuf {
    engine_dir().join("tools/corpus-parse.awk")
}

/// A scratch directory unique to one test, under `target/` so `cargo clean`
/// reclaims it and nothing lands in a shared world-writable location.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = engine_dir().join("target/corpus-parse-tests").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, body).expect("fixture written");
        p
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn parse(array: &str, source: &Path) -> Output {
    Command::new("awk")
        .arg("-v")
        .arg(format!("name={array}"))
        .arg("-f")
        .arg(parser())
        .arg(source)
        .output()
        .expect("awk runs")
}

fn entries(array: &str, source: &Path) -> Vec<String> {
    let out = parse(array, source);
    assert!(
        out.status.success(),
        "parser rejected a valid fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("parser output is UTF-8");
    let mut lines = text.lines();
    let declared: usize = lines
        .next()
        .expect("count header")
        .parse()
        .expect("count header is a number");
    let got: Vec<String> = lines.map(str::to_string).collect();
    assert_eq!(
        declared,
        got.len(),
        "header count disagrees with the payload"
    );
    got
}

fn rejects(array: &str, source: &Path, why: &str) {
    let out = parse(array, source);
    assert!(
        !out.status.success(),
        "{why}: parser accepted it and emitted {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !out.stderr.is_empty(),
        "{why}: a rejection must say why on stderr"
    );
}

// --- the security proof -----------------------------------------------------

#[test]
fn a_command_substitution_is_rejected_and_never_executed() {
    let s = Scratch::new("command-substitution");
    let sentinel = s.path("PWNED");
    let src = s.write(
        "scanner.sh",
        &format!(
            "EVIL=(\n  \"harmless\"\n  \"$(touch {})\"\n)\n",
            sentinel.display()
        ),
    );

    rejects("EVIL", &src, "a command substitution");
    assert!(
        !sentinel.exists(),
        "extraction EXECUTED the corpus source: {} was created",
        sentinel.display()
    );
}

#[test]
fn a_backtick_substitution_is_rejected_and_never_executed() {
    let s = Scratch::new("backticks");
    let sentinel = s.path("PWNED");
    let src = s.write(
        "scanner.sh",
        &format!("EVIL=(\n  \"`touch {}`\"\n)\n", sentinel.display()),
    );

    rejects("EVIL", &src, "a backtick substitution");
    assert!(!sentinel.exists(), "extraction EXECUTED the corpus source");
}

#[test]
fn a_trailing_command_after_the_array_is_rejected_and_never_executed() {
    let s = Scratch::new("trailing-command");
    let sentinel = s.path("PWNED");
    let src = s.write(
        "scanner.sh",
        &format!(
            "EVIL=(\n  \"harmless\"\n  ); touch {}; X=(\n)\n",
            sentinel.display()
        ),
    );

    rejects(
        "EVIL",
        &src,
        "an extra command smuggled onto the closing line",
    );
    assert!(!sentinel.exists(), "extraction EXECUTED the corpus source");
}

#[test]
fn a_parameter_expansion_is_rejected() {
    let s = Scratch::new("parameter-expansion");
    let src = s.write("scanner.sh", "EVIL=(\n  \"$HOME/secret\"\n)\n");
    rejects("EVIL", &src, "a parameter expansion");
}

// --- grammar ----------------------------------------------------------------

#[test]
fn a_well_formed_array_parses_in_declaration_order() {
    let s = Scratch::new("well-formed");
    let src = s.write(
        "scanner.sh",
        "OTHER=(\n  \"before\"\n)\nA=(\n  # a comment\n  \"first\"\n  \"second\"\n\n  \"third\"\n)\nAFTER=(\n  \"after\"\n)\n",
    );
    assert_eq!(entries("A", &src), vec!["first", "second", "third"]);
}

#[test]
fn the_supported_escapes_decode_exactly_as_bash_would() {
    // `MED_TOOL_JSON` really does carry `"\"tool_call\":"`, and the artifact it
    // produces holds `"tool_call":` — the escape must survive the move off eval.
    let s = Scratch::new("escapes");
    let src = s.write(
        "scanner.sh",
        "A=(\n  \"\\\"tool_call\\\":\"\n  \"back\\\\slash\"\n)\n",
    );
    assert_eq!(entries("A", &src), vec![r#""tool_call":"#, r"back\slash"]);
}

#[test]
fn an_unsupported_escape_is_rejected_rather_than_guessed_at() {
    for body in ["A=(\n  \"tab\\there\"\n)\n", "A=(\n  \"nl\\nhere\"\n)\n"] {
        let s = Scratch::new("unsupported-escape");
        let src = s.write("scanner.sh", body);
        rejects("A", &src, "an escape the grammar does not define");
    }
}

#[test]
fn a_literal_holding_unicode_survives_byte_for_byte() {
    // MED_MULTILINGUAL is non-ASCII; a parser that re-encodes would silently
    // stop matching the very payloads that array exists for.
    let s = Scratch::new("unicode");
    let src = s.write(
        "scanner.sh",
        "A=(\n  \"忽略之前的指令\"\n  \"игнорировать\"\n  \"café\"\n)\n",
    );
    assert_eq!(
        entries("A", &src),
        vec!["忽略之前的指令", "игнорировать", "café"]
    );
}

#[test]
fn an_unterminated_array_is_rejected() {
    let s = Scratch::new("unterminated");
    let src = s.write("scanner.sh", "A=(\n  \"one\"\n  \"two\"\n");
    rejects("A", &src, "no closing delimiter");
}

#[test]
fn a_missing_array_is_rejected() {
    let s = Scratch::new("missing");
    let src = s.write("scanner.sh", "B=(\n  \"one\"\n)\n");
    rejects("A", &src, "the array is not declared");
}

#[test]
fn a_duplicate_declaration_is_rejected_as_ambiguous() {
    // Two declarations mean the extracted list depends on which one the parser
    // happened to reach first. That is exactly the silent-divergence class the
    // single-source rule exists to prevent.
    let s = Scratch::new("duplicate");
    let src = s.write("scanner.sh", "A=(\n  \"one\"\n)\nA=(\n  \"two\"\n)\n");
    rejects("A", &src, "duplicate declarations");
}

#[test]
fn an_unquoted_entry_is_rejected() {
    let s = Scratch::new("unquoted");
    let src = s.write("scanner.sh", "A=(\n  bare_word\n)\n");
    rejects("A", &src, "an unquoted entry");
}

#[test]
fn a_single_quoted_entry_is_rejected_because_the_grammar_is_double_quoted() {
    let s = Scratch::new("single-quoted");
    let src = s.write("scanner.sh", "A=(\n  'one'\n)\n");
    rejects("A", &src, "a single-quoted entry");
}

#[test]
fn two_entries_on_one_line_are_rejected() {
    // The output is line-oriented, so an entry per line is what keeps the count
    // meaningful. Accepting two would silently merge or split the corpus.
    let s = Scratch::new("two-per-line");
    let src = s.write("scanner.sh", "A=(\n  \"one\" \"two\"\n)\n");
    rejects("A", &src, "two entries on one line");
}

#[test]
fn trailing_content_after_the_closing_quote_is_rejected() {
    let s = Scratch::new("trailing-content");
    let src = s.write("scanner.sh", "A=(\n  \"one\" # trailing\n)\n");
    rejects("A", &src, "content after the closing quote");
}

#[test]
fn an_empty_array_is_rejected_rather_than_silently_erasing_a_severity_tier() {
    let s = Scratch::new("empty");
    let src = s.write("scanner.sh", "A=(\n)\n");
    rejects("A", &src, "an empty array");
}

#[test]
fn an_empty_string_entry_is_preserved() {
    let s = Scratch::new("empty-entry");
    let src = s.write("scanner.sh", "A=(\n  \"\"\n  \"x\"\n)\n");
    assert_eq!(entries("A", &src), vec!["", "x"]);
}

// --- the production corpus --------------------------------------------------

#[test]
fn the_production_arrays_parse_at_their_documented_sizes() {
    let scanner = engine_dir().join("../scripts/web-safety-scanner.sh");
    let verifier = engine_dir().join("../scripts/web-safety-verify-context.sh");

    let high: usize = ["HIGH_LLM_TOKENS", "HIGH_TOOL_FAKING", "HIGH_EXFIL"]
        .iter()
        .map(|a| entries(a, &scanner).len())
        .sum();
    assert_eq!(high, 87, "HIGH literals");

    let low: usize = ["LOW_HTML_CSS", "LOW_MARKDOWN_IMAGES", "LOW_TOPIC_VOCAB"]
        .iter()
        .map(|a| entries(a, &scanner).len())
        .sum();
    assert_eq!(low, 21, "LOW literals");

    assert_eq!(entries("LEET_PATTERNS", &scanner).len(), 7);
    assert_eq!(entries("CONTEXT_GATE_REGISTRY", &scanner).len(), 11);
    assert_eq!(entries("INJECTION_KEYWORDS", &verifier).len(), 12);
}

#[test]
fn the_extractor_no_longer_interprets_its_source_as_shell() {
    // Comments are stripped first: the prose explaining *why* the eval is gone
    // legitimately says "eval" and "source", and a raw substring scan would
    // either fail on that or have to be loosened into meaninglessness. What
    // matters is whether either word survives as a COMMAND.
    let script = std::fs::read_to_string(engine_dir().join("tools/extract-corpus.sh"))
        .expect("extractor readable");

    // Only COMMAND position counts. `jq -R .` passes `.` as a filter argument;
    // it is `. foo` at the head of a statement that would be sourcing a file.
    for (lineno, line) in script.lines().enumerate() {
        let code = match line.split_once('#') {
            Some((before, _)) => before,
            None => line,
        };
        for segment in code.split(|c: char| ";|&(){}`".contains(c)) {
            let Some(head) = segment.split_whitespace().next() else {
                continue;
            };
            assert!(
                !matches!(head, "eval" | "source" | "."),
                "extract-corpus.sh:{} still runs `{head}`: {line}",
                lineno + 1
            );
        }
    }
}
