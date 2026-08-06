//! Every single-file fixture under `tests/payloads/` through the Rust core.
//!
//! The filename prefix IS the expected verdict — that is the contract the Bash
//! suite has encoded since v4. This test asserts the prefix contract; exact
//! Bash-vs-Rust parity (including which `legit-*` payloads land on clean rather
//! than INFO) is the differential runner's job, since only it can ask Bash.
//!
//! Multi-file `reassembly-*` / `legit-*` DIRECTORIES are E8 cross-call
//! reassembly fixtures — out of scope for this stage, and skipped here.

use std::path::PathBuf;
use web_safety_engine::contract::{Decision, Severity};
use web_safety_engine::engine::Config;
use web_safety_engine::policy::Scanner;

fn payload_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/payloads")
}

fn fixtures() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = std::fs::read_dir(payload_dir())
        .expect("tests/payloads exists")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "txt"))
        .map(|e| {
            let name = e
                .path()
                .file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned();
            (
                name,
                std::fs::read_to_string(e.path()).expect("fixture readable"),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn the_fixture_corpus_is_the_expected_size() {
    // Guards against a silently empty glob making every assertion below vacuous.
    assert_eq!(fixtures().len(), 64, "expected 64 single-file payloads");
}

#[test]
fn every_fixture_meets_its_filename_contract() {
    let scanner = Scanner::new(Config::default());
    let mut failures = Vec::new();

    for (name, body) in fixtures() {
        let r = scanner.scan(&body);
        let bucket = name.split('-').next().expect("bucket prefix");
        let ok = match bucket {
            "high" => r.severity == Severity::High,
            "med" => r.severity == Severity::Medium,
            "low" => r.severity == Severity::Low,
            "info" => r.severity == Severity::Info && r.decision == Decision::Note,
            // The false-positive corpus: the whole point of the suppression
            // layers is that none of these reaches an operator-visible threat.
            "legit" => r.severity < Severity::Medium,
            other => panic!("unknown fixture bucket: {other}"),
        };
        if !ok {
            failures.push(format!(
                "{name}: expected {bucket}, got {:?}/{:?} — {}",
                r.severity,
                r.decision,
                r.kept()
                    .map(|f| f.rule_id.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
    }

    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn no_fixture_takes_an_unreasonable_amount_of_time() {
    let scanner = Scanner::new(Config::default());
    for (name, body) in fixtures() {
        let started = std::time::Instant::now();
        let _ = scanner.scan(&body);
        assert!(
            started.elapsed().as_millis() < 500,
            "{name} took {:?}",
            started.elapsed()
        );
    }
}
