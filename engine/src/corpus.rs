//! The literal pattern corpus, sourced canonically from the Bash scanner.
//!
//! `corpus/patterns.json` is a GENERATED artifact — `engine/tools/extract-corpus.sh`
//! slices the arrays straight out of `scripts/web-safety-scanner.sh` and
//! `scripts/web-safety-verify-context.sh`. Nothing here is hand-transcribed, and
//! [`tests::corpus_matches_bash_source`] re-runs the extractor to prove the
//! checked-in artifact still matches Bash.

use serde::Deserialize;

const CORPUS_JSON: &str = include_str!("../corpus/patterns.json");

/// Grammar class of a context-gated topic word, as declared by the Bash
/// `CONTEXT_GATE_REGISTRY`. Drives the directive verifier's FIRE heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateClass {
    Verb,
    Noun,
}

/// One literal pattern plus the Bash array it came from.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Lowercased, exactly as Bash writes it into `high.pat` / `med.pat` / `low.pat`.
    pub pattern: String,
    /// Original casing from the array — what Bash reports in `FOUND_*` after its
    /// lowercase→original map, and therefore what the operator sees.
    pub display: String,
    /// Stable rule id derived from the source array, e.g. `medium.jailbreak`.
    pub rule_id: String,
}

pub struct Corpus {
    pub high: Vec<Entry>,
    pub medium: Vec<Entry>,
    pub low: Vec<Entry>,
    pub leet: Vec<String>,
    pub injection_keywords: Vec<String>,
    pub context_gate: Vec<(String, GateClass)>,
    /// Bash gates Layer 5 structural verification to this one array.
    pub generic_delimiters: Vec<String>,
    /// The HIGH control tokens that get the structural (not directive) gate.
    pub llm_tokens: Vec<String>,
    /// LOW findings that are topic LABELS, reclassified to INFO at emit time.
    pub topic_vocab: Vec<String>,
}

#[derive(Deserialize)]
struct RawCorpus {
    groups: RawGroups,
}

#[derive(Deserialize)]
struct RawGroups {
    high: Vec<RawArray>,
    medium: Vec<RawArray>,
    low: Vec<RawArray>,
    other: Vec<RawArray>,
}

#[derive(Deserialize)]
struct RawArray {
    array: String,
    patterns: Vec<String>,
}

/// `MED_GENERIC_DELIMITERS` → `medium.generic_delimiters`.
fn rule_id(severity: &str, array: &str) -> String {
    let stem = array
        .trim_start_matches("HIGH_")
        .trim_start_matches("MED_")
        .trim_start_matches("LOW_")
        .to_ascii_lowercase();
    format!("{severity}.{stem}")
}

fn flatten(severity: &str, groups: &[RawArray]) -> Vec<Entry> {
    let mut out = Vec::new();
    for g in groups {
        let rule_id = rule_id(severity, &g.array);
        for p in &g.patterns {
            out.push(Entry {
                pattern: p.to_ascii_lowercase(),
                display: p.clone(),
                rule_id: rule_id.clone(),
            });
        }
    }
    out
}

impl Corpus {
    /// Parse the embedded artifact. Panics on a malformed corpus: a scanner that
    /// cannot build its pattern set must not start and silently match nothing.
    pub fn load() -> Corpus {
        let raw: RawCorpus =
            serde_json::from_str(CORPUS_JSON).expect("engine/corpus/patterns.json parses");

        let take = |groups: &[RawArray], k: &str| -> Vec<String> {
            groups
                .iter()
                .find(|g| g.array == k)
                .unwrap_or_else(|| panic!("corpus is missing {k}"))
                .patterns
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect()
        };

        let context_gate = take(&raw.groups.other, "CONTEXT_GATE_REGISTRY")
            .iter()
            .map(|e| {
                let (p, c) = e
                    .rsplit_once(':')
                    .unwrap_or_else(|| panic!("registry entry without a class: {e}"));
                let class = match c {
                    "verb" => GateClass::Verb,
                    "noun" => GateClass::Noun,
                    other => panic!("unknown gate class {other:?} in {e}"),
                };
                (p.to_string(), class)
            })
            .collect();

        Corpus {
            high: flatten("high", &raw.groups.high),
            medium: flatten("medium", &raw.groups.medium),
            low: flatten("low", &raw.groups.low),
            leet: take(&raw.groups.other, "LEET_PATTERNS"),
            injection_keywords: take(&raw.groups.other, "INJECTION_KEYWORDS"),
            context_gate,
            generic_delimiters: take(&raw.groups.medium, "MED_GENERIC_DELIMITERS"),
            llm_tokens: take(&raw.groups.high, "HIGH_LLM_TOKENS"),
            topic_vocab: take(&raw.groups.low, "LOW_TOPIC_VOCAB"),
        }
    }

    /// `None` when the pattern is not context-gated at all.
    pub fn gate_class(&self, lowercased: &str) -> Option<GateClass> {
        self.context_gate
            .iter()
            .find(|(p, _)| p == lowercased)
            .map(|(_, c)| *c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_full_engine_literal_corpus() {
        let c = Corpus::load();
        assert_eq!(c.high.len(), 87, "HIGH literals");
        assert_eq!(c.medium.len(), 495, "MEDIUM literals");
        assert_eq!(c.low.len(), 21, "LOW literals");
        assert_eq!(c.high.len() + c.medium.len() + c.low.len(), 603);
    }

    #[test]
    fn every_literal_is_lowercased_and_tagged_with_its_bash_array() {
        let c = Corpus::load();
        for e in c.high.iter().chain(&c.medium).chain(&c.low) {
            assert_eq!(e.pattern, e.pattern.to_ascii_lowercase());
            assert!(!e.rule_id.is_empty());
        }
        assert!(c.high.iter().any(|e| e.rule_id == "high.llm_tokens"));
        assert!(c
            .medium
            .iter()
            .any(|e| e.rule_id == "medium.generic_delimiters"));
    }

    #[test]
    fn context_gate_registry_carries_pattern_and_class() {
        let c = Corpus::load();
        assert_eq!(c.context_gate.len(), 11);
        assert_eq!(c.gate_class("exfiltrate"), Some(GateClass::Verb));
        assert_eq!(c.gate_class("jailbreak"), Some(GateClass::Noun));
        assert_eq!(c.gate_class("root access"), Some(GateClass::Noun));
        assert_eq!(c.gate_class("not gated"), None);
    }

    /// The acceptance bar for this stage: no manually divergent Rust/Bash list.
    /// Re-run the extractor against the live Bash sources and diff it against
    /// the artifact this crate compiled in. A pattern added to Bash without
    /// regenerating the corpus fails here rather than silently going unmatched.
    #[test]
    fn corpus_matches_bash_source() {
        let engine_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let extractor = engine_dir.join("tools/extract-corpus.sh");
        let out = engine_dir.join("target/corpus-drift-check.json");

        let status = std::process::Command::new("bash")
            .arg(&extractor)
            .arg(&out)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("extractor runs");
        assert!(status.success(), "extractor exited {status}");

        let regenerated = std::fs::read_to_string(&out).expect("regenerated corpus readable");
        assert_eq!(
            regenerated.trim(),
            CORPUS_JSON.trim(),
            "engine/corpus/patterns.json is stale — re-run engine/tools/extract-corpus.sh"
        );
    }

    #[test]
    fn auxiliary_lists_are_sourced_not_hand_copied() {
        let c = Corpus::load();
        assert_eq!(c.leet.len(), 7);
        assert_eq!(c.injection_keywords.len(), 12);
        assert!(c.injection_keywords.iter().any(|k| k == "system prompt"));
    }
}
