//! Shared scanner core for the web-safety hooks.
//!
//! One engine, three runtimes. Host-specific field names live only in
//! [`hosts`]; everything below it sees the neutral [`contract::ScanRequest`].
//!
//! Layering, matching the Bash pipeline it is ported from:
//!
//! | Module | Bash counterpart |
//! |---|---|
//! | [`corpus`] | the literal pattern arrays in `scripts/web-safety-scanner.sh` |
//! | [`normalize`] | `generate_views()` — the eight evasion-resistant views |
//! | [`engine`] | `run_batch_grep` + the codepoint / base64 / leetspeak passes |
//! | [`verify`] | `scripts/web-safety-verify-context.sh` (structural + directive) |
//! | [`policy`] | the context gate, Layer 5, and the emit-stage reclassification |
//! | [`sanitize`] | `sanitize_content()` / `emit_search_quarantine()` — what replaces a contained result |
//!
//! This crate is the production scanner authority — `hooks/hooks.json` invokes
//! its binary on every wired hook site. The Bash pipeline stays in-tree as the
//! frozen differential oracle and the operator's rollback path.

pub mod contract;
pub mod corpus;
pub mod egress;
pub mod engine;
pub mod hosts;
pub mod normalize;
pub mod oplog;
pub mod policy;
pub mod sanitize;
pub mod state;
pub mod urlscreen;
pub mod verify;
