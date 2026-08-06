//! Content hashes, byte-compatible with the Bash scanner's two hashing sites.
//!
//! The two differ by one newline and that difference is load-bearing, so both
//! are reproduced exactly rather than unified:
//!
//! | Bash | here |
//! |---|---|
//! | `echo "$TOOL_OUTPUT" \| shasum -a 256 \| cut -d' ' -f1` (quarantine row) | [`quarantine_hash`] |
//! | `printf '%s' "$TOOL_OUTPUT" \| shasum -a 256 \| cut -c1-16` (notify key) | [`notify_hash`] |
//!
//! `echo` appends a newline; `printf '%s'` does not. Matching both means a
//! divergence in the state-sequence differential is never "the hashes differ".

use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Full 64-char hex of `sha256(content + "\n")` — the Q-row collapse key.
pub fn quarantine_hash(content: &str) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    h.update(b"\n");
    hex(&h.finalize())
}

/// First 16 hex chars of `sha256(content)` — the notification dedup key.
pub fn notify_hash(content: &str) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    hex(&h.finalize())[..16].to_string()
}

/// First 12 hex chars of `sha256(url)` — the E8 fragment's `url=` column.
pub fn url_hash(url: &str) -> String {
    let mut h = Sha256::new();
    h.update(url.as_bytes());
    h.update(b"\n");
    hex(&h.finalize())[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical empty-string vectors, so a wrong hash is caught here rather
    /// than as a mysterious collapse-behaviour divergence three layers up.
    #[test]
    fn matches_the_shasum_vectors_bash_produces() {
        // `printf '' | shasum -a 256`
        assert_eq!(
            notify_hash(""),
            "e3b0c44298fc1c14"[..16].to_string(),
            "sha256 of the empty string"
        );
        // `echo '' | shasum -a 256` — i.e. sha256 of a single newline.
        assert_eq!(
            quarantine_hash(""),
            "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
        );
    }

    #[test]
    fn the_two_hashes_of_the_same_content_differ_by_the_trailing_newline() {
        let c = "some scanned content";
        assert_ne!(quarantine_hash(c)[..16], notify_hash(c));
        assert_eq!(quarantine_hash(c), quarantine_hash(c));
    }

    #[test]
    fn different_content_hashes_differently() {
        assert_ne!(quarantine_hash("a"), quarantine_hash("b"));
        assert_ne!(notify_hash("a"), notify_hash("b"));
        assert_eq!(notify_hash("a").len(), 16);
        assert_eq!(url_hash("https://example.test/a").len(), 12);
    }
}
