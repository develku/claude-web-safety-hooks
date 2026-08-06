//! Time, injected.
//!
//! Every TTL in the state layer is measured against this trait rather than
//! `SystemTime::now()` at the call site. That is a security property, not a
//! testing convenience: the alternative — letting a caller pass "now" in the
//! request envelope — would hand an attacker the ability to expire another
//! session's strikes or keep a fragment window open forever. Production wires
//! [`SystemClock`]; tests wire [`TestClock`]; nothing on the wire can choose.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch, matching `date +%s` in the Bash scanner.
    fn now_secs(&self) -> i64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            // A clock before the epoch is not a reason to skip containment; it is
            // a reason to treat everything stored as expired.
            .unwrap_or(0)
    }
}

/// A clock the test suite drives by hand. `Arc`-shared, so a test can advance it
/// after handing it to a store.
#[derive(Debug)]
pub struct TestClock {
    now: AtomicI64,
}

impl TestClock {
    pub fn new(now: i64) -> TestClock {
        TestClock {
            now: AtomicI64::new(now),
        }
    }

    pub fn advance(&self, secs: i64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn set(&self, secs: i64) {
        self.now.store(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_secs(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_is_seconds_since_the_epoch() {
        // Sanity, not precision: any plausible wall clock is far past 2020.
        assert!(SystemClock.now_secs() > 1_577_836_800);
    }

    #[test]
    fn a_test_clock_advances_only_when_told_to() {
        let c = TestClock::new(100);
        assert_eq!(c.now_secs(), 100);
        assert_eq!(c.now_secs(), 100);
        c.advance(5);
        assert_eq!(c.now_secs(), 105);
        c.set(7);
        assert_eq!(c.now_secs(), 7);
    }
}
