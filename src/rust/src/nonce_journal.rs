//! Anti-replay nonce journal with TTL-based expiration.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Anti-replay nonce journal. Thread-safe via Mutex.
pub struct NonceJournal {
    inner: Mutex<JournalInner>,
}

struct JournalInner {
    seen: HashMap<String, Instant>,
    ttl: Duration,
    last_prune: Instant,
}

impl NonceJournal {
    /// Create a new nonce journal with the given TTL duration.
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(JournalInner {
                seen: HashMap::new(),
                ttl,
                last_prune: Instant::now(),
            }),
        }
    }

    /// Check and record a nonce. Returns true if new (unseen), false if replay.
    pub fn try_record(&self, nonce: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        inner.maybe_prune();
        let now = Instant::now();
        if let Some(ts) = inner.seen.get(nonce) {
            if now.duration_since(*ts) < inner.ttl {
                return false; // replay
            }
        }
        inner.seen.insert(nonce.to_string(), now);
        true
    }

    /// Check whether a nonce has already been seen (without recording).
    pub fn has_seen(&self, nonce: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        if let Some(ts) = inner.seen.get(nonce) {
            Instant::now().duration_since(*ts) < inner.ttl
        } else {
            false
        }
    }

    /// Number of active (non-expired) nonces.
    pub fn count(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.maybe_prune();
        inner.seen.len()
    }
}

impl JournalInner {
    fn maybe_prune(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_prune) < Duration::from_secs(60) {
            return;
        }
        self.last_prune = now;
        self.seen.retain(|_, ts| now.duration_since(*ts) < self.ttl);
    }
}
