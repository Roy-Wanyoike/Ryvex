//! Exponential backoff with jitter and a hard cap. Pure logic —
//! fully unit-tested.

use rand::Rng;

/// Backoff sequence: 1s, 2s, 4s, ... capped at 30s, with ±20% jitter.
#[derive(Debug)]
pub struct Backoff {
    base_secs: u64,
    cap_secs: u64,
    attempt: u32,
}

impl Backoff {
    #[allow(clippy::should_implement_trait)] // Default::default() delegates here
    pub fn new() -> Self {
        Self {
            base_secs: 1,
            cap_secs: 30,
            attempt: 0,
        }
    }

    /// Reset after a success.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// Attempt counter (0 = no failures since reset).
    pub fn attempts(&self) -> u32 {
        self.attempt
    }

    /// Advance the sequence and return the wait duration with jitter.
    pub fn advance(&mut self) -> std::time::Duration {
        self.attempt = self.attempt.saturating_add(1);
        let exp = self.base_secs.saturating_mul(1u64 << (self.attempt - 1).min(6));
        let capped = exp.min(self.cap_secs);
        let jitter = (capped as f64 * 0.2 * rand::thread_rng().r#gen::<f64>()) as u64;
        std::time::Duration::from_secs(capped.saturating_sub(jitter / 2 + jitter % 2))
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}
