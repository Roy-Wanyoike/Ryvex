//! Exponential backoff with jitter and a hard cap. Pure logic —
//! fully unit-tested.

use rand::Rng;

/// Backoff sequence: 1s, 2s, 4s, ... capped at 30s, with symmetric
/// ±20% jitter on top (waits land in [0.8×, 1.2×) of the sequence
/// value, floored at 1s; at the cap: 24s–35s).
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

    /// Advance the sequence and return the wait duration with symmetric
    /// ±20% jitter: `wait = capped * U(0.8, 1.2)`, floored at 1s.
    ///
    /// Issue #43: the jitter used to be downward-only (~-10%) despite
    /// this doc comment claiming ±20%, so contending agents
    /// synchronized on the ceiling. Now symmetric, per the contract.
    pub fn advance(&mut self) -> std::time::Duration {
        self.attempt = self.attempt.saturating_add(1);
        let exp = self.base_secs.saturating_mul(1u64 << (self.attempt - 1).min(6));
        let capped = exp.min(self.cap_secs);
        let span = capped as f64 * 0.2;
        // thread_rng().r#gen::<f64>() is uniform in [0, 1).
        let delta = rand::thread_rng().r#gen::<f64>() * 2.0 * span - span;
        let secs = (capped as f64 + delta).max(1.0) as u64;
        std::time::Duration::from_secs(secs)
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}
