//! Exponential backoff with full jitter.
//!
//! Many workers retrying on the same schedule hammer a recovering service in
//! synchronized waves. Full jitter draws each delay uniformly from zero up
//! to the exponential ceiling, which spreads retries out while keeping the
//! expected delay growing exponentially. The random source is injected so
//! tests are deterministic.

use std::time::Duration;

use rand::RngExt;

/// Why a retry policy is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RetryPolicyError {
    /// The base delay is zero.
    #[error("backoff base must be greater than zero")]
    ZeroBase,
    /// The cap is smaller than the base.
    #[error("backoff cap must not be smaller than the base")]
    CapBelowBase,
}

/// Backoff parameters for one stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    base: Duration,
    cap: Duration,
}

impl RetryPolicy {
    /// Creates a policy whose ceiling starts at `base` and doubles per
    /// attempt up to `cap`.
    ///
    /// # Errors
    ///
    /// Rejects a zero base and a cap below the base.
    pub fn new(base: Duration, cap: Duration) -> Result<Self, RetryPolicyError> {
        if base.is_zero() {
            return Err(RetryPolicyError::ZeroBase);
        }

        if cap < base {
            return Err(RetryPolicyError::CapBelowBase);
        }

        Ok(Self { base, cap })
    }

    /// The largest delay allowed after the given failed attempt (counting
    /// from 1): `min(cap, base * 2^(attempt - 1))`.
    #[must_use]
    pub fn ceiling(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(63);
        let factor = 1_u64 << exponent;
        let factor = u32::try_from(factor).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.cap)
    }

    /// A delay drawn uniformly from `[0, ceiling(attempt)]`.
    pub fn delay<R: rand::Rng + ?Sized>(&self, attempt: u32, rng: &mut R) -> Duration {
        let ceiling = self.ceiling(attempt);
        let millis = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(rng.random_range(0..=millis))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    fn policy() -> RetryPolicy {
        RetryPolicy::new(Duration::from_secs(2), Duration::from_secs(600)).unwrap()
    }

    #[test]
    fn rejects_invalid_parameters() {
        assert_eq!(
            RetryPolicy::new(Duration::ZERO, Duration::from_secs(1)),
            Err(RetryPolicyError::ZeroBase)
        );
        assert_eq!(
            RetryPolicy::new(Duration::from_secs(2), Duration::from_secs(1)),
            Err(RetryPolicyError::CapBelowBase)
        );
    }

    #[test]
    fn ceiling_doubles_then_caps() {
        let p = policy();

        assert_eq!(p.ceiling(1), Duration::from_secs(2));
        assert_eq!(p.ceiling(2), Duration::from_secs(4));
        assert_eq!(p.ceiling(3), Duration::from_secs(8));
        assert_eq!(p.ceiling(10), Duration::from_secs(600));
        assert_eq!(p.ceiling(u32::MAX), Duration::from_secs(600));
    }

    proptest! {
        #[test]
        fn delay_never_exceeds_ceiling(attempt in 0_u32..200, seed in any::<u64>()) {
            let p = policy();
            let mut rng = StdRng::seed_from_u64(seed);
            prop_assert!(p.delay(attempt, &mut rng) <= p.ceiling(attempt));
        }

        #[test]
        fn ceiling_is_monotonic(attempt in 0_u32..1000) {
            let p = policy();
            prop_assert!(p.ceiling(attempt) <= p.ceiling(attempt + 1));
        }
    }
}
