//! Circuit breakers per stage (ADR 0008).
//!
//! Infrastructure failures are retried without consuming a job's attempts,
//! so a broken dependency of one stage (crates.io unreachable, KVM failing)
//! would otherwise keep every job of the stage cycling. The breaker counts
//! the stage's infrastructure failures and completions in a sliding window.
//! When failures dominate, it opens and the stage stops claiming jobs; the
//! other stages keep draining their queues. After a cooldown it lets jobs
//! through again (half open): the first completion closes it, the first
//! failure opens it again with a longer cooldown.
//!
//! This module only decides. The supervisor reads the counts from the job
//! events, stores the state, and raises the alert when a breaker opens.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// When a breaker opens and how long it stays open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerPolicy {
    /// The sliding window for counting.
    pub window: Duration,
    /// Failures in the window needed to open.
    pub min_failures: u32,
    /// Share of failures among failures and completions needed to open,
    /// in percent.
    pub failure_percent: u8,
    /// First cooldown before the breaker lets jobs through again.
    pub cooldown: Duration,
    /// Longest cooldown, reached by doubling after each failed probe.
    pub max_cooldown: Duration,
}

/// The state of one stage's breaker. Times are seconds since the Unix
/// epoch, as the supervisor reads them from the database clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum BreakerState {
    /// Jobs flow.
    Closed,
    /// The stage claims nothing.
    Open {
        /// When it opened.
        since: i64,
        /// How often it reopened after a failed probe.
        reopened: u32,
    },
    /// Jobs flow again; the next result decides.
    HalfOpen {
        /// When it became half open.
        since: i64,
        /// How often it reopened after a failed probe.
        reopened: u32,
    },
}

impl BreakerState {
    /// Name stored in the database.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open { .. } => "open",
            Self::HalfOpen { .. } => "half_open",
        }
    }

    /// Whether the stage may claim jobs.
    #[must_use]
    pub const fn allows_claims(&self) -> bool {
        !matches!(self, Self::Open { .. })
    }
}

/// Infrastructure failures and completions of a stage since some time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Infrastructure failures.
    pub failures: u32,
    /// Completed stage steps.
    pub completions: u32,
}

/// What changed, for logs and alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The breaker opened from closed: raise the alert.
    Opened,
    /// A probe failed; the breaker opened again.
    Reopened,
    /// The cooldown passed; jobs flow again on probation.
    Probing,
    /// A probe succeeded; the breaker closed.
    Closed,
}

impl BreakerPolicy {
    /// The cooldown after `reopened` failed probes.
    #[must_use]
    pub fn cooldown(&self, reopened: u32) -> Duration {
        let factor = 1_u32.checked_shl(reopened.min(16)).unwrap_or(u32::MAX);
        self.cooldown
            .checked_mul(factor)
            .unwrap_or(self.max_cooldown)
            .min(self.max_cooldown)
    }

    /// The next state. `window` counts over the sliding window ending now;
    /// `since_change` counts since the state's `since` (used while half
    /// open).
    #[must_use]
    pub fn evaluate(
        &self,
        state: BreakerState,
        window: Counts,
        since_change: Counts,
        now: i64,
    ) -> (BreakerState, Option<Change>) {
        match state {
            BreakerState::Closed => {
                let total = u64::from(window.failures) + u64::from(window.completions);
                let dominant = total > 0
                    && u64::from(window.failures) * 100 >= u64::from(self.failure_percent) * total;
                if window.failures >= self.min_failures && dominant {
                    (
                        BreakerState::Open {
                            since: now,
                            reopened: 0,
                        },
                        Some(Change::Opened),
                    )
                } else {
                    (state, None)
                }
            }
            BreakerState::Open { since, reopened } => {
                let waited = u64::try_from(now.saturating_sub(since)).unwrap_or(0);
                if waited >= self.cooldown(reopened).as_secs() {
                    (
                        BreakerState::HalfOpen {
                            since: now,
                            reopened,
                        },
                        Some(Change::Probing),
                    )
                } else {
                    (state, None)
                }
            }
            BreakerState::HalfOpen { reopened, .. } => {
                if since_change.failures > 0 {
                    (
                        BreakerState::Open {
                            since: now,
                            reopened: reopened.saturating_add(1),
                        },
                        Some(Change::Reopened),
                    )
                } else if since_change.completions > 0 {
                    (BreakerState::Closed, Some(Change::Closed))
                } else {
                    (state, None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: BreakerPolicy = BreakerPolicy {
        window: Duration::from_secs(900),
        min_failures: 5,
        failure_percent: 50,
        cooldown: Duration::from_secs(300),
        max_cooldown: Duration::from_secs(3600),
    };

    fn counts(failures: u32, completions: u32) -> Counts {
        Counts {
            failures,
            completions,
        }
    }

    #[test]
    fn opens_only_when_failures_dominate() {
        let closed = BreakerState::Closed;
        let none = Counts::default();
        assert_eq!(POLICY.evaluate(closed, counts(4, 0), none, 0).1, None);
        assert_eq!(POLICY.evaluate(closed, counts(5, 10), none, 0).1, None);
        let (state, change) = POLICY.evaluate(closed, counts(5, 5), none, 100);
        assert_eq!(change, Some(Change::Opened));
        assert_eq!(
            state,
            BreakerState::Open {
                since: 100,
                reopened: 0
            }
        );
        assert!(!state.allows_claims());
    }

    #[test]
    fn probes_after_the_cooldown_and_backs_off() {
        let open = BreakerState::Open {
            since: 0,
            reopened: 0,
        };
        let none = Counts::default();
        assert_eq!(POLICY.evaluate(open, none, none, 299).1, None);
        let (half, change) = POLICY.evaluate(open, none, none, 300);
        assert_eq!(change, Some(Change::Probing));
        assert!(half.allows_claims());
        // Nothing happened yet: stay half open.
        assert_eq!(POLICY.evaluate(half, none, none, 400).1, None);
        let (reopened, change) = POLICY.evaluate(half, none, counts(1, 3), 500);
        assert_eq!(change, Some(Change::Reopened));
        assert_eq!(
            reopened,
            BreakerState::Open {
                since: 500,
                reopened: 1
            }
        );
        // The second cooldown is twice as long.
        assert_eq!(POLICY.evaluate(reopened, none, none, 500 + 599).1, None);
        assert_eq!(
            POLICY.evaluate(reopened, none, none, 500 + 600).1,
            Some(Change::Probing)
        );
        let (closed, change) = POLICY.evaluate(half, none, counts(0, 1), 600);
        assert_eq!(
            (closed, change),
            (BreakerState::Closed, Some(Change::Closed))
        );
    }

    #[test]
    fn cooldown_is_capped() {
        assert_eq!(POLICY.cooldown(0), Duration::from_secs(300));
        assert_eq!(POLICY.cooldown(3), Duration::from_secs(2400));
        assert_eq!(POLICY.cooldown(4), Duration::from_secs(3600));
        assert_eq!(POLICY.cooldown(u32::MAX), Duration::from_secs(3600));
    }
}
