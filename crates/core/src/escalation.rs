//! The closed list of reasons Crateward may interrupt a human.
//!
//! Everything not listed here is logged and visible on the dashboard, but
//! never pushed to a phone. Keeping the list as an enum means a new alert
//! cannot be added without editing this file, the notifier and
//! `docs/RUNBOOK.md` together.

use serde::{Deserialize, Serialize};

use crate::job::{JobId, Stage};

/// A reason to notify the maintainer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HumanEscalation {
    /// A stage keeps failing after retries and its circuit breaker is open.
    StageFailingAfterRetries {
        /// The affected stage.
        stage: Stage,
    },
    /// A filesystem is fuller than the configured threshold.
    DiskUsageAboveThreshold {
        /// Current usage in percent.
        percent: u8,
    },
    /// The kernel reported a KVM error.
    KvmError,
    /// A canary crate produced the wrong verdict.
    CanaryFailure,
    /// A high risk verdict is ready for review, with an evidence pack.
    HighRiskVerdict {
        /// The job that produced the verdict.
        job: JobId,
    },
    /// Something indicates a sandbox escape or host compromise.
    SandboxEscapeIndicator {
        /// The job that was running, if one can be attributed.
        job: Option<JobId>,
    },
}

/// The four escalation categories of the specification. The notifier uses
/// them for priorities and for the weekly digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationCategory {
    /// Operational trouble the automation could not resolve.
    Operations,
    /// A canary produced the wrong verdict; results cannot be trusted.
    Canary,
    /// A verdict needs human review before any disclosure.
    Verdict,
    /// Possible sandbox escape. Highest priority.
    Escape,
}

impl HumanEscalation {
    /// The category of this escalation.
    #[must_use]
    pub const fn category(&self) -> EscalationCategory {
        match self {
            Self::StageFailingAfterRetries { .. }
            | Self::DiskUsageAboveThreshold { .. }
            | Self::KvmError => EscalationCategory::Operations,
            Self::CanaryFailure => EscalationCategory::Canary,
            Self::HighRiskVerdict { .. } => EscalationCategory::Verdict,
            Self::SandboxEscapeIndicator { .. } => EscalationCategory::Escape,
        }
    }

    /// Key used to deduplicate repeated alerts for the same condition.
    ///
    /// Disk usage deliberately ignores the exact percentage, so a disk that
    /// creeps from 86 to 87 percent does not produce a second alert.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        match self {
            Self::StageFailingAfterRetries { stage } => format!("stage_failing:{}", stage.name()),
            Self::DiskUsageAboveThreshold { .. } => "disk_usage".to_owned(),
            Self::KvmError => "kvm_error".to_owned(),
            Self::CanaryFailure => "canary_failure".to_owned(),
            Self::HighRiskVerdict { job } => format!("high_risk:{}", job.0),
            Self::SandboxEscapeIndicator { job } => match job {
                Some(job) => format!("escape:{}", job.0),
                None => "escape:unattributed".to_owned(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_alerts_deduplicate_across_percentages() {
        let a = HumanEscalation::DiskUsageAboveThreshold { percent: 86 };
        let b = HumanEscalation::DiskUsageAboveThreshold { percent: 91 };
        assert_eq!(a.dedup_key(), b.dedup_key());
    }

    #[test]
    fn escape_is_the_highest_category() {
        let escape = HumanEscalation::SandboxEscapeIndicator { job: None }.category();
        for other in [
            HumanEscalation::KvmError,
            HumanEscalation::CanaryFailure,
            HumanEscalation::HighRiskVerdict { job: JobId(1) },
        ] {
            assert!(other.category() < escape);
        }
    }
}
