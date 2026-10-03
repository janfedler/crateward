//! The failure taxonomy and the automated response to each class.
//!
//! Autonomy depends on every failure having a defined response before a
//! human is asked. The classes below are exhaustive: a worker that hits an
//! error must pick one, and the job state machine and the supervisor derive
//! everything else from that choice.
//!
//! A crate that fails to build is deliberately absent. That is a result of
//! the analysis (see [`crate::job::BuildOutcome`]), not a failure of the
//! pipeline. Likewise a hostile archive that the safe extractor rejects is a
//! finding, not a failure.

use serde::{Deserialize, Serialize};

use crate::escalation::HumanEscalation;

/// How a stage attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// Network errors, timeouts, a VM boot hiccup. Retried with exponential
    /// backoff and jitter. Each retry consumes one attempt of the job.
    Transient,
    /// The infrastructure is at fault, not the crate: KVM errors, a full
    /// scratch filesystem, Postgres unavailable. Retried without consuming
    /// the job's attempts, and counted by the stage circuit breaker, which
    /// pauses only the affected stage.
    Infrastructure,
    /// The input can never be processed, for example a malformed index
    /// entry. The job fails immediately.
    Permanent,
    /// Something suggests the sandbox or host may be compromised. The whole
    /// pipeline enters quarantine and the job is never retried automatically,
    /// because retrying would execute the suspicious crate again.
    SuspectedCompromise,
}

/// What the system does about a failure, without asking anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomatedResponse {
    /// Put the job back into its stage queue after a backoff delay.
    RetryWithBackoff,
    /// Retry later and report the failure to the stage circuit breaker.
    RetryAndReportToCircuitBreaker,
    /// Mark the job as failed with its reason.
    FailJob,
    /// Pause the whole pipeline and escalate to a human.
    EnterQuarantine,
}

impl FailureClass {
    /// The lowercase name, as serialized.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Infrastructure => "infrastructure",
            Self::Permanent => "permanent",
            Self::SuspectedCompromise => "suspected_compromise",
        }
    }

    /// Every class.
    pub const ALL: [Self; 4] = [
        Self::Transient,
        Self::Infrastructure,
        Self::Permanent,
        Self::SuspectedCompromise,
    ];

    /// The automated response defined for this class.
    #[must_use]
    pub const fn response(self) -> AutomatedResponse {
        match self {
            Self::Transient => AutomatedResponse::RetryWithBackoff,
            Self::Infrastructure => AutomatedResponse::RetryAndReportToCircuitBreaker,
            Self::Permanent => AutomatedResponse::FailJob,
            Self::SuspectedCompromise => AutomatedResponse::EnterQuarantine,
        }
    }
}

/// Why a stage attempt failed. Its class decides what happens next.
#[derive(Debug, thiserror::Error)]
#[error("{}: {message}", class.name())]
pub struct Failure {
    /// The class, for the state machine.
    pub class: FailureClass,
    /// What happened.
    pub message: String,
    /// An alert to raise, beyond what the class implies.
    pub escalation: Option<HumanEscalation>,
}

impl Failure {
    /// A failure of `class`.
    pub fn new(class: FailureClass, message: impl std::fmt::Display) -> Self {
        Self {
            class,
            message: message.to_string(),
            escalation: None,
        }
    }

    /// A [`FailureClass::Transient`] failure.
    pub fn transient(message: impl std::fmt::Display) -> Self {
        Self::new(FailureClass::Transient, message)
    }

    /// A [`FailureClass::Infrastructure`] failure.
    pub fn infrastructure(message: impl std::fmt::Display) -> Self {
        Self::new(FailureClass::Infrastructure, message)
    }

    /// A [`FailureClass::Permanent`] failure.
    pub fn permanent(message: impl std::fmt::Display) -> Self {
        Self::new(FailureClass::Permanent, message)
    }

    /// A [`FailureClass::SuspectedCompromise`] failure.
    pub fn compromise(message: impl std::fmt::Display) -> Self {
        Self::new(FailureClass::SuspectedCompromise, message)
    }

    /// The same failure, with an alert to raise.
    #[must_use]
    pub const fn escalate(mut self, escalation: HumanEscalation) -> Self {
        self.escalation = Some(escalation);
        self
    }
}

/// The job store being unavailable is never the job's fault.
#[cfg(feature = "store")]
impl From<crate::store::StoreError> for Failure {
    fn from(error: crate::store::StoreError) -> Self {
        Self::infrastructure(error)
    }
}

/// A request that may succeed later is transient, any other is permanent.
#[cfg(feature = "http")]
impl From<crate::http::HttpError> for Failure {
    fn from(error: crate::http::HttpError) -> Self {
        if error.is_transient() {
            Self::transient(error)
        } else {
            Self::permanent(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_the_serialized_form() {
        use FailureClass::*;
        for class in [Transient, Infrastructure, Permanent, SuspectedCompromise] {
            assert_eq!(serde_json::to_value(class).unwrap(), class.name());
        }
    }
}
