//! Property tests for the job state machine.
//!
//! The unit tests in `job.rs` pin down individual paths. These tests drive
//! the machine with arbitrary event sequences and check the invariants that
//! autonomy depends on: every path is finite, retries are bounded,
//! escalation happens at most once, terminal states absorb every event, and
//! coverage labels always match what actually ran.

use crateward_core::failure::FailureClass;
use crateward_core::job::{
    BuildOutcome, Job, JobEvent, JobState, Limits, Outcome, RunKind, StageLimits, Triage,
    representative_events,
};
use crateward_core::verdict::{Coverage, StaticOnlyReason};
use proptest::prelude::*;

const LIMITS: Limits = Limits::uniform(StageLimits {
    max_attempts: 3,
    max_infrastructure_retries: 2,
});

/// Upper bound on valid transitions before a terminal state. Each stage
/// entry allows fewer than `max_attempts` transient retries plus
/// `max_infrastructure_retries` infrastructure retries, each of which may
/// also be followed by a restart of the VM. There are at most eight stage
/// entries on the longest path (including one escalation).
const MAX_STEPS: usize = 8 * 2 * (3 + 2 + 1) + 16;

fn check_invariants(job: &Job) -> Result<(), TestCaseError> {
    prop_assert!(job.attempts < LIMITS.fetch.max_attempts || job.state == JobState::Failed);
    prop_assert!(job.infrastructure_retries <= LIMITS.fetch.max_infrastructure_retries);
    prop_assert_eq!(job.escalated, job.run_kind == RunKind::Full);
    prop_assert!(job.dynamic_runs <= 2);
    prop_assert_eq!(job.state == JobState::Failed, job.failure.is_some());
    prop_assert_eq!(job.state == JobState::Done, job.outcome.is_some());

    if let Some(coverage) = job.coverage {
        prop_assert_eq!(coverage == Coverage::DynamicLinux, job.dynamic_runs > 0);
    }

    if job.state == JobState::Running {
        prop_assert_eq!(job.triage, Some(Triage::Dynamic));
    }

    Ok(())
}

/// An arbitrary event, valid or not.
fn any_event() -> impl Strategy<Value = JobEvent> {
    prop::sample::select(representative_events())
}

/// The event that moves a job forward on its happy path.
fn progress_event(job: &Job) -> Option<JobEvent> {
    Some(match job.state {
        JobState::Discovered => JobEvent::Fetched,
        JobState::Fetched => JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        },
        JobState::ReadyForSandbox => JobEvent::SandboxStarted,
        JobState::Running => JobEvent::SandboxCompleted {
            outcome: BuildOutcome::Succeeded,
        },
        JobState::StaticallyAnalyzed | JobState::DynamicallyAnalyzed => {
            JobEvent::Scored { escalate: false }
        }
        JobState::Scored => JobEvent::Finalized,
        JobState::Done | JobState::Failed => return None,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Arbitrary sequences, including invalid events: rejected events change
    /// nothing, accepted ones keep every invariant, and terminal states
    /// accept nothing.
    #[test]
    fn invariants_hold_for_arbitrary_event_sequences(events in prop::collection::vec(any_event(), 0..300)) {
        let mut job = Job::new();
        for event in events {
            let before = job;
            match job.apply(event, &LIMITS) {
                Ok(transition) => {
                    prop_assert!(!before.state.is_terminal());
                    job = transition.job;
                    check_invariants(&job)?;
                }
                Err(_) => prop_assert_eq!(job, before),
            }
        }
    }

    /// Choosing only among valid events, every run reaches a terminal state
    /// within a fixed bound: there is no infinite path through the machine.
    #[test]
    fn every_path_terminates(choices in prop::collection::vec(any::<usize>(), MAX_STEPS + 1)) {
        let events = representative_events();
        let mut job = Job::new();
        let mut steps = 0;

        for choice in choices {
            if job.state.is_terminal() {
                break;
            }

            let valid: Vec<Job> = events
                .iter()
                .filter_map(|event| job.apply(*event, &LIMITS).ok())
                .map(|transition| transition.job)
                .collect();

            prop_assert!(!valid.is_empty(), "no valid event in {:?}", job.state);
            job = valid[choice % valid.len()];
            steps += 1;
        }

        prop_assert!(job.state.is_terminal(), "still in {:?} after {} steps", job.state, steps);
        prop_assert!(steps <= MAX_STEPS);
    }

    /// From any reachable job, the happy path finishes it in a few steps.
    #[test]
    fn every_reachable_job_can_finish(events in prop::collection::vec(any_event(), 0..60)) {
        let mut job = Job::new();
        for event in events {
            if let Ok(transition) = job.apply(event, &LIMITS) {
                job = transition.job;
            }
        }

        for _ in 0..10 {
            let Some(event) = progress_event(&job) else { break };
            job = job.apply(event, &LIMITS).map_err(|e| TestCaseError::fail(e.to_string()))?.job;
        }

        prop_assert!(job.state.is_terminal());
    }

    /// Repeated transient failures always end in `Failed`, and never take
    /// more than `max_attempts` failures.
    #[test]
    fn transient_failures_are_bounded(events in prop::collection::vec(any_event(), 0..40)) {
        let mut job = Job::new();
        for event in events {
            if let Ok(transition) = job.apply(event, &LIMITS) {
                job = transition.job;
            }
        }

        let failure = JobEvent::StageFailed { class: FailureClass::Transient };
        let mut failures = 0;
        while !job.state.is_terminal() {
            job = job.apply(failure, &LIMITS).map_err(|e| TestCaseError::fail(e.to_string()))?.job;
            failures += 1;
            prop_assert!(failures <= LIMITS.fetch.max_attempts);
        }
    }
}

#[test]
fn done_jobs_carry_an_honest_coverage_label() {
    let paths: [(Triage, Coverage); 3] = [
        (Triage::Dynamic, Coverage::DynamicLinux),
        (
            Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode),
            Coverage::StaticOnly(StaticOnlyReason::NoBuildTimeCode),
        ),
        (Triage::NotApplicableOnLinux, Coverage::NotApplicableOnLinux),
    ];

    for (triage, expected) in paths {
        let mut job = Job::new();
        job = job.apply(JobEvent::Fetched, &LIMITS).unwrap().job;
        job = job
            .apply(JobEvent::StaticAnalysisCompleted { triage }, &LIMITS)
            .unwrap()
            .job;

        while let Some(event) = progress_event(&job) {
            job = job.apply(event, &LIMITS).unwrap().job;
        }

        assert_eq!(job.outcome, Some(Outcome::Analyzed(expected)));
    }
}
