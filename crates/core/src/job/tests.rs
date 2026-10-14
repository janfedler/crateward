use super::*;

#[test]
fn outcome_names_match_the_serialized_form() {
    use BuildOutcome::*;

    for outcome in [Succeeded, Failed, TimedOut, ResourceLimit, GuestStopped] {
        assert_eq!(serde_json::to_value(outcome).unwrap(), outcome.name());
    }
}

const LIMITS: Limits = Limits::uniform(StageLimits {
    max_attempts: 3,
    max_infrastructure_retries: 2,
});

fn run(events: &[JobEvent]) -> Job {
    let mut job = Job::new();
    for event in events {
        job = job.apply(*event, &LIMITS).unwrap().job;
    }

    job
}

#[test]
fn happy_path_with_dynamic_analysis() {
    let job = run(&[
        JobEvent::Fetched,
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        },
        JobEvent::SandboxStarted,
        JobEvent::SandboxCompleted {
            outcome: BuildOutcome::Failed,
        },
        JobEvent::Scored { escalate: false },
        JobEvent::Finalized,
    ]);

    assert_eq!(job.state, JobState::Done);
    assert_eq!(job.outcome, Some(Outcome::Analyzed(Coverage::DynamicLinux)));
    assert_eq!(job.last_build, Some(BuildOutcome::Failed));
}

#[test]
fn static_only_path_is_labeled_with_its_reason() {
    let job = run(&[
        JobEvent::Fetched,
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode),
        },
        JobEvent::Scored { escalate: false },
        JobEvent::Finalized,
    ]);

    assert_eq!(
        job.outcome,
        Some(Outcome::Analyzed(Coverage::StaticOnly(
            StaticOnlyReason::NoBuildTimeCode
        )))
    );
}

#[test]
fn deadline_turns_a_waiting_job_into_static_only() {
    let job = run(&[
        JobEvent::Fetched,
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        },
        JobEvent::CapacityDeadlineExpired,
        JobEvent::Scored { escalate: false },
    ]);

    assert_eq!(
        job.coverage,
        Some(Coverage::StaticOnly(StaticOnlyReason::CapacityDeadline))
    );
}

#[test]
fn escalation_happens_at_most_once() {
    let job = run(&[
        JobEvent::Fetched,
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        },
        JobEvent::SandboxStarted,
        JobEvent::SandboxCompleted {
            outcome: BuildOutcome::Succeeded,
        },
        JobEvent::Scored { escalate: true },
        JobEvent::SandboxStarted,
        JobEvent::SandboxCompleted {
            outcome: BuildOutcome::Succeeded,
        },
    ]);

    assert_eq!(job.run_kind, RunKind::Full);
    assert_eq!(job.dynamic_runs, 2);
    assert!(matches!(
        job.apply(JobEvent::Scored { escalate: true }, &LIMITS),
        Err(TransitionError::NotAllowed { .. })
    ));
}

#[test]
fn transient_failures_retry_then_give_up() {
    let mut job = run(&[JobEvent::Fetched]);
    let failure = JobEvent::StageFailed {
        class: FailureClass::Transient,
    };

    for attempt in 1..3 {
        let t = job.apply(failure, &LIMITS).unwrap();

        assert_eq!(
            t.effect,
            Effect::RetryAfterBackoff {
                stage: Stage::StaticAnalysis,
                attempt
            }
        );

        job = t.job;

        assert_eq!(job.state, JobState::Fetched);
    }

    let job = job.apply(failure, &LIMITS).unwrap().job;
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(
        job.failure,
        Some(FailureReason::RetriesExhausted {
            stage: Stage::StaticAnalysis
        })
    );
}

#[test]
fn a_failed_run_returns_to_the_slot_queue_and_keeps_its_attempts() {
    let job = run(&[
        JobEvent::Fetched,
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        },
        JobEvent::SandboxStarted,
        JobEvent::LeaseExpired,
        JobEvent::SandboxStarted,
    ]);

    assert_eq!(job.state, JobState::Running);
    assert_eq!(job.attempts, 1);
}

#[test]
fn suspected_compromise_holds_the_job_and_quarantines() {
    let job = run(&[
        JobEvent::Fetched,
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        },
        JobEvent::SandboxStarted,
    ]);

    let t = job
        .apply(
            JobEvent::StageFailed {
                class: FailureClass::SuspectedCompromise,
            },
            &LIMITS,
        )
        .unwrap();

    assert_eq!(t.job.state, JobState::Failed);
    assert_eq!(
        t.effect,
        Effect::EnterQuarantine {
            stage: Stage::Sandbox
        }
    );
}

#[test]
fn terminal_states_reject_everything() {
    let job = run(&[JobEvent::Unavailable]);
    for event in representative_events() {
        assert!(matches!(
            job.apply(event, &LIMITS),
            Err(TransitionError::Terminal { .. })
        ));
    }
}

#[test]
fn every_non_terminal_state_except_running_is_claimable_by_its_stage() {
    for state in JobState::ALL {
        let claimable = Stage::ALL
            .iter()
            .any(|stage| stage.claimable_states().contains(&state));

        let expected = !state.is_terminal() && state != JobState::Running;

        assert_eq!(claimable, expected, "{state}");

        if claimable {
            assert!(
                state
                    .stage()
                    .is_some_and(|s| s.claimable_states().contains(&state))
            );
        }
    }
}

#[test]
fn diagram_covers_every_state() {
    let diagram = mermaid_diagram();
    for state in JobState::ALL {
        assert!(diagram.contains(state.name()), "{state} missing");
    }
}
