//! The job state machine that spans the whole pipeline.
//!
//! One Postgres row per crate version tracks everything from discovery to
//! the final verdict. Each stage worker claims rows in its input state,
//! does its work, and reports a [`JobEvent`]. This module decides, as a pure
//! function, what the row looks like afterwards. Keeping the decision pure
//! makes the rules easy to test exhaustively (see the property tests in
//! `tests/state_machine.rs`) and keeps the database layer free of policy.
//!
//! # Design notes
//!
//! * States name what has been achieved, so each stage claims the state its
//!   predecessor produced. The one exception is [`JobState::Running`]: a VM
//!   run owns host resources (a slot, a tap device, a jail) that startup
//!   reconciliation must match against rows, so it is a state of its own.
//! * [`JobState::DynamicallyAnalyzed`] is not in the original list of the
//!   specification. It persists the raw VM results before scoring, so an
//!   analyzer crash never forces an expensive and non deterministic VM rerun.
//! * Leases, heartbeats, priorities and backoff timestamps are columns next to
//!   the state, not states. A transient failure keeps the stage and consumes
//!   one attempt. Attempts reset only when a stage completes.
//! * A lease that expires counts as a failed attempt, because a hostile crate
//!   can crash a worker on purpose. Otherwise it could loop forever.
//! * Escalation from `cargo check` to a full build and test happens at most
//!   once per job, which keeps every path finite.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::failure::FailureClass;
use crate::verdict::{Coverage, StaticOnlyReason};

/// Database identifier of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct JobId(pub i64);

/// A pipeline stage. Each stage has its own worker pool and concurrency
/// limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Download, verify, extract and vendor.
    Fetch,
    /// Parse the sources and decide whether a VM run is worthwhile.
    StaticAnalysis,
    /// Run the job in a microVM.
    Sandbox,
    /// Score static and dynamic results.
    Analysis,
    /// Publish the verdict, raise alerts and export.
    Finalize,
}

impl Stage {
    /// Every stage, in pipeline order.
    pub const ALL: [Self; 5] = [
        Self::Fetch,
        Self::StaticAnalysis,
        Self::Sandbox,
        Self::Analysis,
        Self::Finalize,
    ];

    /// The states a worker of this stage claims rows in. `Running` is not
    /// among them: a sandbox worker keeps its lease from `ReadyForSandbox`
    /// through the whole run.
    #[must_use]
    pub const fn claimable_states(self) -> &'static [JobState] {
        match self {
            Self::Fetch => &[JobState::Discovered],
            Self::StaticAnalysis => &[JobState::Fetched],
            Self::Sandbox => &[JobState::ReadyForSandbox],
            Self::Analysis => &[JobState::StaticallyAnalyzed, JobState::DynamicallyAnalyzed],
            Self::Finalize => &[JobState::Scored],
        }
    }

    /// Short name used in logs, the command line tool and configuration.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::StaticAnalysis => "static_analysis",
            Self::Sandbox => "sandbox",
            Self::Analysis => "analysis",
            Self::Finalize => "finalize",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a job is in the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// The feed saw the version. Waiting for the fetcher.
    Discovered,
    /// Sources are stored and dependencies vendored. Waiting for static
    /// analysis.
    Fetched,
    /// Static results exist and no VM run is pending. Waiting for scoring.
    StaticallyAnalyzed,
    /// Waiting for a free VM slot.
    ReadyForSandbox,
    /// A microVM is executing the job.
    Running,
    /// Raw VM results are stored. Waiting for scoring.
    DynamicallyAnalyzed,
    /// A verdict exists. Waiting for publication and alerts.
    Scored,
    /// Terminal: the pipeline is finished with this version.
    Done,
    /// Terminal: the pipeline gave up. See [`Job::failure`].
    Failed,
}

impl JobState {
    /// Every state, in pipeline order.
    pub const ALL: [Self; 9] = [
        Self::Discovered,
        Self::Fetched,
        Self::StaticallyAnalyzed,
        Self::ReadyForSandbox,
        Self::Running,
        Self::DynamicallyAnalyzed,
        Self::Scored,
        Self::Done,
        Self::Failed,
    ];

    /// Name used in the database and in diagrams.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Discovered => "Discovered",
            Self::Fetched => "Fetched",
            Self::StaticallyAnalyzed => "StaticallyAnalyzed",
            Self::ReadyForSandbox => "ReadyForSandbox",
            Self::Running => "Running",
            Self::DynamicallyAnalyzed => "DynamicallyAnalyzed",
            Self::Scored => "Scored",
            Self::Done => "Done",
            Self::Failed => "Failed",
        }
    }

    /// Whether the pipeline is finished with the job.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed)
    }

    /// The stage that owns the job while it is in this state, if any.
    #[must_use]
    pub const fn stage(self) -> Option<Stage> {
        match self {
            Self::Discovered => Some(Stage::Fetch),
            Self::Fetched => Some(Stage::StaticAnalysis),
            Self::ReadyForSandbox | Self::Running => Some(Stage::Sandbox),
            Self::StaticallyAnalyzed | Self::DynamicallyAnalyzed => Some(Stage::Analysis),
            Self::Scored => Some(Stage::Finalize),
            Self::Done | Self::Failed => None,
        }
    }

    /// The state a job returns to when an attempt in this state fails and
    /// will be retried. For a VM run that is the queue for VM slots.
    #[must_use]
    pub const fn retry_state(self) -> Self {
        match self {
            Self::Running => Self::ReadyForSandbox,
            other => other,
        }
    }
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the VM runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    /// `cargo check`, plus cross target checks when the crate has platform
    /// specific code. The default for every dynamic job.
    Check,
    /// `cargo build` in a fresh VM, the confirmation run after a verdict of
    /// medium or above (ADR 0009). Tests would need the crate's dev
    /// dependencies, which the consumer probe does not resolve.
    Full,
}

impl RunKind {
    /// Name stored with the run.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Full => "full",
        }
    }
}

/// The decision static analysis makes about dynamic analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "reason")]
pub enum Triage {
    /// Run the job in a microVM.
    Dynamic,
    /// Do not run it. The verdict is based on static analysis only.
    StaticOnly(StaticOnlyReason),
    /// No code compiles on Linux, so a Linux run cannot observe anything.
    NotApplicableOnLinux,
}

/// How a VM run ended. Every variant is a valid result of the analysis:
/// a crate that fails to build is information, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildOutcome {
    /// The cargo commands succeeded.
    Succeeded,
    /// A cargo command failed.
    Failed,
    /// The run hit its wall clock limit.
    TimedOut,
    /// The run hit a memory, disk or process limit inside the guest.
    ResourceLimit,
    /// The guest stopped before the agent reported an end: it shut down,
    /// restarted or panicked, or its agent stopped answering. Something in
    /// the guest did that, so it is a result about the crate, not a failure
    /// of the pipeline, and it is not retried (ADR 0008).
    GuestStopped,
}

impl BuildOutcome {
    /// The lowercase name, as serialized and stored with a run.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::ResourceLimit => "resource_limit",
            Self::GuestStopped => "guest_stopped",
        }
    }
}

/// How a job ended when it reached [`JobState::Done`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "coverage")]
pub enum Outcome {
    /// A verdict was produced, qualified by what the analysis covered.
    Analyzed(Coverage),
    /// The version disappeared from crates.io before it could be fetched.
    Unavailable,
}

/// Why a job reached [`JobState::Failed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FailureReason {
    /// Transient failures used up the stage's attempts.
    RetriesExhausted {
        /// The stage that kept failing.
        stage: Stage,
    },
    /// Infrastructure failures used up the stage's infrastructure retries.
    /// The stage circuit breaker normally opens long before this.
    InfrastructureRetriesExhausted {
        /// The stage that kept failing.
        stage: Stage,
    },
    /// The input can never be processed.
    Permanent {
        /// The stage that rejected the input.
        stage: Stage,
    },
    /// A compromise indicator was raised while the job was processed. The
    /// job is held for human review and never retried automatically.
    SuspectedCompromise {
        /// The stage that raised the indicator.
        stage: Stage,
    },
}

/// Something that happened to a job. Workers report events. The state
/// machine decides the next state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum JobEvent {
    /// The fetcher stored and vendored the version.
    Fetched,
    /// The version no longer exists on crates.io.
    Unavailable,
    /// Static analysis finished and made a triage decision.
    StaticAnalysisCompleted {
        /// Whether the job goes to a VM.
        triage: Triage,
    },
    /// The orchestrator started a VM for the job.
    SandboxStarted,
    /// The VM run finished. The raw results are stored.
    SandboxCompleted {
        /// How the build ended.
        outcome: BuildOutcome,
    },
    /// The job waited too long for a VM slot and is scored statically.
    CapacityDeadlineExpired,
    /// The analyzer produced a verdict.
    Scored {
        /// Whether to escalate from `cargo check` to a full build and test.
        escalate: bool,
    },
    /// The verdict was published and any alerts were sent.
    Finalized,
    /// The current attempt failed.
    StageFailed {
        /// The failure class chosen by the worker.
        class: FailureClass,
    },
    /// The worker holding the lease stopped heartbeating.
    LeaseExpired,
}

/// Retry budgets of one stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageLimits {
    /// Attempts before a job fails with [`FailureReason::RetriesExhausted`].
    /// Must be at least one.
    pub max_attempts: u32,
    /// Infrastructure retries before a job fails with
    /// [`FailureReason::InfrastructureRetriesExhausted`].
    pub max_infrastructure_retries: u32,
}

/// Retry budgets of every stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Fetch stage.
    pub fetch: StageLimits,
    /// Static analysis stage.
    pub static_analysis: StageLimits,
    /// Sandbox stage.
    pub sandbox: StageLimits,
    /// Analysis stage.
    pub analysis: StageLimits,
    /// Finalize stage.
    pub finalize: StageLimits,
}

impl Limits {
    /// The same budgets for every stage.
    #[must_use]
    pub const fn uniform(limits: StageLimits) -> Self {
        Self {
            fetch: limits,
            static_analysis: limits,
            sandbox: limits,
            analysis: limits,
            finalize: limits,
        }
    }

    /// The budgets of one stage.
    #[must_use]
    pub const fn for_stage(&self, stage: Stage) -> StageLimits {
        match stage {
            Stage::Fetch => self.fetch,
            Stage::StaticAnalysis => self.static_analysis,
            Stage::Sandbox => self.sandbox,
            Stage::Analysis => self.analysis,
            Stage::Finalize => self.finalize,
        }
    }
}

/// The pipeline relevant part of a job row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Job {
    /// Current state.
    pub state: JobState,
    /// Failed attempts in the current stage.
    pub attempts: u32,
    /// Infrastructure failures in the current stage.
    pub infrastructure_retries: u32,
    /// What the next or current VM run executes.
    pub run_kind: RunKind,
    /// Whether the job was escalated to a full build.
    pub escalated: bool,
    /// Completed VM runs.
    pub dynamic_runs: u8,
    /// The triage decision of static analysis.
    pub triage: Option<Triage>,
    /// Outcome of the most recent VM run.
    pub last_build: Option<BuildOutcome>,
    /// Set once the analyzer produced a verdict.
    pub coverage: Option<Coverage>,
    /// Set when the job is [`JobState::Done`].
    pub outcome: Option<Outcome>,
    /// Set when the job is [`JobState::Failed`].
    pub failure: Option<FailureReason>,
}

impl Default for Job {
    fn default() -> Self {
        Self::new()
    }
}

/// A side effect the caller must carry out after persisting the new state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Effect {
    /// Nothing beyond storing the new state.
    None,
    /// Make the job claimable again after the backoff for this attempt.
    RetryAfterBackoff {
        /// The stage to retry.
        stage: Stage,
        /// The attempt that just failed, counting from 1.
        attempt: u32,
    },
    /// Report an infrastructure failure to the stage circuit breaker and
    /// retry after a backoff.
    ReportInfrastructureFailure {
        /// The affected stage.
        stage: Stage,
        /// Infrastructure failures so far in this stage, counting from 1.
        retry: u32,
    },
    /// Enter quarantine: pause the whole pipeline and escalate.
    EnterQuarantine {
        /// The stage that raised the indicator.
        stage: Stage,
    },
}

/// The result of a valid transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// The job after the event.
    pub job: Job,
    /// What the caller must do next.
    pub effect: Effect,
}

/// Why an event cannot be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// The job is finished. No event applies.
    #[error("job is in terminal state {state}")]
    Terminal {
        /// The terminal state.
        state: JobState,
    },
    /// The event makes no sense in this state.
    #[error("event {event:?} is not valid in state {state}")]
    NotAllowed {
        /// The current state.
        state: JobState,
        /// The rejected event.
        event: JobEvent,
    },
}

impl Job {
    /// A freshly discovered job.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: JobState::Discovered,
            attempts: 0,
            infrastructure_retries: 0,
            run_kind: RunKind::Check,
            escalated: false,
            dynamic_runs: 0,
            triage: None,
            last_build: None,
            coverage: None,
            outcome: None,
            failure: None,
        }
    }

    /// Applies an event and returns the new job and the effect to carry out.
    ///
    /// The receiver is not modified, so a rejected event leaves no trace.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] if the job is terminal or the event is not
    /// valid in the current state.
    pub fn apply(&self, event: JobEvent, limits: &Limits) -> Result<Transition, TransitionError> {
        let state = self.state;
        if state.is_terminal() {
            return Err(TransitionError::Terminal { state });
        }
        let not_allowed = TransitionError::NotAllowed { state, event };
        let mut next = *self;

        let effect = match (state, event) {
            (JobState::Discovered, JobEvent::Fetched) => {
                next.enter(JobState::Fetched);
                Effect::None
            }
            (JobState::Discovered, JobEvent::Unavailable) => {
                next.enter(JobState::Done);
                next.outcome = Some(Outcome::Unavailable);
                Effect::None
            }
            (JobState::Fetched, JobEvent::StaticAnalysisCompleted { triage }) => {
                next.triage = Some(triage);
                next.enter(match triage {
                    Triage::Dynamic => JobState::ReadyForSandbox,
                    Triage::StaticOnly(_) | Triage::NotApplicableOnLinux => {
                        JobState::StaticallyAnalyzed
                    }
                });
                Effect::None
            }
            (JobState::ReadyForSandbox, JobEvent::SandboxStarted) => {
                // Same stage: attempts carry over, otherwise a run that keeps
                // failing after start would retry forever.
                next.state = JobState::Running;
                Effect::None
            }
            (JobState::Running, JobEvent::SandboxCompleted { outcome }) => {
                next.last_build = Some(outcome);
                next.dynamic_runs = next.dynamic_runs.saturating_add(1);
                next.enter(JobState::DynamicallyAnalyzed);
                Effect::None
            }
            (JobState::ReadyForSandbox, JobEvent::CapacityDeadlineExpired) => {
                // Escalated jobs already have dynamic results and outrank
                // everything in the queue. They keep waiting.
                if self.dynamic_runs > 0 {
                    return Err(not_allowed);
                }
                next.triage = Some(Triage::StaticOnly(StaticOnlyReason::CapacityDeadline));
                next.enter(JobState::StaticallyAnalyzed);
                Effect::None
            }
            (
                JobState::StaticallyAnalyzed | JobState::DynamicallyAnalyzed,
                JobEvent::Scored { escalate },
            ) => {
                if escalate {
                    let may_escalate = state == JobState::DynamicallyAnalyzed
                        && !self.escalated
                        && self.run_kind == RunKind::Check;
                    if !may_escalate {
                        return Err(not_allowed);
                    }
                    next.escalated = true;
                    next.run_kind = RunKind::Full;
                    next.enter(JobState::ReadyForSandbox);
                } else {
                    next.coverage = Some(self.coverage_now());
                    next.enter(JobState::Scored);
                }
                Effect::None
            }
            (JobState::Scored, JobEvent::Finalized) => {
                next.outcome = next.coverage.map(Outcome::Analyzed);
                if next.outcome.is_none() {
                    return Err(not_allowed);
                }
                next.enter(JobState::Done);
                Effect::None
            }
            (_, JobEvent::StageFailed { class }) => next.fail_attempt(class, limits),
            (_, JobEvent::LeaseExpired) => next.fail_attempt(FailureClass::Transient, limits),
            _ => return Err(not_allowed),
        };
        Ok(Transition { job: next, effect })
    }

    /// Moves to a new stage and resets the per stage counters.
    fn enter(&mut self, state: JobState) {
        self.state = state;
        self.attempts = 0;
        self.infrastructure_retries = 0;
    }

    /// Coverage label for the verdict about to be produced.
    /// What the analysis covered so far: dynamic once a VM run finished,
    /// otherwise what triage decided.
    #[must_use]
    pub fn coverage_now(&self) -> Coverage {
        if self.dynamic_runs > 0 {
            return Coverage::DynamicLinux;
        }
        match self.triage {
            Some(Triage::StaticOnly(reason)) => Coverage::StaticOnly(reason),
            Some(Triage::NotApplicableOnLinux) => Coverage::NotApplicableOnLinux,
            // A dynamic triage without a completed run cannot reach scoring.
            // The deadline rewrites the triage first. Label it conservatively.
            Some(Triage::Dynamic) | None => {
                Coverage::StaticOnly(StaticOnlyReason::CapacityDeadline)
            }
        }
    }

    fn fail(&mut self, reason: FailureReason) {
        self.enter(JobState::Failed);
        self.failure = Some(reason);
    }

    fn fail_attempt(&mut self, class: FailureClass, limits: &Limits) -> Effect {
        // Only called for non terminal states, which all have a stage.
        let Some(stage) = self.state.stage() else {
            return Effect::None;
        };
        let stage_limits = limits.for_stage(stage);
        match class {
            FailureClass::Transient => {
                self.attempts = self.attempts.saturating_add(1);
                if self.attempts >= stage_limits.max_attempts {
                    self.fail(FailureReason::RetriesExhausted { stage });
                    Effect::None
                } else {
                    self.state = self.state.retry_state();
                    Effect::RetryAfterBackoff {
                        stage,
                        attempt: self.attempts,
                    }
                }
            }
            FailureClass::Infrastructure => {
                self.infrastructure_retries = self.infrastructure_retries.saturating_add(1);
                if self.infrastructure_retries > stage_limits.max_infrastructure_retries {
                    self.fail(FailureReason::InfrastructureRetriesExhausted { stage });
                    Effect::None
                } else {
                    self.state = self.state.retry_state();
                    Effect::ReportInfrastructureFailure {
                        stage,
                        retry: self.infrastructure_retries,
                    }
                }
            }
            FailureClass::Permanent => {
                self.fail(FailureReason::Permanent { stage });
                Effect::None
            }
            FailureClass::SuspectedCompromise => {
                self.fail(FailureReason::SuspectedCompromise { stage });
                Effect::EnterQuarantine { stage }
            }
        }
    }
}

/// One edge of the state diagram.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edge {
    /// Source state.
    pub from: JobState,
    /// Target state.
    pub to: JobState,
    /// Short description of the events that cause the edge.
    pub label: &'static str,
}

/// Representative events used to explore the state machine. Every variant
/// of [`JobEvent`] and every payload that changes the target state appears
/// at least once.
#[must_use]
pub fn representative_events() -> Vec<JobEvent> {
    let mut events = vec![
        JobEvent::Fetched,
        JobEvent::Unavailable,
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        },
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode),
        },
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::NotApplicableOnLinux,
        },
        JobEvent::SandboxStarted,
        JobEvent::SandboxCompleted {
            outcome: BuildOutcome::Succeeded,
        },
        JobEvent::SandboxCompleted {
            outcome: BuildOutcome::Failed,
        },
        JobEvent::CapacityDeadlineExpired,
        JobEvent::Scored { escalate: false },
        JobEvent::Scored { escalate: true },
        JobEvent::Finalized,
        JobEvent::LeaseExpired,
    ];
    events.extend(
        FailureClass::ALL
            .into_iter()
            .map(|class| JobEvent::StageFailed { class }),
    );
    events
}

fn edge_label(event: JobEvent, from: JobState, to: JobState) -> &'static str {
    match event {
        JobEvent::Fetched => "fetched",
        JobEvent::Unavailable => "unavailable",
        JobEvent::StaticAnalysisCompleted {
            triage: Triage::Dynamic,
        } => "triage dynamic",
        JobEvent::StaticAnalysisCompleted { .. } => "triage static only",
        JobEvent::SandboxStarted => "VM slot claimed",
        JobEvent::SandboxCompleted { .. } => "run finished",
        JobEvent::CapacityDeadlineExpired => "dynamic deadline expired",
        JobEvent::Scored { escalate: true } => "escalate to full build",
        JobEvent::Scored { escalate: false } => "scored",
        JobEvent::Finalized => "finalized",
        JobEvent::StageFailed { .. } | JobEvent::LeaseExpired => {
            if to == JobState::Failed {
                "gave up"
            } else if to == from {
                "retry"
            } else {
                "retry run"
            }
        }
    }
}

/// Explores the state machine from representative jobs and returns every
/// edge, sorted. The diagram in `docs/ARCHITECTURE.md` is generated from
/// this, so it cannot drift from the code.
#[must_use]
pub fn edges() -> Vec<Edge> {
    let limits = Limits::uniform(StageLimits {
        max_attempts: 2,
        max_infrastructure_retries: 1,
    });
    let events = representative_events();
    let mut seen = std::collections::BTreeSet::new();
    let mut frontier = vec![Job::new()];
    let mut visited = std::collections::HashSet::new();
    while let Some(job) = frontier.pop() {
        if !visited.insert(job) {
            continue;
        }
        for event in &events {
            if let Ok(transition) = job.apply(*event, &limits) {
                let (from, to) = (job.state, transition.job.state);
                seen.insert(Edge {
                    from,
                    to,
                    label: edge_label(*event, from, to),
                });
                frontier.push(transition.job);
            }
        }
    }
    seen.into_iter().collect()
}

/// The state diagram in Mermaid syntax, generated from [`edges`].
#[must_use]
pub fn mermaid_diagram() -> String {
    use fmt::Write as _;

    let mut out = String::from("stateDiagram-v2\n");
    let _ = writeln!(out, "    [*] --> {}", JobState::Discovered);
    for edge in edges() {
        let _ = writeln!(out, "    {} --> {}: {}", edge.from, edge.to, edge.label);
    }
    for state in JobState::ALL.into_iter().filter(|s| s.is_terminal()) {
        let _ = writeln!(out, "    {state} --> [*]");
    }
    out
}

#[cfg(test)]
mod tests {
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
}
