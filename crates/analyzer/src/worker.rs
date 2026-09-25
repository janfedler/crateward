//! The analysis and finalize stages (ADR 0021).
//!
//! Analysis loads what the earlier stages stored (the static report of the
//! crate's own file, the diff, the VM runs, the previous version's profile),
//! scores it, stores the verdict, and decides whether a `cargo check` run
//! gets one confirmation run. Finalize puts high and critical verdicts into
//! the "needs you" inbox with an alert that carries no details.

use std::time::Duration;

use crateward_core::escalation::HumanEscalation;
use crateward_core::failure::FailureClass;
use crateward_core::job::{JobEvent, RunKind, Stage};
use crateward_core::store::{Policies, Review, Store, StoreError, StoredJob};
use crateward_core::verdict::Verdict;
use crateward_orchestrator::worker::RunReport;
use crateward_static_analysis::analyze::StaticReport;
use crateward_static_analysis::diff::VersionDiff;

use crate::score::{Inputs, score, should_escalate};

/// Why a job could not be scored. The analyzer reads only stored data, so
/// anything but a database error means that data is unusable.
#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Stored data does not decode.
    #[error("{0}")]
    Data(String),
}

/// One analyzer process: a store connection and its identity.
#[derive(Debug)]
pub struct Analyzer {
    store: Store,
    policies: Policies,
    worker: String,
    lease: Duration,
}

impl Analyzer {
    /// An analyzer.
    #[must_use]
    pub const fn new(store: Store, policies: Policies, worker: String, lease: Duration) -> Self {
        Self {
            store,
            policies,
            worker,
            lease,
        }
    }

    /// The store, for reaping.
    pub fn store(&mut self) -> &mut Store {
        &mut self.store
    }

    /// The retry policies.
    #[must_use]
    pub fn policies(&self) -> &Policies {
        &self.policies
    }

    /// Scores one job. Returns `false` when there was none.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails while claiming or completing.
    pub async fn analyze_once(&mut self) -> Result<bool, StoreError> {
        let Some(job) = self
            .store
            .claim(Stage::Analysis, &self.worker, self.lease)
            .await?
        else {
            return Ok(false);
        };
        let event = match self.analyze(&job).await {
            Ok(escalate) => JobEvent::Scored { escalate },
            Err(AnalyzeError::Store(error)) => {
                tracing::warn!(job = job.id.0, %error, "analysis failed");
                JobEvent::StageFailed {
                    class: FailureClass::Infrastructure,
                }
            }
            Err(AnalyzeError::Data(error)) => {
                tracing::error!(job = job.id.0, %error, "stored data is unusable");
                JobEvent::StageFailed {
                    class: FailureClass::Permanent,
                }
            }
        };
        let worker = self.worker.clone();
        self.store
            .complete(job.id, &worker, event, &self.policies, false)
            .await?;
        Ok(true)
    }

    /// Recomputes verdicts an older analyzer produced for finished jobs,
    /// a few per call. A recomputed verdict that newly needs review enters
    /// the inbox like a fresh one. Returns how many were recomputed.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails.
    pub async fn rescore_some(&mut self) -> Result<usize, StoreError> {
        let jobs = self
            .store
            .outdated_verdicts(crate::score::ANALYZER_VERSION, 20)
            .await?;
        for job in &jobs {
            let before = self.store.verdict(job.id).await?;
            match self.score_job(job).await {
                Ok(verdict) => {
                    self.store.record_verdict(job.id, &verdict).await?;
                    let was_quiet = before.as_ref().is_some_and(|(v, review)| {
                        !v.level.needs_review() && *review == Review::None
                    });
                    let waiting = before
                        .as_ref()
                        .is_some_and(|(_, review)| *review == Review::Pending);
                    // No longer high: it leaves the inbox unless a human
                    // already decided.
                    if !verdict.level.needs_review() && waiting {
                        self.store.set_review(job.id, Review::None, None).await?;
                    }
                    if verdict.level.needs_review() && was_quiet {
                        self.store.set_review(job.id, Review::Pending, None).await?;
                        self.store
                            .raise_alert(&HumanEscalation::HighRiskVerdict { job: job.id })
                            .await?;
                    }
                }
                Err(error) => tracing::warn!(job = job.id.0, %error, "rescoring failed"),
            }
        }
        Ok(jobs.len())
    }

    async fn analyze(&self, job: &StoredJob) -> Result<bool, AnalyzeError> {
        let verdict = self.score_job(job).await?;
        let escalate =
            job.job.run_kind == RunKind::Check && !job.job.escalated && should_escalate(&verdict);
        tracing::info!(
            job = job.id.0, name = %job.name, version = %job.version,
            score = verdict.score, level = verdict.level.name(), escalate,
            "scored"
        );
        self.store.record_verdict(job.id, &verdict).await?;
        Ok(escalate)
    }

    async fn score_job(&self, job: &StoredJob) -> Result<Verdict, AnalyzeError> {
        let data = |what: &str, e: serde_json::Error| AnalyzeError::Data(format!("{what}: {e}"));
        let report: Option<StaticReport> = match self.store.static_report(&job.cksum).await? {
            Some((_, value)) => Some(serde_json::from_value(value).map_err(|e| data("report", e))?),
            None => None,
        };
        let diff: Option<VersionDiff> = match self.store.job_static(job.id).await? {
            Some((_, _, Some(value))) => {
                Some(serde_json::from_value(value).map_err(|e| data("diff", e))?)
            }
            _ => None,
        };
        let mut runs = Vec::new();
        for (kind, value) in self.store.job_runs(job.id).await? {
            let run: RunReport =
                serde_json::from_value(value).map_err(|e| data(&format!("{kind} run"), e))?;
            runs.push(run);
        }
        let version = semver::Version::parse(&job.version)
            .map_err(|e| AnalyzeError::Data(format!("version: {e}")))?;
        let canonical = job.name.to_ascii_lowercase().replace('-', "_");
        let previous = self.store.previous_profile(&canonical, &version).await?;
        Ok(score(&Inputs {
            name: &job.name,
            coverage: job.job.coverage_now(),
            report: report.as_ref(),
            diff: diff.as_ref(),
            runs: &runs,
            previous_profile: previous.as_deref(),
        }))
    }

    /// Finalizes one job. Returns `false` when there was none.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails.
    pub async fn finalize_once(&mut self) -> Result<bool, StoreError> {
        let Some(job) = self
            .store
            .claim(Stage::Finalize, &self.worker, self.lease)
            .await?
        else {
            return Ok(false);
        };
        let needs_review = self
            .store
            .verdict(job.id)
            .await?
            .is_some_and(|(verdict, review)| {
                verdict.level.needs_review() && review == Review::None
            });
        if needs_review {
            self.store.set_review(job.id, Review::Pending, None).await?;
            self.store
                .raise_alert(&HumanEscalation::HighRiskVerdict { job: job.id })
                .await?;
            tracing::warn!(job = job.id.0, name = %job.name, version = %job.version, "verdict needs review");
        }
        let worker = self.worker.clone();
        self.store
            .complete(job.id, &worker, JobEvent::Finalized, &self.policies, false)
            .await?;
        Ok(true)
    }
}
