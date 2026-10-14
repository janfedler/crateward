//! The analysis and finalize stages (ADR 0009).
//!
//! Analysis loads what the earlier stages stored (the static report of the
//! crate's own file, the diff, the VM runs, the previous version's profile),
//! scores it, stores the verdict, and decides whether a `cargo check` run
//! gets one confirmation run. Finalize puts high and critical verdicts into
//! the "needs you" inbox with an alert that carries no details, and writes
//! the job's SBOM (ADR 0012).

use std::time::{Duration, Instant};

use crateward_core::escalation::HumanEscalation;
use crateward_core::failure::FailureClass;
use crateward_core::job::{JobEvent, JobId, RunKind, Stage};
use crateward_core::report::run::RunReport;
use crateward_core::report::static_report::{StaticReport, VersionDiff};
use crateward_core::store::{Policies, Review, SbomOutcome, Store, StoreError, StoredJob};
use crateward_core::verdict::Verdict;

use crate::score::{Inputs, score, should_escalate};

/// Crateward's version, named as the tool in SBOMs.
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How many jobs one call of [`Analyzer::refresh_sboms`] looks at.
const SBOM_BATCH: i64 = 20;

/// How long the SBOM sweep waits after it found nothing to do.
const SBOM_PAUSE: Duration = Duration::from_secs(600);

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
    /// When the SBOM sweep may look again after it found nothing.
    sbom_pause: Option<Instant>,
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
            sbom_pause: None,
        }
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
    /// a few per call, more in burst mode. A recomputed verdict that newly
    /// needs review enters the inbox like a fresh one. Returns how many
    /// were recomputed.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails.
    pub async fn rescore_some(&mut self) -> Result<usize, StoreError> {
        let batch = if self.store.bursting().await? {
            200
        } else {
            20
        };

        let jobs = self
            .store
            .outdated_verdicts(crate::score::ANALYZER_VERSION, batch)
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
        let dismissed = self.store.dismissed_evidence(&canonical, &version).await?;

        Ok(score(&Inputs {
            name: &job.name,
            coverage: job.job.coverage_now(),
            report: report.as_ref(),
            diff: diff.as_ref(),
            runs: &runs,
            previous_profile: previous.as_deref(),
            dismissed: &dismissed,
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

        self.write_sbom(job.id).await?;
        let worker = self.worker.clone();
        self.store
            .complete(job.id, &worker, JobEvent::Finalized, &self.policies, false)
            .await?;

        Ok(true)
    }

    /// Writes the SBOM of a job (ADR 0012) and logs what it still lacks.
    async fn write_sbom(&self, job: JobId) -> Result<(), StoreError> {
        if let SbomOutcome::Written { version, gaps } =
            self.store.refresh_sbom(job, TOOL_VERSION).await?
        {
            tracing::info!(
                job = job.0,
                version,
                gaps = gaps.len(),
                first_gap = gaps.first().map(String::as_str),
                "wrote the SBOM"
            );
        }

        Ok(())
    }

    /// Writes SBOMs for finished jobs that have none, or whose SBOM lacks
    /// data that may have arrived since, a few per call. Returns how many
    /// jobs were looked at.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails.
    pub async fn refresh_sboms(&mut self) -> Result<usize, StoreError> {
        if self.sbom_pause.is_some_and(|until| Instant::now() < until) {
            return Ok(0);
        }

        let jobs = self.store.jobs_needing_sbom(SBOM_BATCH).await?;
        self.sbom_pause = jobs.is_empty().then(|| Instant::now() + SBOM_PAUSE);

        for job in &jobs {
            self.write_sbom(*job).await?;
        }

        Ok(jobs.len())
    }
}
