//! Verdicts and what scoring reads (ADR 0009).

use serde_json::Value;

use super::{Store, StoreError};
use crate::job::JobId;
use crate::verdict::Verdict;

/// Where a verdict stands in the "needs you" inbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Review {
    /// Not for review.
    None,
    /// Waits for a human.
    Pending,
    /// A human confirmed it.
    Confirmed,
    /// A human found it harmless.
    FalsePositive,
}

impl Review {
    /// Name stored in the database.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
        }
    }

    /// The review of a stored name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::None,
            Self::Pending,
            Self::Confirmed,
            Self::FalsePositive,
        ]
        .into_iter()
        .find(|r| r.name() == name)
    }
}

fn corrupt(id: i64, reason: impl Into<String>) -> StoreError {
    StoreError::Corrupt {
        id,
        reason: reason.into(),
    }
}

impl Store {
    /// The static analysis decision of a job: triage, reasons and the diff
    /// against the previous version.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn job_static(
        &self,
        job: JobId,
    ) -> Result<Option<(Value, Value, Option<Value>)>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT triage, reasons, diff FROM job_static WHERE job_id = $1",
                &[&job.0],
            )
            .await?;
        row.map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?)))
            .transpose()
    }

    /// The VM runs of a job, `check` before `full`, with their reports.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn job_runs(&self, job: JobId) -> Result<Vec<(String, Value)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT run_kind, report FROM job_runs WHERE job_id = $1 ORDER BY run_kind",
                &[&job.0],
            )
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect()
    }

    /// Stores a job's verdict, replacing an earlier one.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_verdict(&self, job: JobId, verdict: &Verdict) -> Result<(), StoreError> {
        let value = serde_json::to_value(verdict).map_err(|e| corrupt(job.0, e.to_string()))?;
        let score = i32::try_from(verdict.score).unwrap_or(100);
        let version = i32::try_from(verdict.analyzer_version).unwrap_or(i32::MAX);
        self.client
            .execute(
                "INSERT INTO verdicts (job_id, score, level, verdict, analyzer_version)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (job_id) DO UPDATE
                 SET score = $2, level = $3, verdict = $4, analyzer_version = $5,
                     scored_at = now()",
                &[&job.0, &score, &verdict.level.name(), &value, &version],
            )
            .await?;

        Ok(())
    }

    /// A job's verdict and its review.
    ///
    /// # Errors
    ///
    /// Fails on database errors or a verdict that does not decode.
    pub async fn verdict(&self, job: JobId) -> Result<Option<(Verdict, Review)>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT verdict, review FROM verdicts WHERE job_id = $1",
                &[&job.0],
            )
            .await?;
        let Some(row) = row else { return Ok(None) };
        let verdict = serde_json::from_value(row.try_get(0)?)
            .map_err(|e| corrupt(job.0, format!("verdict: {e}")))?;
        let review: String = row.try_get(1)?;
        let review = Review::parse(&review).ok_or_else(|| corrupt(job.0, "review"))?;

        Ok(Some((verdict, review)))
    }

    /// Sets a verdict's review, with an optional note.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn set_review(
        &self,
        job: JobId,
        review: Review,
        note: Option<&str>,
    ) -> Result<bool, StoreError> {
        let updated = self
            .client
            .execute(
                "UPDATE verdicts SET review = $2, review_note = COALESCE($3, review_note),
                        reviewed_at = CASE WHEN $2 IN ('confirmed', 'false_positive')
                                           THEN now() ELSE reviewed_at END
                 WHERE job_id = $1",
                &[&job.0, &review.name(), &note],
            )
            .await?;

        Ok(updated == 1)
    }

    /// Finished jobs whose verdict an older analyzer produced, oldest first.
    /// Jobs with trimmed runs keep their verdict (see `retention`).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn outdated_verdicts(
        &self,
        analyzer_version: u32,
        limit: i64,
    ) -> Result<Vec<super::StoredJob>, StoreError> {
        let version = i32::try_from(analyzer_version).unwrap_or(i32::MAX);
        let rows = self
            .client
            .query(
                &format!(
                    "SELECT {} FROM jobs j JOIN verdicts v ON v.job_id = j.id
                     WHERE j.state = 'Done' AND v.analyzer_version < $1
                       AND NOT EXISTS (SELECT 1 FROM job_runs r
                                       WHERE r.job_id = j.id AND r.trimmed_at IS NOT NULL)
                     ORDER BY v.scored_at LIMIT $2",
                    super::COLUMNS_J
                ),
                &[&version, &limit],
            )
            .await?;

        rows.iter().map(super::stored).collect()
    }

    /// The behavior profile of the newest scored version of the crate
    /// before `version`, by semantic version order.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn previous_profile(
        &self,
        canonical_name: &str,
        version: &semver::Version,
    ) -> Result<Option<Vec<String>>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT j.version, v.verdict->'profile' FROM verdicts v
                 JOIN jobs j ON j.id = v.job_id WHERE j.canonical_name = $1",
                &[&canonical_name],
            )
            .await?;
        let mut best: Option<(semver::Version, Value)> = None;

        for row in rows {
            let text: String = row.try_get(0)?;
            let Ok(other) = semver::Version::parse(&text) else {
                continue;
            };

            if other < *version && best.as_ref().is_none_or(|(b, _)| other > *b) {
                best = Some((other, row.try_get(1)?));
            }
        }

        Ok(best.and_then(|(_, profile)| serde_json::from_value(profile).ok()))
    }
}
