//! Retention of raw run data.
//!
//! A run report keeps two kinds of data: evidence (what the job read,
//! wrote, reached or left behind, honeytokens, the network summary) and raw
//! material (every process with its arguments, the tails of cargo's
//! output). The raw part is most of the size. Once a run is older than
//! `storage.raw_log_retention_days` and its job finished with a verdict of
//! none or low that no human touched, the raw part goes. The evidence, the
//! verdict and its behavior profile stay.
//!
//! A trimmed job keeps its verdict when the analyzer version changes, since
//! scoring it again would miss the attribution the process list gave.

use super::{Store, StoreError};

/// The trim of one run report, in SQL: the process list and output tails
/// are emptied, the omitted count grows by the processes removed, and the
/// report says it was trimmed.
const TRIM: &str = "report
    || jsonb_build_object('stdout_tail', '', 'stderr_tail', '', 'trimmed', true)
    || CASE WHEN jsonb_typeof(report->'trace') = 'object' THEN jsonb_build_object('trace',
         (report->'trace') || jsonb_build_object(
           'processes', '[]'::jsonb,
           'processes_omitted',
             COALESCE((report->'trace'->>'processes_omitted')::bigint, 0)
             + COALESCE(jsonb_array_length(report->'trace'->'processes'), 0)))
       ELSE '{}'::jsonb END";

impl Store {
    /// Trims up to `limit` run reports older than `days` days whose job is
    /// done with a verdict of none or low and no review. Returns how many.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn trim_raw_runs(&self, days: u32, limit: i64) -> Result<u64, StoreError> {
        let days = i32::try_from(days).unwrap_or(i32::MAX);
        let trimmed = self
            .client
            .execute(
                &format!(
                    "UPDATE job_runs r SET report = {TRIM}, trimmed_at = now()
                     FROM (SELECT r2.job_id, r2.run_kind FROM job_runs r2
                           JOIN jobs j ON j.id = r2.job_id
                           JOIN verdicts v ON v.job_id = r2.job_id
                           WHERE r2.trimmed_at IS NULL
                             AND r2.recorded_at < now() - make_interval(days => $1)
                             AND j.state = 'Done'
                             AND v.level IN ('none', 'low') AND v.review = 'none'
                           ORDER BY r2.recorded_at LIMIT $2
                           FOR UPDATE OF r2 SKIP LOCKED) old
                     WHERE r.job_id = old.job_id AND r.run_kind = old.run_kind"
                ),
                &[&days, &limit],
            )
            .await?;

        Ok(trimmed)
    }
}
