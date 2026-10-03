//! Read queries for the dashboard.

use super::{Store, StoreError};
use crate::job::JobId;

/// A row in the inbox or a job list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRow {
    /// The job.
    pub id: JobId,
    /// Crate name as published.
    pub name: String,
    /// Version.
    pub version: String,
    /// State name.
    pub state: String,
    /// Score, if scored.
    pub score: Option<i32>,
    /// Risk level name, if scored.
    pub level: Option<String>,
    /// Review name, if scored.
    pub review: Option<String>,
    /// The strongest evidence's summary, if any.
    pub top_evidence: Option<String>,
    /// Seconds since the job last changed.
    pub age_secs: i64,
    /// Whether a report of it was recorded (`crateward disclosure report`).
    pub reported: bool,
}

/// Filters for the job list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobFilter {
    /// Crate name prefix, compared in canonical form.
    pub name: Option<String>,
    /// Risk level.
    pub level: Option<String>,
    /// Review state.
    pub review: Option<String>,
    /// Only confirmed jobs without a recorded report.
    pub unreported: bool,
}

/// Numbers for the overview.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overview {
    /// Jobs per state.
    pub states: Vec<(String, i64)>,
    /// Verdicts per level.
    pub levels: Vec<(String, i64)>,
    /// Jobs finished in the last 24 hours.
    pub done_24h: i64,
    /// Of those, how many had a dynamic run.
    pub dynamic_24h: i64,
    /// Verdicts waiting for review, and confirmed ones not reported yet.
    pub pending_reviews: i64,
}

/// Aggregates for the public site: no crate names, no evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicStats {
    /// Versions Crateward has seen.
    pub versions: i64,
    /// Versions with a finished verdict.
    pub finished: i64,
    /// Finished versions per coverage kind (`dynamic_linux`, `static_only`,
    /// `not_applicable_on_linux`).
    pub coverage: Vec<(String, i64)>,
    /// Verdicts per level.
    pub levels: Vec<(String, i64)>,
    /// Finished versions per day, `YYYY-MM-DD`, the last 30 days.
    pub daily: Vec<(String, i64)>,
}

const ROW: &str = "j.id, j.crate_name, j.version, j.state, v.score, v.level, v.review,
     v.verdict->'evidence'->0->>'summary',
     extract(epoch FROM now() - j.updated_at)::bigint,
     EXISTS (SELECT 1 FROM disclosures d WHERE d.job_id = j.id)";

/// Confirmed, and nobody recorded a report yet.
const UNREPORTED: &str = "v.review = 'confirmed'
     AND NOT EXISTS (SELECT 1 FROM disclosures d WHERE d.job_id = j.id)";

fn job_row(row: &tokio_postgres::Row) -> Result<JobRow, StoreError> {
    Ok(JobRow {
        id: JobId(row.try_get(0)?),
        name: row.try_get(1)?,
        version: row.try_get(2)?,
        state: row.try_get(3)?,
        score: row.try_get(4)?,
        level: row.try_get(5)?,
        review: row.try_get(6)?,
        top_evidence: row.try_get(7)?,
        age_secs: row.try_get(8)?,
        reported: row.try_get(9)?,
    })
}

impl Store {
    /// Makes every later transaction of this connection read only: the
    /// dashboard's page queries run on such a connection, so a bug in a page
    /// cannot write. A second connection makes the few deliberate writes.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn make_read_only(&self) -> Result<(), StoreError> {
        self.client
            .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            .await?;
        Ok(())
    }

    /// The overview's numbers.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn overview(&self) -> Result<Overview, StoreError> {
        let states = self
            .client
            .query(
                "SELECT state, count(*) FROM jobs GROUP BY 1 ORDER BY 1",
                &[],
            )
            .await?
            .iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect::<Result<_, StoreError>>()?;
        let levels = self
            .client
            .query(
                "SELECT level, count(*) FROM verdicts GROUP BY 1 ORDER BY min(score)",
                &[],
            )
            .await?
            .iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect::<Result<_, StoreError>>()?;
        let row = self
            .client
            .query_one(
                &format!(
                    "SELECT count(*) FILTER (WHERE j.state = 'Done'),
                        count(*) FILTER (WHERE j.state = 'Done'
                                         AND (j.job->>'dynamic_runs')::int > 0),
                        (SELECT count(*) FROM verdicts v JOIN jobs j ON j.id = v.job_id
                         WHERE v.review = 'pending' OR ({UNREPORTED}))
                 FROM jobs j WHERE j.updated_at > now() - interval '24 hours'"
                ),
                &[],
            )
            .await?;
        Ok(Overview {
            states,
            levels,
            done_24h: row.try_get(0)?,
            dynamic_24h: row.try_get(1)?,
            pending_reviews: row.try_get(2)?,
        })
    }

    /// Aggregates for the public site.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn public_stats(&self) -> Result<PublicStats, StoreError> {
        let row = self
            .client
            .query_one(
                "SELECT count(*), count(*) FILTER (WHERE state = 'Done') FROM jobs",
                &[],
            )
            .await?;
        let pairs = |rows: Vec<tokio_postgres::Row>| {
            rows.iter()
                .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
                .collect::<Result<Vec<(String, i64)>, StoreError>>()
        };

        let coverage = pairs(
            self.client
                .query(
                    "SELECT COALESCE(job->'coverage'->>'kind', 'unknown'), count(*) FROM jobs
                     WHERE state = 'Done' GROUP BY 1 ORDER BY 2 DESC",
                    &[],
                )
                .await?,
        )?;

        let levels = pairs(
            self.client
                .query(
                    "SELECT level, count(*) FROM verdicts GROUP BY 1 ORDER BY min(score)",
                    &[],
                )
                .await?,
        )?;

        let daily = pairs(
            self.client
                .query(
                    "SELECT to_char(date_trunc('day', updated_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD'),
                            count(*)
                     FROM jobs WHERE state = 'Done' AND updated_at > now() - interval '30 days'
                     GROUP BY 1 ORDER BY 1",
                    &[],
                )
                .await?,
        )?;

        Ok(PublicStats {
            versions: row.try_get(0)?,
            finished: row.try_get(1)?,
            coverage,
            levels,
            daily,
        })
    }

    /// Verdicts waiting for review, oldest first.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn inbox(&self) -> Result<Vec<JobRow>, StoreError> {
        self.client
            .query(
                &format!(
                    "SELECT {ROW} FROM verdicts v JOIN jobs j ON j.id = v.job_id
                     WHERE v.review = 'pending' ORDER BY v.scored_at LIMIT 200"
                ),
                &[],
            )
            .await?
            .iter()
            .map(job_row)
            .collect()
    }

    /// Confirmed jobs without a recorded report, oldest first: each still
    /// needs its evidence pack and report (DISCLOSURE.md).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn unreported(&self) -> Result<Vec<JobRow>, StoreError> {
        self.client
            .query(
                &format!(
                    "SELECT {ROW} FROM verdicts v JOIN jobs j ON j.id = v.job_id
                     WHERE {UNREPORTED} ORDER BY j.id LIMIT 200"
                ),
                &[],
            )
            .await?
            .iter()
            .map(job_row)
            .collect()
    }

    /// Jobs matching `filter`, newest first, at most `limit`.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn jobs(&self, filter: &JobFilter, limit: i64) -> Result<Vec<JobRow>, StoreError> {
        let prefix = filter.name.as_deref().map(|n| {
            format!(
                "{}%",
                n.to_ascii_lowercase().replace('-', "_").replace('%', "")
            )
        });

        self.client
            .query(
                &format!(
                    "SELECT {ROW} FROM jobs j LEFT JOIN verdicts v ON v.job_id = j.id
                     WHERE ($1::text IS NULL OR j.canonical_name LIKE $1)
                       AND ($2::text IS NULL OR v.level = $2)
                       AND ($3::text IS NULL OR v.review = $3)
                       AND (NOT $4 OR ({UNREPORTED}))
                     ORDER BY j.id DESC LIMIT $5"
                ),
                &[
                    &prefix,
                    &filter.level,
                    &filter.review,
                    &filter.unreported,
                    &limit,
                ],
            )
            .await?
            .iter()
            .map(job_row)
            .collect()
    }
}
