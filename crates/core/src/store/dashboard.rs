//! Read queries for the dashboard.

use super::verdicts::needs_reprocessing;
use super::{Store, StoreError};
use crate::job::{JobId, JobState};
use crate::verdict::{ANALYZER_VERSION, STATIC_ANALYZER_VERSION};

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
    /// Only jobs that wait for the current analyzer or static analysis.
    pub rescore: bool,
    /// Job state name.
    pub state: Option<String>,
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
    /// Finished versions per day, `YYYY-MM-DD`, the last 30 days, newest first.
    pub daily: Vec<(String, i64)>,
}

/// A finished, scored job, as `crateward archive` chooses among them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveCandidate {
    /// The job.
    pub id: JobId,
    /// Crate name as published.
    pub name: String,
    /// Version.
    pub version: String,
    /// Score.
    pub score: i32,
    /// Risk level name.
    pub level: String,
    /// Review name.
    pub review: String,
    /// Coverage kind: `dynamic_linux`, `static_only` or
    /// `not_applicable_on_linux`.
    pub coverage: String,
    /// Whether its finding was published (`crateward disclosure publish`).
    pub published: bool,
    /// The strongest evidence's summary, or empty.
    pub top_evidence: String,
}

impl ArchiveCandidate {
    /// Why the archive must not show this job, if it must not. A crate
    /// is named only once a person reviewed what the archive would say
    /// about it, and a confirmed finding only after it was published
    /// (DISCLOSURE.md).
    #[must_use]
    pub fn refusal(&self) -> Option<&'static str> {
        match self.review.as_str() {
            "pending" => Some("waits for review"),
            "confirmed" if !self.published => Some("confirmed, not published yet"),
            _ => None,
        }
    }
}

/// A scored version of a crate, for comparing versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedVersion {
    /// The job.
    pub id: JobId,
    /// Version.
    pub version: String,
    /// Score.
    pub score: i32,
    /// Risk level name.
    pub level: String,
}

const ROW: &str = "j.id, j.crate_name, j.version, j.state, v.score, v.level, v.review,
     v.verdict->'evidence'->0->>'summary',
     extract(epoch FROM now() - j.updated_at)::bigint,
     EXISTS (SELECT 1 FROM disclosures d WHERE d.job_id = j.id)";

/// Confirmed, and nobody recorded a report yet.
const UNREPORTED: &str = "v.review = 'confirmed'
     AND NOT EXISTS (SELECT 1 FROM disclosures d WHERE d.job_id = j.id)";

/// The job list's filters but the state, as `$1` to `$7`.
fn filtered() -> String {
    format!(
        "FROM jobs j LEFT JOIN verdicts v ON v.job_id = j.id
         WHERE ($1::text IS NULL OR j.canonical_name LIKE $1)
           AND ($2::text IS NULL OR v.level = $2)
           AND ($3::text IS NULL OR v.review = $3)
           AND (NOT $4 OR ({UNREPORTED}))
           AND (NOT $5 OR ({}))",
        needs_reprocessing("$6", "$7")
    )
}

/// The current analyzer version, as the database stores it.
fn analyzer_version() -> i32 {
    i32::try_from(ANALYZER_VERSION).unwrap_or(i32::MAX)
}

/// A crate name prefix as a `LIKE` pattern on the canonical name.
fn name_pattern(filter: &JobFilter) -> Option<String> {
    filter.name.as_deref().map(|n| {
        format!(
            "{}%",
            n.to_ascii_lowercase().replace('-', "_").replace('%', "")
        )
    })
}

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
                     GROUP BY 1 ORDER BY 1 DESC",
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

    /// Finished, scored jobs for the archive, highest score first: those
    /// in `ids`, or all of them.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn archive_candidates(
        &self,
        ids: Option<&[i64]>,
    ) -> Result<Vec<ArchiveCandidate>, StoreError> {
        self.client
            .query(
                "SELECT j.id, j.crate_name, j.version, v.score, v.level, v.review,
                        COALESCE(j.job->'coverage'->>'kind', 'unknown'),
                        EXISTS (SELECT 1 FROM disclosures d
                                WHERE d.job_id = j.id AND d.published_at IS NOT NULL),
                        COALESCE(v.verdict->'evidence'->0->>'summary', '')
                 FROM jobs j JOIN verdicts v ON v.job_id = j.id
                 WHERE j.state = 'Done' AND ($1::bigint[] IS NULL OR j.id = ANY($1))
                 ORDER BY v.score DESC, j.id DESC",
                &[&ids],
            )
            .await?
            .iter()
            .map(|r| {
                Ok(ArchiveCandidate {
                    id: JobId(r.try_get(0)?),
                    name: r.try_get(1)?,
                    version: r.try_get(2)?,
                    score: r.try_get(3)?,
                    level: r.try_get(4)?,
                    review: r.try_get(5)?,
                    coverage: r.try_get(6)?,
                    published: r.try_get(7)?,
                    top_evidence: r.try_get(8)?,
                })
            })
            .collect()
    }

    /// The scored versions of `job`'s crate, newest first in semantic
    /// version order, `job` among them. A version scored by more than one
    /// job appears once, with its latest job. Versions that are not
    /// semantic versions are left out.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn analyzed_versions(&self, job: JobId) -> Result<Vec<AnalyzedVersion>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT DISTINCT ON (j.version) j.id, j.version, v.score, v.level
                 FROM jobs j JOIN verdicts v ON v.job_id = j.id
                 WHERE j.canonical_name = (SELECT canonical_name FROM jobs WHERE id = $1)
                 ORDER BY j.version, j.id DESC",
                &[&job.0],
            )
            .await?;

        let mut versions = Vec::with_capacity(rows.len());
        for r in &rows {
            let version: String = r.try_get(1)?;
            let Ok(order) = semver::Version::parse(&version) else {
                continue;
            };

            let analyzed = AnalyzedVersion {
                id: JobId(r.try_get(0)?),
                version,
                score: r.try_get(2)?,
                level: r.try_get(3)?,
            };

            versions.push((order, analyzed));
        }

        versions.sort_by(|a, b| b.0.cmp(&a.0));

        Ok(versions.into_iter().map(|(_, v)| v).collect())
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

    /// Jobs matching `filter`, newest first, `limit` of them after skipping
    /// `offset`.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn jobs(
        &self,
        filter: &JobFilter,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<JobRow>, StoreError> {
        self.client
            .query(
                // The offset skips IDs only: skipping whole rows would
                // read every skipped verdict.
                &format!(
                    "SELECT {ROW} FROM jobs j LEFT JOIN verdicts v ON v.job_id = j.id
                     WHERE j.id IN (
                         SELECT j.id {}
                           AND ($8::text IS NULL OR j.state = $8)
                         ORDER BY j.id DESC LIMIT $9 OFFSET $10)
                     ORDER BY j.id DESC",
                    filtered()
                ),
                &[
                    &name_pattern(filter),
                    &filter.level,
                    &filter.review,
                    &filter.unreported,
                    &filter.rescore,
                    &analyzer_version(),
                    &STATIC_ANALYZER_VERSION,
                    &filter.state,
                    &limit,
                    &offset,
                ],
            )
            .await?
            .iter()
            .map(job_row)
            .collect()
    }

    /// How many finished jobs wait for the current analyzer or static
    /// analysis.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn rescore_backlog(&self) -> Result<i64, StoreError> {
        let row = self
            .client
            .query_one(
                &format!(
                    "SELECT count(*) FROM jobs j JOIN verdicts v ON v.job_id = j.id WHERE {}",
                    needs_reprocessing("$1", "$2")
                ),
                &[&analyzer_version(), &STATIC_ANALYZER_VERSION],
            )
            .await?;

        Ok(row.try_get(0)?)
    }

    /// Jobs matching `filter` per state, every state in pipeline order. The
    /// state filter is ignored.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn job_states(&self, filter: &JobFilter) -> Result<Vec<(String, i64)>, StoreError> {
        let rows = self
            .client
            .query(
                &format!("SELECT j.state, count(*) {} GROUP BY 1", filtered()),
                &[
                    &name_pattern(filter),
                    &filter.level,
                    &filter.review,
                    &filter.unreported,
                    &filter.rescore,
                    &analyzer_version(),
                    &STATIC_ANALYZER_VERSION,
                ],
            )
            .await?;

        let counts = rows
            .iter()
            .map(|r| Ok((r.try_get::<_, String>(0)?, r.try_get::<_, i64>(1)?)))
            .collect::<Result<std::collections::HashMap<_, _>, StoreError>>()?;

        Ok(JobState::ALL
            .iter()
            .map(|s| {
                (
                    s.name().to_owned(),
                    counts.get(s.name()).copied().unwrap_or(0),
                )
            })
            .collect())
    }
}
