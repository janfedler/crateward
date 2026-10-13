//! The Postgres job store: the queue and the state of every job (ADR 0001).
//!
//! Workers claim rows with `SELECT ... FOR UPDATE SKIP LOCKED`, hold a lease
//! that they renew with heartbeats, and finish by reporting a
//! [`JobEvent`]. The store applies the event with the pure state machine of
//! [`crate::job`] inside one transaction, writes the new state, sets the
//! backoff for a retry, releases the lease and records the transition in
//! `job_events`. A worker whose lease expired can no longer complete: its
//! update matches no row, so a stale worker cannot overwrite the work of
//! the one that took over.
//!
//! Enabled with the `store` feature. The guest agent never links it.

mod autonomy;
mod dashboard;
mod disclosures;
mod retention;
mod verdicts;
pub use autonomy::{AlertOutcome, Pause, PauseReason, PendingAlert};
use autonomy::{insert_alert, insert_pause};
pub use dashboard::{AnalyzedVersion, ArchiveCandidate, JobFilter, JobRow, Overview, PublicStats};
pub use disclosures::{
    Disclosure, DisclosureKind, DisclosureRefusal, PublishedFinding, REMOVED_FIRST,
};
pub use verdicts::Review;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde_json::Value;
use tokio_postgres::{Client, NoTls, Row};

use crate::digest::Sha256Digest;
use crate::escalation::HumanEscalation;
use crate::job::{
    Effect, Job, JobEvent, JobId, JobState, Limits, Stage, Transition, TransitionError,
};
use crate::name::CrateName;
use crate::retry::RetryPolicy;

/// Migrations, applied in order. Never edit one that has shipped.
const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../migrations/0001_jobs.sql")),
    (2, include_str!("../migrations/0002_fetch.sql")),
    (3, include_str!("../migrations/0003_crate_stats.sql")),
    (4, include_str!("../migrations/0004_static.sql")),
    (5, include_str!("../migrations/0005_dynamic.sql")),
    (6, include_str!("../migrations/0006_autonomy.sql")),
    (7, include_str!("../migrations/0007_verdicts.sql")),
    (8, include_str!("../migrations/0008_retention.sql")),
    (9, include_str!("../migrations/0009_disclosures.sql")),
    (
        10,
        include_str!("../migrations/0010_removed_before_report.sql"),
    ),
    (
        11,
        include_str!("../migrations/0011_shared_finding_pages.sql"),
    ),
    (12, include_str!("../migrations/0012_burst.sql")),
];

/// The server's message for database errors, which the error's own
/// `Display` leaves out.
fn describe(error: &tokio_postgres::Error) -> String {
    match error.as_db_error() {
        Some(db) => format!("{}: {} ({})", error, db.message(), db.code().code()),
        None => error.to_string(),
    }
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database failed.
    #[error("postgres: {}", describe(.0))]
    Postgres(#[from] tokio_postgres::Error),
    /// A stored value does not decode.
    #[error("corrupt row {id}: {reason}")]
    Corrupt {
        /// The job.
        id: i64,
        /// What is wrong.
        reason: String,
    },
    /// The state machine rejected the event.
    #[error("transition: {0}")]
    Transition(#[from] TransitionError),
    /// The worker no longer holds the lease on the job.
    #[error("job {0} is not leased by this worker")]
    LeaseLost(i64),
}

/// A version the feed wants analyzed.
#[derive(Debug, Clone)]
pub struct NewJob {
    /// Crate name as published.
    pub name: CrateName,
    /// Version as published.
    pub version: semver::Version,
    /// SHA-256 of the `.crate` file, from the index.
    pub cksum: Sha256Digest,
    /// Publish time, from the index when available.
    pub published_at: Option<SystemTime>,
    /// Higher runs first.
    pub priority: i16,
    /// The version's index line.
    pub index_entry: Value,
}

/// A job as stored.
#[derive(Debug, Clone)]
pub struct StoredJob {
    /// Row identifier.
    pub id: JobId,
    /// Crate name as published.
    pub name: String,
    /// Version as published.
    pub version: String,
    /// SHA-256 of the `.crate` file.
    pub cksum: Sha256Digest,
    /// Priority.
    pub priority: i16,
    /// State machine value.
    pub job: Job,
    /// The version's index line.
    pub index_entry: Value,
}

/// One recorded transition.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    /// When it happened.
    pub at: SystemTime,
    /// State before.
    pub from: String,
    /// State after.
    pub to: String,
    /// The event, as JSON.
    pub event: Value,
    /// The effect, as JSON.
    pub effect: Value,
    /// The worker that reported it.
    pub worker: String,
}

/// A validated crate file, as recorded by the fetcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateFile {
    /// SHA-256 of the `.crate` file.
    pub sha256: Sha256Digest,
    /// Crate name as published.
    pub name: String,
    /// Version.
    pub version: String,
    /// BLAKE3 of the unpacked tar, if the archive was stored.
    pub blake3: Option<String>,
    /// Size of the `.crate` file.
    pub compressed_bytes: i64,
    /// Unpacked size.
    pub unpacked_bytes: i64,
    /// Size of the stored blob.
    pub stored_bytes: Option<i64>,
    /// The validation report.
    pub report: Value,
}

/// Backoff policies per stage, used to schedule retries.
#[derive(Debug, Clone)]
pub struct Policies {
    /// Retry budgets for the state machine.
    pub limits: Limits,
    /// Backoff per stage.
    pub backoff: BTreeMap<&'static str, RetryPolicy>,
}

impl Policies {
    /// The policies configured for every stage.
    ///
    /// # Errors
    ///
    /// Fails if a stage has an invalid backoff. Configuration validation
    /// already rejects those.
    pub fn from_config(
        stages: &crate::config::StagesConfig,
    ) -> Result<Self, crate::retry::RetryPolicyError> {
        let mut backoff = BTreeMap::new();
        for stage in Stage::ALL {
            backoff.insert(stage.name(), stages.get(stage).retry_policy()?);
        }

        Ok(Self {
            limits: stages.limits(),
            backoff,
        })
    }

    fn delay(&self, effect: &Effect) -> Option<Duration> {
        let (stage, attempt) = match *effect {
            Effect::RetryAfterBackoff { stage, attempt } => (stage, attempt),
            Effect::ReportInfrastructureFailure { stage, retry } => (stage, retry),
            Effect::None | Effect::EnterQuarantine { .. } => return None,
        };

        let policy = self.backoff.get(stage.name())?;

        Some(policy.delay(attempt, &mut rand::rng()))
    }
}

/// A connection to the job store.
pub struct Store {
    client: Client,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

fn state_name(state: JobState) -> &'static str {
    state.name()
}

fn decode_job(id: i64, value: Value) -> Result<Job, StoreError> {
    serde_json::from_value(value).map_err(|e| StoreError::Corrupt {
        id,
        reason: e.to_string(),
    })
}

fn to_json<T: serde::Serialize>(value: &T) -> Value {
    // Serializing our own plain data types cannot fail.
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn stored(row: &Row) -> Result<StoredJob, StoreError> {
    let id: i64 = row.try_get("id")?;
    let cksum: Vec<u8> = row.try_get("cksum")?;
    let cksum: [u8; 32] = cksum.try_into().map_err(|_| StoreError::Corrupt {
        id,
        reason: "checksum is not 32 bytes".into(),
    })?;

    Ok(StoredJob {
        id: JobId(id),
        name: row.try_get("crate_name")?,
        version: row.try_get("version")?,
        cksum: Sha256Digest::from_bytes(cksum),
        priority: row.try_get("priority")?,
        job: decode_job(id, row.try_get("job")?)?,
        index_entry: row.try_get("index_entry")?,
    })
}

const COLUMNS: &str = "id, crate_name, version, cksum, priority, job, index_entry";
/// [`COLUMNS`] for queries that alias `jobs` as `j`.
const COLUMNS_J: &str = "j.id, j.crate_name, j.version, j.cksum, j.priority, j.job, j.index_entry";

fn lease_interval(lease: Duration) -> f64 {
    lease.as_secs_f64()
}

impl Store {
    /// Connects with a libpq style connection string or URL, for example
    /// `host=/var/run/postgresql dbname=crateward`. The connection task runs
    /// on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails if the database is unreachable.
    pub async fn connect(config: &str) -> Result<Self, StoreError> {
        let (client, connection) = tokio_postgres::connect(config, NoTls).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!(%error, "postgres connection ended");
            }
        });

        Ok(Self { client })
    }

    /// Wraps an existing client, for example one whose `search_path` a test
    /// set to a private schema.
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    /// Applies migrations that have not run yet, each in its own transaction.
    ///
    /// # Errors
    ///
    /// Fails if a migration fails. Nothing of that migration is applied.
    pub async fn migrate(&mut self) -> Result<Vec<i32>, StoreError> {
        self.client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                    version integer PRIMARY KEY,
                    applied_at timestamptz NOT NULL DEFAULT now())",
            )
            .await?;
        let mut applied = Vec::new();

        for (version, sql) in MIGRATIONS {
            let tx = self.client.transaction().await?;

            // Serialize concurrent migrators.
            tx.batch_execute("LOCK TABLE schema_migrations IN EXCLUSIVE MODE")
                .await?;
            let done = tx
                .query_opt(
                    "SELECT 1 FROM schema_migrations WHERE version = $1",
                    &[version],
                )
                .await?
                .is_some();
            if !done {
                tx.batch_execute(sql).await?;
                tx.execute(
                    "INSERT INTO schema_migrations (version) VALUES ($1)",
                    &[version],
                )
                .await?;
                applied.push(*version);
            }

            tx.commit().await?;
        }

        Ok(applied)
    }

    /// Creates the job for a version unless one exists. Returns the new ID,
    /// or `None` if the version is already known.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn enqueue(&self, new: &NewJob) -> Result<Option<JobId>, StoreError> {
        let job = Job::new();
        let row = self
            .client
            .query_opt(
                "INSERT INTO jobs (crate_name, canonical_name, version, cksum, published_at,
                                   priority, state, job, index_entry)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (canonical_name, version) DO NOTHING
                 RETURNING id",
                &[
                    &new.name.as_str(),
                    &new.name.canonical(),
                    &new.version.to_string(),
                    &new.cksum.as_bytes().as_slice(),
                    &new.published_at,
                    &new.priority,
                    &state_name(job.state),
                    &to_json(&job),
                    &new.index_entry,
                ],
            )
            .await?;

        Ok(row.map(|r| r.get::<_, i64>(0)).map(JobId))
    }

    /// Whether a version is already known.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn contains(&self, name: &CrateName, version: &str) -> Result<bool, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT 1 FROM jobs WHERE canonical_name = $1 AND version = $2",
                &[&name.canonical(), &version],
            )
            .await?
            .is_some())
    }

    /// Claims the highest priority unleased job that `stage` works on and
    /// whose backoff has passed.
    ///
    /// # Errors
    ///
    /// Fails on database errors or a corrupt row.
    pub async fn claim(
        &self,
        stage: Stage,
        worker: &str,
        lease: Duration,
    ) -> Result<Option<StoredJob>, StoreError> {
        let states: Vec<&str> = stage.claimable_states().iter().map(|s| s.name()).collect();
        let row = self
            .client
            .query_opt(
                &format!(
                    "UPDATE jobs SET lease_owner = $2,
                                     lease_expires_at = now() + make_interval(secs => $3),
                                     updated_at = now()
                     WHERE id = (
                         SELECT id FROM jobs
                         WHERE state = ANY($1) AND lease_owner IS NULL AND not_before <= now()
                           AND NOT EXISTS (SELECT 1 FROM pipeline_pauses p
                                           WHERE $4 = ANY(p.stages))
                           AND NOT EXISTS (SELECT 1 FROM stage_breakers b
                                           WHERE b.stage = $4 AND b.state = 'open')
                         ORDER BY priority DESC, id
                         LIMIT 1
                         FOR UPDATE SKIP LOCKED)
                     RETURNING {COLUMNS}"
                ),
                &[&states, &worker, &lease_interval(lease), &stage.name()],
            )
            .await?;

        row.as_ref().map(stored).transpose()
    }

    /// Renews a lease. Returns `false` if the worker no longer holds it.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn heartbeat(
        &self,
        id: JobId,
        worker: &str,
        lease: Duration,
    ) -> Result<bool, StoreError> {
        let updated = self
            .client
            .execute(
                "UPDATE jobs SET lease_expires_at = now() + make_interval(secs => $3)
                 WHERE id = $1 AND lease_owner = $2",
                &[&id.0, &worker, &lease_interval(lease)],
            )
            .await?;

        Ok(updated == 1)
    }

    /// Applies an event to a job the worker holds, releases the lease unless
    /// `keep_lease` is set (used by `SandboxStarted`, since the VM run
    /// continues under the same lease), schedules a retry if the effect
    /// asks for one, and records the transition.
    ///
    /// # Errors
    ///
    /// [`StoreError::LeaseLost`] if the worker does not hold the lease.
    /// [`StoreError::Transition`] if the state machine rejects the event.
    pub async fn complete(
        &mut self,
        id: JobId,
        worker: &str,
        event: JobEvent,
        policies: &Policies,
        keep_lease: bool,
    ) -> Result<Transition, StoreError> {
        let tx = self.client.transaction().await?;
        let row = tx
            .query_opt(
                "SELECT job FROM jobs WHERE id = $1 AND lease_owner = $2 FOR UPDATE",
                &[&id.0, &worker],
            )
            .await?
            .ok_or(StoreError::LeaseLost(id.0))?;

        let before = decode_job(id.0, row.try_get("job")?)?;
        let transition = before.apply(event, &policies.limits)?;
        let delay = policies.delay(&transition.effect).unwrap_or_default();
        let after = transition.job;
        let release = !keep_lease || after.state.is_terminal();
        tx.execute(
            "UPDATE jobs SET state = $2, job = $3,
                             lease_owner = CASE WHEN $4 THEN NULL ELSE lease_owner END,
                             lease_expires_at = CASE WHEN $4 THEN NULL ELSE lease_expires_at END,
                             not_before = now() + make_interval(secs => $5),
                             updated_at = now()
             WHERE id = $1",
            &[
                &id.0,
                &state_name(after.state),
                &to_json(&after),
                &release,
                &delay.as_secs_f64(),
            ],
        )
        .await?;
        tx.execute(
            "INSERT INTO job_events (job_id, from_state, to_state, event, effect, worker)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &id.0,
                &state_name(before.state),
                &state_name(after.state),
                &to_json(&event),
                &to_json(&transition.effect),
                &worker,
            ],
        )
        .await?;

        // A suspected compromise pauses everything and alerts, in the same
        // transaction as the event, so it cannot be recorded without them.
        if let Effect::EnterQuarantine { stage } = transition.effect {
            let detail = format!("stage {} reported a suspected compromise", stage.name());
            insert_pause(&tx, PauseReason::Quarantine, Some(id), &detail).await?;
            let alert = HumanEscalation::SandboxEscapeIndicator { job: Some(id) };
            insert_alert(&tx, &alert).await?;
        }

        tx.commit().await?;

        Ok(transition)
    }

    /// Applies `LeaseExpired` to every job whose lease ran out, which
    /// consumes one attempt (a hostile input can crash a worker on purpose).
    /// Returns the number of jobs reaped.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn reap_expired(&mut self, policies: &Policies) -> Result<u64, StoreError> {
        let expired = self
            .client
            .query(
                "SELECT id, lease_owner FROM jobs
                 WHERE lease_owner IS NOT NULL AND lease_expires_at < now()",
                &[],
            )
            .await?;

        let mut reaped = 0;

        for row in expired {
            let id = JobId(row.try_get("id")?);
            let owner: String = row.try_get("lease_owner")?;
            match self
                .complete(id, &owner, JobEvent::LeaseExpired, policies, false)
                .await
            {
                Ok(_) => reaped += 1,
                // Renewed or completed in the meantime.
                Err(StoreError::LeaseLost(_)) => {}
                Err(other) => return Err(other),
            }
        }

        Ok(reaped)
    }

    /// One job by ID.
    ///
    /// # Errors
    ///
    /// Fails on database errors or a corrupt row.
    pub async fn get(&self, id: JobId) -> Result<Option<StoredJob>, StoreError> {
        let row = self
            .client
            .query_opt(
                &format!("SELECT {COLUMNS} FROM jobs WHERE id = $1"),
                &[&id.0],
            )
            .await?;

        row.as_ref().map(stored).transpose()
    }

    /// The transitions of one job, oldest first.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn events(&self, id: JobId) -> Result<Vec<StoredEvent>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT at, from_state, to_state, event, effect, worker
                 FROM job_events WHERE job_id = $1 ORDER BY id",
                &[&id.0],
            )
            .await?;

        rows.iter()
            .map(|r| {
                Ok(StoredEvent {
                    at: r.try_get("at")?,
                    from: r.try_get("from_state")?,
                    to: r.try_get("to_state")?,
                    event: r.try_get("event")?,
                    effect: r.try_get("effect")?,
                    worker: r.try_get("worker")?,
                })
            })
            .collect()
    }

    /// Records a validated crate file. Recording the same file twice is
    /// a no op.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_crate_file(&self, file: &CrateFile) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO crate_files (sha256, crate_name, version, blake3, compressed_bytes,
                                          unpacked_bytes, stored_bytes, report)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (sha256) DO NOTHING",
                &[
                    &file.sha256.as_bytes().as_slice(),
                    &file.name,
                    &file.version,
                    &file.blake3,
                    &file.compressed_bytes,
                    &file.unpacked_bytes,
                    &file.stored_bytes,
                    &file.report,
                ],
            )
            .await?;

        Ok(())
    }

    /// A recorded crate file by its SHA-256.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn crate_file(&self, sha256: &Sha256Digest) -> Result<Option<CrateFile>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT crate_name, version, blake3, compressed_bytes, unpacked_bytes,
                        stored_bytes, report
                 FROM crate_files WHERE sha256 = $1",
                &[&sha256.as_bytes().as_slice()],
            )
            .await?;

        row.map(|r| {
            Ok(CrateFile {
                sha256: *sha256,
                name: r.try_get(0)?,
                version: r.try_get(1)?,
                blake3: r.try_get(2)?,
                compressed_bytes: r.try_get(3)?,
                unpacked_bytes: r.try_get(4)?,
                stored_bytes: r.try_get(5)?,
                report: r.try_get(6)?,
            })
        })
        .transpose()
    }

    /// Records the fetch stage's result for a job, replacing an earlier one
    /// (a retried fetch overwrites it).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_fetch(
        &self,
        job: JobId,
        lockfile: Option<&str>,
        resolution_error: Option<&str>,
        packages: &Value,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO job_fetches (job_id, lockfile, resolution_error, packages)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (job_id) DO UPDATE
                 SET lockfile = $2, resolution_error = $3, packages = $4, fetched_at = now()",
                &[&job.0, &lockfile, &resolution_error, packages],
            )
            .await?;

        Ok(())
    }

    /// Replaces the popularity of the given crates (name, downloads,
    /// reverse dependencies) in batches.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn upsert_crate_stats(
        &self,
        stats: &[(String, i64, i64)],
    ) -> Result<u64, StoreError> {
        let mut written = 0;

        for chunk in stats.chunks(10_000) {
            let names: Vec<&str> = chunk.iter().map(|s| s.0.as_str()).collect();
            let canonical: Vec<String> = chunk
                .iter()
                .map(|s| s.0.to_ascii_lowercase().replace('-', "_"))
                .collect();

            let downloads: Vec<i64> = chunk.iter().map(|s| s.1).collect();
            let reverse: Vec<i64> = chunk.iter().map(|s| s.2).collect();
            written += self
                .client
                .execute(
                    "INSERT INTO crate_stats (canonical_name, crate_name, downloads, reverse_dependencies)
                     SELECT * FROM unnest($1::text[], $2::text[], $3::bigint[], $4::bigint[])
                     ON CONFLICT (canonical_name) DO UPDATE
                     SET crate_name = EXCLUDED.crate_name, downloads = EXCLUDED.downloads,
                         reverse_dependencies = EXCLUDED.reverse_dependencies, updated_at = now()",
                    &[&canonical, &names, &downloads, &reverse],
                )
                .await?;
        }

        Ok(written)
    }

    /// Reverse dependency count of a crate, if the dump knows it.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn reverse_dependencies(&self, name: &CrateName) -> Result<Option<i64>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT reverse_dependencies FROM crate_stats WHERE canonical_name = $1",
                &[&name.canonical()],
            )
            .await?
            .map(|r| r.get(0)))
    }

    /// The stored static report of a crate file: analyzer version and
    /// report.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn static_report(
        &self,
        sha256: &Sha256Digest,
    ) -> Result<Option<(i32, Value)>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT analyzer_version, report FROM static_reports WHERE sha256 = $1",
                &[&sha256.as_bytes().as_slice()],
            )
            .await?
            .map(|r| (r.get(0), r.get(1))))
    }

    /// Crate files of scored jobs whose static report an older analyzer
    /// wrote, verdicts waiting for review first, then the newest.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn outdated_static_reports(
        &self,
        analyzer_version: i32,
        limit: i64,
    ) -> Result<Vec<Sha256Digest>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT r.sha256, max(j.id) FROM static_reports r
                 JOIN jobs j ON j.cksum = r.sha256
                 JOIN verdicts v ON v.job_id = j.id
                 WHERE r.analyzer_version < $1
                 GROUP BY r.sha256
                 ORDER BY bool_or(v.review = 'pending') DESC, max(j.id) DESC
                 LIMIT $2",
                &[&analyzer_version, &limit],
            )
            .await?;

        rows.iter()
            .map(|r| {
                let bytes: Vec<u8> = r.get(0);
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt {
                    id: r.get(1),
                    reason: "checksum is not 32 bytes".into(),
                })?;

                Ok(Sha256Digest::from_bytes(bytes))
            })
            .collect()
    }

    /// Stores or replaces the static report of a crate file.
    ///
    /// # Errors
    ///
    /// Fails on database errors, including a crate file that is not recorded.
    pub async fn record_static_report(
        &self,
        sha256: &Sha256Digest,
        analyzer_version: i32,
        build_time_code: bool,
        max_severity: Option<&str>,
        report: &Value,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO static_reports (sha256, analyzer_version, build_time_code, max_severity, report)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (sha256) DO UPDATE
                 SET analyzer_version = $2, build_time_code = $3, max_severity = $4,
                     report = $5, analyzed_at = now()",
                &[&sha256.as_bytes().as_slice(), &analyzer_version, &build_time_code, &max_severity, report],
            )
            .await?;

        Ok(())
    }

    /// The locked packages the fetch stage recorded for a job, as stored.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn fetch_packages(&self, job: JobId) -> Result<Option<Value>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT packages FROM job_fetches WHERE job_id = $1",
                &[&job.0],
            )
            .await?
            .map(|r| r.get(0)))
    }

    /// Other versions of a crate that have a fetch record: job, version and
    /// locked packages.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn other_fetches(
        &self,
        name: &CrateName,
        except: JobId,
    ) -> Result<Vec<(JobId, String, Sha256Digest, Value)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT j.id, j.version, j.cksum, f.packages
                 FROM jobs j JOIN job_fetches f ON f.job_id = j.id
                 WHERE j.canonical_name = $1 AND j.id <> $2",
                &[&name.canonical(), &except.0],
            )
            .await?;

        rows.iter()
            .map(|r| {
                let id: i64 = r.try_get(0)?;
                let cksum: Vec<u8> = r.try_get(2)?;
                let cksum: [u8; 32] = cksum.try_into().map_err(|_| StoreError::Corrupt {
                    id,
                    reason: "checksum is not 32 bytes".into(),
                })?;

                Ok((
                    JobId(id),
                    r.try_get(1)?,
                    Sha256Digest::from_bytes(cksum),
                    r.try_get(3)?,
                ))
            })
            .collect()
    }

    /// The canonical names among `names` of crates with at least
    /// `min_reverse` reverse dependencies or `min_downloads` downloads.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn popular_among(
        &self,
        names: &[String],
        min_reverse: i64,
        min_downloads: i64,
    ) -> Result<Vec<String>, StoreError> {
        let canonical: Vec<String> = names
            .iter()
            .map(|n| n.to_ascii_lowercase().replace('-', "_"))
            .collect();

        let rows = self
            .client
            .query(
                "SELECT canonical_name FROM crate_stats
                 WHERE canonical_name = ANY($1)
                   AND (reverse_dependencies >= $2 OR downloads >= $3)",
                &[&canonical, &min_reverse, &min_downloads],
            )
            .await?;

        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    /// Recent fetch records that have a lockfile, newest first: job, crate
    /// name, version, lockfile and locked packages. The warm build replays
    /// them (ADR 0006).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn recent_fetches(
        &self,
        limit: i64,
    ) -> Result<Vec<(JobId, String, String, String, Value)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT j.id, j.crate_name, j.version, f.lockfile, f.packages
                 FROM job_fetches f JOIN jobs j ON j.id = f.job_id
                 WHERE f.lockfile IS NOT NULL AND f.packages IS NOT NULL
                 ORDER BY f.fetched_at DESC LIMIT $1",
                &[&limit],
            )
            .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    JobId(r.try_get(0)?),
                    r.try_get(1)?,
                    r.try_get(2)?,
                    r.try_get(3)?,
                    r.try_get(4)?,
                ))
            })
            .collect()
    }

    /// The BLAKE3 blob names of the given crate files (SHA-256) that are
    /// stored.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn crate_blobs(
        &self,
        sha256: &[Vec<u8>],
    ) -> Result<Vec<(Vec<u8>, String)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT sha256, blake3 FROM crate_files
                 WHERE sha256 = ANY($1) AND blake3 IS NOT NULL",
                &[&sha256],
            )
            .await?;

        rows.iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect()
    }

    /// Of the given crate files (SHA-256), those Crateward stored at least
    /// `min_age_secs` ago that have a static report and no report with a
    /// high severity finding, with the BLAKE3 name of their blob. This is the
    /// gate of the warm build cache (ADR 0006).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn warm_eligible(
        &self,
        sha256: &[Vec<u8>],
        min_age_secs: f64,
    ) -> Result<Vec<(Vec<u8>, String)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT cf.sha256, cf.blake3 FROM crate_files cf
                 WHERE cf.sha256 = ANY($1)
                   AND cf.fetched_at <= now() - make_interval(secs => $2)
                   AND EXISTS (SELECT 1 FROM static_reports s WHERE s.sha256 = cf.sha256)
                   AND NOT EXISTS (SELECT 1 FROM static_reports s
                                   WHERE s.sha256 = cf.sha256 AND s.max_severity = 'high')",
                &[&sha256, &min_age_secs],
            )
            .await?;

        rows.iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect()
    }

    /// Records the static analysis decision of a job.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_job_static(
        &self,
        job: JobId,
        triage: &Value,
        reasons: &Value,
        diff: Option<&Value>,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO job_static (job_id, triage, reasons, diff) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (job_id) DO UPDATE
                 SET triage = $2, reasons = $3, diff = $4, analyzed_at = now()",
                &[&job.0, triage, reasons, &diff],
            )
            .await?;

        Ok(())
    }

    /// The lockfile the fetch stage recorded for a job.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn fetch_lockfile(&self, job: JobId) -> Result<Option<String>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT lockfile FROM job_fetches WHERE job_id = $1",
                &[&job.0],
            )
            .await?
            .and_then(|r| r.get(0)))
    }

    /// Records the honeytokens planted for a job, replacing earlier ones.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_honeytokens(
        &self,
        job: JobId,
        tokens: &[(String, String)],
    ) -> Result<(), StoreError> {
        let kinds: Vec<&str> = tokens.iter().map(|t| t.0.as_str()).collect();
        let values: Vec<&str> = tokens.iter().map(|t| t.1.as_str()).collect();
        self.client
            .execute("DELETE FROM job_honeytokens WHERE job_id = $1", &[&job.0])
            .await?;
        self.client
            .execute(
                "INSERT INTO job_honeytokens (job_id, kind, value)
                 SELECT $1, * FROM unnest($2::text[], $3::text[])",
                &[&job.0, &kinds, &values],
            )
            .await?;

        Ok(())
    }

    /// Records the result of one VM run.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_run(
        &self,
        job: JobId,
        run_kind: &str,
        outcome: &str,
        report: &Value,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO job_runs (job_id, run_kind, outcome, report) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (job_id, run_kind) DO UPDATE
                 SET outcome = $3, report = $4, recorded_at = now()",
                &[&job.0, &run_kind, &outcome, report],
            )
            .await?;

        Ok(())
    }

    /// Number of jobs per state.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn count_by_state(&self) -> Result<BTreeMap<String, i64>, StoreError> {
        let rows = self
            .client
            .query("SELECT state, count(*) FROM jobs GROUP BY state", &[])
            .await?;

        rows.iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect()
    }
}

/// Keeps a lease alive from its own connection while a job is processed.
pub fn heartbeat(
    store: std::sync::Arc<Store>,
    job: JobId,
    worker: String,
    lease: Duration,
    every: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;

            match store.heartbeat(job, &worker, lease).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(job = job.0, "lease lost");
                    return;
                }
                Err(error) => tracing::warn!(%error, "heartbeat failed"),
            }
        }
    })
}
