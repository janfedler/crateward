//! The Postgres job store: the queue and the state of every job (ADR 0004).
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
//! Enabled with the `store` feature; the guest agent never links it.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde_json::Value;
use tokio_postgres::{Client, NoTls, Row};

use crate::digest::Sha256Digest;
use crate::job::{
    Effect, Job, JobEvent, JobId, JobState, Limits, Stage, Transition, TransitionError,
};
use crate::name::CrateName;
use crate::retry::RetryPolicy;

/// Migrations, applied in order. Never edit one that has shipped.
const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("../migrations/0001_jobs.sql")),
    (2, include_str!("../migrations/0002_fetch.sql")),
];

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database failed.
    #[error("postgres: {0}")]
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
    /// Fails if a stage has an invalid backoff; configuration validation
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
    /// Fails if a migration fails; nothing of that migration is applied.
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
                         ORDER BY priority DESC, id
                         LIMIT 1
                         FOR UPDATE SKIP LOCKED)
                     RETURNING {COLUMNS}"
                ),
                &[&states, &worker, &lease_interval(lease)],
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
    /// [`StoreError::LeaseLost`] if the worker does not hold the lease;
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
