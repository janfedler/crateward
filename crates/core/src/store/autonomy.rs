//! Breakers, pauses, alerts and canary results (ADR 0020).
//!
//! The supervisor decides; these functions only store and read. Claiming
//! (see [`Store::claim`]) consults the breakers and pauses, so a paused
//! stage stops taking work without any worker knowing why.

use std::collections::HashMap;

use serde_json::Value;
use tokio_postgres::GenericClient;

use super::{Policies, Store, StoreError};
use crate::breaker::{BreakerState, Counts};
use crate::escalation::HumanEscalation;
use crate::job::{JobEvent, JobId, JobState, Stage};

/// Why stages stop claiming jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauseReason {
    /// A possible sandbox escape: everything stops until a human lifts it.
    Quarantine,
    /// A canary produced the wrong result: stages that produce or publish
    /// results stop until a canary passes again.
    Canary,
    /// The scratch filesystem is too full: the sandbox stage stops until
    /// usage drops.
    Disk,
}

impl PauseReason {
    /// Every reason.
    pub const ALL: [Self; 3] = [Self::Quarantine, Self::Canary, Self::Disk];

    /// Name stored in the database.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::Canary => "canary",
            Self::Disk => "disk",
        }
    }

    /// The stages this reason pauses.
    #[must_use]
    pub const fn stages(self) -> &'static [Stage] {
        match self {
            Self::Quarantine => &Stage::ALL,
            Self::Canary => &[Stage::Sandbox, Stage::Analysis, Stage::Finalize],
            Self::Disk => &[Stage::Sandbox],
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == name)
    }
}

/// An active pause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pause {
    /// Why.
    pub reason: PauseReason,
    /// Since when, in seconds since the Unix epoch.
    pub since: i64,
    /// The job that caused it, if one did.
    pub job: Option<JobId>,
    /// Details for the dashboard and the command line; never sent out.
    pub detail: String,
}

/// An alert waiting for the notifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAlert {
    /// Row ID.
    pub id: i64,
    /// Deduplication key.
    pub dedup_key: String,
    /// What to report.
    pub escalation: HumanEscalation,
}

/// What became of an alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertOutcome {
    /// Delivered.
    Sent,
    /// Not sent: the same alert went out recently.
    Suppressed,
    /// Delivery failed; it is tried again.
    Failed(String),
}

fn stage_by_name(name: &str) -> Option<Stage> {
    Stage::ALL.into_iter().find(|s| s.name() == name)
}

/// The event kind that completes a step of `stage`, as stored.
const fn completion_kind(stage: Stage) -> &'static str {
    match stage {
        Stage::Fetch => "fetched",
        Stage::StaticAnalysis => "static_analysis_completed",
        Stage::Sandbox => "sandbox_completed",
        Stage::Analysis => "scored",
        Stage::Finalize => "finalized",
    }
}

fn corrupt(reason: impl Into<String>) -> StoreError {
    StoreError::Corrupt {
        id: 0,
        reason: reason.into(),
    }
}

/// Sets a pause on a connection or inside a transaction. Returns `false`
/// if it was already set.
pub(super) async fn insert_pause(
    db: &(impl GenericClient + Sync),
    reason: PauseReason,
    job: Option<JobId>,
    detail: &str,
) -> Result<bool, StoreError> {
    let stages: Vec<&str> = reason.stages().iter().map(|s| s.name()).collect();
    let job = job.map(|j| j.0);
    let inserted = db
        .execute(
            "INSERT INTO pipeline_pauses (reason, stages, job_id, detail)
             VALUES ($1, $2, $3, $4) ON CONFLICT (reason) DO NOTHING",
            &[&reason.name(), &stages, &job, &detail],
        )
        .await?;
    Ok(inserted == 1)
}

/// Queues an alert on a connection or inside a transaction.
pub(super) async fn insert_alert(
    db: &(impl GenericClient + Sync),
    escalation: &HumanEscalation,
) -> Result<(), StoreError> {
    db.execute(
        "INSERT INTO alerts (dedup_key, escalation) VALUES ($1, $2)",
        &[
            &escalation.dedup_key(),
            &serde_json::to_value(escalation).unwrap_or(Value::Null),
        ],
    )
    .await?;
    Ok(())
}

impl Store {
    /// The database clock, in seconds since the Unix epoch. Every time the
    /// supervisor compares comes from this one clock.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn now_epoch(&self) -> Result<i64, StoreError> {
        let row = self
            .client
            .query_one("SELECT extract(epoch FROM now())::bigint", &[])
            .await?;
        Ok(row.try_get(0)?)
    }

    /// Every stage's breaker; stages without a row are closed.
    ///
    /// # Errors
    ///
    /// Fails on database errors or an unknown stored state.
    pub async fn breakers(&self) -> Result<HashMap<Stage, BreakerState>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT stage, state, extract(epoch FROM since)::bigint, reopened
                 FROM stage_breakers",
                &[],
            )
            .await?;
        let mut out: HashMap<Stage, BreakerState> = Stage::ALL
            .into_iter()
            .map(|s| (s, BreakerState::Closed))
            .collect();
        for row in rows {
            let name: String = row.try_get(0)?;
            let stage = stage_by_name(&name).ok_or_else(|| corrupt(format!("stage {name}")))?;
            let state: String = row.try_get(1)?;
            let since: i64 = row.try_get(2)?;
            let reopened = u32::try_from(row.try_get::<_, i32>(3)?).unwrap_or(0);
            let value = match state.as_str() {
                "closed" => BreakerState::Closed,
                "open" => BreakerState::Open { since, reopened },
                "half_open" => BreakerState::HalfOpen { since, reopened },
                other => return Err(corrupt(format!("breaker state {other}"))),
            };
            out.insert(stage, value);
        }
        Ok(out)
    }

    /// Stores a stage's breaker.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn set_breaker(&self, stage: Stage, state: BreakerState) -> Result<(), StoreError> {
        let (since, reopened) = match state {
            BreakerState::Closed => (None, 0),
            BreakerState::Open { since, reopened } | BreakerState::HalfOpen { since, reopened } => {
                (Some(since), reopened)
            }
        };
        let reopened = i32::try_from(reopened).unwrap_or(i32::MAX);
        self.client
            .execute(
                "INSERT INTO stage_breakers (stage, state, since, reopened)
                 VALUES ($1, $2, COALESCE(to_timestamp($3::bigint), now()), $4)
                 ON CONFLICT (stage) DO UPDATE
                 SET state = $2, since = COALESCE(to_timestamp($3::bigint), now()),
                     reopened = $4, updated_at = now()",
                &[&stage.name(), &state.name(), &since, &reopened],
            )
            .await?;
        Ok(())
    }

    /// Infrastructure failures and completed steps per stage since `since`
    /// (seconds since the Unix epoch), from the job events.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn stage_counts(&self, since: i64) -> Result<HashMap<Stage, Counts>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT effect->>'stage', event->>'kind', effect->>'kind', count(*)
                 FROM job_events
                 WHERE at >= to_timestamp($1::bigint)
                 GROUP BY 1, 2, 3",
                &[&since],
            )
            .await?;
        let mut out: HashMap<Stage, Counts> = HashMap::new();
        for row in rows {
            let effect_stage: Option<String> = row.try_get(0)?;
            let event: Option<String> = row.try_get(1)?;
            let effect: Option<String> = row.try_get(2)?;
            let n = u32::try_from(row.try_get::<_, i64>(3)?).unwrap_or(u32::MAX);
            if effect.as_deref() == Some("report_infrastructure_failure")
                && let Some(stage) = effect_stage.as_deref().and_then(stage_by_name)
            {
                let c = out.entry(stage).or_default();
                c.failures = c.failures.saturating_add(n);
            }
            for stage in Stage::ALL {
                if event.as_deref() == Some(completion_kind(stage)) {
                    let c = out.entry(stage).or_default();
                    c.completions = c.completions.saturating_add(n);
                }
            }
        }
        Ok(out)
    }

    /// Sets a pause. Returns `false` if it was already set, in which case
    /// the original time, job and detail are kept.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn pause(
        &self,
        reason: PauseReason,
        job: Option<JobId>,
        detail: &str,
    ) -> Result<bool, StoreError> {
        insert_pause(&self.client, reason, job, detail).await
    }

    /// Lifts a pause. Returns `false` if it was not set.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn lift_pause(&self, reason: PauseReason) -> Result<bool, StoreError> {
        let deleted = self
            .client
            .execute(
                "DELETE FROM pipeline_pauses WHERE reason = $1",
                &[&reason.name()],
            )
            .await?;
        Ok(deleted == 1)
    }

    /// Active pauses.
    ///
    /// # Errors
    ///
    /// Fails on database errors or an unknown stored reason.
    pub async fn pauses(&self) -> Result<Vec<Pause>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT reason, extract(epoch FROM since)::bigint, job_id, detail
                 FROM pipeline_pauses ORDER BY since",
                &[],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let reason: String = row.try_get(0)?;
                Ok(Pause {
                    reason: PauseReason::parse(&reason)
                        .ok_or_else(|| corrupt(format!("pause reason {reason}")))?,
                    since: row.try_get(1)?,
                    job: row.try_get::<_, Option<i64>>(2)?.map(JobId),
                    detail: row.try_get(3)?,
                })
            })
            .collect()
    }

    /// Queues an alert for the notifier. Deduplication happens when it is
    /// sent, so every occurrence stays on record.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn raise_alert(&self, escalation: &HumanEscalation) -> Result<(), StoreError> {
        insert_alert(&self.client, escalation).await
    }

    /// Alerts not yet sent or suppressed, oldest first.
    ///
    /// # Errors
    ///
    /// Fails on database errors or an alert that does not decode.
    pub async fn pending_alerts(&self, limit: i64) -> Result<Vec<PendingAlert>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT id, dedup_key, escalation FROM alerts
                 WHERE sent_at IS NULL AND NOT suppressed ORDER BY id LIMIT $1",
                &[&limit],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let id: i64 = row.try_get(0)?;
                let escalation =
                    serde_json::from_value(row.try_get(2)?).map_err(|e| StoreError::Corrupt {
                        id,
                        reason: format!("alert: {e}"),
                    })?;
                Ok(PendingAlert {
                    id,
                    dedup_key: row.try_get(1)?,
                    escalation,
                })
            })
            .collect()
    }

    /// Seconds since an alert with this key was last sent, if ever.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn seconds_since_sent(&self, dedup_key: &str) -> Result<Option<i64>, StoreError> {
        let row = self
            .client
            .query_one(
                "SELECT extract(epoch FROM now() - max(sent_at))::bigint FROM alerts
                 WHERE dedup_key = $1 AND sent_at IS NOT NULL",
                &[&dedup_key],
            )
            .await?;
        Ok(row.try_get(0)?)
    }

    /// Records what became of an alert.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn mark_alert(&self, id: i64, outcome: &AlertOutcome) -> Result<(), StoreError> {
        match outcome {
            AlertOutcome::Sent => {
                self.client
                    .execute(
                        "UPDATE alerts SET sent_at = now(), attempts = attempts + 1 WHERE id = $1",
                        &[&id],
                    )
                    .await?
            }
            AlertOutcome::Suppressed => {
                self.client
                    .execute("UPDATE alerts SET suppressed = true WHERE id = $1", &[&id])
                    .await?
            }
            AlertOutcome::Failed(error) => {
                self.client
                    .execute(
                        "UPDATE alerts SET attempts = attempts + 1, last_error = $2 WHERE id = $1",
                        &[&id, error],
                    )
                    .await?
            }
        };
        Ok(())
    }

    /// Records a canary result.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_canary(
        &self,
        canary: &str,
        passed: bool,
        detail: &Value,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO canary_runs (canary, passed, detail) VALUES ($1, $2, $3)",
                &[&canary, &passed, detail],
            )
            .await?;
        Ok(())
    }

    /// The latest result of every canary: name, passed, when (seconds since
    /// the Unix epoch).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn latest_canaries(&self) -> Result<Vec<(String, bool, i64)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT DISTINCT ON (canary) canary, passed, extract(epoch FROM at)::bigint
                 FROM canary_runs ORDER BY canary, id DESC",
                &[],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?)))
            .collect()
    }

    /// Applies `CapacityDeadlineExpired` to jobs that have waited for a VM
    /// slot longer than `deadline_secs`, so they are scored as static only.
    /// Returns how many.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn expire_waiting(
        &mut self,
        deadline_secs: u64,
        policies: &Policies,
        worker: &str,
    ) -> Result<u64, StoreError> {
        let deadline = f64::from(u32::try_from(deadline_secs).unwrap_or(u32::MAX));
        let rows = self
            .client
            .query(
                "UPDATE jobs SET lease_owner = $3, lease_expires_at = now() + interval '5 minutes'
                 WHERE id IN (
                     SELECT id FROM jobs
                     WHERE state = $1 AND lease_owner IS NULL
                       AND updated_at < now() - make_interval(secs => $2)
                     FOR UPDATE SKIP LOCKED)
                 RETURNING id",
                &[&JobState::ReadyForSandbox.name(), &deadline, &worker],
            )
            .await?;
        let mut expired = 0;
        for row in rows {
            let id = JobId(row.try_get(0)?);
            self.complete(
                id,
                worker,
                JobEvent::CapacityDeadlineExpired,
                policies,
                false,
            )
            .await?;
            expired += 1;
        }
        Ok(expired)
    }
}
