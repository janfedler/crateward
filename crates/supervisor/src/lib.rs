//! Keeps the pipeline healthy without a human (ADR 0020).
//!
//! Zone: control plane.
//!
//! Why it looks the way it does: autonomy means every failure class has an
//! automated response before anyone is paged. Workers already retry with
//! backoff; the state machine records every infrastructure failure and every
//! suspected compromise. The supervisor turns those records into decisions,
//! in one round every `supervisor.interval_secs`:
//!
//! * it reaps expired leases of every stage;
//! * it evaluates each stage's circuit breaker from the job events, so
//!   persistent infrastructure trouble pauses only the affected stage;
//! * it scores jobs that waited too long for a VM slot as static only;
//! * it checks disk usage, and pauses the sandbox stage while the scratch
//!   filesystem is too full;
//! * it trims the raw data (process lists, output tails) of unflagged runs
//!   older than `storage.raw_log_retention_days`;
//! * it looks for signs of a host escape (ADR 0023): files that differ
//!   from the integrity manifest, any access to a decoy file, and
//!   processes running as a slot UID that the jail did not start; any of
//!   them quarantines the pipeline;
//! * it reads the canary results the orchestrator records and pauses the
//!   producing stages while a canary gives the wrong result;
//! * it delivers alerts from the closed list in `crateward_core::escalation`
//!   through the notifier, repeating the same alert at most every
//!   `supervisor.alert_repeat_hours`.
//!
//! A separate task pings healthchecks.io while rounds succeed, so a dead
//! server, a dead supervisor or an unreachable database all end in the
//! heartbeat alert. Quarantine is set in the same transaction as the
//! suspected compromise (see `Store::complete`) and only a human lifts it.

#![forbid(unsafe_code)]

pub mod checks;
pub mod integrity;
pub mod notify;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use crateward_core::app::ComponentError;
use crateward_core::breaker::{Change, Counts};
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::escalation::HumanEscalation;
use crateward_core::store::{AlertOutcome, PauseReason, Policies, Store, StoreError};
use secrecy::ExposeSecret;

use crate::checks::CanaryAction;
use crate::notify::Notifier;

/// The component this package implements.
pub const COMPONENT: Component = Component::Supervisor;

/// The name the supervisor uses when it holds a lease.
const WORKER: &str = "supervisor";

/// Run reports trimmed per round at most, so one round stays short.
const TRIM_BATCH: i64 = 500;

fn fatal(error: impl std::fmt::Display) -> ComponentError {
    ComponentError::Fatal {
        component: COMPONENT,
        reason: error.to_string(),
    }
}

/// Everything one round needs.
struct Supervisor<'a> {
    config: &'a Config,
    store: Store,
    policies: Policies,
    notifier: Notifier,
    integrity: integrity::Integrity,
}

impl Supervisor<'_> {
    async fn round(&mut self) -> Result<(), StoreError> {
        let reaped = self.store.reap_expired(&self.policies).await?;
        if reaped > 0 {
            tracing::warn!(reaped, "reaped expired leases");
        }
        self.breakers().await?;
        let deadline = self
            .config
            .triage
            .dynamic_deadline_hours
            .saturating_mul(3600);
        let expired = self
            .store
            .expire_waiting(deadline, &self.policies, WORKER)
            .await?;
        if expired > 0 {
            tracing::info!(
                expired,
                "jobs waited too long for a VM and are scored statically"
            );
        }
        self.disks().await?;
        let trimmed = self
            .store
            .trim_raw_runs(self.config.storage.raw_log_retention_days, TRIM_BATCH)
            .await?;
        if trimmed > 0 {
            tracing::info!(trimmed, "trimmed raw data of old unflagged runs");
        }
        self.escape().await?;
        self.canaries().await?;
        self.alerts().await
    }

    async fn breakers(&mut self) -> Result<(), StoreError> {
        let policy = self.config.supervisor.breaker_policy();
        let now = self.store.now_epoch().await?;
        let window_start = now - i64::try_from(policy.window.as_secs()).unwrap_or(i64::MAX);
        let window = self.store.stage_counts(window_start).await?;
        for (stage, state) in self.store.breakers().await? {
            let since = match state {
                crateward_core::breaker::BreakerState::HalfOpen { since, .. } => {
                    self.store.stage_counts(since).await?.get(&stage).copied()
                }
                _ => None,
            }
            .unwrap_or_default();
            let counts = window.get(&stage).copied().unwrap_or(Counts::default());
            let (next, change) = policy.evaluate(state, counts, since, now);
            let Some(change) = change else { continue };
            self.store.set_breaker(stage, next).await?;
            tracing::warn!(stage = stage.name(), ?change, ?counts, "circuit breaker");
            if change == Change::Opened {
                self.store
                    .raise_alert(&HumanEscalation::StageFailingAfterRetries { stage })
                    .await?;
            }
        }
        Ok(())
    }

    async fn disks(&mut self) -> Result<(), StoreError> {
        let threshold = self.config.storage.disk_alert_percent;
        let instance = &self.config.instance;
        let mut scratch_full = false;
        for (path, is_scratch) in [(&instance.data_dir, false), (&instance.run_dir, true)] {
            let Some(percent) = usage(path) else {
                tracing::warn!(path = %path.display(), "cannot read filesystem usage");
                continue;
            };
            if percent >= threshold {
                tracing::warn!(path = %path.display(), percent, "filesystem above the threshold");
                self.store
                    .raise_alert(&HumanEscalation::DiskUsageAboveThreshold { percent })
                    .await?;
                scratch_full |= is_scratch;
            }
        }
        if scratch_full {
            let detail = "the scratch filesystem is above the alert threshold";
            if self.store.pause(PauseReason::Disk, None, detail).await? {
                tracing::warn!("sandbox stage paused: scratch filesystem full");
            }
        } else if self.store.lift_pause(PauseReason::Disk).await? {
            tracing::info!("sandbox stage resumed: scratch filesystem has room again");
        }
        Ok(())
    }

    async fn escape(&mut self) -> Result<(), StoreError> {
        let sandbox = &self.config.sandbox;
        // The spare slot, used for the base snapshot, is included.
        let slot_uids = sandbox.slot_uid_base..=sandbox.slot_uid_base.saturating_add(sandbox.slots);
        let mut findings = self.integrity.manifest();
        findings.extend(self.integrity.decoys(&self.config.supervisor.decoys));
        findings.extend(self.integrity.processes(slot_uids));
        if findings.is_empty() {
            return Ok(());
        }
        for finding in &findings {
            tracing::error!(%finding, "sandbox escape indicator");
        }
        let detail = format!("host escape indicator: {}", findings.join("; "));
        self.store
            .pause(PauseReason::Quarantine, None, &detail)
            .await?;
        self.store
            .raise_alert(&HumanEscalation::SandboxEscapeIndicator { job: None })
            .await
    }

    async fn canaries(&mut self) -> Result<(), StoreError> {
        match checks::canary_action(&self.store.latest_canaries().await?) {
            CanaryAction::Wait => {}
            CanaryAction::AllPassed => {
                if self.store.lift_pause(PauseReason::Canary).await? {
                    tracing::info!("canaries pass again; producing stages resumed");
                }
            }
            CanaryAction::Failed(names) => {
                let detail = format!("wrong result from {}", names.join(", "));
                if self.store.pause(PauseReason::Canary, None, &detail).await? {
                    tracing::error!(%detail, "canary failed; producing stages paused");
                    self.store
                        .raise_alert(&HumanEscalation::CanaryFailure)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn alerts(&mut self) -> Result<(), StoreError> {
        let repeat = self.config.supervisor.alert_repeat_hours;
        for alert in self.store.pending_alerts(50).await? {
            let since = self.store.seconds_since_sent(&alert.dedup_key).await?;
            let outcome = if checks::should_send(since, repeat) {
                match self.notifier.send(&alert.escalation).await {
                    Ok(()) => AlertOutcome::Sent,
                    Err(error) => {
                        tracing::warn!(%error, key = %alert.dedup_key, "alert not delivered");
                        AlertOutcome::Failed(error.to_string())
                    }
                }
            } else {
                AlertOutcome::Suppressed
            };
            self.store.mark_alert(alert.id, &outcome).await?;
            if matches!(outcome, AlertOutcome::Failed(_)) {
                // Keep the order; try again next round.
                break;
            }
        }
        Ok(())
    }
}

/// Percent of the filesystem holding `path` in use.
fn usage(path: &Path) -> Option<u8> {
    let stat = rustix::fs::statvfs(path).ok()?;
    Some(checks::used_percent(
        stat.f_blocks,
        stat.f_bfree,
        stat.f_bavail,
    ))
}

/// Pings the heartbeat URL while rounds keep succeeding.
async fn heartbeat(
    client: reqwest::Client,
    url: String,
    interval: Duration,
    last_ok: Arc<AtomicI64>,
    stop: Arc<AtomicBool>,
) {
    let placeholder = checks::is_placeholder_ping(&url);
    if placeholder {
        tracing::warn!("heartbeat.ping_url is the example placeholder; not pinging");
    }
    while !stop.load(Ordering::SeqCst) {
        let fresh = now_secs().saturating_sub(last_ok.load(Ordering::SeqCst))
            <= i64::try_from(interval.as_secs().saturating_mul(3)).unwrap_or(i64::MAX);
        if fresh && !placeholder {
            match client.get(&url).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => tracing::warn!(status = %response.status(), "heartbeat refused"),
                Err(error) => tracing::warn!(error = %error.without_url(), "heartbeat failed"),
            }
        }
        tokio::time::sleep(interval).await;
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Runs the component until shutdown.
///
/// # Errors
///
/// Fails if the database or the HTTP client cannot be set up.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(fatal)?;
    runtime.block_on(async {
        let mut store = Store::connect(config.database.url.expose_secret())
            .await
            .map_err(fatal)?;
        store.migrate().await.map_err(fatal)?;
        let client = reqwest::Client::builder()
            .user_agent(notify::USER_AGENT)
            .timeout(Duration::from_secs(20))
            .https_only(true)
            .build()
            .map_err(fatal)?;
        let mut supervisor = Supervisor {
            config,
            store,
            policies: Policies::from_config(&config.stages).map_err(fatal)?,
            notifier: Notifier::new(&config.notifier, &client),
            integrity: integrity::Integrity::new(
                &config.instance.data_dir,
                Duration::from_secs(
                    config
                        .supervisor
                        .integrity_interval_minutes
                        .saturating_mul(60),
                ),
            )
            .map_err(fatal)?,
        };

        let stop = Arc::new(AtomicBool::new(false));
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(fatal)?;
        let flag = Arc::clone(&stop);
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            flag.store(true, Ordering::SeqCst);
        });
        let last_ok = Arc::new(AtomicI64::new(0));
        tokio::spawn(heartbeat(
            client,
            config.heartbeat.ping_url.expose_secret().to_owned(),
            Duration::from_secs(config.heartbeat.interval_secs),
            Arc::clone(&last_ok),
            Arc::clone(&stop),
        ));

        let interval = Duration::from_secs(config.supervisor.interval_secs);
        while !stop.load(Ordering::SeqCst) {
            match supervisor.round().await {
                Ok(()) => last_ok.store(now_secs(), Ordering::SeqCst),
                // The heartbeat stops by itself; the next round retries.
                Err(error) => tracing::error!(%error, "supervisor round failed"),
            }
            tokio::time::sleep(interval).await;
        }
        tracing::info!("stopping");
        Ok(())
    })
}
