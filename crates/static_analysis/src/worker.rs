//! The static analysis stage worker.
//!
//! For each job it makes sure a current report exists for the crate file
//! and for every locked dependency, analyzing missing ones in one sandboxed
//! child, then diffs against the previous version and decides the triage.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crateward_core::blobs::BlobStore;
use crateward_core::digest::Sha256Digest;
use crateward_core::failure::FailureClass;
use crateward_core::job::{JobEvent, Stage, Triage};
use crateward_core::name::CrateName;
use crateward_core::store::{Policies, Store, StoreError, StoredJob, heartbeat};
use crateward_core::verdict::StaticOnlyReason;
use serde::Deserialize;

use crate::analyze::{ANALYZER_VERSION, StaticReport};
use crate::diff::{VersionDiff, diff};
use crate::sandboxed::{MAX_TAR_BYTES, Outcome, analyze_in_sandbox};
use crate::triage::{Decision, Dependency, decide};

/// Tar bytes handed to one child at most; more start another child.
const BATCH_BYTES: usize = 512 * 1024 * 1024;

/// Why a job's static analysis failed.
#[derive(Debug, thiserror::Error)]
#[error("{class:?}: {message}")]
pub struct Failure {
    /// Retry class.
    pub class: FailureClass,
    /// What happened.
    pub message: String,
}

impl Failure {
    fn infrastructure(message: impl std::fmt::Display) -> Self {
        Self {
            class: FailureClass::Infrastructure,
            message: message.to_string(),
        }
    }

    fn permanent(message: impl std::fmt::Display) -> Self {
        Self {
            class: FailureClass::Permanent,
            message: message.to_string(),
        }
    }
}

impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Self {
        Self::infrastructure(error)
    }
}

/// A locked package as the fetch stage recorded it.
#[derive(Debug, Clone, Deserialize)]
struct Locked {
    name: String,
    version: String,
    checksum: String,
}

fn parse_locked(value: &serde_json::Value) -> Vec<Locked> {
    serde_json::from_value(value.clone()).unwrap_or_default()
}

/// The static analysis worker.
#[derive(Debug)]
pub struct Analyzer {
    store: Store,
    heartbeats: Arc<Store>,
    blobs: BlobStore,
    exe: PathBuf,
    popular: (i64, i64),
    /// Retry budgets and backoff.
    pub policies: Policies,
    /// Lease owner name.
    pub worker: String,
    /// Lease duration.
    pub lease: Duration,
}

impl Analyzer {
    /// An analyzer. `exe` is the binary that runs the sandboxed child;
    /// `popular` holds the reverse dependency and download thresholds.
    #[must_use]
    pub fn new(
        store: Store,
        heartbeats: Store,
        blobs: BlobStore,
        exe: PathBuf,
        popular: (i64, i64),
        policies: Policies,
        lease: Duration,
    ) -> Self {
        Self {
            store,
            heartbeats: Arc::new(heartbeats),
            blobs,
            exe,
            popular,
            policies,
            worker: format!("static-{}", std::process::id()),
            lease,
        }
    }

    /// Claims and processes one job. Returns `false` when there was none.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails while claiming or completing.
    pub async fn run_once(&mut self) -> Result<bool, StoreError> {
        let Some(job) = self
            .store
            .claim(Stage::StaticAnalysis, &self.worker, self.lease)
            .await?
        else {
            return Ok(false);
        };
        let beat = heartbeat(
            Arc::clone(&self.heartbeats),
            job.id,
            self.worker.clone(),
            self.lease,
            self.lease / 4,
        );
        let started = std::time::Instant::now();
        let result = self.process(&job).await;
        beat.abort();
        let event = match result {
            Ok(decision) => {
                tracing::info!(
                    job = job.id.0, name = %job.name, version = %job.version,
                    triage = ?decision.triage, ms = started.elapsed().as_millis(),
                    "analyzed"
                );
                JobEvent::StaticAnalysisCompleted {
                    triage: decision.triage,
                }
            }
            Err(failure) => {
                tracing::warn!(job = job.id.0, name = %job.name, version = %job.version, %failure, "static analysis failed");
                JobEvent::StageFailed {
                    class: failure.class,
                }
            }
        };
        let worker = self.worker.clone();
        let policies = self.policies.clone();
        self.store
            .complete(job.id, &worker, event, &policies, false)
            .await?;
        Ok(true)
    }

    /// Analyzes one job and records the decision.
    ///
    /// # Errors
    ///
    /// Returns the failure class for the state machine.
    pub async fn process(&self, job: &StoredJob) -> Result<Decision, Failure> {
        let name = CrateName::parse(&job.name).map_err(Failure::permanent)?;
        let version = semver::Version::parse(&job.version).map_err(Failure::permanent)?;
        let target = self
            .store
            .crate_file(&job.cksum)
            .await?
            .ok_or_else(|| Failure::infrastructure("the fetch stage stored no crate file"))?;
        if target.blake3.is_none() {
            let decision = Decision {
                triage: Triage::StaticOnly(StaticOnlyReason::ArchiveRejected),
                reasons: vec!["the archive failed validation and was not unpacked".to_owned()],
            };
            self.record(job, &decision, None).await?;
            return Ok(decision);
        }
        if self.store.fetch_lockfile(job.id).await?.is_none() {
            let decision = Decision {
                triage: Triage::StaticOnly(StaticOnlyReason::UnresolvedDependencies),
                reasons: vec!["cargo could not resolve the dependencies".to_owned()],
            };
            // The crate's own report is still useful evidence.
            let _ = self.ensure_reports(&[job.cksum]).await?;
            self.record(job, &decision, None).await?;
            return Ok(decision);
        }
        let packages = self
            .store
            .fetch_packages(job.id)
            .await?
            .map(|v| parse_locked(&v))
            .unwrap_or_default();
        let dependencies: Vec<(Locked, Sha256Digest)> = packages
            .into_iter()
            .filter(|p| !(p.name == job.name && p.version == job.version))
            .filter_map(|p| p.checksum.parse::<Sha256Digest>().ok().map(|s| (p, s)))
            .collect();

        // Earlier versions: their locks say which dependencies are familiar,
        // and the newest one is the diff base.
        let mut seen = BTreeSet::new();
        let mut previous: Option<(semver::Version, Sha256Digest, BTreeSet<String>)> = None;
        for (_, v, cksum, packages) in self.store.other_fetches(&name, job.id).await? {
            let Ok(v) = semver::Version::parse(&v) else {
                continue;
            };
            if v >= version {
                continue;
            }
            let names: BTreeSet<String> = parse_locked(&packages)
                .into_iter()
                .map(|p| p.name)
                .filter(|n| n != &job.name)
                .collect();
            seen.extend(names.iter().cloned());
            if previous.as_ref().is_none_or(|(pv, _, _)| &v > pv) {
                previous = Some((v, cksum, names));
            }
        }

        let mut wanted = vec![job.cksum];
        wanted.extend(dependencies.iter().map(|(_, s)| *s));
        if let Some((_, cksum, _)) = &previous {
            wanted.push(*cksum);
        }
        let reports = self.ensure_reports(&wanted).await?;
        let report = reports
            .get(&job.cksum)
            .ok_or_else(|| Failure::permanent("the crate archive could not be analyzed"))?;

        let names: Vec<String> = dependencies.iter().map(|(p, _)| p.name.clone()).collect();
        let popular: BTreeSet<String> = self
            .store
            .popular_among(&names, self.popular.0, self.popular.1)
            .await?
            .into_iter()
            .collect();
        let mut deps: Vec<Dependency> = dependencies
            .iter()
            .map(|(p, sha)| Dependency {
                name: p.name.clone(),
                version: p.version.clone(),
                // A dependency without a report (missing on crates.io or
                // rejected) counts as running code: that is the safe side.
                build_time_code: reports
                    .get(sha)
                    .is_none_or(StaticReport::has_build_time_code),
                popular: popular.contains(&p.name.to_ascii_lowercase().replace('-', "_")),
                seen_before: seen.contains(&p.name),
                tracked: false,
            })
            .collect();
        for dep in deps
            .iter_mut()
            .filter(|d| d.build_time_code && !d.popular && !d.seen_before)
        {
            if let Ok(dep_name) = CrateName::parse(&dep.name) {
                dep.tracked = self.store.contains(&dep_name, &dep.version).await?;
            }
        }
        let decision = decide(report, &deps);
        let version_diff = previous.as_ref().and_then(|(v, cksum, previous_names)| {
            let current: BTreeSet<String> = names.iter().cloned().collect();
            reports
                .get(cksum)
                .map(|old| diff(report, old, &v.to_string(), &current, previous_names))
        });
        self.record(job, &decision, version_diff.as_ref()).await?;
        Ok(decision)
    }

    async fn record(
        &self,
        job: &StoredJob,
        decision: &Decision,
        version_diff: Option<&VersionDiff>,
    ) -> Result<(), Failure> {
        self.store
            .record_job_static(
                job.id,
                &json(&decision.triage),
                &json(&decision.reasons),
                version_diff.map(json).as_ref(),
            )
            .await?;
        Ok(())
    }

    /// Current reports for the given crate files, analyzing missing ones.
    /// Files without a stored blob or that fail analysis are left out.
    async fn ensure_reports(
        &self,
        files: &[Sha256Digest],
    ) -> Result<BTreeMap<Sha256Digest, StaticReport>, Failure> {
        let mut reports = BTreeMap::new();
        let mut missing = Vec::new();
        for sha in files.iter().collect::<BTreeSet<_>>() {
            if let Some((ANALYZER_VERSION, value)) = self.store.static_report(sha).await?
                && let Ok(report) = serde_json::from_value::<StaticReport>(value)
            {
                reports.insert(*sha, report);
                continue;
            }
            if let Some(file) = self.store.crate_file(sha).await?
                && let Some(blake3) = file.blake3
            {
                missing.push((*sha, blake3));
            }
        }
        let mut batch: Vec<(Sha256Digest, Vec<u8>)> = Vec::new();
        let mut batch_bytes = 0;
        let mut iter = missing.into_iter().peekable();
        while let Some((sha, blake3)) = iter.next() {
            let blobs = self.blobs.clone();
            let tar = tokio::task::spawn_blocking(move || blobs.get(&blake3, MAX_TAR_BYTES))
                .await
                .map_err(Failure::infrastructure)?
                .map_err(Failure::infrastructure)?;
            batch_bytes += tar.len();
            batch.push((sha, tar));
            if batch_bytes >= BATCH_BYTES || iter.peek().is_none() {
                let (shas, tars): (Vec<_>, Vec<_>) = std::mem::take(&mut batch).into_iter().unzip();
                batch_bytes = 0;
                let exe = self.exe.clone();
                let outcomes = tokio::task::spawn_blocking(move || analyze_in_sandbox(&exe, tars))
                    .await
                    .map_err(Failure::infrastructure)?
                    .map_err(Failure::infrastructure)?;
                for (sha, outcome) in shas.into_iter().zip(outcomes) {
                    match outcome {
                        Outcome::Report(report) => {
                            let max = report
                                .max_severity()
                                .and_then(|s| serde_json::to_value(s).ok())
                                .and_then(|v| v.as_str().map(str::to_owned));
                            let value = json(&report);
                            self.store
                                .record_static_report(
                                    &sha,
                                    ANALYZER_VERSION,
                                    report.has_build_time_code(),
                                    max.as_deref(),
                                    &value,
                                )
                                .await?;
                            reports.insert(sha, *report);
                        }
                        Outcome::Error(error) => {
                            tracing::warn!(%sha, %error, "archive not analyzable");
                        }
                    }
                }
            }
        }
        Ok(reports)
    }
}

/// Serializes to a JSON value for a `jsonb` column. The types used here
/// have no maps with non string keys, so serialization cannot fail.
fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    let mut value = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    scrub(&mut value);
    value
}

/// Replaces NUL, which `jsonb` rejects, in every string. Manifest values
/// and file names come from the crate and may contain it.
fn scrub(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) if s.contains('\0') => *s = s.replace('\0', "\\u{0}"),
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub),
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().filter(|k| k.contains('\0')).cloned().collect();
            for key in keys {
                if let Some(v) = map.remove(&key) {
                    map.insert(key.replace('\0', "\\u{0}"), v);
                }
            }
            map.values_mut().for_each(scrub);
        }
        _ => {}
    }
}
