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
use crateward_core::job::{JobEvent, JobId, Stage, Triage};
use crateward_core::name::CrateName;
use crateward_core::store::{Policies, Store, StoreError, StoredJob, heartbeat};
use crateward_core::verdict::StaticOnlyReason;
use serde::Deserialize;

use crate::analyze::{ANALYZER_VERSION, StaticReport};
use crate::diff::{VersionDiff, diff};
use crate::findings::Severity;
use crate::sandboxed::{MAX_TAR_BYTES, Outcome, analyze_in_sandbox};
use crate::triage::{Decision, Dependency, decide};

/// Tar bytes handed to one child at most; more start another child.
const BATCH_BYTES: usize = 512 * 1024 * 1024;

/// Reports by the SHA-256 of their crate file.
type Reports = BTreeMap<Sha256Digest, StaticReport>;

/// Why a job's static analysis failed.
#[derive(Debug, thiserror::Error)]
#[error("{}: {message}", class.name())]
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
    /// Crate files that failed to analyze again, left alone until restart.
    unrefreshable: BTreeSet<Sha256Digest>,
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
            unrefreshable: BTreeSet::new(),
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

    /// Analyzes again, a few per call, the crate files of scored jobs whose
    /// report an older analyzer wrote, so the dashboard shows what the
    /// current one adds, such as line numbers. Verdicts waiting for
    /// review go first. Returns how many reports were written.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails.
    pub async fn refresh_some(&mut self) -> Result<usize, StoreError> {
        let limit = 10 + self.unrefreshable.len();
        let outdated: Vec<Sha256Digest> = self
            .store
            .outdated_static_reports(ANALYZER_VERSION, i64::try_from(limit).unwrap_or(i64::MAX))
            .await?
            .into_iter()
            .filter(|sha| !self.unrefreshable.contains(sha))
            .take(10)
            .collect();
        let reports = match self.ensure_reports(&outdated).await {
            Ok(reports) => reports,
            Err(failure) => {
                tracing::warn!(%failure, "cannot refresh static reports");
                return Ok(0);
            }
        };
        self.unrefreshable
            .extend(outdated.iter().filter(|sha| !reports.contains_key(sha)));
        Ok(reports.len())
    }

    /// Analyzes one job and records the decision.
    ///
    /// # Errors
    ///
    /// Returns the failure class for the state machine.
    pub async fn process(&self, job: &StoredJob) -> Result<Decision, Failure> {
        let (decision, version_diff) = self.assess(job).await?;
        self.record(job, &decision, version_diff.as_ref()).await?;
        Ok(decision)
    }

    /// The decision for a job, and the diff to the previous version.
    async fn assess(&self, job: &StoredJob) -> Result<(Decision, Option<VersionDiff>), Failure> {
        let name = CrateName::parse(&job.name).map_err(Failure::permanent)?;
        let version = semver::Version::parse(&job.version).map_err(Failure::permanent)?;
        if let Some(decision) = self.early_decision(job).await? {
            return Ok((decision, None));
        }
        let dependencies = self.dependencies(job).await?;
        let fetches = self.store.other_fetches(&name, job.id).await?;
        let history = earlier_versions(fetches, job, &version);

        let mut wanted = vec![job.cksum];
        wanted.extend(dependencies.iter().map(|(_, sha)| *sha));
        wanted.extend(history.previous.iter().map(|p| p.cksum));
        let reports = self.ensure_reports(&wanted).await?;
        let report = reports
            .get(&job.cksum)
            .ok_or_else(|| Failure::permanent("the crate archive could not be analyzed"))?;

        let facts = self
            .dependency_facts(&dependencies, &reports, &history.seen)
            .await?;
        let version_diff =
            diff_to_previous(report, &reports, history.previous.as_ref(), &dependencies);
        Ok((decide(report, &facts), version_diff))
    }

    /// The static only decision for a job that needs no dependency
    /// analysis: the archive was rejected, or cargo could not resolve the
    /// dependencies.
    async fn early_decision(&self, job: &StoredJob) -> Result<Option<Decision>, Failure> {
        let target = self
            .store
            .crate_file(&job.cksum)
            .await?
            .ok_or_else(|| Failure::infrastructure("the fetch stage stored no crate file"))?;
        if target.blake3.is_none() {
            return Ok(Some(static_only(
                StaticOnlyReason::ArchiveRejected,
                "the archive failed validation and was not unpacked",
            )));
        }
        if self.store.fetch_lockfile(job.id).await?.is_none() {
            // The crate's own report is still useful evidence.
            let _ = self.ensure_reports(&[job.cksum]).await?;
            return Ok(Some(static_only(
                StaticOnlyReason::UnresolvedDependencies,
                "cargo could not resolve the dependencies",
            )));
        }
        Ok(None)
    }

    /// The locked packages of a job except the crate itself, with their
    /// checksums. Packages without a SHA-256 checksum are left out.
    async fn dependencies(&self, job: &StoredJob) -> Result<Vec<(Locked, Sha256Digest)>, Failure> {
        let packages = self.store.fetch_packages(job.id).await?;
        Ok(packages
            .map(|value| parse_locked(&value))
            .unwrap_or_default()
            .into_iter()
            .filter(|p| !(p.name == job.name && p.version == job.version))
            .filter_map(|p| p.checksum.parse::<Sha256Digest>().ok().map(|s| (p, s)))
            .collect())
    }

    /// What the triage needs to know about each dependency.
    async fn dependency_facts(
        &self,
        dependencies: &[(Locked, Sha256Digest)],
        reports: &Reports,
        seen: &BTreeSet<String>,
    ) -> Result<Vec<Dependency>, Failure> {
        let names: Vec<String> = dependencies.iter().map(|(p, _)| p.name.clone()).collect();
        let popular: BTreeSet<String> = self
            .store
            .popular_among(&names, self.popular.0, self.popular.1)
            .await?
            .into_iter()
            .collect();
        let mut facts: Vec<Dependency> = dependencies
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
        for dep in facts
            .iter_mut()
            .filter(|d| d.build_time_code && !d.popular && !d.seen_before)
        {
            if let Ok(dep_name) = CrateName::parse(&dep.name) {
                dep.tracked = self.store.contains(&dep_name, &dep.version).await?;
            }
        }
        Ok(facts)
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
    async fn ensure_reports(&self, files: &[Sha256Digest]) -> Result<Reports, Failure> {
        let mut reports = Reports::new();
        let mut missing = Vec::new();
        for sha in files.iter().collect::<BTreeSet<_>>() {
            if let Some(report) = self.stored_report(sha).await? {
                reports.insert(*sha, report);
            } else if let Some(file) = self.store.crate_file(sha).await?
                && let Some(blake3) = file.blake3
            {
                missing.push((*sha, blake3));
            }
        }
        let mut batch = Vec::new();
        let mut batch_bytes = 0;
        let mut iter = missing.into_iter().peekable();
        while let Some((sha, blake3)) = iter.next() {
            let tar = self.read_blob(blake3).await?;
            batch_bytes += tar.len();
            batch.push((sha, tar));
            if batch_bytes >= BATCH_BYTES || iter.peek().is_none() {
                reports.extend(self.analyze_batch(std::mem::take(&mut batch)).await?);
                batch_bytes = 0;
            }
        }
        Ok(reports)
    }

    /// The stored report of a crate file, if the current analyzer wrote it
    /// and it still parses.
    async fn stored_report(&self, sha: &Sha256Digest) -> Result<Option<StaticReport>, Failure> {
        Ok(match self.store.static_report(sha).await? {
            Some((ANALYZER_VERSION, value)) => serde_json::from_value(value).ok(),
            _ => None,
        })
    }

    async fn read_blob(&self, blake3: String) -> Result<Vec<u8>, Failure> {
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || blobs.get(&blake3, MAX_TAR_BYTES))
            .await
            .map_err(Failure::infrastructure)?
            .map_err(Failure::infrastructure)
    }

    /// Analyzes the tars in one sandboxed child and stores the reports.
    /// Archives that cannot be analyzed are left out.
    async fn analyze_batch(
        &self,
        batch: Vec<(Sha256Digest, Vec<u8>)>,
    ) -> Result<Vec<(Sha256Digest, StaticReport)>, Failure> {
        let (shas, tars): (Vec<_>, Vec<_>) = batch.into_iter().unzip();
        let exe = self.exe.clone();
        let outcomes = tokio::task::spawn_blocking(move || analyze_in_sandbox(&exe, tars))
            .await
            .map_err(Failure::infrastructure)?
            .map_err(Failure::infrastructure)?;
        let mut analyzed = Vec::new();
        for (sha, outcome) in shas.into_iter().zip(outcomes) {
            match outcome {
                Outcome::Report(report) => {
                    self.store_report(&sha, &report).await?;
                    analyzed.push((sha, *report));
                }
                Outcome::Error(error) => tracing::warn!(%sha, %error, "archive not analyzable"),
            }
        }
        Ok(analyzed)
    }

    async fn store_report(&self, sha: &Sha256Digest, report: &StaticReport) -> Result<(), Failure> {
        self.store
            .record_static_report(
                sha,
                ANALYZER_VERSION,
                report.has_build_time_code(),
                report.max_severity().map(Severity::name),
                &json(report),
            )
            .await?;
        Ok(())
    }
}

/// A decision that stops the analysis with one reason.
fn static_only(reason: StaticOnlyReason, text: &str) -> Decision {
    Decision {
        triage: Triage::StaticOnly(reason),
        reasons: vec![text.to_owned()],
    }
}

/// The newest earlier version of a crate and the dependency names in the
/// locks of all earlier versions.
#[derive(Debug, Default)]
struct History {
    seen: BTreeSet<String>,
    previous: Option<Previous>,
}

/// The newest earlier version, the base of the diff.
#[derive(Debug)]
struct Previous {
    version: semver::Version,
    cksum: Sha256Digest,
    names: BTreeSet<String>,
}

/// Earlier versions: their locks say which dependencies are familiar, and
/// the newest one is the diff base. Later and unparsable versions do not
/// count.
fn earlier_versions(
    fetches: Vec<(JobId, String, Sha256Digest, serde_json::Value)>,
    job: &StoredJob,
    version: &semver::Version,
) -> History {
    let mut history = History::default();
    for (_, other, cksum, packages) in fetches {
        let Ok(other) = semver::Version::parse(&other) else {
            continue;
        };
        if other >= *version {
            continue;
        }
        let names: BTreeSet<String> = parse_locked(&packages)
            .into_iter()
            .map(|p| p.name)
            .filter(|n| n != &job.name)
            .collect();
        history.seen.extend(names.iter().cloned());
        if history.previous.as_ref().is_none_or(|p| other > p.version) {
            history.previous = Some(Previous {
                version: other,
                cksum,
                names,
            });
        }
    }
    history
}

/// The diff to the previous version, if there is one with a report.
fn diff_to_previous(
    report: &StaticReport,
    reports: &Reports,
    previous: Option<&Previous>,
    dependencies: &[(Locked, Sha256Digest)],
) -> Option<VersionDiff> {
    let previous = previous?;
    let old = reports.get(&previous.cksum)?;
    let current = dependencies.iter().map(|(p, _)| p.name.clone()).collect();
    let version = previous.version.to_string();
    Some(diff(report, old, &version, &current, &previous.names))
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
