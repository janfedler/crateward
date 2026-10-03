//! The static analysis worker on a real database: which decision a job gets
//! from its crate file, its lock, its earlier versions and the crate
//! statistics.
//!
//! The crates are inert fixtures that are only parsed, never built. Most
//! cases record the static reports up front, so they need no child. The
//! cases that fill in missing reports run the sandboxed child and skip on
//! kernels that refuse the sandbox, unless `CRATEWARD_REQUIRE_SANDBOX` is
//! set. The database setup is `crateward_core::testing`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crateward_core::blobs::BlobStore;
use crateward_core::digest::Sha256Digest;
use crateward_core::failure::{Failure, FailureClass};
use crateward_core::job::Triage;
use crateward_core::sandbox;
use crateward_core::store::{CrateFile, NewJob, Review, Store, StoredJob};
use crateward_core::testing::{TestDb, policies};
use crateward_core::verdict::{Coverage, RiskLevel, StaticOnlyReason, Verdict};

use crateward_static_analysis::analyze::{ANALYZER_VERSION, AnalyzeLimits, StaticReport, analyze};
use crateward_static_analysis::diff::diff;
use crateward_static_analysis::sandboxed::analyze_in_sandbox;
use crateward_static_analysis::triage::Decision;
use crateward_static_analysis::worker::Analyzer;
use crateward_static_analysis::yara::Rules;
use serde_json::{Value, json};

const EXE: &str = env!("CARGO_BIN_EXE_crateward_static_analysis");

/// Whether this host lets the child enter its sandbox.
fn sandbox_available() -> bool {
    match analyze_in_sandbox(Path::new(EXE), Vec::new()) {
        Ok(_) => true,
        Err(error) if sandbox::unavailable(&error) => false,
        Err(error) => panic!("{error}"),
    }
}

/// A stand in for the checksum of `name version`.
fn sha(name: &str, version: &str) -> Sha256Digest {
    let mut hasher = DefaultHasher::new();
    (name, version).hash(&mut hasher);
    let word = hasher.finish().to_be_bytes();
    Sha256Digest::from_bytes(std::array::from_fn(|i| word[i % 8]))
}

fn tar_with(name: &str, version: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    for (path, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{name}-{version}/{path}"), *data)
            .unwrap();
    }

    builder.into_inner().unwrap()
}

/// An archive with a manifest and a library, and a build script if asked.
fn tar_of(name: &str, version: &str, build: bool) -> Vec<u8> {
    let manifest = format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n");
    let mut files: Vec<(&str, &[u8])> = vec![
        ("Cargo.toml", manifest.as_bytes()),
        ("src/lib.rs", b"pub fn f() {}\n"),
    ];

    if build {
        files.push(("build.rs", b"fn main() {}\n"));
    }

    tar_with(name, version, &files)
}

fn report_of(tar: &[u8]) -> StaticReport {
    analyze(tar, &Rules::builtin().unwrap(), &AnalyzeLimits::default()).unwrap()
}

fn max_severity(report: &StaticReport) -> Option<String> {
    let severity = serde_json::to_value(report.max_severity()?).unwrap();
    severity.as_str().map(str::to_owned)
}

fn reasons(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// A migrated private schema, a blob store and the worker in front of them.
struct Lab {
    db: TestDb,
    dir: PathBuf,
    store: Store,
    blobs: BlobStore,
    analyzer: Analyzer,
}

impl Lab {
    async fn start() -> Option<Self> {
        let db = TestDb::new("static").await?;
        let store = db.migrated().await;

        let dir = std::env::temp_dir().join(format!("cw-{}", db.schema()));
        let _ = std::fs::remove_dir_all(&dir);
        let blobs = BlobStore::open(&dir).unwrap();

        let analyzer = Analyzer::new(
            db.store().await,
            db.store().await,
            blobs.clone(),
            PathBuf::from(EXE),
            (50, 1000),
            policies(),
            Duration::from_secs(30),
        );

        Some(Self {
            db,
            dir,
            store,
            blobs,
            analyzer,
        })
    }

    async fn finish(self) {
        self.db.drop().await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    /// A job for `name version`, without a crate file.
    async fn job(&self, name: &str, version: &str) -> StoredJob {
        let new = NewJob {
            name: name.parse().unwrap(),
            version: version.parse().unwrap(),
            cksum: sha(name, version),
            published_at: None,
            priority: 0,
            index_entry: json!({}),
        };

        let id = self.store.enqueue(&new).await.unwrap().unwrap();
        self.store.get(id).await.unwrap().unwrap()
    }

    /// A job whose archive was validated and stored.
    async fn publish(&self, name: &str, version: &str, tar: &[u8]) -> StoredJob {
        let job = self.job(name, version).await;
        let blob = self.blobs.put(tar).unwrap();
        self.crate_file(&job, Some(blob.blake3), tar.len()).await;
        job
    }

    async fn crate_file(&self, job: &StoredJob, blake3: Option<String>, unpacked: usize) {
        let file = CrateFile {
            sha256: job.cksum,
            name: job.name.clone(),
            version: job.version.clone(),
            blake3,
            compressed_bytes: 1,
            unpacked_bytes: i64::try_from(unpacked).unwrap(),
            stored_bytes: Some(1),
            report: json!({}),
        };

        self.store.record_crate_file(&file).await.unwrap();
    }

    /// A published job whose static report is already stored.
    async fn analyzed(&self, name: &str, version: &str, build: bool) -> StoredJob {
        let tar = tar_of(name, version, build);
        let job = self.publish(name, version, &tar).await;
        let report = report_of(&tar);
        self.store_report(
            &job,
            ANALYZER_VERSION,
            &serde_json::to_value(&report).unwrap(),
        )
        .await;
        job
    }

    async fn store_report(&self, job: &StoredJob, analyzer_version: i32, report: &Value) {
        self.store
            .record_static_report(&job.cksum, analyzer_version, false, None, report)
            .await
            .unwrap();
    }

    /// The locked packages of a job, as `name version` pairs whose checksum
    /// stands for the crate file of that pair.
    async fn lock(&self, job: &StoredJob, packages: &[(&str, &str)]) {
        let list: Vec<Value> = packages
            .iter()
            .map(|(name, version)| {
                json!({ "name": name, "version": version, "checksum": sha(name, version).to_string() })
            })
            .collect();
        self.record_packages(job, &Value::Array(list)).await;
    }

    async fn record_packages(&self, job: &StoredJob, packages: &Value) {
        let record = self
            .store
            .record_fetch(job.id, Some("# lockfile"), None, packages);
        record.await.unwrap();
    }

    async fn stats(&self, name: &str, downloads: i64, reverse: i64) {
        let stats = [(name.to_owned(), downloads, reverse)];
        self.store.upsert_crate_stats(&stats).await.unwrap();
    }

    /// Runs the worker and checks that it recorded what it returned.
    async fn decide(&self, job: &StoredJob) -> Decision {
        let decision = self.analyzer.process(job).await.unwrap();
        let (triage, reasons, _) = self.store.job_static(job.id).await.unwrap().unwrap();

        assert_eq!(triage, serde_json::to_value(decision.triage).unwrap());
        assert_eq!(reasons, json!(decision.reasons));

        decision
    }

    async fn failure(&self, job: &StoredJob) -> Failure {
        let failure = self.analyzer.process(job).await.unwrap_err();

        assert!(self.store.job_static(job.id).await.unwrap().is_none());

        failure
    }

    async fn recorded_diff(&self, job: &StoredJob) -> Option<Value> {
        self.store.job_static(job.id).await.unwrap().unwrap().2
    }

    async fn stored_report(&self, job: &StoredJob) -> Option<(i32, Value)> {
        self.store.static_report(&job.cksum).await.unwrap()
    }

    /// The `build_time_code` and `max_severity` columns of a stored report.
    async fn report_columns(&self, job: &StoredJob) -> (bool, Option<String>) {
        let query = format!(
            "SELECT build_time_code, max_severity FROM {}.static_reports WHERE sha256 = $1",
            self.db.schema()
        );

        let row = self
            .db
            .admin()
            .query_one(&query, &[&job.cksum.as_bytes().as_slice()])
            .await
            .unwrap();
        (row.get(0), row.get(1))
    }

    /// Changes a stored version, as an older or damaged database could hold it.
    async fn set_version(&self, job: &StoredJob, version: &str) {
        let update = format!(
            "UPDATE {}.jobs SET version = $1 WHERE id = $2",
            self.db.schema()
        );

        self.db
            .admin()
            .execute(&update, &[&version, &job.id.0])
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_rejected_archive_is_static_only() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let job = lab.job("bomb", "1.0.0").await;
    lab.crate_file(&job, None, 0).await;
    let decision = lab.decide(&job).await;

    assert_eq!(
        decision,
        Decision {
            triage: Triage::StaticOnly(StaticOnlyReason::ArchiveRejected),
            reasons: reasons(&["the archive failed validation and was not unpacked"]),
        }
    );
    assert_eq!(lab.recorded_diff(&job).await, None);
    assert!(lab.stored_report(&job).await.is_none());

    lab.finish().await;
}

#[tokio::test]
async fn no_lockfile_means_unresolved_dependencies() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let unlocked = lab.analyzed("solo", "1.0.0", true).await;
    let expected = Decision {
        triage: Triage::StaticOnly(StaticOnlyReason::UnresolvedDependencies),
        reasons: reasons(&["cargo could not resolve the dependencies"]),
    };

    assert_eq!(lab.decide(&unlocked).await, expected);
    assert_eq!(lab.recorded_diff(&unlocked).await, None);

    let failed = lab.analyzed("failed", "1.0.0", true).await;
    let none = json!([]);
    let record = lab
        .store
        .record_fetch(failed.id, None, Some("no matching package"), &none);
    record.await.unwrap();

    assert_eq!(lab.decide(&failed).await, expected);

    lab.finish().await;
}

#[tokio::test]
async fn a_lock_without_registry_dependencies_is_static_only() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let job = lab.analyzed("app", "1.0.0", false).await;
    lab.lock(&job, &[("app", "1.0.0")]).await;
    let decision = lab.decide(&job).await;

    assert_eq!(
        decision,
        Decision {
            triage: Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode),
            reasons: reasons(&[
                "building it runs no code of its own or of unfamiliar dependencies"
            ]),
        }
    );
    assert_eq!(lab.recorded_diff(&job).await, None);

    lab.finish().await;
}

#[tokio::test]
async fn an_unreadable_package_list_counts_as_empty() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let job = lab.analyzed("app", "1.0.0", false).await;
    lab.record_packages(&job, &json!({ "not": "a list" })).await;
    let decision = lab.decide(&job).await;

    assert_eq!(
        decision.triage,
        Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode)
    );

    lab.finish().await;
}

/// Earlier versions, statistics and tracked jobs decide which dependencies
/// with build time code are unfamiliar, and the newest earlier version is
/// the diff base.
#[tokio::test]
async fn familiar_dependencies_and_the_diff_base() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    // Earlier versions. Only 1.0.0 and 1.5.0 count, and 1.5.0 is the base.
    let first = lab.analyzed("app", "1.0.0", false).await;
    lab.lock(
        &first,
        &[("app", "1.0.0"), ("old", "1.0.0"), ("gone", "1.0.0")],
    )
    .await;
    let base = lab.analyzed("app", "1.5.0", false).await;
    lab.lock(&base, &[("app", "1.5.0"), ("old", "1.0.0")]).await;

    // A later version and one with an unreadable version teach nothing.
    let later = lab.job("app", "3.0.0").await;
    lab.lock(&later, &[("app", "3.0.0"), ("future", "1.0.0")])
        .await;
    let odd = lab.job("app", "0.9.0").await;
    lab.lock(&odd, &[("skipped", "1.0.0")]).await;
    lab.set_version(&odd, "oops").await;

    // Statistics: popular by reverse dependencies, by downloads, or not.
    lab.stats("by-reverse", 10, 50).await;
    lab.stats("by-downloads", 1000, 0).await;
    lab.stats("almost", 999, 49).await;

    // Tracked: a job for exactly that version exists.
    lab.job("tracked", "1.0.0").await;
    lab.job("wrong", "1.0.0").await;
    lab.analyzed("plain-dep", "1.0.0", false).await;

    let tar = tar_of("app", "2.0.0", true);
    let job = lab.publish("app", "2.0.0", &tar).await;
    let report = report_of(&tar);
    lab.store_report(
        &job,
        ANALYZER_VERSION,
        &serde_json::to_value(&report).unwrap(),
    )
    .await;
    let packages = [
        ("app", "2.0.0"),
        ("old", "1.0.0"),
        ("gone", "1.0.0"),
        ("future", "1.0.0"),
        ("skipped", "1.0.0"),
        ("by-reverse", "1.0.0"),
        ("by-downloads", "1.0.0"),
        ("almost", "1.0.0"),
        ("tracked", "1.0.0"),
        ("wrong", "1.0.1"),
        ("plain-dep", "1.0.0"),
        ("ghost", "1.0.0"),
    ];

    let mut list: Vec<Value> = packages
        .iter()
        .map(|(n, v)| json!({ "name": n, "version": v, "checksum": sha(n, v).to_string() }))
        .collect();
    list.push(json!({ "name": "bad", "version": "1.0.0", "checksum": "zz" }));
    lab.record_packages(&job, &Value::Array(list)).await;

    let decision = lab.decide(&job).await;

    assert_eq!(
        decision,
        Decision {
            triage: Triage::Dynamic,
            reasons: reasons(&[
                "build script build.rs",
                "unfamiliar dependencies with build time code: future 1.0.0, skipped 1.0.0, \
                 almost 1.0.0, wrong 1.0.1, ghost 1.0.0",
            ]),
        }
    );

    let previous = report_of(&tar_of("app", "1.5.0", false));
    let current: BTreeSet<String> = [
        "old",
        "gone",
        "future",
        "skipped",
        "by-reverse",
        "by-downloads",
        "almost",
        "tracked",
        "wrong",
        "plain-dep",
        "ghost",
    ]
    .map(str::to_owned)
    .into();
    let before = BTreeSet::from(["old".to_owned()]);
    let expected = diff(&report, &previous, "1.5.0", &current, &before);
    let recorded = lab.recorded_diff(&job).await.unwrap();

    assert_eq!(recorded, serde_json::to_value(&expected).unwrap());
    assert_eq!(recorded["previous_version"], "1.5.0");
    assert_eq!(recorded["build_script_added"], true);
    assert_eq!(
        recorded["new_dependencies"],
        json!([
            "almost",
            "by-downloads",
            "by-reverse",
            "future",
            "ghost",
            "gone",
            "plain-dep",
            "skipped",
            "tracked",
            "wrong"
        ])
    );

    lab.finish().await;
}

#[tokio::test]
async fn an_earlier_version_without_a_report_gives_no_diff() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let rejected = lab.job("app", "1.0.0").await;
    lab.crate_file(&rejected, None, 0).await;
    lab.lock(&rejected, &[("app", "1.0.0"), ("kept", "1.0.0")])
        .await;
    let job = lab.analyzed("app", "2.0.0", false).await;
    lab.lock(
        &job,
        &[("app", "2.0.0"), ("kept", "1.0.0"), ("new", "1.0.0")],
    )
    .await;
    let decision = lab.decide(&job).await;

    // `kept` is familiar from the earlier lock, `new` has no report and so
    // counts as running code.
    assert_eq!(
        decision,
        Decision {
            triage: Triage::Dynamic,
            reasons: reasons(&["unfamiliar dependencies with build time code: new 1.0.0"]),
        }
    );
    assert_eq!(lab.recorded_diff(&job).await, None);

    lab.finish().await;
}

#[tokio::test]
async fn a_job_without_a_crate_file_is_an_infrastructure_failure() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let job = lab.job("app", "1.0.0").await;
    let failure = lab.failure(&job).await;

    assert_eq!(failure.class, FailureClass::Infrastructure);
    assert_eq!(failure.message, "the fetch stage stored no crate file");

    lab.finish().await;
}

#[tokio::test]
async fn a_name_or_version_that_does_not_parse_fails_for_good() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let mut job = lab.job("app", "1.0.0").await;
    job.name = "not a name".to_owned();
    let failure = lab.failure(&job).await;

    assert_eq!(failure.class, FailureClass::Permanent);
    assert!(!failure.message.is_empty());

    job.name = "app".to_owned();
    job.version = "one".to_owned();
    let failure = lab.failure(&job).await;

    assert_eq!(failure.class, FailureClass::Permanent);
    assert!(!failure.message.is_empty());

    lab.finish().await;
}

#[tokio::test]
async fn a_missing_blob_is_an_infrastructure_failure() {
    let Some(lab) = Lab::start().await else {
        return;
    };

    let job = lab.job("app", "1.0.0").await;
    lab.crate_file(&job, Some("0".repeat(64)), 10).await;
    lab.lock(&job, &[("app", "1.0.0")]).await;
    let failure = lab.failure(&job).await;

    assert_eq!(failure.class, FailureClass::Infrastructure);

    let unlocked = lab.job("other", "1.0.0").await;
    lab.crate_file(&unlocked, Some("0".repeat(64)), 10).await;
    let failure = lab.failure(&unlocked).await;

    assert_eq!(failure.class, FailureClass::Infrastructure);

    lab.finish().await;
}

/// The child analyzes everything that has no current report in one go and
/// the reports land on the right crate files.
#[tokio::test]
async fn missing_reports_are_analyzed_and_recorded() {
    if !sandbox_available() {
        return;
    }

    let Some(lab) = Lab::start().await else {
        return;
    };

    let old_tar = tar_of("app", "1.0.0", false);
    let old = lab.publish("app", "1.0.0", &old_tar).await;
    lab.lock(&old, &[("app", "1.0.0")]).await;

    let tars = [
        ("app", "2.0.0", true),
        ("dep-a", "1.0.0", true),
        ("dep-b", "1.0.0", false),
    ]
    .map(|(name, version, build)| (name, version, tar_of(name, version, build)));

    let mut jobs = Vec::new();
    for (name, version, tar) in &tars {
        jobs.push(lab.publish(name, version, tar).await);
    }

    lab.lock(
        &jobs[0],
        &[
            ("app", "2.0.0"),
            ("dep-a", "1.0.0"),
            ("dep-b", "1.0.0"),
            ("dep-c", "1.0.0"),
        ],
    )
    .await;

    // `dep-a` runs code at build time, but it has a job of its own.
    let decision = lab.decide(&jobs[0]).await;

    assert_eq!(
        decision,
        Decision {
            triage: Triage::Dynamic,
            reasons: reasons(&[
                "build script build.rs",
                "unfamiliar dependencies with build time code: dep-c 1.0.0",
            ]),
        }
    );

    for ((job, (_, _, tar)), build) in jobs.iter().zip(&tars).zip([true, true, false]) {
        let report = report_of(tar);
        let (version, stored) = lab.stored_report(job).await.unwrap();

        assert_eq!(version, ANALYZER_VERSION);
        assert_eq!(stored, serde_json::to_value(&report).unwrap());
        assert_eq!(
            lab.report_columns(job).await,
            (build, max_severity(&report))
        );
    }

    let (version, stored) = lab.stored_report(&old).await.unwrap();

    assert_eq!(version, ANALYZER_VERSION);
    assert_eq!(stored, serde_json::to_value(report_of(&old_tar)).unwrap());

    let recorded = lab.recorded_diff(&jobs[0]).await.unwrap();

    assert_eq!(recorded["previous_version"], "1.0.0");
    assert_eq!(recorded["build_script_added"], true);
    assert_eq!(
        recorded["new_dependencies"],
        json!(["dep-a", "dep-b", "dep-c"])
    );

    lab.finish().await;
}

#[tokio::test]
async fn old_and_damaged_reports_are_analyzed_again() {
    if !sandbox_available() {
        return;
    }

    let Some(lab) = Lab::start().await else {
        return;
    };

    let tar = tar_of("app", "1.0.0", false);
    let job = lab.publish("app", "1.0.0", &tar).await;
    let dep_tar = tar_of("dep", "1.0.0", true);
    let dep = lab.publish("dep", "1.0.0", &dep_tar).await;
    let fresh = serde_json::to_value(report_of(&tar)).unwrap();
    let mut stale = fresh.clone();
    stale["files"] = json!(999);
    lab.store_report(&job, ANALYZER_VERSION - 1, &stale).await;
    lab.store_report(&dep, ANALYZER_VERSION, &json!({ "not": "a report" }))
        .await;
    lab.lock(&job, &[("app", "1.0.0"), ("dep", "1.0.0")]).await;

    lab.decide(&job).await;
    let (version, report) = lab.stored_report(&job).await.unwrap();

    assert_eq!(version, ANALYZER_VERSION);
    assert_eq!(report, fresh);

    let (version, report) = lab.stored_report(&dep).await.unwrap();

    assert_eq!(version, ANALYZER_VERSION);
    assert_eq!(report, serde_json::to_value(report_of(&dep_tar)).unwrap());
    assert!(lab.report_columns(&dep).await.0);

    lab.finish().await;
}

#[tokio::test]
async fn idle_time_refreshes_the_reports_of_scored_jobs_waiting_first() {
    if !sandbox_available() {
        return;
    }

    let Some(mut lab) = Lab::start().await else {
        return;
    };

    let tar = tar_of("app", "1.0.0", true);
    let waiting = lab.publish("app", "1.0.0", &tar).await;
    let unscored = lab
        .publish("lib", "1.0.0", &tar_of("lib", "1.0.0", false))
        .await;
    let broken = lab
        .publish(
            "bad",
            "1.0.0",
            &tar_with("bad", "1.0.0", &[("src/lib.rs", b"")]),
        )
        .await;
    for job in [&waiting, &unscored, &broken] {
        lab.store_report(job, ANALYZER_VERSION - 1, &json!({}))
            .await;
    }

    let verdict = Verdict {
        score: 60,
        level: RiskLevel::High,
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    };

    for job in [&waiting, &broken] {
        lab.store.record_verdict(job.id, &verdict).await.unwrap();
    }

    lab.store
        .set_review(waiting.id, Review::Pending, None)
        .await
        .unwrap();

    assert_eq!(lab.analyzer.refresh_some().await.unwrap(), 1);

    let (version, report) = lab.stored_report(&waiting).await.unwrap();

    assert_eq!(version, ANALYZER_VERSION);
    assert_eq!(report, serde_json::to_value(report_of(&tar)).unwrap());
    assert_eq!(
        lab.stored_report(&unscored).await.unwrap().0,
        ANALYZER_VERSION - 1
    );
    assert_eq!(
        lab.stored_report(&broken).await.unwrap().0,
        ANALYZER_VERSION - 1
    );

    // The archive that fails is not tried again.
    assert_eq!(lab.analyzer.refresh_some().await.unwrap(), 0);

    lab.finish().await;
}

#[tokio::test]
async fn an_archive_without_a_manifest_fails_the_job_after_the_others_are_recorded() {
    if !sandbox_available() {
        return;
    }

    let Some(lab) = Lab::start().await else {
        return;
    };

    let broken = tar_with("app", "1.0.0", &[("src/lib.rs", b"")]);
    let job = lab.publish("app", "1.0.0", &broken).await;
    let dep = lab
        .publish("dep", "1.0.0", &tar_of("dep", "1.0.0", false))
        .await;
    lab.lock(&job, &[("app", "1.0.0"), ("dep", "1.0.0")]).await;
    let failure = lab.failure(&job).await;

    assert_eq!(failure.class, FailureClass::Permanent);
    assert_eq!(failure.message, "the crate archive could not be analyzed");
    assert!(lab.stored_report(&job).await.is_none());
    assert!(lab.stored_report(&dep).await.is_some());

    lab.finish().await;
}

#[tokio::test]
async fn the_own_report_is_recorded_without_a_lockfile() {
    if !sandbox_available() {
        return;
    }

    let Some(lab) = Lab::start().await else {
        return;
    };

    let tar = tar_of("solo", "1.0.0", true);
    let job = lab.publish("solo", "1.0.0", &tar).await;
    let decision = lab.decide(&job).await;

    assert_eq!(
        decision.triage,
        Triage::StaticOnly(StaticOnlyReason::UnresolvedDependencies)
    );

    let (version, stored) = lab.stored_report(&job).await.unwrap();

    assert_eq!(version, ANALYZER_VERSION);
    assert_eq!(stored, serde_json::to_value(report_of(&tar)).unwrap());

    // A report that cannot be made does not fail the job here.
    let broken = tar_with("odd", "1.0.0", &[("src/lib.rs", b"")]);
    let odd = lab.publish("odd", "1.0.0", &broken).await;
    let decision = lab.decide(&odd).await;

    assert_eq!(
        decision.triage,
        Triage::StaticOnly(StaticOnlyReason::UnresolvedDependencies)
    );
    assert!(lab.stored_report(&odd).await.is_none());

    lab.finish().await;
}
