//! Integration tests of the job store against a real PostgreSQL.
//!
//! Set `CRATEWARD_TEST_DATABASE_URL` (for example
//! `host=/var/run/postgresql dbname=crateward_dev`). Each test works in its
//! own schema, dropped at the end. Without the variable the tests skip,
//! unless `CRATEWARD_REQUIRE_DB=1`, which CI sets so that a missing database
//! fails instead of passing silently.

#![cfg(feature = "store")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crateward_core::breaker::{BreakerState, Counts};
use crateward_core::escalation::HumanEscalation;
use crateward_core::failure::FailureClass;
use crateward_core::job::{JobEvent, JobId, JobState, Limits, Stage, StageLimits, Triage};
use crateward_core::name::CrateName;
use crateward_core::retry::RetryPolicy;
use crateward_core::store::{
    AlertOutcome, CrateFile, DisclosureKind, DisclosureRefusal, NewJob, PauseReason, Policies,
    Review, Store, StoreError,
};
use crateward_core::verdict::{Coverage, RiskLevel, Verdict};

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct TestDb {
    config: String,
    schema: String,
}

impl TestDb {
    async fn new() -> Option<Self> {
        let Ok(config) = std::env::var("CRATEWARD_TEST_DATABASE_URL") else {
            assert!(
                std::env::var("CRATEWARD_REQUIRE_DB").is_err(),
                "CRATEWARD_REQUIRE_DB is set but CRATEWARD_TEST_DATABASE_URL is not"
            );
            eprintln!("skipping: CRATEWARD_TEST_DATABASE_URL is not set");
            return None;
        };
        let schema = format!(
            "test_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let db = Self { config, schema };
        let admin = db.raw().await;
        admin
            .batch_execute(&format!("CREATE SCHEMA {}", db.schema))
            .await
            .unwrap();
        Some(db)
    }

    async fn raw(&self) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(&self.config, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client
    }

    /// A store whose session uses the test schema.
    async fn store(&self) -> Store {
        let client = self.raw().await;
        client
            .batch_execute(&format!("SET search_path TO {}", self.schema))
            .await
            .unwrap();
        Store::from_client(client)
    }

    async fn drop(self) {
        self.raw()
            .await
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

fn policies() -> Policies {
    let policy = RetryPolicy::new(Duration::from_secs(60), Duration::from_secs(600)).unwrap();
    Policies {
        limits: Limits::uniform(StageLimits {
            max_attempts: 3,
            max_infrastructure_retries: 2,
        }),
        backoff: Stage::ALL
            .iter()
            .map(|s| (s.name(), policy))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn new_job(name: &str, version: &str, priority: i16) -> NewJob {
    NewJob {
        name: CrateName::parse(name).unwrap(),
        version: version.parse().unwrap(),
        cksum: "ab".repeat(32).parse().unwrap(),
        published_at: None,
        priority,
        index_entry: serde_json::json!({"name": name, "vers": version}),
    }
}

const LEASE: Duration = Duration::from_secs(30);

#[tokio::test]
async fn migrations_are_idempotent() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    assert_eq!(
        store.migrate().await.unwrap(),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    );
    assert!(store.migrate().await.unwrap().is_empty());
    db.drop().await;
}

#[tokio::test]
async fn enqueue_is_idempotent_per_canonical_name_and_version() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    assert!(
        store
            .enqueue(&new_job("serde-json", "1.0.0", 0))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .enqueue(&new_job("serde-json", "1.0.0", 0))
            .await
            .unwrap()
            .is_none()
    );
    // crates.io treats these names as the same crate.
    assert!(
        store
            .enqueue(&new_job("Serde_Json", "1.0.0", 0))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .enqueue(&new_job("serde-json", "1.0.1", 0))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .contains(&CrateName::parse("serde_json").unwrap(), "1.0.1")
            .await
            .unwrap()
    );
    db.drop().await;
}

#[tokio::test]
async fn claims_follow_priority_stage_and_skip_locked_rows() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let low = store
        .enqueue(&new_job("low", "1.0.0", 1))
        .await
        .unwrap()
        .unwrap();
    let high = store
        .enqueue(&new_job("high", "1.0.0", 9))
        .await
        .unwrap()
        .unwrap();
    // Nothing is fetched yet, so the static analysis stage finds nothing.
    assert!(
        store
            .claim(Stage::StaticAnalysis, "w", LEASE)
            .await
            .unwrap()
            .is_none()
    );
    let other = db.store().await;
    let first = store
        .claim(Stage::Fetch, "w1", LEASE)
        .await
        .unwrap()
        .unwrap();
    let second = other
        .claim(Stage::Fetch, "w2", LEASE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.id, high);
    assert_eq!(second.id, low);
    assert!(
        store
            .claim(Stage::Fetch, "w3", LEASE)
            .await
            .unwrap()
            .is_none()
    );
    db.drop().await;
}

#[tokio::test]
async fn complete_advances_releases_and_records() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let id = store
        .enqueue(&new_job("a", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    store
        .claim(Stage::Fetch, "fetcher-1", LEASE)
        .await
        .unwrap()
        .unwrap();
    // Another worker cannot complete a job it does not hold.
    assert!(matches!(
        store
            .complete(id, "intruder", JobEvent::Fetched, &policies(), false)
            .await,
        Err(StoreError::LeaseLost(_))
    ));
    store
        .complete(id, "fetcher-1", JobEvent::Fetched, &policies(), false)
        .await
        .unwrap();
    let job = store.get(id).await.unwrap().unwrap();
    assert_eq!(job.job.state, JobState::Fetched);
    // Released: the next stage can claim it at once.
    let claimed = store
        .claim(Stage::StaticAnalysis, "sa", LEASE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.id, id);
    store
        .complete(
            id,
            "sa",
            JobEvent::StaticAnalysisCompleted {
                triage: Triage::Dynamic,
            },
            &policies(),
            false,
        )
        .await
        .unwrap();
    let events = store.events(id).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].from, "Discovered");
    assert_eq!(events[1].to, "ReadyForSandbox");
    assert_eq!(events[1].worker, "sa");
    // A rejected event changes nothing.
    store
        .claim(Stage::Sandbox, "sb", LEASE)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        store
            .complete(id, "sb", JobEvent::Finalized, &policies(), false)
            .await,
        Err(StoreError::Transition(_))
    ));
    assert_eq!(
        store.get(id).await.unwrap().unwrap().job.state,
        JobState::ReadyForSandbox
    );
    db.drop().await;
}

#[tokio::test]
async fn a_transient_failure_backs_off() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let id = store
        .enqueue(&new_job("flaky", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    store
        .claim(Stage::Fetch, "w", LEASE)
        .await
        .unwrap()
        .unwrap();
    let failure = JobEvent::StageFailed {
        class: FailureClass::Transient,
    };
    store
        .complete(id, "w", failure, &policies(), false)
        .await
        .unwrap();
    let job = store.get(id).await.unwrap().unwrap();
    assert_eq!(job.job.state, JobState::Discovered);
    assert_eq!(job.job.attempts, 1);
    // The delay is drawn from [0, 60 s]. It is almost always still running.
    // Either way the job must stay in its stage.
    if let Some(again) = store.claim(Stage::Fetch, "w", LEASE).await.unwrap() {
        assert_eq!(again.id, id);
    }
    db.drop().await;
}

#[tokio::test]
async fn expired_leases_are_reaped_and_cost_an_attempt() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let id = store
        .enqueue(&new_job("crashy", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    store
        .claim(Stage::Fetch, "dead-worker", Duration::from_millis(100))
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(store.reap_expired(&policies()).await.unwrap(), 1);
    let job = store.get(id).await.unwrap().unwrap();
    assert_eq!(job.job.attempts, 1);
    // The dead worker's late heartbeat and completion are refused.
    assert!(!store.heartbeat(id, "dead-worker", LEASE).await.unwrap());
    assert!(matches!(
        store
            .complete(id, "dead-worker", JobEvent::Fetched, &policies(), false)
            .await,
        Err(StoreError::LeaseLost(_))
    ));
    db.drop().await;
}

#[tokio::test]
async fn sandbox_start_keeps_the_lease_for_the_run() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let id = store
        .enqueue(&new_job("vm", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    let p = policies();
    store.claim(Stage::Fetch, "f", LEASE).await.unwrap();
    store
        .complete(id, "f", JobEvent::Fetched, &p, false)
        .await
        .unwrap();
    store
        .claim(Stage::StaticAnalysis, "s", LEASE)
        .await
        .unwrap();
    let triage = JobEvent::StaticAnalysisCompleted {
        triage: Triage::Dynamic,
    };
    store.complete(id, "s", triage, &p, false).await.unwrap();
    store
        .claim(Stage::Sandbox, "o", LEASE)
        .await
        .unwrap()
        .unwrap();
    store
        .complete(id, "o", JobEvent::SandboxStarted, &p, true)
        .await
        .unwrap();
    assert!(
        store.heartbeat(id, "o", LEASE).await.unwrap(),
        "lease was dropped"
    );
    let counts = store.count_by_state().await.unwrap();
    assert_eq!(counts.get("Running"), Some(&1));
    db.drop().await;
}

#[tokio::test]
async fn static_reports_fetches_and_popularity_round_trip() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let old = store
        .enqueue(&new_job("lib", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    let new = store
        .enqueue(&new_job("lib", "1.1.0", 0))
        .await
        .unwrap()
        .unwrap();
    let packages = serde_json::json!([{"name": "cc", "version": "1.0.0", "checksum": "00"}]);
    store
        .record_fetch(old, Some("lock"), None, &packages)
        .await
        .unwrap();
    store
        .record_fetch(new, Some("lock"), None, &packages)
        .await
        .unwrap();
    assert_eq!(
        store.fetch_packages(new).await.unwrap(),
        Some(packages.clone())
    );
    let name = CrateName::parse("lib").unwrap();
    let others = store.other_fetches(&name, new).await.unwrap();
    assert_eq!(others.len(), 1);
    assert_eq!((others[0].0, others[0].1.as_str()), (old, "1.0.0"));

    let sha = "cd".repeat(32).parse().unwrap();
    assert_eq!(store.static_report(&sha).await.unwrap(), None);
    store
        .record_crate_file(&CrateFile {
            sha256: sha,
            name: "lib".into(),
            version: "1.1.0".into(),
            blake3: Some("ef".repeat(32)),
            compressed_bytes: 1,
            unpacked_bytes: 2,
            stored_bytes: Some(1),
            report: serde_json::json!({}),
        })
        .await
        .unwrap();
    let report = serde_json::json!({"findings": []});
    store
        .record_static_report(&sha, 7, true, Some("high"), &report)
        .await
        .unwrap();
    assert_eq!(store.static_report(&sha).await.unwrap(), Some((7, report)));

    store
        .upsert_crate_stats(&[
            ("Many-Deps".into(), 10, 500),
            ("many_downloads".into(), 5_000, 1),
        ])
        .await
        .unwrap();
    let mut popular = store
        .popular_among(
            &[
                "many-deps".into(),
                "many_downloads".into(),
                "unknown".into(),
            ],
            100,
            1_000,
        )
        .await
        .unwrap();
    popular.sort();
    assert_eq!(
        popular,
        vec!["many_deps".to_owned(), "many_downloads".to_owned()]
    );

    let triage = serde_json::json!({"kind": "dynamic"});
    store
        .record_job_static(new, &triage, &serde_json::json!(["build script"]), None)
        .await
        .unwrap();
    db.drop().await;
}

#[tokio::test]
async fn a_suspected_compromise_quarantines_everything_until_lifted() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let a = store
        .enqueue(&new_job("a", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    store
        .enqueue(&new_job("b", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    let job = store
        .claim(Stage::Fetch, "w", LEASE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.id, a);
    let event = JobEvent::StageFailed {
        class: FailureClass::SuspectedCompromise,
    };
    store
        .complete(a, "w", event, &policies(), false)
        .await
        .unwrap();
    // The other job waits: every stage is paused.
    assert!(
        store
            .claim(Stage::Fetch, "w", LEASE)
            .await
            .unwrap()
            .is_none()
    );
    let pauses = store.pauses().await.unwrap();
    assert_eq!(pauses.len(), 1);
    assert_eq!(pauses[0].reason, PauseReason::Quarantine);
    assert_eq!(pauses[0].job, Some(a));
    let alerts = store.pending_alerts(10).await.unwrap();
    assert_eq!(
        alerts[0].escalation,
        HumanEscalation::SandboxEscapeIndicator { job: Some(a) }
    );
    assert!(store.lift_pause(PauseReason::Quarantine).await.unwrap());
    assert!(!store.lift_pause(PauseReason::Quarantine).await.unwrap());
    assert!(
        store
            .claim(Stage::Fetch, "w", LEASE)
            .await
            .unwrap()
            .is_some()
    );
    db.drop().await;
}

#[tokio::test]
async fn an_open_breaker_or_pause_stops_only_its_stages() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    store
        .enqueue(&new_job("a", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();
    let now = store.now_epoch().await.unwrap();
    let open = BreakerState::Open {
        since: now,
        reopened: 1,
    };
    store.set_breaker(Stage::Fetch, open).await.unwrap();
    assert_eq!(store.breakers().await.unwrap()[&Stage::Fetch], open);
    assert_eq!(
        store.breakers().await.unwrap()[&Stage::Sandbox],
        BreakerState::Closed
    );
    assert!(
        store
            .claim(Stage::Fetch, "w", LEASE)
            .await
            .unwrap()
            .is_none()
    );
    store
        .set_breaker(
            Stage::Fetch,
            BreakerState::HalfOpen {
                since: now,
                reopened: 1,
            },
        )
        .await
        .unwrap();
    // A disk pause does not concern the fetch stage.
    assert!(store.pause(PauseReason::Disk, None, "full").await.unwrap());
    assert!(!store.pause(PauseReason::Disk, None, "again").await.unwrap());
    let job = store
        .claim(Stage::Fetch, "w", LEASE)
        .await
        .unwrap()
        .unwrap();
    store
        .complete(
            job.id,
            "w",
            JobEvent::StageFailed {
                class: FailureClass::Infrastructure,
            },
            &policies(),
            false,
        )
        .await
        .unwrap();
    let counts = store.stage_counts(now - 60).await.unwrap();
    assert_eq!(
        counts[&Stage::Fetch],
        Counts {
            failures: 1,
            completions: 0
        }
    );
    db.drop().await;
}

#[tokio::test]
async fn alerts_are_recorded_and_marked() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    store.raise_alert(&HumanEscalation::KvmError).await.unwrap();
    store.raise_alert(&HumanEscalation::KvmError).await.unwrap();
    let pending = store.pending_alerts(10).await.unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(store.seconds_since_sent("kvm_error").await.unwrap(), None);
    store
        .mark_alert(pending[0].id, &AlertOutcome::Sent)
        .await
        .unwrap();
    store
        .mark_alert(pending[1].id, &AlertOutcome::Suppressed)
        .await
        .unwrap();
    assert!(store.pending_alerts(10).await.unwrap().is_empty());
    assert!(
        store
            .seconds_since_sent("kvm_error")
            .await
            .unwrap()
            .is_some()
    );
    store
        .record_canary("known_bad", false, &serde_json::json!({"why": "missed"}))
        .await
        .unwrap();
    store
        .record_canary("known_bad", true, &serde_json::json!({}))
        .await
        .unwrap();
    let latest = store.latest_canaries().await.unwrap();
    assert_eq!(latest.len(), 1);
    assert!(latest[0].1);
    db.drop().await;
}

#[tokio::test]
async fn verdicts_are_stored_reviewed_and_found_for_the_previous_version() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let old = store
        .enqueue(&new_job("demo", "1.2.0", 0))
        .await
        .unwrap()
        .unwrap();
    let new = store
        .enqueue(&new_job("demo", "1.10.0", 0))
        .await
        .unwrap()
        .unwrap();
    let verdict = |score, profile: &[&str]| Verdict {
        score,
        level: RiskLevel::from_score(score),
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: profile.iter().map(|p| (*p).to_owned()).collect(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    };
    store
        .record_verdict(old, &verdict(10, &["exec:shell"]))
        .await
        .unwrap();
    store
        .record_verdict(new, &verdict(70, &["net:example.com"]))
        .await
        .unwrap();
    let (stored, review) = store.verdict(new).await.unwrap().unwrap();
    assert_eq!((stored.score, review), (70, Review::None));
    assert!(
        store
            .set_review(new, Review::Pending, Some("look"))
            .await
            .unwrap()
    );
    assert_eq!(
        store.verdict(new).await.unwrap().unwrap().1,
        Review::Pending
    );
    // Semantic version order: 1.2.0 comes before 1.10.0.
    let previous = store
        .previous_profile("demo", &"1.10.0".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(previous, Some(vec!["exec:shell".to_owned()]));
    assert_eq!(
        store
            .previous_profile("demo", &"1.2.0".parse().unwrap())
            .await
            .unwrap(),
        None
    );
    // Neither job is finished, so nothing is outdated yet.
    assert!(store.outdated_verdicts(2, 10).await.unwrap().is_empty());
    db.drop().await;
}

#[tokio::test]
async fn old_unflagged_runs_lose_their_raw_data_only() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let report = serde_json::json!({
        "stdout_tail": "out", "stderr_tail": "err",
        "trace": {"processes": [{"pid": 1}, {"pid": 2}], "processes_omitted": 3,
                  "sockets": [{"to": "example.com"}]},
        "network": {"lookups": 1}
    });
    let mut jobs = Vec::new();
    for (version, score, review) in [
        ("1.0.0", 5, Review::None),
        ("2.0.0", 70, Review::Pending),
        ("3.0.0", 5, Review::None),
    ] {
        let job = store
            .enqueue(&new_job("kept", version, 0))
            .await
            .unwrap()
            .unwrap();
        store
            .record_run(job, "check", "Built", &report)
            .await
            .unwrap();
        store
            .record_verdict(
                job,
                &Verdict {
                    score,
                    level: RiskLevel::from_score(score),
                    coverage: Coverage::DynamicLinux,
                    evidence: Vec::new(),
                    profile: Vec::new(),
                    new_behavior: Vec::new(),
                    analyzer_version: 1,
                },
            )
            .await
            .unwrap();
        store.set_review(job, review, None).await.unwrap();
        jobs.push(job);
    }
    let raw = db.raw().await;
    raw.batch_execute(&format!(
        "SET search_path TO {}; UPDATE jobs SET state = 'Done';
         UPDATE job_runs SET recorded_at = now() - interval '9 days'
         WHERE job_id IN ({}, {})",
        db.schema, jobs[0].0, jobs[1].0
    ))
    .await
    .unwrap();

    assert_eq!(store.trim_raw_runs(7, 100).await.unwrap(), 1);
    assert_eq!(store.trim_raw_runs(7, 100).await.unwrap(), 0);
    let trimmed = &store.job_runs(jobs[0]).await.unwrap()[0].1;
    assert_eq!(trimmed["stderr_tail"], "");
    assert_eq!(trimmed["trimmed"], true);
    assert_eq!(trimmed["trace"]["processes"], serde_json::json!([]));
    assert_eq!(trimmed["trace"]["processes_omitted"], 5);
    assert_eq!(trimmed["trace"]["sockets"], report["trace"]["sockets"]);
    assert_eq!(trimmed["network"], report["network"]);
    for job in &jobs[1..] {
        assert_eq!(store.job_runs(*job).await.unwrap()[0].1, report);
    }
    // A trimmed job keeps its verdict when the analyzer changes.
    let outdated: Vec<_> = store
        .outdated_verdicts(2, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|j| j.id)
        .collect();
    assert!(!outdated.contains(&jobs[0]));
    assert!(outdated.contains(&jobs[2]));
    db.drop().await;
}

#[tokio::test]
async fn findings_are_reported_resolved_and_only_then_published() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let job = store
        .enqueue(&new_job("evil", "0.1.0", 0))
        .await
        .unwrap()
        .unwrap();
    let other = store
        .enqueue(&new_job("worse", "0.2.0", 0))
        .await
        .unwrap()
        .unwrap();
    let verdict = Verdict {
        score: 90,
        level: RiskLevel::from_score(90),
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    };
    let report = |job| {
        let store = &store;
        async move {
            store
                .record_report(job, DisclosureKind::Malicious, "help@crates.io", None, None)
                .await
                .unwrap()
        }
    };
    // No verdict, then an unconfirmed one: nothing is reported.
    assert_eq!(report(job).await, Err(DisclosureRefusal::NotConfirmed));
    store.record_verdict(job, &verdict).await.unwrap();
    store.set_review(job, Review::Pending, None).await.unwrap();
    assert_eq!(report(job).await, Err(DisclosureRefusal::NotConfirmed));
    // Publishing needs a report, then a resolution.
    assert_eq!(
        store.publish_finding(job, "evil").await.unwrap(),
        Err(DisclosureRefusal::NotReported)
    );
    assert_eq!(
        store.mark_resolved(job, None).await.unwrap(),
        Err(DisclosureRefusal::NotReported)
    );
    store
        .set_review(job, Review::Confirmed, None)
        .await
        .unwrap();
    assert_eq!(report(job).await, Ok(()));
    assert_eq!(
        store.publish_finding(job, "evil").await.unwrap(),
        Err(DisclosureRefusal::NotResolved)
    );
    assert!(store.published_findings().await.unwrap().is_empty());
    assert_eq!(
        store.mark_resolved(job, Some("CRATES-1")).await.unwrap(),
        Ok(())
    );
    assert_eq!(
        store.publish_finding(job, "Bad/Slug").await.unwrap(),
        Err(DisclosureRefusal::BadSlug)
    );
    assert_eq!(
        store.publish_finding(job, "evil-0-1-0").await.unwrap(),
        Ok(())
    );
    let record = store.disclosure(job).await.unwrap().unwrap();
    assert_eq!(record.reference.as_deref(), Some("CRATES-1"));
    assert!(record.resolved_on.is_some() && record.published_on.is_some());
    let published = store.published_findings().await.unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(
        (published[0].name.as_str(), published[0].slug.as_str()),
        ("evil", "evil-0-1-0")
    );
    // A second finding cannot take the same page.
    store.record_verdict(other, &verdict).await.unwrap();
    store
        .set_review(other, Review::Confirmed, None)
        .await
        .unwrap();
    assert_eq!(report(other).await, Ok(()));
    store.mark_resolved(other, None).await.unwrap().unwrap();
    assert_eq!(
        store.publish_finding(other, "evil-0-1-0").await.unwrap(),
        Err(DisclosureRefusal::SlugTaken)
    );
    assert!(store.disclosure(JobId(i64::MAX)).await.unwrap().is_none());

    // crates.io removed a crate before it was reported: no report, but
    // resolved, so it may be published. Only a confirmed verdict counts.
    let gone = store
        .enqueue(&new_job("gone", "0.1.0", 0))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store.record_removal(gone, None).await.unwrap(),
        Err(DisclosureRefusal::NotConfirmed)
    );
    store.record_verdict(gone, &verdict).await.unwrap();
    store
        .set_review(gone, Review::Confirmed, None)
        .await
        .unwrap();
    let note = Some("removed on 2026-10-01");
    assert_eq!(store.record_removal(gone, note).await.unwrap(), Ok(()));
    let record = store.disclosure(gone).await.unwrap().unwrap();
    assert_eq!(record.kind, DisclosureKind::Malicious);
    assert!(record.reported_on.is_none() && record.reported_to.is_none());
    assert!(record.resolved_on.is_some());
    assert_eq!(record.reported(), crateward_core::store::REMOVED_FIRST);
    assert_eq!(store.publish_finding(gone, "gone").await.unwrap(), Ok(()));
    let published = store.published_findings().await.unwrap();
    assert!(
        published
            .iter()
            .any(|f| f.slug == "gone" && f.reported_on.is_none())
    );
    // A report recorded later fills the report in.
    assert_eq!(report(gone).await, Ok(()));
    let record = store.disclosure(gone).await.unwrap().unwrap();
    assert!(record.reported_on.is_some() && record.resolved_on.is_some());
    // The database refuses a vulnerability without a report.
    let raw = db.raw().await;
    let refused = raw
        .batch_execute(&format!(
            "SET search_path TO {}; UPDATE disclosures
             SET kind = 'vulnerability', reported_to = NULL, reported_at = NULL
             WHERE job_id = {}",
            db.schema, gone.0
        ))
        .await;
    assert!(refused.is_err());
    db.drop().await;
}
