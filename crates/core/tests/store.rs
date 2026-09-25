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
use crateward_core::job::{JobEvent, JobState, Limits, Stage, StageLimits, Triage};
use crateward_core::name::CrateName;
use crateward_core::retry::RetryPolicy;
use crateward_core::store::{
    AlertOutcome, CrateFile, NewJob, PauseReason, Policies, Store, StoreError,
};

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
    assert_eq!(store.migrate().await.unwrap(), vec![1, 2, 3, 4, 5, 6]);
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
    // The delay is drawn from [0, 60 s]; it is almost always still running.
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
