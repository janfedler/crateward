//! Enqueueing, claiming, completing and leases.

use super::*;

#[tokio::test]
async fn migrations_are_idempotent() {
    let Some(db) = TestDb::new("test").await else {
        return;
    };

    let mut store = db.store().await;
    assert_eq!(
        store.migrate().await.unwrap(),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    );
    assert!(store.migrate().await.unwrap().is_empty());

    db.drop().await;
}

#[tokio::test]
async fn enqueue_is_idempotent_per_canonical_name_and_version() {
    let Some(db) = TestDb::new("test").await else {
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
    let Some(db) = TestDb::new("test").await else {
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
    let Some(db) = TestDb::new("test").await else {
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
    let Some(db) = TestDb::new("test").await else {
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
    let Some(db) = TestDb::new("test").await else {
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
    let Some(db) = TestDb::new("test").await else {
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
