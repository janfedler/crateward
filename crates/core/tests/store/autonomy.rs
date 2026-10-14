//! Quarantine, breakers, pauses and alerts.

use super::*;

#[tokio::test]
async fn a_suspected_compromise_quarantines_everything_until_lifted() {
    let Some(db) = TestDb::new("test").await else {
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
    let Some(db) = TestDb::new("test").await else {
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
        BreakerState::default()
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
    assert!(!store.bursting().await.unwrap());

    // Burst mode, like a full disk, stops only the sandbox stage.
    assert!(
        store
            .pause(PauseReason::Burst, None, "burst")
            .await
            .unwrap()
    );
    assert!(store.bursting().await.unwrap());
    assert_eq!(PauseReason::Burst.stages(), PauseReason::Disk.stages());

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
    let Some(db) = TestDb::new("test").await else {
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
