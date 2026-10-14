//! Supervisor rounds against a private schema: alerts, burst mode, disk
//! usage, canaries and decoys.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use crateward_core::config::Config;
use crateward_core::escalation::HumanEscalation;
use crateward_core::store::{PauseReason, Store};
use crateward_core::testing::TestDb;
use crateward_supervisor::Supervisor;
use serde_json::json;

const EXAMPLE: &str = include_str!("../../../config/crateward.example.toml");

/// A scratch directory for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cw-supervisor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    dir
}

/// The example configuration with its directories and decoy in `dir`, no
/// notifier, and disk alerts from `disk_percent`.
fn config(dir: &Path, disk_percent: u8) -> Config {
    let mut config = Config::from_toml(EXAMPLE).unwrap();
    config.instance.data_dir = dir.to_path_buf();
    config.instance.run_dir = dir.to_path_buf();
    config.supervisor.decoys = vec![dir.join("decoy")];
    config.storage.disk_alert_percent = disk_percent;
    config.ntfy = None;

    config
}

async fn paused(store: &Store) -> Vec<PauseReason> {
    store
        .pauses()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.reason)
        .collect()
}

#[tokio::test]
async fn a_round_delivers_alerts_and_ends_a_finished_burst() {
    let Some(db) = TestDb::new("supervisor_quiet").await else {
        return;
    };

    let dir = scratch("quiet");
    let config = config(&dir, 101);
    let store = db.store().await;
    let mut supervisor = Supervisor::new(&config, db.migrated().await).unwrap();
    store
        .raise_alert(&HumanEscalation::CanaryFailure)
        .await
        .unwrap();
    store.pause(PauseReason::Burst, None, "test").await.unwrap();

    supervisor.round().await.unwrap();

    assert!(store.pending_alerts(10).await.unwrap().is_empty());
    assert!(paused(&store).await.is_empty());
    assert!(dir.join("decoy").exists());

    db.drop().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_full_disk_pauses_the_sandbox_until_it_has_room() {
    let Some(db) = TestDb::new("supervisor_disk").await else {
        return;
    };

    let dir = scratch("disk");
    let store = db.migrated().await;

    let full = config(&dir, 0);
    let mut supervisor = Supervisor::new(&full, db.store().await).unwrap();
    supervisor.round().await.unwrap();
    assert_eq!(paused(&store).await, [PauseReason::Disk]);

    let room = config(&dir, 101);
    let mut supervisor = Supervisor::new(&room, db.store().await).unwrap();
    supervisor.round().await.unwrap();
    assert!(paused(&store).await.is_empty());

    db.drop().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_failed_canary_pauses_until_it_passes_again() {
    let Some(db) = TestDb::new("supervisor_canary").await else {
        return;
    };

    let dir = scratch("canary");
    let config = config(&dir, 101);
    let store = db.migrated().await;
    let mut supervisor = Supervisor::new(&config, db.store().await).unwrap();

    store
        .record_canary("steal", false, &json!({}))
        .await
        .unwrap();
    supervisor.round().await.unwrap();
    assert_eq!(paused(&store).await, [PauseReason::Canary]);

    store
        .record_canary("steal", true, &json!({}))
        .await
        .unwrap();
    supervisor.round().await.unwrap();
    assert!(paused(&store).await.is_empty());

    db.drop().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn reading_a_decoy_quarantines_the_pipeline() {
    let Some(db) = TestDb::new("supervisor_decoy").await else {
        return;
    };

    let dir = scratch("decoy");
    let config = config(&dir, 101);
    let store = db.migrated().await;
    let mut supervisor = Supervisor::new(&config, db.store().await).unwrap();

    supervisor.round().await.unwrap();
    assert!(paused(&store).await.is_empty());

    std::fs::read(dir.join("decoy")).unwrap();
    supervisor.round().await.unwrap();
    assert_eq!(paused(&store).await, [PauseReason::Quarantine]);

    db.drop().await;
    std::fs::remove_dir_all(dir).unwrap();
}
