//! The analysis and finalize stages against a private schema: scoring,
//! the review inbox, rescoring and the SBOM sweep.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use crateward_analyzer::score::ANALYZER_VERSION;
use crateward_analyzer::worker::Analyzer;
use crateward_core::escalation::HumanEscalation;
use crateward_core::job::{JobEvent, JobId, JobState, Stage, Triage};
use crateward_core::store::{CrateFile, NewJob, Review, Store};
use crateward_core::testing::{TestDb, policies};
use crateward_core::verdict::{
    Coverage, Evidence, EvidenceSource, RiskLevel, STATIC_ANALYZER_VERSION, StaticOnlyReason,
    Verdict,
};
use serde_json::{Value, json};

const LEASE: Duration = Duration::from_secs(30);

/// A static only job of `name`, moved through `events` after the fetch and
/// static analysis.
async fn job(store: &mut Store, name: &str, n: u8, events: &[(Stage, JobEvent)]) -> JobId {
    let new = NewJob {
        name: name.parse().unwrap(),
        version: "0.1.0".parse().unwrap(),
        cksum: format!("{n:02x}").repeat(32).parse().unwrap(),
        published_at: None,
        priority: 0,
        index_entry: json!({}),
    };

    let job = store.enqueue(&new).await.unwrap().unwrap();
    let triage = Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode);
    let steps = [
        (Stage::Fetch, JobEvent::Fetched),
        (
            Stage::StaticAnalysis,
            JobEvent::StaticAnalysisCompleted { triage },
        ),
    ];

    for (stage, event) in steps.iter().chain(events) {
        store.claim(*stage, "w", LEASE).await.unwrap().unwrap();
        store
            .complete(job, "w", *event, &policies(), false)
            .await
            .unwrap();
    }

    store
        .record_fetch(job, None, Some("unresolvable"), &json!([]))
        .await
        .unwrap();

    job
}

/// The steps from analysis to done, without the analyzer.
fn finished() -> [(Stage, JobEvent); 2] {
    [
        (Stage::Analysis, JobEvent::Scored { escalate: false }),
        (Stage::Finalize, JobEvent::Finalized),
    ]
}

/// A verdict of `score` from analyzer `version`.
fn verdict(score: u32, version: u32) -> Verdict {
    Verdict {
        score,
        level: RiskLevel::from_score(score),
        coverage: Coverage::DynamicLinux,
        evidence: vec![Evidence {
            signal: "honeytoken_left_vm".to_owned(),
            points: score,
            source: EvidenceSource::Network,
            summary: "sent a token".to_owned(),
            package: None,
            location: None,
        }],
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: version,
    }
}

/// Records `report` as the static report of job `n`'s crate file.
async fn report(store: &Store, n: u8, report: &Value) {
    let sha256 = format!("{n:02x}").repeat(32).parse().unwrap();
    store
        .record_crate_file(&CrateFile {
            sha256,
            sha512: None,
            name: "odd".into(),
            version: "0.1.0".into(),
            blake3: Some("ef".repeat(32)),
            compressed_bytes: 1,
            unpacked_bytes: 2,
            stored_bytes: Some(1),
            report: json!({}),
        })
        .await
        .unwrap();

    store
        .record_static_report(&sha256, STATIC_ANALYZER_VERSION, false, None, report)
        .await
        .unwrap();
}

async fn state(store: &Store, job: JobId) -> JobState {
    store.get(job).await.unwrap().unwrap().job.state
}

async fn analyzer(db: &TestDb) -> (Analyzer, Store) {
    let analyzer = Analyzer::new(db.migrated().await, policies(), "a".to_owned(), LEASE);

    (analyzer, db.store().await)
}

#[tokio::test]
async fn a_job_is_scored_finalized_and_gets_an_sbom() {
    let Some(db) = TestDb::new("analyzer_flow").await else {
        return;
    };

    let (mut analyzer, mut store) = analyzer(&db).await;
    let job = job(&mut store, "plain", 1, &[]).await;

    assert!(analyzer.analyze_once().await.unwrap());
    assert!(!analyzer.analyze_once().await.unwrap());
    assert_eq!(state(&store, job).await, JobState::Scored);

    let (scored, review) = store.verdict(job).await.unwrap().unwrap();
    assert_eq!(scored.analyzer_version, ANALYZER_VERSION);
    assert!(!scored.level.needs_review());

    assert!(analyzer.finalize_once().await.unwrap());
    assert!(!analyzer.finalize_once().await.unwrap());
    assert_eq!(state(&store, job).await, JobState::Done);
    assert_eq!(review, Review::None);
    assert!(store.job_sbom(job).await.unwrap().is_some());
    assert!(store.pending_alerts(10).await.unwrap().is_empty());

    db.drop().await;
}

#[tokio::test]
async fn a_high_verdict_enters_the_inbox_with_an_alert() {
    let Some(db) = TestDb::new("analyzer_inbox").await else {
        return;
    };

    let (mut analyzer, mut store) = analyzer(&db).await;
    let scored = [(Stage::Analysis, JobEvent::Scored { escalate: false })];
    let job = job(&mut store, "loud", 2, &scored).await;
    store
        .record_verdict(job, &verdict(90, ANALYZER_VERSION))
        .await
        .unwrap();

    assert!(analyzer.finalize_once().await.unwrap());

    let (_, review) = store.verdict(job).await.unwrap().unwrap();
    assert_eq!(review, Review::Pending);

    let alerts = store.pending_alerts(10).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0].escalation,
        HumanEscalation::HighRiskVerdict { job }
    );

    db.drop().await;
}

#[tokio::test]
async fn unusable_stored_data_fails_the_job_for_good() {
    let Some(db) = TestDb::new("analyzer_data").await else {
        return;
    };

    let (mut analyzer, mut store) = analyzer(&db).await;
    let job = job(&mut store, "odd", 3, &[]).await;
    report(&store, 3, &json!("not a report")).await;

    assert!(analyzer.analyze_once().await.unwrap());
    assert_eq!(state(&store, job).await, JobState::Failed);
    assert_eq!(store.verdict(job).await.unwrap(), None);

    db.drop().await;
}

#[tokio::test]
async fn old_verdicts_are_rescored_and_leave_the_inbox() {
    let Some(db) = TestDb::new("analyzer_rescore").await else {
        return;
    };

    let (mut analyzer, mut store) = analyzer(&db).await;
    let calmed = job(&mut store, "calmed", 4, &finished()).await;
    store.record_verdict(calmed, &verdict(90, 1)).await.unwrap();
    store
        .set_review(calmed, Review::Pending, None)
        .await
        .unwrap();

    // Its report no longer decodes, so it keeps the old verdict.
    let broken = job(&mut store, "odd", 5, &finished()).await;
    store.record_verdict(broken, &verdict(10, 1)).await.unwrap();
    report(&store, 5, &json!("not a report")).await;

    assert_eq!(analyzer.rescore_some().await.unwrap(), 2);

    let (rescored, review) = store.verdict(calmed).await.unwrap().unwrap();
    assert_eq!(rescored.analyzer_version, ANALYZER_VERSION);
    assert!(!rescored.level.needs_review());
    assert_eq!(review, Review::None);

    let (kept, _) = store.verdict(broken).await.unwrap().unwrap();
    assert_eq!(kept.analyzer_version, 1);

    db.drop().await;
}

#[tokio::test]
async fn the_sweep_writes_missing_sboms_then_pauses() {
    let Some(db) = TestDb::new("analyzer_sbom").await else {
        return;
    };

    let (mut analyzer, mut store) = analyzer(&db).await;
    let first = job(&mut store, "plain", 6, &finished()).await;

    assert!(store.job_sbom(first).await.unwrap().is_none());
    assert_eq!(analyzer.refresh_sboms().await.unwrap(), 1);
    assert!(store.job_sbom(first).await.unwrap().is_some());

    // Nothing is left, so the sweep rests even once another job finishes.
    assert_eq!(analyzer.refresh_sboms().await.unwrap(), 0);
    let later = job(&mut store, "later", 7, &finished()).await;
    assert_eq!(analyzer.refresh_sboms().await.unwrap(), 0);
    assert!(store.job_sbom(later).await.unwrap().is_none());

    db.drop().await;
}
