//! Stored SBOMs against a real PostgreSQL (ADR 0012).
//!
//! The database setup is [`crateward_core::testing`].

#![cfg(all(feature = "testing", feature = "sbom"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use crateward_core::digest::Sha256Digest;
use crateward_core::job::JobId;
use crateward_core::name::CrateName;
use crateward_core::store::{CrateFile, NewJob, Review, SbomOutcome, Store};
use crateward_core::testing::TestDb;
use crateward_core::verdict::{Coverage, RiskLevel, STATIC_ANALYZER_VERSION, Verdict};
use serde_json::json;

const LOCK: &str = r#"version = 4

[[package]]
name = "app"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
dependencies = ["dep"]

[[package]]
name = "crateward-probe"
version = "0.0.0"
dependencies = ["app"]

[[package]]
name = "dep"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;

fn sha(c: char) -> Sha256Digest {
    c.to_string().repeat(64).parse().unwrap()
}

async fn file(store: &Store, name: &str, sha256: Sha256Digest, sha512: Option<String>) {
    store
        .record_crate_file(&CrateFile {
            sha256,
            sha512,
            name: name.into(),
            version: "1".into(),
            blake3: None,
            compressed_bytes: 1,
            unpacked_bytes: 1,
            stored_bytes: None,
            report: json!({}),
        })
        .await
        .unwrap();

    let report = json!({"manifest": {"package": {"license": "MIT", "authors": []}}});
    store
        .record_static_report(&sha256, STATIC_ANALYZER_VERSION, false, None, &report)
        .await
        .unwrap();
}

/// A finished job of `app` 1.0.0 whose dependency has no SHA-512 yet.
async fn job(db: &TestDb, store: &Store) -> JobId {
    let job = store
        .enqueue(&NewJob {
            name: CrateName::parse("app").unwrap(),
            version: "1.0.0".parse().unwrap(),
            cksum: sha('a'),
            published_at: None,
            priority: 0,
            index_entry: json!({}),
        })
        .await
        .unwrap()
        .unwrap();

    file(store, "app", sha('a'), Some("1".repeat(128))).await;
    file(store, "dep", sha('b'), None).await;
    store
        .record_fetch(job, Some(LOCK), None, &json!([]))
        .await
        .unwrap();

    let verdict = Verdict {
        score: 0,
        level: RiskLevel::None,
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    };

    store.record_verdict(job, &verdict).await.unwrap();
    db.admin()
        .batch_execute(&format!(
            "SET search_path TO {}; UPDATE jobs SET state = 'Done'",
            db.schema()
        ))
        .await
        .unwrap();

    job
}

#[tokio::test]
async fn an_sbom_is_written_once_and_replaced_only_when_it_lacked_data() {
    let Some(db) = TestDb::new("sbom").await else {
        return;
    };

    let store = db.migrated().await;
    let job = job(&db, &store).await;
    assert_eq!(store.jobs_needing_sbom(10).await.unwrap(), [job]);

    let written = store.refresh_sbom(job, "0.1.0").await.unwrap();
    assert_eq!(
        written,
        SbomOutcome::Written {
            version: 1,
            gaps: vec!["dep 0.1.0: no SHA-512".to_owned()],
        }
    );

    let first = store.job_sbom(job).await.unwrap().unwrap();
    assert_eq!((first.version, first.gaps), (1, 1));
    assert_eq!(first.document["version"], 1);
    assert_eq!(first.document["serialNumber"], first.serial);
    assert_eq!(
        first.document["metadata"]["component"]["licenses"][0]["license"]["id"],
        "MIT"
    );

    // Checked a moment ago: the sweep waits a day before looking again.
    assert!(store.jobs_needing_sbom(10).await.unwrap().is_empty());

    // Nothing new: the stored document stays.
    assert_eq!(
        store.refresh_sbom(job, "0.1.0").await.unwrap(),
        SbomOutcome::Kept
    );

    // The fetcher hashed the dependency since.
    let unhashed = store.unhashed_crate_files(10).await.unwrap();
    assert_eq!(unhashed.len(), 1);
    assert_eq!(unhashed[0].sha256, sha('b'));
    store
        .record_sha512(&sha('b'), &"2".repeat(128))
        .await
        .unwrap();
    assert!(store.unhashed_crate_files(10).await.unwrap().is_empty());

    let again = store.refresh_sbom(job, "0.1.0").await.unwrap();
    assert_eq!(
        again,
        SbomOutcome::Written {
            version: 2,
            gaps: Vec::new(),
        }
    );

    let second = store.job_sbom(job).await.unwrap().unwrap();
    assert_eq!((second.version, second.gaps), (2, 0));
    assert_eq!(second.serial, first.serial);
    assert_eq!(second.document["version"], 2);

    // Complete documents never change.
    assert_eq!(
        store.refresh_sbom(job, "0.2.0").await.unwrap(),
        SbomOutcome::Kept
    );
    assert_eq!(store.job_sbom(job).await.unwrap().unwrap(), second);

    db.drop().await;
}

#[tokio::test]
async fn the_revision_counts_changes_of_the_verdict_and_review() {
    let Some(db) = TestDb::new("sbom").await else {
        return;
    };

    let store = db.migrated().await;
    let job = job(&db, &store).await;
    let revision = || async { store.verdict_revision(job).await.unwrap().unwrap().0 };
    assert_eq!(revision().await, 1);

    let (verdict, _) = store.verdict(job).await.unwrap().unwrap();
    store.record_verdict(job, &verdict).await.unwrap();
    assert_eq!(revision().await, 1);

    store.set_review(job, Review::Pending, None).await.unwrap();
    store.set_review(job, Review::Pending, None).await.unwrap();
    assert_eq!(revision().await, 2);

    let higher = Verdict {
        score: 30,
        level: RiskLevel::Medium,
        ..verdict
    };

    store.record_verdict(job, &higher).await.unwrap();
    assert_eq!(revision().await, 3);
    assert_eq!(store.run_kinds(job).await.unwrap(), Vec::<String>::new());

    db.drop().await;
}
