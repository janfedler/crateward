//! The public site, built from a database as the export builds it: counts,
//! canaries and published findings, and no other crate names.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use crateward_api::export;
use crateward_core::job::JobId;
use crateward_core::store::{DisclosureKind, NewJob, Review, Store};
use crateward_core::testing::TestDb;
use crateward_core::verdict::{Coverage, RiskLevel, Verdict};
use serde_json::{Value, json};

const CKSUM: &str = "abababababababababababababababababababababababababababababababab";

async fn enqueue(store: &Store, name: &str) -> JobId {
    let new = NewJob {
        name: name.parse().unwrap(),
        version: "0.1.0".parse().unwrap(),
        cksum: CKSUM.parse().unwrap(),
        published_at: None,
        priority: 0,
        index_entry: json!({}),
    };

    store.enqueue(&new).await.unwrap().unwrap()
}

async fn score(store: &Store, job: JobId, score: u32) {
    let verdict = Verdict {
        score,
        level: RiskLevel::from_score(score),
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    };

    store.record_verdict(job, &verdict).await.unwrap();
}

/// Marks a job done with a coverage kind, `days` ago.
async fn finish(db: &TestDb, job: JobId, coverage: &str, days: i32) {
    db.client()
        .await
        .execute(
            "UPDATE jobs SET state = 'Done',
                             job = jsonb_set(job, '{coverage}', jsonb_build_object('kind', $2::text)),
                             updated_at = now() - make_interval(days => $3)
             WHERE id = $1",
            &[&job.0, &coverage, &days],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn the_site_shows_counts_canaries_and_published_findings_only() {
    let Some(db) = TestDb::new("site").await else {
        return;
    };

    let store = db.migrated().await;

    let quiet = enqueue(&store, "quiet").await;
    let evil = enqueue(&store, "evil").await;
    let older = enqueue(&store, "older").await;
    enqueue(&store, "waiting").await;

    score(&store, quiet, 0).await;
    score(&store, evil, 90).await;
    score(&store, older, 0).await;

    finish(&db, quiet, "dynamic_linux", 0).await;
    finish(&db, evil, "static_only", 0).await;
    finish(&db, older, "static_only", 40).await;

    // A finding reaches the site only once it was reported, resolved and
    // published.
    store
        .set_review(evil, Review::Confirmed, None)
        .await
        .unwrap();
    store
        .record_report(
            evil,
            DisclosureKind::Malicious,
            "help@crates.io",
            None,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    store.mark_resolved(evil, None).await.unwrap().unwrap();

    let unpublished = export::build(&store, false).await.unwrap();
    let page = |files: &[(String, Vec<u8>)]| {
        String::from_utf8(
            files
                .iter()
                .find(|(n, _)| n == "index.html")
                .unwrap()
                .1
                .clone(),
        )
        .unwrap()
    };

    assert!(page(&unpublished).contains("<p>None yet.</p>"));

    store
        .publish_finding(evil, "evil-0-1-0")
        .await
        .unwrap()
        .unwrap();
    store
        .record_canary("canary-exfil", true, &json!({}))
        .await
        .unwrap();
    store
        .record_canary("canary-inert", false, &json!({}))
        .await
        .unwrap();

    let files = export::build(&store, false).await.unwrap();
    let index = page(&files);
    let stats: Value =
        serde_json::from_slice(&files.iter().find(|(n, _)| n == "stats.json").unwrap().1).unwrap();

    for row in [
        "<tr><th>Versions seen</th><td>4</td></tr>",
        "<tr><th>Versions with a verdict</th><td>3</td></tr>",
        "<tr><th>Static analysis only</th><td>2 (66%)</td></tr>",
        "<tr><th>Built and traced in a microVM on Linux</th><td>1 (33%)</td></tr>",
        "<tr><th>none</th><td>2</td></tr>",
        "<tr><th>critical</th><td>1</td></tr>",
        "A canary gave an unexpected result.",
        r#"<a href="findings/evil-0-1-0/">details</a>"#,
    ] {
        assert!(index.contains(row), "{row}");
    }

    assert_eq!(stats["versions"], 4);
    assert_eq!(stats["finished"], 3);
    assert_eq!(stats["canaries_pass"], false);
    assert_eq!(stats["findings"][0]["crate"], "evil");

    // The version finished 40 days ago is outside the daily window.
    assert_eq!(stats["daily"].as_array().unwrap().len(), 1);
    assert_eq!(stats["daily"][0]["finished"], 2);

    // No other crate is named.
    for name in ["quiet", "older", "waiting"] {
        assert!(!index.contains(name), "{name}");
        assert!(!stats.to_string().contains(name), "{name}");
    }

    db.drop().await;
}
