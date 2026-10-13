//! The archive as `crateward archive` writes it: static files from a
//! private schema with finished jobs.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use crateward_api::archive::{self, ArchiveError};
use crateward_core::job::{JobEvent, JobId, Stage, Triage};
use crateward_core::store::{DisclosureKind, NewJob, Review, Store};
use crateward_core::testing::{TestDb, policies};
use crateward_core::verdict::{
    Coverage, Evidence, EvidenceSource, RiskLevel, StaticOnlyReason, Verdict,
};
use serde_json::json;

/// The honeytoken of job `n`, with the characters a page escapes.
fn token(n: u8) -> String {
    format!("ghp_<tok\"en>&{n}")
}

/// A finished job of `name` with a verdict of `score`.
async fn done(store: &mut Store, name: &str, score: u32, n: u8) -> JobId {
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
        (Stage::Analysis, JobEvent::Scored { escalate: false }),
        (Stage::Finalize, JobEvent::Finalized),
    ];

    for (stage, event) in steps {
        let lease = Duration::from_secs(30);
        let claimed = store.claim(stage, "w", lease).await.unwrap().unwrap();
        assert_eq!(claimed.id, job);
        let policies = policies();
        store
            .complete(job, "w", event, &policies, false)
            .await
            .unwrap();
    }

    let verdict = Verdict {
        score,
        level: RiskLevel::from_score(score),
        coverage: Coverage::DynamicLinux,
        evidence: vec![Evidence {
            signal: "honeytoken_left_vm".to_owned(),
            points: score,
            source: EvidenceSource::Network,
            summary: format!("{name} sent {}", token(n)),
            package: None,
            location: None,
        }],
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    };

    store.record_verdict(job, &verdict).await.unwrap();
    store
        .record_honeytokens(job, &[("github".to_owned(), token(n))])
        .await
        .unwrap();

    job
}

/// Confirms `job` and goes through the disclosure up to `published`.
async fn confirm(store: &Store, job: JobId, published: bool) {
    assert!(
        store
            .set_review(job, Review::Confirmed, None)
            .await
            .unwrap()
    );

    let kind = DisclosureKind::Malicious;
    let reported = store.record_report(job, kind, "help@crates.io", None, None);
    reported.await.unwrap().unwrap();

    if published {
        store.mark_resolved(job, None).await.unwrap().unwrap();
        store
            .publish_finding(job, "evil-0-1-0")
            .await
            .unwrap()
            .unwrap();
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "crateward-archive-test-{name}-{}",
        std::process::id()
    ));

    let _ = std::fs::remove_dir_all(&dir);

    dir
}

fn read(dir: &Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap()
}

#[tokio::test]
async fn chosen_jobs_become_static_pages_without_the_dashboard_parts() {
    let Some(db) = TestDb::new("archive").await else {
        return;
    };

    let mut store = db.migrated().await;
    let evil = done(&mut store, "evil", 90, 1).await;
    confirm(&store, evil, true).await;
    let odd = done(&mut store, "odd", 30, 2).await;
    let benign = done(&mut store, "benign", 60, 3).await;
    assert!(
        store
            .set_review(benign, Review::FalsePositive, None)
            .await
            .unwrap()
    );

    let candidates = store.archive_candidates(None).await.unwrap();
    let order: Vec<i64> = candidates.iter().map(|c| c.id.0).collect();
    assert_eq!(order, [evil.0, benign.0, odd.0]);
    assert!(candidates.iter().all(|c| c.refusal().is_none()));

    let dir = scratch("pages");
    let selection = json!({"levels": ["critical"]});
    let ids = [evil.0, odd.0, benign.0];
    let written = archive::write(&store, &ids, &dir, &selection).await;
    assert_eq!(written.unwrap(), 3);

    let index = read(&dir, "index.html");
    assert!(index.contains("<link rel=\"stylesheet\" href=\"static/crateward.css\">"));
    assert!(
        index.contains("<a href=\"jobs/1.html\">evil <span class=\"version\">0.1.0</span></a>")
    );
    assert!(index.contains("<span class=\"badge ok\">false positive</span>"));
    assert!(index.contains("<label for=\"lvl-critical\" class=\"tone-critical\">critical <span class=\"count\">1</span></label>"));
    assert!(!index.contains("<script"));

    let page = read(&dir, "jobs/1.html");
    assert!(page.contains("<link rel=\"stylesheet\" href=\"../static/crateward.css\">"));
    assert!(page.contains("<a class=\"brand\" href=\"../index.html\">Crateward</a>"));
    assert!(page.contains("href=\"https://crateward.com/findings/evil-0-1-0/\""));
    assert!(!page.contains("<script"));
    assert!(!page.contains("<form"));
    assert!(!page.contains("/jobs/1"));
    assert!(!page.contains("id=\"disclosure\""));
    assert!(page.contains(" UTC</td>"));
    assert!(page.contains("evil sent [honeytoken]"));

    for file in ["index.html", "jobs/1.html", "jobs/2.html", "jobs/3.html"] {
        let html = read(&dir, file);
        assert!(!html.contains("ghp_"), "{file}");
    }

    assert!(read(&dir, "jobs/2.html").contains("<b>Automated verdict.</b>"));
    assert!(read(&dir, "jobs/3.html").contains("False positive.</b>"));

    let saved: serde_json::Value = serde_json::from_str(&read(&dir, "selection.json")).unwrap();
    assert_eq!(saved, selection);

    for file in [
        "static/crateward.css",
        "static/lobster-latin-400.woff2",
        "static/OFL.txt",
        ".nojekyll",
    ] {
        assert!(dir.join(file).is_file(), "{file}");
    }

    // Writing again replaces the pages of the earlier archive.
    let again = archive::write(&store, &[odd.0], &dir, &selection).await;
    assert_eq!(again.unwrap(), 1);
    assert!(!dir.join("jobs/1.html").exists());
    assert!(dir.join("jobs/2.html").exists());

    std::fs::remove_dir_all(dir).unwrap();
    db.drop().await;
}

#[tokio::test]
async fn unreviewed_and_unpublished_findings_are_refused_before_anything_is_written() {
    let Some(db) = TestDb::new("archive").await else {
        return;
    };

    let mut store = db.migrated().await;
    let pending = done(&mut store, "pending", 90, 1).await;
    assert!(
        store
            .set_review(pending, Review::Pending, None)
            .await
            .unwrap()
    );
    let reported = done(&mut store, "reported", 90, 2).await;
    confirm(&store, reported, false).await;

    let dir = scratch("refused");
    let none = json!({});

    let error = archive::write(&store, &[pending.0], &dir, &none).await;
    assert!(matches!(
        error,
        Err(ArchiveError::Refused {
            reason: "waits for review",
            ..
        })
    ));

    let error = archive::write(&store, &[reported.0], &dir, &none).await;
    assert_eq!(
        error.unwrap_err().to_string(),
        format!(
            "job {} may not be archived: confirmed, not published yet",
            reported.0
        )
    );

    let error = archive::write(&store, &[99], &dir, &none).await;
    assert!(matches!(error, Err(ArchiveError::NotCandidate(99))));
    assert!(!dir.exists());

    db.drop().await;
}
