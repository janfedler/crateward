//! The archive as `crateward archive` writes it: static files from a
//! private schema with finished jobs.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use crateward_api::archive::{self, ArchiveError};
use crateward_api::export;
use crateward_core::config::ExportConfig;
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
    release(store, name, "0.1.0", score, n).await
}

/// A finished job of `name` at `version` with a verdict of `score`.
async fn release(store: &mut Store, name: &str, version: &str, score: u32, n: u8) -> JobId {
    let new = NewJob {
        name: name.parse().unwrap(),
        version: version.parse().unwrap(),
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
    store
        .record_fetch(job, None, Some("unresolvable"), &json!([]))
        .await
        .unwrap();
    store.refresh_sbom(job, "0.1.0").await.unwrap();

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
    let written = archive::write(&store, &ids, &dir, Some(&selection)).await;
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

    // The SBOM and findings document lie next to the page.
    assert!(page.contains("<a class=\"muted\" href=\"1.cdx.json\" download"));
    let sbom: serde_json::Value = serde_json::from_str(&read(&dir, "jobs/1.cdx.json")).unwrap();
    assert_eq!(
        sbom["metadata"]["component"]["purl"],
        "pkg:cargo/evil@0.1.0"
    );
    let vex: serde_json::Value = serde_json::from_str(&read(&dir, "jobs/1.vex.cdx.json")).unwrap();
    assert_eq!(
        vex["vulnerabilities"][0]["description"],
        "evil sent [honeytoken]"
    );

    for file in [
        "index.html",
        "jobs/1.html",
        "jobs/2.html",
        "jobs/3.html",
        "jobs/1.vex.cdx.json",
    ] {
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
    let again = archive::write(&store, &[odd.0], &dir, Some(&selection)).await;
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

    let error = archive::write(&store, &[pending.0], &dir, Some(&none)).await;
    assert!(matches!(
        error,
        Err(ArchiveError::Refused {
            reason: "waits for review",
            ..
        })
    ));

    let error = archive::write(&store, &[reported.0], &dir, Some(&none)).await;
    assert_eq!(
        error.unwrap_err().to_string(),
        format!(
            "job {} may not be archived: confirmed, not published yet",
            reported.0
        )
    );

    let error = archive::write(&store, &[99], &dir, Some(&none)).await;
    assert!(matches!(error, Err(ArchiveError::NotCandidate(99))));
    assert!(!dir.exists());

    db.drop().await;
}

#[tokio::test]
async fn versions_archived_together_are_compared() {
    let Some(db) = TestDb::new("archive").await else {
        return;
    };

    let mut store = db.migrated().await;
    let old = release(&mut store, "pair", "0.1.0", 30, 1).await;
    let new = release(&mut store, "pair", "0.2.0", 40, 2).await;

    let dir = scratch("diff");
    let written = archive::write(&store, &[new.0, old.0], &dir, Some(&json!({}))).await;
    assert_eq!(written.unwrap(), 2);

    let page = read(&dir, &format!("jobs/{}.html", new.0));
    assert!(page.contains(&format!(
        "<a class=\"button compare\" href=\"{}-diff.html\">Compare with 0.1.0</a>",
        new.0
    )));
    assert!(!read(&dir, &format!("jobs/{}.html", old.0)).contains("Compare with"));

    let diff = read(&dir, &format!("jobs/{}-diff.html", new.0));
    assert!(diff.contains("<link rel=\"stylesheet\" href=\"../static/crateward.css\">"));
    assert!(diff.contains(&format!("<a href=\"{}.html\">0.1.0 report</a>", old.0)));
    assert!(!diff.contains("/jobs/") && !diff.contains("<script"));
    assert!(!diff.contains("class=\"versions\""));
    assert!(diff.contains("pair sent [honeytoken]"));
    assert!(!diff.contains("ghp_"));

    // Without the version before, there is nothing to compare with.
    let alone = archive::write(&store, &[new.0], &dir, Some(&json!({}))).await;
    assert_eq!(alone.unwrap(), 1);
    assert!(!dir.join(format!("jobs/{}-diff.html", new.0)).exists());
    assert!(!read(&dir, &format!("jobs/{}.html", new.0)).contains("Compare with"));

    std::fs::remove_dir_all(dir).unwrap();
    db.drop().await;
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();

    assert!(output.status.success(), "git {args:?}: {output:?}");

    String::from_utf8(output.stdout).unwrap()
}

/// A bare site repository with one commit on `main`, pushed to over
/// `file://`, so no SSH is involved.
fn site_repository(root: &Path) -> ExportConfig {
    std::fs::create_dir_all(root.join("seed")).unwrap();
    git(
        root,
        &[
            "init",
            "--quiet",
            "--bare",
            "--initial-branch=main",
            "site.git",
        ],
    );

    let seed = root.join("seed");
    git(&seed, &["init", "--quiet", "--initial-branch=main"]);
    std::fs::write(seed.join("finding.html"), "by hand\n").unwrap();
    git(&seed, &["add", "--all"]);
    git(&seed, &["commit", "--quiet", "--message", "Seed"]);
    git(&seed, &["push", "--quiet", "../site.git", "main"]);

    ExportConfig {
        repository: format!("file://{}", root.join("site.git").display()),
        branch: "main".into(),
        deploy_key: root.join("no-key"),
        interval_hours: 24,
        reports: true,
    }
}

#[tokio::test]
async fn published_reports_follow_the_saved_selection_without_history() {
    let Some(db) = TestDb::new("archive_publish").await else {
        return;
    };

    let mut store = db.migrated().await;
    let evil = done(&mut store, "evil", 90, 1).await;
    let other = done(&mut store, "other", 80, 2).await;

    let root = scratch("publish");
    let config = site_repository(&root);
    let work = root.join("work");
    let bare = root.join("site.git");

    // The default selection takes both.
    let saved = root.join("report-selection.json");
    std::fs::write(&saved, "{}").unwrap();
    let ids = export::saved_reports(&store, &saved)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ids, [evil.0, other.0]);
    assert!(
        export::publish(&store, &config, "security@example.com", &work, Some(&ids))
            .await
            .unwrap()
    );

    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);

    assert!(
        files.contains(&format!("reports/jobs/{}.html", other.0)),
        "{files}"
    );
    assert!(files.contains("reports/index.html"), "{files}");
    assert!(!files.contains("selection.json"), "{files}");
    assert!(files.contains("finding.html"), "{files}");
    assert!(git(&bare, &["show", "main:index.html"]).contains("href=\"reports/\""));

    let page = git(
        &bare,
        &["show", &format!("main:reports/jobs/{}.html", evil.0)],
    );

    assert!(!page.contains("ghp_"), "a honeytoken was published");

    // Once a reviewer reopens `other`, the next export takes it down, and
    // the history does not keep it.
    assert!(
        store
            .set_review(other, Review::Pending, None)
            .await
            .unwrap()
    );

    let ids = export::saved_reports(&store, &saved)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ids, [evil.0]);
    assert!(
        export::publish(&store, &config, "security@example.com", &work, Some(&ids))
            .await
            .unwrap()
    );

    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);

    assert!(
        !files.contains(&format!("reports/jobs/{}.html", other.0)),
        "{files}"
    );
    assert_eq!(git(&bare, &["rev-list", "--count", "main"]).trim(), "1");
    assert_eq!(git(&bare, &["show", "main:finding.html"]), "by hand\n");

    // Without a saved selection, the reports stay as they are.
    let missing = root.join("missing.json");

    assert!(
        export::saved_reports(&store, &missing)
            .await
            .unwrap()
            .is_none()
    );

    std::fs::remove_dir_all(&root).unwrap();
    db.drop().await;
}
