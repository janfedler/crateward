//! Static reports, fetches, verdicts and the raw run data.

use super::*;

#[tokio::test]
async fn static_reports_fetches_and_popularity_round_trip() {
    let Some(db) = TestDb::new("test").await else {
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
            sha512: None,
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
async fn verdicts_are_stored_reviewed_and_found_for_the_previous_version() {
    let Some(db) = TestDb::new("test").await else {
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
    let Some(db) = TestDb::new("test").await else {
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

    let raw = db.admin();
    raw.batch_execute(&format!(
        "SET search_path TO {}; UPDATE jobs SET state = 'Done';
         UPDATE job_runs SET recorded_at = now() - interval '9 days'
         WHERE job_id IN ({}, {})",
        db.schema(),
        jobs[0].0,
        jobs[1].0
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

/// The jobs waiting for the current analyzer: the analyzer's queue, the
/// dashboard's filter and its count.
/// The verdicts the analyzer rescores now, and the jobs the dashboard
/// lists as waiting, which also wait for a static report refresh.
async fn outdated(store: &Store) -> (Vec<JobId>, Vec<JobId>) {
    let queue: Vec<JobId> = store
        .outdated_verdicts(ANALYZER_VERSION, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|j| j.id)
        .collect();

    let filter = JobFilter {
        rescore: true,
        ..JobFilter::default()
    };

    let listed: Vec<JobId> = store
        .jobs(&filter, 0, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();

    assert!(queue.iter().all(|id| listed.contains(id)));
    assert_eq!(store.rescore_backlog().await.unwrap(), listed.len() as i64);

    (queue, listed)
}

/// A finished job of crate file `ab…ab`, whose static report the static
/// analysis version before the current one wrote, and whose verdict
/// `analyzer_version` wrote after it. `blake3` names the stored archive.
async fn scored_on_an_old_report(
    db: &TestDb,
    store: &Store,
    blake3: Option<&str>,
    analyzer_version: u32,
) -> (JobId, Sha256Digest, Verdict) {
    let job = store
        .enqueue(&new_job("lib", "1.0.0", 0))
        .await
        .unwrap()
        .unwrap();

    let sha = "ab".repeat(32).parse().unwrap();
    store
        .record_crate_file(&CrateFile {
            sha256: sha,
            sha512: None,
            name: "lib".into(),
            version: "1.0.0".into(),
            blake3: blake3.map(str::to_owned),
            compressed_bytes: 1,
            unpacked_bytes: 1,
            stored_bytes: Some(1),
            report: serde_json::json!({}),
        })
        .await
        .unwrap();
    let report = serde_json::json!({"findings": []});
    store
        .record_static_report(&sha, STATIC_ANALYZER_VERSION - 1, true, None, &report)
        .await
        .unwrap();
    let verdict = Verdict {
        score: 0,
        level: RiskLevel::None,
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version,
    };

    store.record_verdict(job, &verdict).await.unwrap();
    db.admin()
        .batch_execute(&format!(
            "SET search_path TO {}; UPDATE jobs SET state = 'Done';
             UPDATE static_reports SET analyzed_at = now() - interval '2 minutes';
             UPDATE verdicts SET scored_at = now() - interval '1 minute'",
            db.schema()
        ))
        .await
        .unwrap();

    (
        job,
        sha,
        Verdict {
            analyzer_version: ANALYZER_VERSION,
            ..verdict
        },
    )
}

#[tokio::test]
async fn a_verdict_older_than_its_static_report_is_outdated() {
    let Some(db) = TestDb::new("test").await else {
        return;
    };

    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let (job, sha, verdict) = scored_on_an_old_report(&db, &store, None, ANALYZER_VERSION).await;

    // The report waits for a refresh before the verdict is rescored.
    assert_eq!(outdated(&store).await, (vec![], vec![job]));

    // The static analyzer refreshed the report after the verdict.
    let report = serde_json::json!({"findings": []});
    store
        .record_static_report(&sha, STATIC_ANALYZER_VERSION, true, Some("high"), &report)
        .await
        .unwrap();

    assert_eq!(outdated(&store).await, (vec![job], vec![job]));

    store.record_verdict(job, &verdict).await.unwrap();

    assert_eq!(outdated(&store).await, (vec![], vec![]));

    db.drop().await;
}

#[tokio::test]
async fn an_old_verdict_waits_for_its_report_to_be_refreshed() {
    let Some(db) = TestDb::new("test").await else {
        return;
    };

    let mut store = db.store().await;
    store.migrate().await.unwrap();
    let (job, sha, _) =
        scored_on_an_old_report(&db, &store, Some("blob"), ANALYZER_VERSION - 1).await;

    // Scoring now would score again after the refresh.
    assert_eq!(outdated(&store).await, (vec![], vec![job]));

    let report = serde_json::json!({"findings": []});
    store
        .record_static_report(&sha, STATIC_ANALYZER_VERSION, true, None, &report)
        .await
        .unwrap();

    assert_eq!(outdated(&store).await, (vec![job], vec![job]));

    // A report whose archive was never stored cannot be refreshed.
    store
        .record_static_report(&sha, STATIC_ANALYZER_VERSION - 1, true, None, &report)
        .await
        .unwrap();
    db.admin()
        .batch_execute(&format!(
            "SET search_path TO {}; UPDATE crate_files SET blake3 = NULL",
            db.schema()
        ))
        .await
        .unwrap();

    assert_eq!(outdated(&store).await, (vec![job], vec![job]));

    db.drop().await;
}
