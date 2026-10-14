//! Status, quarantine, breakers, disclosures and the archive.

use super::*;

#[tokio::test]
async fn status_lists_pauses_breakers_canaries_and_alerts() {
    let Some(db) = Db::new().await else { return };
    let site = Site::new(&db.url);
    let breakers = |sandbox: &str| -> String {
        Stage::ALL
            .iter()
            .map(|stage| {
                let state = if *stage == Stage::Sandbox {
                    sandbox
                } else {
                    "closed"
                };

                format!("breaker {:<16} {state}\n", stage.name())
            })
            .collect()
    };

    let idle = site.run(&["status"]);
    idle.expect(
        0,
        &format!("pauses: none\n{}alerts waiting: 0\n", breakers("closed")),
        "",
    );

    let job = db.job("evil", "0.1.0", json!({})).await;
    let store = &db.store;
    store
        .pause(PauseReason::Quarantine, Some(job), "escape indicator")
        .await
        .unwrap();
    store
        .pause(PauseReason::Disk, None, "scratch is full")
        .await
        .unwrap();
    let now = store.now_epoch().await.unwrap();
    let open = BreakerState::Open {
        since: now,
        reopened: 1,
    };

    store.set_breaker(Stage::Sandbox, open).await.unwrap();
    store.record_canary("bad", false, &json!({})).await.unwrap();
    store.record_canary("good", true, &json!({})).await.unwrap();
    store
        .record_canary("good", false, &json!({}))
        .await
        .unwrap();
    store.record_canary("good", true, &json!({})).await.unwrap();
    store.raise_alert(&HumanEscalation::KvmError).await.unwrap();
    store
        .raise_alert(&HumanEscalation::CanaryFailure)
        .await
        .unwrap();

    let busy = site.run(&["status"]);
    assert_eq!((busy.code, busy.err.as_str()), (0, ""));

    let lines: Vec<&str> = busy.out.lines().collect();
    let job_id = job.0;

    assert!(with_seconds(
        lines[0],
        "paused: quarantine for ",
        &format!(" s, job {job_id}: escape indicator")
    ));
    assert!(with_seconds(
        lines[1],
        "paused: disk for ",
        " s: scratch is full"
    ));
    assert_eq!(lines[2..7].join("\n") + "\n", breakers("open"));
    assert!(with_seconds(
        lines[7],
        &format!("canary {:<16} FAILED ", "bad"),
        " s ago"
    ));
    assert!(with_seconds(
        lines[8],
        &format!("canary {:<16} passed ", "good"),
        " s ago"
    ));
    assert_eq!(&lines[9..], ["alerts waiting: 2"]);

    db.drop().await;
}

#[tokio::test]
async fn quarantine_lift_ends_only_the_quarantine() {
    let Some(db) = Db::new().await else { return };
    let site = Site::new(&db.url);
    site.run(&["quarantine", "lift"])
        .expect(0, "no quarantine was active\n", "");
    db.store
        .pause(PauseReason::Quarantine, None, "escape")
        .await
        .unwrap();
    db.store
        .pause(PauseReason::Canary, None, "canary")
        .await
        .unwrap();
    site.run(&["quarantine", "lift"])
        .expect(0, "quarantine lifted\n", "");
    let left: Vec<PauseReason> = db
        .store
        .pauses()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.reason)
        .collect();

    assert_eq!(left, [PauseReason::Canary]);

    db.drop().await;
}

#[tokio::test]
async fn breaker_close_closes_the_named_stage() {
    let Some(db) = Db::new().await else { return };
    let site = Site::new(&db.url);
    let now = db.store.now_epoch().await.unwrap();
    for stage in [Stage::Sandbox, Stage::Fetch] {
        let open = BreakerState::Open {
            since: now,
            reopened: 2,
        };

        db.store.set_breaker(stage, open).await.unwrap();
    }

    site.run(&["breaker", "close", "sandbox"])
        .expect(0, "breaker of sandbox closed\n", "");
    let breakers = db.store.breakers().await.unwrap();

    assert!(matches!(breakers[&Stage::Sandbox], BreakerState::Closed { since } if since >= now));
    assert!(!matches!(
        breakers[&Stage::Fetch],
        BreakerState::Closed { .. }
    ));

    db.drop().await;
}

#[tokio::test]
async fn a_disclosure_goes_through_its_steps_in_order() {
    let Some(db) = Db::new().await else { return };
    let site = Site::new(&db.url);
    let job = db.job("evil", "0.1.0", json!({})).await;
    let id = job.0.to_string();
    let id = id.as_str();
    let report = |kind: &str| {
        let (to, reference, note) = ("help@crates.io", "T-1", "first");
        site.run(&[
            "disclosure",
            "report",
            id,
            "--kind",
            kind,
            "--to",
            to,
            "--reference",
            reference,
            "--note",
            note,
        ])
    };

    site.run(&["disclosure", "show", id]).expect(
        0,
        &format!("job {id} has no disclosure record\n"),
        "",
    );
    report("malicious").expect(1, "", "the verdict is not confirmed: review it first\n");
    db.confirmed(job).await;
    report("bogus").expect(1, "", "kind must be malicious or vulnerability\n");
    report("malicious").expect(
        0,
        &format!("recorded the report of job {id} to help@crates.io\n"),
        "",
    );

    let shown = site.run(&["disclosure", "show", id]);
    assert_eq!((shown.code, shown.err.as_str()), (0, ""));

    let lines: Vec<&str> = shown.out.lines().collect();
    assert_eq!(lines[0], "kind       malicious");

    let day = lines[1].strip_prefix("reported   ").unwrap();
    let (day, to) = day.split_once(" to ").unwrap();

    assert_eq!(to, "help@crates.io");
    assert!(day.len() == 10 && day.bytes().filter(u8::is_ascii_digit).count() == 8);
    assert_eq!(
        lines[2..],
        [
            "reference  T-1",
            "resolved   -",
            "published  -",
            "page       -",
            "note       first"
        ]
    );

    let publish = |slug: &str| site.run(&["disclosure", "publish", id, "--slug", slug]);
    publish("evil-0-1-0").expect(
        1,
        "",
        "the report is not resolved yet and the embargo has not passed\n",
    );
    site.run(&["disclosure", "resolved", id, "--reference", "T-2"])
        .expect(
            0,
            &format!("job {id} is resolved and may be published\n"),
            "",
        );
    publish("Bad/Slug").expect(
        1,
        "",
        "the page name must be 1 to 64 lowercase letters, digits or dashes\n",
    );
    publish("evil-0-1-0").expect(
        0,
        &format!("job {id} is listed as findings/evil-0-1-0/ at the next export\n"),
        "",
    );
    let shown = site.run(&["disclosure", "show", id]);
    let lines: Vec<&str> = shown.out.lines().collect();

    assert_eq!(lines[2], "reference  T-2");
    assert!(lines[3].starts_with("resolved   2") && lines[4].starts_with("published  2"));
    assert_eq!(lines[5], "page       evil-0-1-0");

    db.drop().await;
}

#[tokio::test]
async fn archive_writes_a_saved_selection_and_needs_a_terminal_without_one() {
    let Some(mut db) = Db::new().await else {
        return;
    };

    let site = Site::new(&db.url);
    let job = db.job("odd", "0.2.0", json!({})).await;
    db.finish(job).await;

    let medium = Verdict {
        score: 30,
        level: RiskLevel::from_score(30),
        ..verdict()
    };

    db.store.record_verdict(job, &medium).await.unwrap();

    let out = site.path("archive");
    let out_arg = out.to_str().unwrap();
    let ran = site.run(&["archive", "--out", out_arg]);
    ran.expect(
        1,
        "",
        "not a terminal: pass a saved selection with --selection\n",
    );

    let selection = site.path("selection.json");
    std::fs::write(&selection, r#"{"levels": ["medium"]}"#).unwrap();
    let ran = site.run(&[
        "archive",
        "--out",
        out_arg,
        "--selection",
        selection.to_str().unwrap(),
    ]);

    let index = out.join("index.html");
    ran.expect(
        0,
        &format!(
            "writing 1 reports to {out_arg}\nwrote 1 reports, open {}\n",
            index.display()
        ),
        "",
    );
    assert!(out.join(format!("jobs/{}.html", job.0)).is_file());

    let saved: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("selection.json")).unwrap())
            .unwrap();
    assert_eq!(saved["levels"], json!(["medium"]));
    assert_eq!(saved["per_level"], json!(25));

    let missing = site.path("missing.json");
    let ran = site.run(&[
        "archive",
        "--out",
        out_arg,
        "--selection",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(ran.code, 1);
    assert!(
        ran.err.starts_with(&format!("{}: ", missing.display())),
        "{}",
        ran.err
    );

    db.drop().await;
}

#[tokio::test]
async fn sbom_writes_the_documents_of_a_finished_job() {
    let Some(mut db) = Db::new().await else {
        return;
    };

    let site = Site::new(&db.url);
    let job = db.job("odd", "0.2.0", json!({})).await;
    db.finish(job).await;
    db.store.record_verdict(job, &verdict()).await.unwrap();

    let docs = site.path("sbom");
    let docs_arg = docs.to_str().unwrap();
    let id = job.0.to_string();
    let ran = site.run(&["sbom", &id, "--out", docs_arg]);
    ran.expect(
        1,
        "",
        &format!("job {id} has no SBOM yet: it is unknown or not finished\n"),
    );

    let store = &db.store;
    store
        .record_fetch(job, None, Some("unresolvable"), &json!([]))
        .await
        .unwrap();
    store.refresh_sbom(job, "0.1.0").await.unwrap();
    let ran = site.run(&["sbom", &id, "--out", docs_arg]);
    ran.expect(
        0,
        &format!(
            "wrote {}\nwrote {}\n",
            docs.join("odd-0.2.0.cdx.json").display(),
            docs.join("odd-0.2.0.vex.cdx.json").display()
        ),
        "",
    );

    db.drop().await;
}

#[tokio::test]
async fn a_second_crate_cannot_take_a_published_page() {
    let Some(db) = Db::new().await else { return };
    let site = Site::new(&db.url);
    let first = db.job("evil", "0.1.0", json!({})).await;
    let store = &db.store;

    db.confirmed(first).await;
    store
        .record_report(
            first,
            DisclosureKind::Malicious,
            "help@crates.io",
            None,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    store.mark_resolved(first, None).await.unwrap().unwrap();
    store
        .publish_finding(first, "evil-0-1-0")
        .await
        .unwrap()
        .unwrap();

    let other = db.job("worse", "0.2.0", json!({})).await.0.to_string();
    site.run(&["disclosure", "resolved", &other]).expect(
        1,
        "",
        "no report is recorded for this job\n",
    );
    db.confirmed(JobId(other.parse().unwrap())).await;
    site.run(&[
        "disclosure",
        "report",
        &other,
        "--kind",
        "vulnerability",
        "--to",
        "owners",
    ])
    .expect(
        0,
        &format!("recorded the report of job {other} to owners\n"),
        "",
    );
    site.run(&["disclosure", "resolved", &other]).expect(
        0,
        &format!("job {other} is resolved and may be published\n"),
        "",
    );
    site.run(&["disclosure", "publish", &other, "--slug", "evil-0-1-0"])
        .expect(1, "", "another finding uses this page name\n");

    db.drop().await;
}
