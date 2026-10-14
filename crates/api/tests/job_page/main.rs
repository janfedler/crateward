//! The job page, as a browser gets it: the real router on a loopback port,
//! in front of a private schema that holds a seeded job.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod html;
mod seed;

use crateward_core::job::{JobEvent, JobId, Stage, Triage};
use crateward_core::store::{CrateFile, Disclosure, DisclosureKind, NewJob, Review};
use crateward_core::verdict::{EvidenceSource, RiskLevel, StaticOnlyReason};
use serde_json::{Value, json};

use html::{facts, groups, row, run_section, table, text};
use seed::{CKSUM, Dashboard, crate_file, evidence, run_report, seed_full_job, verdict};

/// The title, the meta line, the verdict and the review forms.
fn assert_header(html: &str, job: JobId) {
    assert_eq!(text(html, "<h1>", "</h1>"), "evil 0.1.0");
    assert_eq!(
        text(html, "<p class=\"meta\">", "</p>"),
        format!("Scored static only job {} crates.io", job.0)
    );
    assert!(html.contains("href=\"https://crates.io/crates/evil/0.1.0\""));
    assert_eq!(
        text(html, "<p class=\"headline\">", "</p>"),
        "a token went out"
    );
    assert_eq!(
        text(
            html,
            "<div class=\"verdict tone-critical\">",
            "<div class=\"decision\">"
        ),
        "85 critical"
    );
    assert_eq!(
        text(html, "<div class=\"decision\">", "<form"),
        "Review confirmed"
    );
    assert_eq!(
        text(html, "<nav class=\"toc\"", "</nav>"),
        "Disclosure Evidence 6 Behavior 2 Static findings 365 Run: full 1 Timeline 3"
    );

    let form = format!("action=\"/jobs/{}/review\"", job.0);
    assert_eq!(html.matches(&form).count(), 2);
}

/// The facts of the reported finding.
fn assert_disclosure(html: &str, day: &Disclosure) {
    let reported_on = format!("{} to crates.io", day.reported_on.as_deref().unwrap());
    let disclosure = facts(html, "<h2 id=\"disclosure\">");

    assert_eq!(
        disclosure,
        [
            row(&["Kind", "malicious"]),
            row(&["Reported", &reported_on]),
            row(&["Reference", "RUSTSEC-1"]),
            row(&["Resolved", day.resolved_on.as_deref().unwrap()]),
            row(&["Published", day.published_on.as_deref().unwrap()]),
            row(&["Page", "evil-0-1-0"]),
            row(&["Note", "n<1>"]),
        ]
    );
}

/// The evidence table with its points and signals.
fn assert_evidence(html: &str) {
    // Points, the signal with its source and package, where, what.
    assert_eq!(
        table(html, "<h2 id=\"evidence\">"),
        [
            row(&["Points", "Signal", "Where", "What"]),
            row(&[
                "60",
                "honeytoken_left_vmnetwork · evil",
                "203.0.113.9:443",
                "a token went out"
            ]),
            row(&[
                "10",
                "exec_curltrace",
                "build.rs:12",
                "ran <curl> & \"more\""
            ]),
            row(&["5", "obfuscationstatic · dep", "", "packed string"]),
            row(&["4", "new_networkdiff", "", "new since 0.0.9"]),
            row(&["3", "disk_writedisk", "", "wrote outside target"]),
            row(&["3", "timeoutrun", "", "the run ended late"]),
        ]
    );
    assert!(html.contains("<span class=\"points bad\">60</span>"));
    assert!(html.contains("<span class=\"points warn\">10</span>"));
    assert!(html.contains("<span class=\"points low\">5</span>"));
    assert!(!html.contains("without points"));
    assert!(html.contains("<code class=\"chip new\">exec:curl</code>"));
    assert!(html.contains("<code class=\"chip\">net:203.0.113.9:443</code>"));
}

/// The static findings, grouped.
fn assert_findings(html: &str) {
    // Grouped by severity, kind and context, severe and large groups
    // first, with one filter button per severity.
    assert_eq!(
        text(html, "<div class=\"filter\"", "</div>"),
        "All 365 high 1 medium 60 low 1 info 301 other 2 6 groups"
    );

    let groups = groups(html);
    assert_eq!(groups.len(), 6);
    assert_eq!(
        groups[0],
        row(&[
            "high build_script net_call fn main 1",
            "Command::new(\"curl\") build.rs:12"
        ])
    );
    assert!(html.contains("<details class=\"group sev-high\" open>"));
    assert!(html.contains("<details class=\"group sev-medium\">"));

    let spawn = &groups[1];
    assert_eq!(spawn.len(), 2);
    assert_eq!(spawn[0], "medium process_spawn build_script 60");
    assert!(spawn[1].starts_with("Command::new build.rs:1 build.rs:2 "));
    assert!(spawn[1].ends_with(" build.rs:50 and 10 more"));

    assert_eq!(
        groups[2],
        row(&["low unsafe_block lib 1", "unsafe { <x> } src/lib.rs"])
    );
    assert_eq!(groups[3].len(), 302);
    assert_eq!(groups[3][0], "info filler 301");
    assert_eq!(groups[3][301], "e304 src/f.rs");
    assert_eq!(groups[4], row(&["3 odd null 1", "true src/odd.rs"]));
    assert_eq!(groups[5], row(&["sparse 1", ""]));
}

/// The state changes.
fn assert_timeline(html: &str) {
    let timeline = table(html, "<h2>Timeline</h2>");
    assert_eq!(timeline[0], row(&["When", "From", "To", "Event", "Worker"]));
    assert!(timeline[1..].iter().all(|r| r[0].ends_with(" ago")));

    let steps: Vec<&[String]> = timeline[1..].iter().map(|r| &r[1..]).collect();
    assert_eq!(
        steps,
        [
            row(&["Discovered", "Fetched", "fetched", "w-fetch"]),
            row(&[
                "Fetched",
                "StaticallyAnalyzed",
                "static_analysis_completed",
                "w-static"
            ]),
            row(&["StaticallyAnalyzed", "Scored", "scored", "w-analysis"]),
        ]
    );
}

/// The full run's section: alerts, facts and the process tree.
fn assert_full_run(html: &str) {
    assert!(
        !html.contains("<h2>Run: check</h2>"),
        "the full run replaces it"
    );

    let full = run_section(html, "full");
    assert_eq!(
        text(full, "<ul class=\"alerts\">", "</ul>"),
        "Honeytoken github_token left the VM through dns:evil.example"
    );
    assert!(full.contains("<span class=\"badge ok\">succeeded</span>"));

    for (label, value) in [
        ("Ended", "agent reported the end"),
        ("Guest", "exit code 0"),
        ("Run time", "4.2 s"),
        ("Payload", "3 files, 4.0 KiB"),
        ("Files opened", "12"),
    ] {
        assert!(
            full.contains(&format!("<dt>{label}</dt><dd>{value}</dd>")),
            "{label}"
        );
    }

    let tree = table(full, "<h3>Processes");
    assert_eq!(tree.len(), 5);
    assert_eq!(tree[3][0], "└build_script /w/build-script-build");
    assert_eq!(
        tree[4],
        row(&[
            "└other /usr/bin/<curl>",
            "https://evil.example/x",
            "12 ms",
            "",
            "0"
        ])
    );
    assert!(full.contains("<tr class=\"role-rustc compiler\">"));
    assert!(
        !full.contains("<curl>") && !full.contains("<unused>"),
        "guest text is escaped"
    );
    assert!(full.contains("<code class=\"chip\">evil.example</code>"));
    assert!(full.contains("href=\"/jobs/1/runs/full.json\""));
    assert!(full.contains("<a href=\"/jobs/1/runs/check.json\" download>"));
}

#[tokio::test]
async fn a_scored_and_confirmed_job_shows_everything_the_store_knows() {
    let Some(mut db) = Dashboard::start().await else {
        return;
    };

    let job = seed_full_job(&mut db).await;
    let day = db.store.disclosure(job).await.unwrap().unwrap();

    let html = db.page(job).await;
    assert_header(&html, job);
    assert_disclosure(&html, &day);
    assert_evidence(&html);
    assert_findings(&html);
    assert_timeline(&html);
    assert_full_run(&html);

    let (status, head, body) = db.fetch("/jobs/1/runs/full.json").await;
    assert_eq!(status, 200);

    let file = "filename=\"crateward-job-1-full.json\"";
    assert!(head.contains(&format!("content-disposition: attachment; {file}")));
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), run_report());

    let (_, _, body) = db.fetch("/jobs/1/runs/check.json").await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"network": "x"})
    );
    assert_eq!(db.fetch("/jobs/1/runs/other.json").await.0, 404);
    assert_eq!(db.fetch("/jobs/1/runs/check").await.0, 404);

    db.drop().await;
}

#[tokio::test]
async fn a_new_job_shows_empty_sections() {
    let Some(db) = Dashboard::start().await else {
        return;
    };

    let job = db.job().await;

    let html = db.page(job).await;
    assert_eq!(text(&html, "<h1>", "</h1>"), "evil 0.1.0");
    assert_eq!(
        text(&html, "<p class=\"meta\">", "</p>"),
        format!("Discovered job {} crates.io", job.0)
    );
    assert!(!html.contains("/review"));
    assert!(!html.contains("class=\"verdict"));
    assert!(!html.contains("class=\"headline\""));
    assert!(!html.contains("id=\"disclosure\""));
    assert!(!html.contains("New since the previous version"));
    assert!(!html.contains("<h2>Run:"));
    assert!(
        html.contains("<h2 id=\"evidence\">Evidence</h2>\n<p class=\"muted\">No evidence.</p>")
    );
    assert!(html.contains("<h4>Profile</h4>\n<p class=\"muted\">Empty.</p>"));
    assert!(
        html.contains("<h2 id=\"findings\">Static findings</h2>\n<p class=\"muted\">None.</p>")
    );

    let timeline = table(&html, "<h2>Timeline</h2>");
    assert_eq!(timeline, [row(&["When", "From", "To", "Event", "Worker"])]);

    db.drop().await;
}

#[tokio::test]
async fn a_scored_job_offers_a_review_and_a_confirmed_one_its_disclosure() {
    let Some(db) = Dashboard::start().await else {
        return;
    };

    let job = db.job().await;
    db.store.record_verdict(job, &verdict()).await.unwrap();

    let html = db.page(job).await;

    assert_eq!(
        text(
            &html,
            "<div class=\"verdict tone-critical\">",
            "<div class=\"decision\">"
        ),
        "85 critical"
    );
    assert_eq!(
        text(&html, "<div class=\"decision\">", "<form"),
        "Review none"
    );

    let form = format!("action=\"/jobs/{}/review\"", job.0);
    assert_eq!(html.matches(&form).count(), 2);
    assert!(!html.contains("id=\"disclosure\""));

    assert!(
        db.store
            .set_review(job, Review::Confirmed, None)
            .await
            .unwrap()
    );

    let html = db.page(job).await;
    assert!(
        html.contains(
            "<h2 id=\"disclosure\">Disclosure</h2>\n\n<p class=\"muted\">Not reported yet."
        )
    );

    // Until the report is recorded, the inbox and a filter find it.
    let link = format!("<a href=\"/jobs/{}\">", job.0);
    let (_, inbox) = db.get("/inbox").await;
    let (waiting, unreported) = inbox.split_once("<h2>Confirmed, not reported").unwrap();

    assert!(!waiting.contains(&link) && unreported.contains(&link));
    assert!(unreported.contains("<span class=\"badge warn\">not reported</span>"));

    let (_, found) = db.get("/jobs?review=unreported").await;
    assert!(found.contains(&link));
    assert!(found.contains("<option value=\"unreported\" selected>"));
    assert!(!db.get("/jobs?review=pending").await.1.contains(&link));
    assert!(html.contains(&format!(
        "<code>crateward evidence {} --out &lt;dir&gt;</code>",
        job.0
    )));

    let kind = DisclosureKind::Vulnerability;
    let reported = db
        .store
        .record_report(job, kind, "the maintainer", None, None);

    reported.await.unwrap().unwrap();
    let day = db
        .store
        .disclosure(job)
        .await
        .unwrap()
        .unwrap()
        .reported_on
        .unwrap();

    assert!(!db.get("/jobs?review=unreported").await.1.contains(&link));
    assert!(db.get("/jobs?review=confirmed").await.1.contains(&link));

    let (_, inbox) = db.get("/inbox").await;
    assert!(inbox.contains("Every confirmed verdict was reported."));

    let html = db.page(job).await;
    assert_eq!(
        facts(&html, "<h2 id=\"disclosure\">"),
        [
            row(&["Kind", "vulnerability"]),
            row(&["Reported", &format!("{day} to the maintainer")]),
            row(&["Reference", "-"]),
            row(&["Resolved", "-"]),
            row(&["Published", "-"]),
            row(&["Page", "-"]),
            row(&["Note", "-"]),
        ]
    );

    db.drop().await;
}

#[tokio::test]
async fn events_without_a_kind_or_from_the_future_still_render() {
    let Some(db) = Dashboard::start().await else {
        return;
    };

    let job = db.job().await;
    db.raw_event(job, "now() + interval '1 hour'", "{}").await;
    db.raw_event(job, "now() - interval '3 days'", "{\"kind\": \"old\"}")
        .await;

    let html = db.page(job).await;

    let timeline = table(&html, "<h2>Timeline</h2>");
    assert_eq!(
        timeline[1..],
        [
            row(&["0 s ago", "Scored", "Finalized", "?", "w-raw"]),
            row(&["3 d ago", "Scored", "Finalized", "old", "w-raw"]),
        ]
    );

    db.drop().await;
}

#[tokio::test]
async fn an_unknown_job_is_not_found() {
    let Some(db) = Dashboard::start().await else {
        return;
    };

    assert_eq!(db.get("/jobs/999").await, (404, "no such job".to_owned()));

    db.drop().await;
}

#[tokio::test]
async fn the_job_list_counts_states_and_pages() {
    let Some(db) = Dashboard::start().await else {
        return;
    };

    for i in 0..101 {
        let new = NewJob {
            name: format!("many-{i}").parse().unwrap(),
            version: "0.1.0".parse().unwrap(),
            cksum: CKSUM.parse().unwrap(),
            published_at: None,
            priority: 0,
            index_entry: json!({}),
        };

        db.store.enqueue(&new).await.unwrap().unwrap();
    }

    let fail = format!(
        "UPDATE {}.jobs SET state = 'Failed' WHERE id = 7",
        db.db.schema()
    );

    db.db.admin().execute(&fail, &[]).await.unwrap();

    let link = |id: i64| format!("<a href=\"/jobs/{id}\">");
    let (status, first) = db.get("/jobs").await;

    assert_eq!(status, 200);
    assert!(first.contains("101 matching. Showing 1 to 10."));
    assert!(first.contains("<h1>Jobs <span class=\"count\">101</span></h1>"));
    assert!(first.contains("Discovered <span class=\"count\">100</span>"));
    assert!(first.contains("<a href=\"/jobs?state=Failed\">Failed <span class=\"count\">1</span>"));
    assert!(first.contains("Running <span class=\"count\">0</span>"));
    assert!(first.contains("<a href=\"/jobs\" aria-current=\"page\">Jobs</a>"));
    assert!(first.contains(&link(92)) && !first.contains(&link(91)));
    assert!(first.contains("<span class=\"disabled\" title=\"first page\">«</span>"));
    assert!(first.contains(
        "<span class=\"current\" title=\"page 1, shown\" aria-current=\"page\">1</span>"
    ));
    assert!(first.contains("<a href=\"/jobs?page=2\" title=\"next page\">›</a>"));
    assert!(first.contains("<a href=\"/jobs?page=11\" title=\"last page\">»</a>"));

    let (_, second) = db.get("/jobs?page=2").await;

    assert!(second.contains("<a href=\"/jobs\" title=\"previous page\">‹</a>"));

    let (_, last) = db.get("/jobs?page=11").await;

    assert!(last.contains("Showing 101 to 101."));
    assert!(last.contains(&link(1)) && !last.contains(&link(2)));
    assert!(last.contains("<a href=\"/jobs?page=10\" title=\"previous page\">‹</a>"));
    assert!(last.contains("<span class=\"disabled\" title=\"last page\">»</span>"));

    // Another page size, and links that keep the first job in view.
    let (_, third) = db.get("/jobs?per=25&page=3").await;

    assert!(third.contains("Showing 51 to 75."));
    assert!(third.contains(&link(51)) && third.contains(&link(27)));
    assert!(!third.contains(&link(52)) && !third.contains(&link(26)));
    assert!(third.contains("<span class=\"current\" aria-current=\"true\">25</span>"));
    assert!(
        third.contains("<a href=\"/jobs?per=50&#38;page=2\" title=\"50 jobs per page\">50</a>")
    );
    assert!(third.contains("<a href=\"/jobs?page=6\" title=\"10 jobs per page\">10</a>"));
    assert!(third.contains("<a href=\"/jobs?state=Failed&#38;per=25\">Failed"));

    // Out of range pages and sizes fall back.
    assert!(
        db.get("/jobs?page=99")
            .await
            .1
            .contains("Showing 101 to 101.")
    );
    assert!(db.get("/jobs?per=500").await.1.contains("Showing 1 to 10."));

    // The counts keep the other filters, the list takes the state.
    let (_, failed) = db.get("/jobs?name=many&state=Failed").await;

    assert!(failed.contains("1 matching"));
    assert!(failed.contains(&link(7)) && !failed.contains(&link(8)));
    assert!(
        failed.contains("<a href=\"/jobs?name=many&#38;state=Failed\" class=\"selected\" aria-current=\"page\">Failed")
    );
    assert!(failed.contains("<a href=\"/jobs?name=many\">all</a>"));
    assert!(failed.contains("<option value=\"Failed\" selected>"));

    // An unknown state is no filter.
    assert!(db.get("/jobs?state=Bogus").await.1.contains("101 matching"));
    assert!(db.get("/jobs?name=zzz").await.1.contains(
        "<p class=\"empty\">No job matches these filters. <a href=\"/jobs\">Clear them</a>.</p>"
    ));

    // The overview draws the states as bars on the same scale.
    let (status, overview) = db.get("/").await;
    assert_eq!(status, 200);
    assert!(overview.contains("<a href=\"/\" aria-current=\"page\">Overview</a>"));
    assert!(overview.contains(
        "<a class=\"bar\" href=\"/jobs?state=Discovered\"><span class=\"name\">Discovered</span>\n<meter min=\"0\" max=\"101\" value=\"100\">100</meter>"
    ));

    db.drop().await;
}

#[tokio::test]
async fn static_evidence_links_to_its_line_on_crates_io() {
    let Some(db) = Dashboard::start().await else {
        return;
    };

    let job = db.job().await;
    let spawn = evidence(
        "static:process_spawn",
        30,
        EvidenceSource::Static,
        "high severity process_spawn in build_script code",
        Some("evil"),
        Some("build.rs:3"),
    );

    // A verdict from before YARA matches had a line names only the file.
    let yara = evidence(
        "static:yara:reverse_shell",
        10,
        EvidenceSource::Static,
        "reverse shell",
        Some("evil"),
        Some("build.rs"),
    );

    let mut v = verdict();
    v.evidence = vec![spawn, yara];
    db.store.record_verdict(job, &v).await.unwrap();
    db.store.record_crate_file(&crate_file()).await.unwrap();
    let report = json!({"findings": [
        {"severity": "high", "kind": "process_spawn", "file": "build.rs", "line": 3,
         "evidence": "Command::new"},
        {"severity": "high", "kind": "yara_match", "rule": "reverse_shell", "file": "build.rs",
         "line": 9, "evidence": "reverse shell"},
        {"severity": "low", "kind": "process_spawn", "file": "src/lib.rs", "line": 3, "evidence": "other"}
    ]});

    let cksum = CKSUM.parse().unwrap();
    let recorded = db
        .store
        .record_static_report(&cksum, 4, true, None, &report);

    recorded.await.unwrap();

    let html = db.page(job).await;
    let evidence = &html
        [html.find("<h2 id=\"evidence\">").unwrap()..html.find("<h2 id=\"findings\">").unwrap()];

    let viewer = "https://crates.io/crates/evil/0.1.0/code/build.rs";

    assert!(evidence.contains(&format!("<a href=\"{viewer}#L3\"")));

    // The old verdict names only the file. The finding knows the line.
    assert!(evidence.contains(&format!("<a href=\"{viewer}#L9\"")));

    let findings = &html[html.find("<h2 id=\"findings\">").unwrap()..];
    assert!(findings.contains("href=\"https://crates.io/crates/evil/0.1.0/code/src/lib.rs#L3\""));

    db.drop().await;
}

#[tokio::test]
async fn burst_mode_is_switched_on_the_jobs_page() {
    let Some(db) = Dashboard::start().await else {
        return;
    };

    assert!(!db.get("/jobs").await.1.contains("Stop burst mode"));
    assert_eq!(db.post("/burst", "action=start").await, 303);
    assert!(db.store.bursting().await.unwrap());
    assert!(db.get("/jobs").await.1.contains("Stop burst mode"));

    assert_eq!(db.post("/burst", "action=stop").await, 303);
    assert!(!db.store.bursting().await.unwrap());
    assert_eq!(db.post("/burst", "action=later").await, 400);

    db.drop().await;
}

/// A scored version of `masker` with its file, static report, run and
/// package diff.
async fn version(
    db: &mut Dashboard,
    version: &str,
    n: u8,
    score: u32,
    findings: Value,
    run: Value,
) -> JobId {
    let cksum = format!("{n:02x}").repeat(32);
    let new = NewJob {
        name: "masker".parse().unwrap(),
        version: version.parse().unwrap(),
        cksum: cksum.parse().unwrap(),
        published_at: None,
        priority: 0,
        index_entry: json!({}),
    };

    let job = db.store.enqueue(&new).await.unwrap().unwrap();
    db.step(job, Stage::Fetch, "w", JobEvent::Fetched).await;
    let triage = Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode);
    let analyzed = JobEvent::StaticAnalysisCompleted { triage };
    db.step(job, Stage::StaticAnalysis, "w", analyzed).await;
    db.step(
        job,
        Stage::Analysis,
        "w",
        JobEvent::Scored { escalate: false },
    )
    .await;

    let store = &db.store;
    let mut v = verdict();
    v.score = score;
    v.level = RiskLevel::from_score(score);
    v.evidence.truncate(if score > 50 { 2 } else { 1 });
    store.record_verdict(job, &v).await.unwrap();
    store
        .record_crate_file(&CrateFile {
            sha256: cksum.parse().unwrap(),
            sha512: None,
            name: "masker".to_owned(),
            version: version.to_owned(),
            ..crate_file()
        })
        .await
        .unwrap();
    store
        .record_static_report(
            &cksum.parse().unwrap(),
            7,
            true,
            Some("high"),
            &json!({"findings": findings}),
        )
        .await
        .unwrap();
    store
        .record_run(job, "full", "completed", &run)
        .await
        .unwrap();
    let diff = json!({"previous_version": "0.1.0", "build_script_added": true, "proc_macro_added": false,
                      "links_changed": false, "new_findings": [], "removed_findings": 0, "new_dependencies": ["cc"]});

    store
        .record_job_static(job, &json!({}), &json!([]), Some(&diff))
        .await
        .unwrap();

    job
}

#[tokio::test]
async fn a_version_is_compared_with_the_one_before() {
    let Some(mut db) = Dashboard::start().await else {
        return;
    };

    let finding = |evidence: &str, line: u32| json!({"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": line, "evidence": evidence});

    let mut quiet = run_report();
    quiet["trace"]["processes"]
        .as_array_mut()
        .unwrap()
        .truncate(3);
    quiet["network"]["dns"] = json!([]);

    let old = version(&mut db, "0.1.0", 1, 20, json!([finding("curl", 3)]), quiet).await;
    let new = version(
        &mut db,
        "0.2.0",
        2,
        85,
        json!([finding("curl", 9), finding("wget <x>", 10)]),
        run_report(),
    )
    .await;

    // The newer job links its comparison, the oldest has none.
    let html = db.page(new).await;
    assert!(html.contains(&format!(
        "<a class=\"button compare\" href=\"/jobs/{}/diff\">Compare with 0.1.0</a>",
        new.0
    )));
    assert!(!db.page(old).await.contains("Compare with"));
    assert_eq!(
        db.get(&format!("/jobs/{}/diff", old.0)).await,
        (404, "nothing to compare with".to_owned())
    );

    let (status, diff) = db.get(&format!("/jobs/{}/diff", new.0)).await;
    assert_eq!(status, 200);
    assert_eq!(text(&diff, "<h1>", "</h1>"), "masker 0.1.0 → 0.2.0");
    assert!(diff.contains("href=\"https://diff.rs/masker/0.1.0/0.2.0/\""));
    assert_eq!(
        text(&diff, "<div class=\"versus\">", "<p class=\"versions\">"),
        "20 medium → 85 critical"
    );
    assert_eq!(
        text(&diff, "<nav class=\"toc\"", "</nav>"),
        "Evidence 1 Package Static findings 1 Run: full 2 Behavior 0"
    );
    assert_eq!(
        table(&diff, "<h2 id=\"evidence\">"),
        [
            row(&["Change", "Points", "Signal", "What"]),
            row(&["added", "10", "exec_curl", "ran <curl> & \"more\""]),
        ]
    );
    assert_eq!(
        facts(&diff, "<h2 id=\"package\">"),
        [
            row(&["Build script", "added"]),
            row(&["Proc macro", "no change"]),
            row(&["links", "no change"]),
            row(&["New dependencies", "cc"]),
        ]
    );
    assert!(diff.contains(
        "<p class=\"tally\">1 new, 0 gone, 1 the same. Code that only moved counts as the same.</p>"
    ));
    assert!(diff.contains("<code class=\"evidence-text\">wget &#60;x&#62;</code>"));
    assert!(diff.contains("href=\"https://crates.io/crates/masker/0.2.0/code/build.rs#L10\""));

    let full = run_section(&diff, "full");
    assert!(
        full.contains("<h3>Processes <span class=\"muted\">1 new, 0 gone, 3 the same</span></h3>")
    );
    assert!(full.contains("<tr class=\"role-other added\">"));
    assert!(full.contains("<tr class=\"role-build_script context\">"));
    assert!(full.contains("<code class=\"chip new\">evil.example</code>"));

    // Another version can be chosen, and only of the same crate.
    let (_, back) = db
        .get(&format!("/jobs/{}/diff?against={}", old.0, new.0))
        .await;

    assert_eq!(text(&back, "<h1>", "</h1>"), "masker 0.2.0 → 0.1.0");
    assert!(back.contains("<p class=\"empty\">The static analysis compared this version with 0.1.0, so its package diff is not shown here.</p>"));
    assert!(back.contains(&format!(
        "<a class=\"chip selected\" href=\"/jobs/{}/diff?against={}\" aria-current=\"page\">0.2.0</a>",
        old.0, new.0
    )));

    let other = db.job().await;
    assert_eq!(
        db.get(&format!("/jobs/{}/diff?against={}", new.0, other.0))
            .await
            .0,
        404
    );

    db.drop().await;
}

#[tokio::test]
async fn a_finished_job_offers_its_sbom_and_findings_document() {
    let Some(mut db) = Dashboard::start().await else {
        return;
    };

    let job = seed_full_job(&mut db).await;
    let page = db.page(job).await;
    assert!(!page.contains("sbom.cdx.json"));
    let (status, body) = db.get(&format!("/jobs/{}/vex.cdx.json", job.0)).await;
    assert_eq!((status, body.as_str()), (404, "no SBOM for this job yet"));

    let lock = format!(
        "version = 4\n\n[[package]]\nname = \"evil\"\nversion = \"0.1.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"{CKSUM}\"\n"
    );

    db.store
        .record_fetch(job, Some(&lock), None, &json!([]))
        .await
        .unwrap();
    db.store.refresh_sbom(job, "0.1.0").await.unwrap();

    let page = db.page(job).await;
    assert!(page.contains(&format!(
        "<a class=\"muted\" href=\"/jobs/{}/sbom.cdx.json\" download",
        job.0
    )));
    assert!(page.contains(&format!("href=\"/jobs/{}/vex.cdx.json\" download", job.0)));

    let (status, head, body) = db.fetch(&format!("/jobs/{}/sbom.cdx.json", job.0)).await;
    assert_eq!(status, 200);
    assert!(head.contains("content-type: application/vnd.cyclonedx+json"));
    assert!(head.contains("filename=\"evil-0.1.0.cdx.json\""));
    let sbom: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        sbom["metadata"]["component"]["purl"],
        "pkg:cargo/evil@0.1.0"
    );

    let (status, head, body) = db.fetch(&format!("/jobs/{}/vex.cdx.json", job.0)).await;
    assert_eq!(status, 200);
    assert!(head.contains("filename=\"evil-0.1.0.vex.cdx.json\""));
    let vex: Value = serde_json::from_str(&body).unwrap();

    // Scored, confirmed and published: three changes.
    assert_eq!(vex["version"], 3);
    let serial = sbom["serialNumber"].as_str().unwrap();
    let link = format!(
        "urn:cdx:{}/1#pkg:cargo/evil@0.1.0",
        serial.trim_start_matches("urn:uuid:")
    );

    let token = vex["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == format!("CW-{}-honeytoken_left_vm", job.0))
        .unwrap();
    assert_eq!(token["affects"][0]["ref"], link);
    assert_eq!(token["analysis"]["state"], "exploitable");
    assert_eq!(
        token["source"]["url"],
        "https://crateward.com/findings/evil-0-1-0/"
    );

    db.drop().await;
}
