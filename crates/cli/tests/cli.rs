//! The `crateward` tool, run as the maintainer runs it: a process with a
//! configuration file, arguments in, text and an exit code out.
//!
//! The commands that use the job store need `CRATEWARD_TEST_DATABASE_URL`
//! (for example `host=/var/run/postgresql dbname=crateward_test`). Each test
//! works in its own schema, dropped at the end. Without the variable those
//! tests skip, unless `CRATEWARD_REQUIRE_DB=1`, which CI sets so that a
//! missing database fails instead of passing silently.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crateward_core::breaker::BreakerState;
use crateward_core::escalation::HumanEscalation;
use crateward_core::job::{JobEvent, JobId, JobState, Limits, Stage, StageLimits, mermaid_diagram};
use crateward_core::retry::RetryPolicy;
use crateward_core::store::{CrateFile, NewJob, PauseReason, Policies, Review, Store};
use crateward_core::verdict::{Coverage, RiskLevel, Verdict};
use serde_json::{Value, json};

const TOOL: &str = env!("CARGO_BIN_EXE_crateward");
const EXAMPLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/crateward.example.toml"
);
const MISSING: &str = "/nonexistent/crateward.toml";
const TOKEN: &str = "cioTOKEN123";
const CKSUM: &str = "abababababababababababababababababababababababababababababababab";

/// What a run of the tool left behind.
struct Ran {
    code: i32,
    out: String,
    err: String,
}

impl Ran {
    fn expect(&self, code: i32, out: &str, err: &str) {
        assert_eq!(
            (self.code, self.out.as_str(), self.err.as_str()),
            (code, out, err)
        );
    }
}

fn run(tool: impl AsRef<Path>, config: Option<&Path>, args: &[&str]) -> Ran {
    let mut command = Command::new(tool.as_ref());
    command.args(args).env_remove("CRATEWARD_CONFIG");
    if let Some(config) = config {
        command.env("CRATEWARD_CONFIG", config);
    }
    let output = command.output().unwrap();
    Ran {
        code: output.status.code().unwrap(),
        out: String::from_utf8(output.stdout).unwrap(),
        err: String::from_utf8(output.stderr).unwrap(),
    }
}

/// Whether `line` is `before`, a number of seconds, then `after`. The tests
/// cannot know how long a pause or a canary result has been there.
fn with_seconds(line: &str, before: &str, after: &str) -> bool {
    line.strip_prefix(before)
        .and_then(|rest| rest.strip_suffix(after))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

static SITES: AtomicU32 = AtomicU32::new(0);

/// A private directory with a configuration, the files the integrity
/// manifest covers and a link to the tool in `bin/`.
struct Site {
    dir: PathBuf,
    config: PathBuf,
}

impl Site {
    const FILES: [&str; 6] = [
        "firecracker",
        "vmjail",
        "fake_internet",
        "kernel",
        "rootfs",
        "cargo",
    ];

    fn new(database_url: &str) -> Self {
        let n = SITES.fetch_add(1, Ordering::SeqCst);
        let name = format!("cli-{}-{n}", std::process::id());
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["bin", "files", "data", "run"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        // A link, not a copy: a file open for writing cannot be run.
        std::fs::hard_link(TOOL, dir.join("bin/crateward")).unwrap();
        for name in Self::FILES {
            std::fs::write(dir.join("files").join(name), name).unwrap();
        }
        let config = dir.join("crateward.toml");
        std::fs::write(&config, Self::config_text(&dir, database_url)).unwrap();
        Self { dir, config }
    }

    /// The example configuration with this site's paths and database.
    fn config_text(dir: &Path, database_url: &str) -> String {
        let files = dir.join("files");
        let mut text = std::fs::read_to_string(EXAMPLE).unwrap();
        let replacements = [
            ("/var/lib/crateward", dir.join("data")),
            ("/run/crateward", dir.join("run")),
            (
                "/usr/local/lib/crateward/firecracker",
                files.join("firecracker"),
            ),
            (
                "/usr/local/lib/crateward/crateward-vmjail",
                files.join("vmjail"),
            ),
            (
                "/usr/local/lib/crateward/crateward_fake_internet",
                files.join("fake_internet"),
            ),
            (
                "/usr/local/lib/crateward/guest/current/kernel.bzImage",
                files.join("kernel"),
            ),
            (
                "/usr/local/lib/crateward/guest/current/rootfs.erofs",
                files.join("rootfs"),
            ),
            (
                "/usr/local/lib/crateward/toolchain/bin/cargo",
                files.join("cargo"),
            ),
        ];
        for (old, new) in replacements {
            let old = format!("\"{old}\"");
            assert!(text.contains(&old), "the example configuration lost {old}");
            text = text.replace(&old, &format!("\"{}\"", new.display()));
        }
        let old = "\"postgresql://crateward@localhost/crateward?host=/run/postgresql\"";
        assert!(
            text.contains(old),
            "the example configuration lost its database"
        );
        text.replace(old, &format!("\"{database_url}\""))
    }

    fn run(&self, args: &[&str]) -> Ran {
        run(self.dir.join("bin/crateward"), Some(&self.config), args)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.join(relative)
    }

    fn manifest(&self) -> PathBuf {
        self.path("data/integrity.b3")
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// The commands that need no database.

#[test]
fn config_check_accepts_a_valid_file() {
    run(TOOL, None, &["config", "check", "--config", EXAMPLE]).expect(
        0,
        &format!("{EXAMPLE} is valid\n"),
        "",
    );
}

#[test]
fn a_bad_configuration_exits_78_and_says_why() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let text = std::fs::read_to_string(&site.config).unwrap();
    std::fs::write(
        &site.config,
        text.replace("[instance]", "[instance]\nnickname = 1"),
    )
    .unwrap();
    let ran = site.run(&["config", "check"]);
    assert_eq!((ran.code, ran.out.as_str()), (78, ""));
    assert!(ran.err.contains("nickname"), "{}", ran.err);
    let missing = run(TOOL, None, &["config", "check", "--config", MISSING]);
    missing.expect(
        78,
        "",
        &format!("cannot read {MISSING}: No such file or directory (os error 2)\n"),
    );
}

#[test]
fn every_command_that_reads_the_configuration_exits_78_without_it() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-such-pack");
    let out = out.to_str().unwrap();
    let commands: [&[&str]; 9] = [
        &["config", "check", "--config", MISSING],
        &["status", "--config", MISSING],
        &["quarantine", "--config", MISSING, "lift"],
        &["integrity", "--config", MISSING, "record"],
        &["integrity", "--config", MISSING, "check"],
        &["egress", "--config", MISSING],
        &["evidence", "1", "--out", out, "--config", MISSING],
        &["disclosure", "--config", MISSING, "show", "1"],
        &["breaker", "--config", MISSING, "close", "sandbox"],
    ];
    for args in commands {
        let ran = run(TOOL, None, args);
        assert_eq!((ran.code, ran.out.as_str()), (78, ""), "{args:?}");
        assert!(ran.err.contains(MISSING), "{args:?}: {}", ran.err);
    }
    assert!(!Path::new(out).exists());
}

#[test]
fn an_unknown_stage_is_refused_before_the_configuration_is_read() {
    let ran = run(
        TOOL,
        None,
        &["breaker", "--config", MISSING, "close", "bogus"],
    );
    ran.expect(1, "", "unknown stage bogus\n");
}

#[test]
fn state_machine_diagram_prints_the_mermaid_source() {
    let ran = run(TOOL, None, &["state-machine", "diagram"]);
    ran.expect(0, &mermaid_diagram(), "");
    assert!(ran.out.ends_with("\n") && !ran.out.ends_with("\n\n"));
}

#[test]
fn state_machine_states_lists_the_stage_that_owns_each_state() {
    let ran = run(TOOL, None, &["state-machine", "states"]);
    let expected: String = JobState::ALL
        .iter()
        .map(|state| {
            let owner = state
                .stage()
                .map_or("none (terminal)", |stage| stage.name());
            format!("{:<20} {owner}\n", state.name())
        })
        .collect();
    ran.expect(0, &expected, "");
    assert!(ran.out.starts_with("Discovered           fetch\n"));
    assert!(ran.out.ends_with("Failed               none (terminal)\n"));
}

#[test]
fn a_closed_pipe_ends_the_tool_quietly() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = Command::new(TOOL)
        .args(["state-machine", "diagram"])
        .env_remove("CRATEWARD_CONFIG")
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn an_unreachable_database_exits_1() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let ran = site.run(&["status"]);
    assert_eq!((ran.code, ran.out.as_str()), (1, ""));
    assert!(ran.err.ends_with('\n') && ran.err.len() > 1, "{}", ran.err);
}

#[test]
fn the_manifest_is_recorded_and_checked() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let manifest = site.manifest();
    site.run(&["integrity", "record"]).expect(
        0,
        &format!("recorded 7 files in {}\n", manifest.display()),
        "",
    );
    let text = std::fs::read_to_string(&manifest).unwrap();
    let mut expected: Vec<String> = Site::FILES
        .iter()
        .map(|name| site.path(&format!("files/{name}")))
        .chain([site.path("bin/crateward")])
        .map(|path| path.display().to_string())
        .collect();
    expected.sort();
    let recorded: Vec<&str> = text
        .lines()
        .map(|l| l.split_once("  ").unwrap().1)
        .collect();
    assert_eq!(recorded, expected);
    assert!(!site.path("data/integrity.tmp").exists());
    site.run(&["integrity", "check"])
        .expect(0, "7 files match\n", "");

    let kernel = site.path("files/kernel");
    std::fs::write(&kernel, "changed").unwrap();
    site.run(&["integrity", "check"]).expect(
        1,
        &format!("MISMATCH {}: digest differs\n", kernel.display()),
        "1 files differ\n",
    );
    let rootfs = site.path("files/rootfs");
    std::fs::remove_file(&rootfs).unwrap();
    let ran = site.run(&["integrity", "check"]);
    assert_eq!((ran.code, ran.err.as_str()), (1, "2 files differ\n"));
    let lines: Vec<&str> = ran.out.lines().collect();
    assert_eq!(
        lines[0],
        format!("MISMATCH {}: digest differs", kernel.display())
    );
    assert!(lines[1].starts_with(&format!("MISMATCH {}: ", rootfs.display())));
    assert!(lines[1].ends_with("No such file or directory (os error 2)"));
    assert_eq!(lines.len(), 2);
}

#[test]
fn a_manifest_that_is_missing_or_malformed_fails_the_check() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let manifest = site.manifest();
    site.run(&["integrity", "check"]).expect(
        1,
        "",
        &format!(
            "{}: No such file or directory (os error 2)\n",
            manifest.display()
        ),
    );
    std::fs::write(&manifest, "garbage\n").unwrap();
    site.run(&["integrity", "check"])
        .expect(1, "", "manifest line 1 is malformed\n");
}

#[test]
fn recording_into_a_missing_directory_fails() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    std::fs::remove_dir_all(site.path("data")).unwrap();
    let ran = site.run(&["integrity", "record"]);
    let temporary = site.path("data/integrity.tmp");
    let error = format!(
        "{}: No such file or directory (os error 2)\n",
        temporary.display()
    );
    ran.expect(1, "", &error);
}

// The commands that use the job store.

static SCHEMAS: AtomicU32 = AtomicU32::new(0);

async fn connect(config: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(config, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    client
}

/// A migrated private schema. `store` seeds it; `url` is what the tool
/// connects with.
struct Db {
    admin: tokio_postgres::Client,
    schema: String,
    url: String,
    store: Store,
}

impl Db {
    async fn new() -> Option<Self> {
        let Ok(config) = std::env::var("CRATEWARD_TEST_DATABASE_URL") else {
            assert!(
                std::env::var("CRATEWARD_REQUIRE_DB").is_err(),
                "CRATEWARD_REQUIRE_DB is set but CRATEWARD_TEST_DATABASE_URL is not"
            );
            eprintln!("skipping: CRATEWARD_TEST_DATABASE_URL is not set");
            return None;
        };
        let n = SCHEMAS.fetch_add(1, Ordering::SeqCst);
        let schema = format!("cli_{}_{n}", std::process::id());
        let admin = connect(&config).await;
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let client = connect(&config).await;
        client
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        let mut store = Store::from_client(client);
        store.migrate().await.unwrap();
        // The configuration wants a URL: each `key=value` becomes a
        // parameter, and the session option selects the schema.
        let pairs: String = config.split_whitespace().map(|p| format!("{p}&")).collect();
        let url = format!("postgresql:///?{pairs}options=-c%20search_path%3D{schema}");
        Some(Self {
            admin,
            schema,
            url,
            store,
        })
    }

    async fn job(&self, name: &str, version: &str, index_entry: Value) -> JobId {
        let new = NewJob {
            name: name.parse().unwrap(),
            version: version.parse().unwrap(),
            cksum: CKSUM.parse().unwrap(),
            published_at: None,
            priority: 0,
            index_entry,
        };
        self.store.enqueue(&new).await.unwrap().unwrap()
    }

    async fn confirmed(&self, job: JobId) {
        self.store.record_verdict(job, &verdict()).await.unwrap();
        let review = self.store.set_review(job, Review::Confirmed, None);
        assert!(review.await.unwrap());
    }

    async fn drop(self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

fn policies() -> Policies {
    let policy = RetryPolicy::new(Duration::from_secs(60), Duration::from_secs(600)).unwrap();
    Policies {
        limits: Limits::uniform(StageLimits {
            max_attempts: 3,
            max_infrastructure_retries: 2,
        }),
        backoff: Stage::ALL
            .iter()
            .map(|stage| (stage.name(), policy))
            .collect::<BTreeMap<_, _>>(),
    }
}

fn verdict() -> Verdict {
    Verdict {
        score: 90,
        level: RiskLevel::from_score(90),
        coverage: Coverage::DynamicLinux,
        evidence: Vec::new(),
        profile: vec!["exec:curl".to_owned()],
        new_behavior: Vec::new(),
        analyzer_version: 1,
    }
}

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
    assert_eq!(breakers[&Stage::Sandbox], BreakerState::Closed);
    assert_ne!(breakers[&Stage::Fetch], BreakerState::Closed);
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
    report("malicious").expect(1, "", "the verdict is not confirmed; review it first\n");
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
        "the report is not resolved yet; the embargo has not passed\n",
    );
    site.run(&["disclosure", "resolved", id, "--reference", "T-2"])
        .expect(
            0,
            &format!("job {id} is resolved; it may be published\n"),
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
        &format!("job {other} is resolved; it may be published\n"),
        "",
    );
    site.run(&["disclosure", "publish", &other, "--slug", "evil-0-1-0"])
        .expect(1, "", "another finding uses this page name\n");
    db.drop().await;
}

fn json_file(pack: &Path, name: &str) -> Value {
    let text = std::fs::read_to_string(pack.join(name)).unwrap();
    assert!(
        text.ends_with("}\n") || text.ends_with("]\n") || text == "null\n",
        "{name}"
    );
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn evidence_writes_a_redacted_and_checksummed_pack() {
    let Some(mut db) = Db::new().await else {
        return;
    };
    let site = Site::new(&db.url);
    let entry = json!({"name": "evil", "vers": "0.1.0", "note": TOKEN});
    let job = db.job("evil", "0.1.0", entry).await;
    let store = &mut db.store;
    let lease = Duration::from_secs(30);
    store
        .claim(Stage::Fetch, "fetcher-1", lease)
        .await
        .unwrap()
        .unwrap();
    let policies = policies();
    let done = store.complete(job, "fetcher-1", JobEvent::Fetched, &policies, false);
    done.await.unwrap();
    store
        .record_honeytokens(job, &[("crates_io".to_owned(), TOKEN.to_owned())])
        .await
        .unwrap();
    store.record_verdict(job, &verdict()).await.unwrap();
    let file = CrateFile {
        sha256: CKSUM.parse().unwrap(),
        name: "evil".to_owned(),
        version: "0.1.0".to_owned(),
        blake3: None,
        compressed_bytes: 5,
        unpacked_bytes: 9,
        stored_bytes: None,
        report: json!({}),
    };
    store.record_crate_file(&file).await.unwrap();
    let report = json!({"findings": []});
    let cksum = CKSUM.parse().unwrap();
    store
        .record_static_report(&cksum, 7, true, Some("high"), &report)
        .await
        .unwrap();
    let (triage, reasons, diff) = (
        json!({"decision": "dynamic"}),
        json!(["build script"]),
        json!({"added": 1}),
    );
    store
        .record_job_static(job, &triage, &reasons, Some(&diff))
        .await
        .unwrap();
    store
        .record_run(job, "full", "completed", &json!({"network": TOKEN}))
        .await
        .unwrap();
    store
        .record_run(job, "check", "completed", &json!({"tokens": [TOKEN]}))
        .await
        .unwrap();
    let packages = json!([{"name": "evil", "version": "0.1.0"}]);
    store
        .record_fetch(job, Some(&format!("# {TOKEN}\n")), None, &packages)
        .await
        .unwrap();
    let originals = site.path("data/originals");
    std::fs::create_dir_all(&originals).unwrap();
    std::fs::write(originals.join(format!("{CKSUM}.crate")), b"crate bytes").unwrap();

    let pack = site.path("pack");
    let id = job.0.to_string();
    let ran = site.run(&["evidence", &id, "--out", pack.to_str().unwrap()]);
    let names = [
        "job.json",
        "verdict.json",
        "static.json",
        "runs.json",
        "resolution.json",
        "evil-0.1.0.crate",
        "SHA256SUMS",
    ];
    let listing: String = names.iter().map(|n| format!("  {n}\n")).collect();
    ran.expect(
        0,
        &format!("wrote 7 files to {}\n{listing}", pack.display()),
        "",
    );

    let mut record = json_file(&pack, "job.json");
    let at = record["events"][0]["at_unix"].take();
    assert!(at.as_u64().unwrap() > 1_700_000_000, "{at}");
    let expected = json!({
        "id": job.0,
        "name": "evil",
        "version": "0.1.0",
        "sha256": CKSUM,
        "state": {
            "attempts": 0, "coverage": null, "dynamic_runs": 0, "escalated": false,
            "failure": null, "infrastructure_retries": 0, "last_build": null,
            "outcome": null, "run_kind": "check", "state": "fetched", "triage": null,
        },
        "index_entry": {"name": "evil", "vers": "0.1.0", "note": "[honeytoken]"},
        "events": [{
            "at_unix": null, "from": "Discovered", "to": "Fetched",
            "event": {"kind": "fetched"}, "effect": {"kind": "none"},
        }],
    });
    assert_eq!(record, expected);
    let raw = std::fs::read_to_string(pack.join("job.json")).unwrap();
    assert!(raw.starts_with("{\n  \""), "{raw}");
    assert!(raw.contains("\n  \"events\": [\n    {\n"), "{raw}");
    let attack = json!({"version": "v19", "crate": null, "evidence": []});
    let expected = json!({"verdict": verdict(), "review": "none", "attack": attack});
    assert_eq!(json_file(&pack, "verdict.json"), expected);
    let expected = json!({
        "triage": triage,
        "reasons": reasons,
        "diff": diff,
        "report": {"analyzer_version": 7, "report": report},
    });
    assert_eq!(json_file(&pack, "static.json"), expected);
    let expected = json!([
        {"kind": "check", "report": {"tokens": ["[honeytoken]"]}},
        {"kind": "full", "report": {"network": "[honeytoken]"}},
    ]);
    assert_eq!(json_file(&pack, "runs.json"), expected);
    let expected = json!({"packages": packages, "lockfile": "# [honeytoken]\n"});
    assert_eq!(json_file(&pack, "resolution.json"), expected);
    assert_eq!(
        std::fs::read(pack.join("evil-0.1.0.crate")).unwrap(),
        b"crate bytes"
    );

    let sums = std::fs::read_to_string(pack.join("SHA256SUMS")).unwrap();
    let mut lines = sums.lines();
    for name in &names[..6] {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(std::fs::read(pack.join(name)).unwrap());
        assert_eq!(lines.next().unwrap(), format!("{digest:x}  {name}"));
    }
    assert_eq!(lines.next(), None);
    for name in names {
        let text = std::fs::read(pack.join(name)).unwrap();
        assert!(
            !text.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()),
            "{name}"
        );
    }
    db.drop().await;
}

#[tokio::test]
async fn evidence_of_a_bare_job_and_the_ways_it_fails() {
    let Some(db) = Db::new().await else { return };
    let site = Site::new(&db.url);
    let job = db.job("evil", "0.1.0", json!({})).await;
    let id = job.0.to_string();
    let pack = site.path("pack");
    let pack_arg = pack.to_str().unwrap();
    let ran = site.run(&["evidence", &id, "--out", pack_arg]);
    assert_eq!(
        (ran.code, ran.err.as_str().lines().count()),
        (0, 1),
        "{}",
        ran.err
    );
    assert!(
        ran.err.starts_with("the original crate file is missing ("),
        "{}",
        ran.err
    );
    assert!(ran.err.ends_with("); the pack has none\n"), "{}", ran.err);
    let listing = [
        "job.json",
        "verdict.json",
        "static.json",
        "runs.json",
        "resolution.json",
        "SHA256SUMS",
    ];
    let listing: String = listing.iter().map(|n| format!("  {n}\n")).collect();
    assert_eq!(
        ran.out,
        format!("wrote 6 files to {}\n{listing}", pack.display())
    );
    assert_eq!(json_file(&pack, "verdict.json"), Value::Null);
    let expected = json!({"triage": null, "reasons": null, "diff": null, "report": null});
    assert_eq!(json_file(&pack, "static.json"), expected);
    assert_eq!(json_file(&pack, "runs.json"), json!([]));
    let expected = json!({"packages": null, "lockfile": null});
    assert_eq!(json_file(&pack, "resolution.json"), expected);

    let again = site.run(&["evidence", &id, "--out", pack_arg]);
    assert_eq!((again.code, again.out.as_str()), (1, ""));
    assert!(
        again.err.starts_with(&format!("{}: ", pack.display())),
        "{}",
        again.err
    );
    let other = site.path("other");
    let unknown = site.run(&["evidence", "999999", "--out", other.to_str().unwrap()]);
    unknown.expect(1, "", "no job 999999\n");
    assert!(!other.exists());
    db.drop().await;
}
