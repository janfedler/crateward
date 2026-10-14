//! The `crateward` tool, run as the maintainer runs it: a process with a
//! configuration file, arguments in, text and an exit code out.
//!
//! The commands that use the job store get their database from
//! `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod evidence;
mod offline;
mod operations;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crateward_core::breaker::BreakerState;
use crateward_core::escalation::HumanEscalation;
use crateward_core::job::{JobEvent, JobId, JobState, Stage, Triage, mermaid_diagram};
use crateward_core::store::{CrateFile, DisclosureKind, NewJob, PauseReason, Review, Store};
use crateward_core::testing::{TestDb, policies};
use crateward_core::verdict::{Coverage, RiskLevel, StaticOnlyReason, Verdict};
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
                "/usr/local/lib/crateward/crateward-fake-internet",
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

/// A migrated private schema. `store` seeds it. `url` is what the tool
/// connects with.
struct Db {
    db: TestDb,
    url: String,
    store: Store,
}

impl Db {
    async fn new() -> Option<Self> {
        let db = TestDb::new("cli").await?;
        let store = db.migrated().await;

        // The configuration wants a URL: each `key=value` becomes a
        // parameter, and the session option selects the schema.
        let pairs: String = db
            .config()
            .split_whitespace()
            .map(|p| format!("{p}&"))
            .collect();

        let url = format!(
            "postgresql:///?{pairs}options=-c%20search_path%3D{}",
            db.schema()
        );

        Some(Self { db, url, store })
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

    /// Moves a static only job through every stage to done.
    async fn finish(&mut self, job: JobId) {
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
            self.store.claim(stage, "w", lease).await.unwrap().unwrap();
            self.store
                .complete(job, "w", event, &policies(), false)
                .await
                .unwrap();
        }
    }

    async fn drop(self) {
        self.db.drop().await;
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
