//! The sandbox stage worker: one per VM slot.
//!
//! For each job it builds the payload image and a scratch disk, plants
//! fresh honeytokens, runs `cargo check` in the slot's microVM, records the
//! run, and deletes the per job files. The job holds its lease for the
//! whole run (`SandboxStarted` keeps it), and a heartbeat renews it.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crateward_core::blobs::BlobStore;
use crateward_core::breaker::BreakerState;
use crateward_core::digest::Sha256Digest;
use crateward_core::escalation::HumanEscalation;
use crateward_core::failure::FailureClass;
use crateward_core::guest;
use crateward_core::job::{BuildOutcome, JobEvent, RunKind, Stage};
use crateward_core::name::CrateName;
use crateward_core::protocol::{ExitStatus, JobSpec, MountSpec, PathSpec, WallClock, Workspace};
use crateward_core::store::{PauseReason, Policies, Store, StoreError, StoredJob, heartbeat};
use serde::{Deserialize, Serialize};

use crateward_fake_internet::server::{Event, EventKind, unhex};
use crateward_fake_internet::sniff::Sniffed;

use crate::backend::{FirecrackerBackend, JobEnd, JobInput, VmBackend};
use crate::canary::Canary;
use crate::firecracker::vm::JobDrives;
use crate::honeytokens::{Honeytokens, Token};
use crate::payload::{Package, PayloadSpec, PayloadStats, build_image};
use crate::scratch::{ScanSpec, ScratchReport};
use crate::trace::TraceSummary;

/// Output kept per stream in the report.
const OUTPUT_TAIL: usize = 16 * 1024;

/// Output the agent forwards per run.
const OUTPUT_LIMIT: u32 = 4 * 1024 * 1024;

/// Extra wall clock the host allows beyond the guest's own timeout.
const HOST_MARGIN: Duration = Duration::from_secs(60);

/// Why a run could not happen. The job is not at fault for any of these.
#[derive(Debug, thiserror::Error)]
#[error("{}: {message}", class.name())]
pub struct Failure {
    /// Retry class.
    pub class: FailureClass,
    /// What happened.
    pub message: String,
    /// An alert to raise, beyond what the failure class implies.
    pub escalation: Option<HumanEscalation>,
}

impl Failure {
    fn new(class: FailureClass, message: impl std::fmt::Display) -> Self {
        Self {
            class,
            message: message.to_string(),
            escalation: None,
        }
    }

    fn infrastructure(message: impl std::fmt::Display) -> Self {
        Self::new(FailureClass::Infrastructure, message)
    }

    fn permanent(message: impl std::fmt::Display) -> Self {
        Self::new(FailureClass::Permanent, message)
    }

    fn compromise(message: impl std::fmt::Display) -> Self {
        Self::new(FailureClass::SuspectedCompromise, message)
    }
}

impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Self {
        Self::infrastructure(error)
    }
}

/// What one VM run produced, as stored in `job_runs.report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    /// How the build ended.
    pub outcome: BuildOutcome,
    /// How the run ended from the host's view.
    pub end: String,
    /// The guest's exit status, when the agent reported one.
    pub exit: Option<ExitStatus>,
    /// Restore to ready agent, in milliseconds.
    pub restore_ms: u64,
    /// The run itself, in milliseconds.
    pub run_ms: u64,
    /// The last bytes of stdout.
    pub stdout_tail: String,
    /// The last bytes of stderr.
    pub stderr_tail: String,
    /// Output beyond the limit was dropped.
    pub truncated: bool,
    /// Files and bytes in the payload.
    pub payload_files: u64,
    /// Bytes of file contents in the payload.
    pub payload_bytes: u64,
    /// Locked crates missing from the payload (not stored by the fetcher).
    pub missing_packages: Vec<String>,
    /// What the guest tried to reach, from the fake internet's log.
    pub network: NetworkSummary,
    /// Honeytokens that left the VM.
    pub leaked: Vec<Leak>,
    /// The guest's eBPF trace. Absent when the run ended without a report.
    #[serde(default)]
    pub trace: TraceSummary,
    /// Honeytokens the trace shows inside the VM, for example in a
    /// program's arguments. `via` names the process or path.
    #[serde(default)]
    pub tokens_in_trace: Vec<Leak>,
    /// What the job left on its scratch disk, read by the host. `None` if
    /// the scanner itself failed.
    #[serde(default)]
    pub scratch: Option<ScratchReport>,
    /// Honeytokens copied into files on the scratch disk. `via` is the path.
    #[serde(default)]
    pub tokens_on_disk: Vec<Leak>,
}

/// The guest's network activity, as the fake internet saw it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Names looked up, in order, without repeats.
    pub dns: Vec<String>,
    /// TCP connections, in order.
    pub connections: Vec<Connection>,
    /// UDP datagrams other than DNS.
    pub udp_datagrams: u32,
    /// Connections refused because too many were open.
    pub refused: u32,
    /// Frames no proxy saw (IPv6, ICMP, other protocols), described.
    #[serde(default)]
    pub packets: Vec<String>,
    /// More such frames arrived than the fake internet logs.
    #[serde(default)]
    pub packets_truncated: bool,
    /// The log hit its event limit.
    pub truncated: bool,
}

/// One TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// Destination the guest dialed.
    pub dst: String,
    /// What it sent, as recognized.
    #[serde(flatten)]
    pub sniffed: Sniffed,
    /// Bytes it sent.
    pub bytes: u64,
    /// Inside TLS, when the fake internet could terminate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner: Option<Box<Sniffed>>,
}

/// A honeytoken found outside the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leak {
    /// Which token.
    pub kind: String,
    /// Where it was seen: a DNS name, a TCP destination or `udp`.
    pub via: String,
}

/// Entries kept per list in the summary.
const MAX_LISTED: usize = 200;

/// Largest network log read back.
const MAX_NETWORK_LOG: u64 = 64 * 1024 * 1024;

/// Reads the fake internet's log and looks for the job's honeytokens in
/// everything the guest sent. Unparsable lines are skipped: the log is
/// written by a process that handles guest input.
fn analyze_network(path: &Path, tokens: &[Token]) -> (NetworkSummary, Vec<Leak>) {
    let mut log = NetworkLog {
        tokens,
        summary: NetworkSummary::default(),
        leaked: Vec::new(),
    };
    if let Ok(file) = std::fs::File::open(path) {
        for line in BufReader::new(file.take(MAX_NETWORK_LOG)).lines() {
            let Ok(line) = line else { break };
            if let Ok(event) = serde_json::from_str::<Event>(&line) {
                log.record(event.kind);
            }
        }
    }
    (log.summary, log.leaked)
}

/// What is known of the network log so far.
struct NetworkLog<'a> {
    tokens: &'a [Token],
    summary: NetworkSummary,
    leaked: Vec<Leak>,
}

impl NetworkLog<'_> {
    fn record(&mut self, kind: EventKind) {
        match kind {
            EventKind::Dns { name, .. } => {
                self.leak(name.as_bytes(), &name);
                if !self.summary.dns.contains(&name) && self.summary.dns.len() < MAX_LISTED {
                    self.summary.dns.push(name);
                }
            }
            EventKind::Tcp {
                dst,
                sniffed,
                bytes,
                data,
                inner,
                decrypted,
            } => {
                let via = route(&dst, &sniffed);
                self.leak(&unhex(&data).unwrap_or_default(), &via);
                if let Some(plain) = decrypted.as_deref().and_then(unhex) {
                    self.leak(&plain, &via.replacen("tls://", "https://", 1));
                }
                if self.summary.connections.len() < MAX_LISTED {
                    let connection = Connection {
                        dst,
                        sniffed,
                        bytes,
                        inner,
                    };
                    self.summary.connections.push(connection);
                }
            }
            EventKind::Udp { data, .. } => {
                self.leak(&unhex(&data).unwrap_or_default(), "udp");
                self.summary.udp_datagrams = self.summary.udp_datagrams.saturating_add(1);
            }
            EventKind::Packet { summary, data, .. } => {
                self.leak(&unhex(&data).unwrap_or_default(), "packet");
                if self.summary.packets.len() < MAX_LISTED {
                    self.summary.packets.push(summary);
                }
            }
            EventKind::PacketLimit => self.summary.packets_truncated = true,
            EventKind::Refused { .. } => {
                self.summary.refused = self.summary.refused.saturating_add(1);
            }
            EventKind::Truncated => self.summary.truncated = true,
        }
    }

    /// Notes the honeytokens in `haystack`, once per token and route.
    fn leak(&mut self, haystack: &[u8], via: &str) {
        for token in Honeytokens::found_in(self.tokens, haystack) {
            let known = self
                .leaked
                .iter()
                .any(|l| l.kind == token.kind && l.via == via);
            if !known {
                self.leaked.push(Leak {
                    kind: token.kind.to_owned(),
                    via: via.to_owned(),
                });
            }
        }
    }
}

/// Where a connection went. Every name resolves to the sink, so the name
/// the guest asked for says more than the address.
fn route(dst: &str, sniffed: &Sniffed) -> String {
    match sniffed {
        Sniffed::Http {
            host: Some(host), ..
        } => format!("http://{host}"),
        Sniffed::Tls { sni: Some(sni) } => format!("tls://{sni}"),
        _ => dst.to_owned(),
    }
}

fn tail(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(OUTPUT_TAIL);
    String::from_utf8_lossy(bytes.get(start..).unwrap_or_default()).into_owned()
}

/// A locked package as the fetch stage recorded it.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Locked {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) checksum: String,
}

/// Paths and limits the worker needs.
#[derive(Debug, Clone)]
pub struct WorkerSetup {
    /// The orchestrator binary, for the image building child.
    pub exe: PathBuf,
    /// Directory for per job payload and scratch images (tmpfs).
    pub work_dir: PathBuf,
    /// Size of each scratch disk.
    pub scratch_mib: u64,
    /// Guest side limit for `cargo check`.
    pub check_timeout: Duration,
    /// Guest side limit for the full build after an escalation.
    pub full_timeout: Duration,
    /// The warm build cache jobs mount, if one was built (ADR 0006).
    pub warm: Option<PathBuf>,
    /// The empty file the base snapshot's warm drive points at.
    pub warm_placeholder: PathBuf,
}

/// One VM slot with what a job needs to run in it.
#[derive(Debug, Clone)]
pub struct Sandbox {
    /// The VMM backend, shared by all slots.
    pub backend: Arc<FirecrackerBackend>,
    /// The slot whose VM runs the job.
    pub slot: u32,
    /// Paths and limits.
    pub setup: WorkerSetup,
    /// Where the crate files of a payload are read from.
    pub blobs: BlobStore,
}

/// The worker of one slot.
#[derive(Debug)]
pub struct SandboxWorker {
    store: Store,
    heartbeats: Arc<Store>,
    sandbox: Sandbox,
    /// Retry budgets and backoff.
    pub policies: Policies,
    /// Lease owner name.
    pub worker: String,
    /// Lease duration.
    pub lease: Duration,
}

impl SandboxWorker {
    /// A worker for the slot of `sandbox`.
    #[must_use]
    pub fn new(
        store: Store,
        heartbeats: Store,
        sandbox: Sandbox,
        policies: Policies,
        lease: Duration,
    ) -> Self {
        let worker = format!("orchestrator-{}-slot{}", std::process::id(), sandbox.slot);
        Self {
            store,
            heartbeats: Arc::new(heartbeats),
            sandbox,
            policies,
            worker,
            lease,
        }
    }

    /// Runs both canaries (ADR 0008) in this worker's slot and records the
    /// results. Nothing runs while the pipeline is quarantined.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails.
    pub async fn run_canaries(&mut self) -> Result<(), StoreError> {
        let quarantined = self
            .store
            .pauses()
            .await?
            .iter()
            .any(|p| p.reason == PauseReason::Quarantine);
        if quarantined {
            return Ok(());
        }
        for canary in &crate::canary::ALL {
            let report = match self.run_canary(canary).await {
                Ok(report) => report,
                // The run itself failed: that says nothing about verdicts,
                // so it is logged but not counted as a wrong result.
                Err(failure) => {
                    tracing::warn!(canary = canary.name, %failure, "canary run failed");
                    continue;
                }
            };
            let problems = canary.check(&report);
            let passed = problems.is_empty();
            let detail = serde_json::json!({
                "problems": problems,
                "outcome": report.outcome,
                "run_ms": report.run_ms,
            });
            tracing::info!(canary = canary.name, passed, %detail, "canary finished");
            self.store
                .record_canary(canary.name, passed, &detail)
                .await?;
        }
        Ok(())
    }

    async fn run_canary(&self, canary: &Canary) -> Result<RunReport, Failure> {
        let setup = &self.sandbox.setup;
        let spec = canary
            .payload(&self.sandbox.blobs)
            .map_err(Failure::infrastructure)?;
        let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
        let plan = RunPlan::check(setup.check_timeout);
        let files = JobFiles::named(setup, canary.name);
        let result = self.sandbox.execute(0, spec, &tokens, &files, &plan).await;
        files.remove();
        result
    }

    /// Claims and runs one job. Returns `false` when there was none.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails while claiming or completing.
    pub async fn run_once(&mut self) -> Result<bool, StoreError> {
        let Some(job) = self
            .store
            .claim(Stage::Sandbox, &self.worker, self.lease)
            .await?
        else {
            return Ok(false);
        };
        self.store
            .complete(
                job.id,
                &self.worker,
                JobEvent::SandboxStarted,
                &self.policies,
                true,
            )
            .await?;
        let beat = heartbeat(
            Arc::clone(&self.heartbeats),
            job.id,
            self.worker.clone(),
            self.lease,
            self.lease / 4,
        );
        let started = std::time::Instant::now();
        let result = self.run(&job).await;
        beat.abort();
        let event = match result {
            Ok(report) => {
                tracing::info!(
                    job = job.id.0, name = %job.name, version = %job.version, slot = self.sandbox.slot,
                    outcome = ?report.outcome, restore_ms = report.restore_ms,
                    run_ms = report.run_ms, total_ms = started.elapsed().as_millis(),
                    "run finished"
                );
                JobEvent::SandboxCompleted {
                    outcome: report.outcome,
                }
            }
            Err(failure) => {
                tracing::warn!(job = job.id.0, name = %job.name, version = %job.version, %failure, "run failed");
                self.escalate(&failure).await?;
                JobEvent::StageFailed {
                    class: failure.class,
                }
            }
        };
        self.store
            .complete(job.id, &self.worker, event, &self.policies, false)
            .await?;
        Ok(true)
    }

    /// Raises the alert a failure asks for. A KVM error also stops the stage
    /// at once. The supervisor probes again after the cooldown.
    async fn escalate(&mut self, failure: &Failure) -> Result<(), StoreError> {
        let Some(escalation) = &failure.escalation else {
            return Ok(());
        };
        self.store.raise_alert(escalation).await?;
        if *escalation == HumanEscalation::KvmError {
            let since = self.store.now_epoch().await?;
            let open = BreakerState::Open { since, reopened: 0 };
            self.store.set_breaker(Stage::Sandbox, open).await?;
        }
        Ok(())
    }

    async fn run(&self, job: &StoredJob) -> Result<RunReport, Failure> {
        let files = JobFiles::named(&self.sandbox.setup, &format!("job-{}", job.id.0));
        let result = self.run_with(job, &files).await;
        files.remove();
        result
    }

    async fn run_with(&self, job: &StoredJob, files: &JobFiles) -> Result<RunReport, Failure> {
        let (spec, missing) = self.payload_spec(job).await?;
        let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
        self.store
            .record_honeytokens(job.id, &tokens.records())
            .await?;
        let setup = &self.sandbox.setup;
        let plan = match job.job.run_kind {
            RunKind::Check => RunPlan::check(setup.check_timeout),
            RunKind::Full => RunPlan::full(setup.full_timeout),
        };
        let mut report = self
            .sandbox
            .execute(job.id.0, spec, &tokens, files, &plan)
            .await?;
        report.missing_packages = missing;
        if !report.leaked.is_empty() {
            tracing::warn!(job = job.id.0, name = %job.name, version = %job.version, leaked = ?report.leaked, "honeytokens left the VM");
        }
        let value = serde_json::to_value(&report).map_err(Failure::infrastructure)?;
        self.store
            .record_run(
                job.id,
                job.job.run_kind.name(),
                report.outcome.name(),
                &value,
            )
            .await?;
        Ok(report)
    }

    /// The payload of a job, and the locked crates it lacks.
    async fn payload_spec(&self, job: &StoredJob) -> Result<(PayloadSpec, Vec<String>), Failure> {
        let name = CrateName::parse(&job.name).map_err(Failure::permanent)?;
        let version = semver::Version::parse(&job.version).map_err(Failure::permanent)?;
        let lockfile = self
            .store
            .fetch_lockfile(job.id)
            .await?
            .ok_or_else(|| Failure::permanent("the job has no lockfile"))?;
        let (packages, missing) = self.stored_packages(job).await?;
        let spec = PayloadSpec {
            name,
            version,
            lockfile,
            packages,
            extra_probes: Vec::new(),
            files: Vec::new(),
            stubs: Vec::new(),
        };
        Ok((spec, missing))
    }

    /// The locked packages of a job whose crate files are stored, and the
    /// names of those whose files are not.
    async fn stored_packages(
        &self,
        job: &StoredJob,
    ) -> Result<(Vec<Package>, Vec<String>), StoreError> {
        let locked: Vec<Locked> = self
            .store
            .fetch_packages(job.id)
            .await?
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let mut packages = Vec::new();
        let mut missing = Vec::new();
        for p in locked {
            let file = match p.checksum.parse::<Sha256Digest>() {
                Ok(sha) => self.store.crate_file(&sha).await?,
                Err(_) => None,
            };
            match file.and_then(|f| f.blake3) {
                Some(blake3) => packages.push(Package {
                    name: p.name,
                    version: p.version,
                    checksum: p.checksum,
                    blake3,
                }),
                None => missing.push(format!("{} {}", p.name, p.version)),
            }
        }
        Ok((packages, missing))
    }
}

/// The per job files on the host.
#[derive(Debug, Clone)]
pub struct JobFiles {
    /// Payload image.
    pub payload: PathBuf,
    /// Scratch disk image.
    pub scratch: PathBuf,
    /// The fake internet's event log.
    pub network: PathBuf,
    /// The warm build cache to mount, if there is one (ADR 0006).
    pub warm: Option<PathBuf>,
    /// An empty file that stands in for the warm image when there is none.
    pub warm_placeholder: PathBuf,
}

impl JobFiles {
    /// The files of the job or canary called `stem`, in the work directory.
    #[must_use]
    pub fn named(setup: &WorkerSetup, stem: &str) -> Self {
        let file = |kind: &str| setup.work_dir.join(format!("{stem}.{kind}"));
        Self {
            payload: file("payload"),
            scratch: file("scratch"),
            network: file("network"),
            warm: setup.warm.clone(),
            warm_placeholder: setup.warm_placeholder.clone(),
        }
    }

    /// Removes the payload, the scratch disk and the network log. A missing
    /// file is fine. Any other failure is logged.
    pub fn remove(&self) {
        for file in [&self.payload, &self.scratch, &self.network] {
            if let Err(error) = remove_file(file) {
                tracing::warn!(file = %file.display(), %error, "cannot remove a job file");
            }
        }
    }
}

/// Removes a file. A missing one is fine.
fn remove_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// What runs in the VM.
#[derive(Debug, Clone)]
pub struct RunPlan {
    /// The command.
    pub argv: Vec<String>,
    /// Its working directory.
    pub cwd: String,
    /// Guest side wall clock limit.
    pub timeout: Duration,
}

impl RunPlan {
    /// `cargo check` of the probe, the analysis every dynamic job gets.
    #[must_use]
    pub fn check(timeout: Duration) -> Self {
        Self {
            argv: ["cargo", "check", "--locked", "--offline"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            cwd: guest::PROBE.into(),
            timeout,
        }
    }

    /// The confirmation run after an escalation (ADR 0009): a full build,
    /// with code generation and linking, in a fresh VM with fresh
    /// honeytokens.
    #[must_use]
    pub fn full(timeout: Duration) -> Self {
        Self {
            argv: ["cargo", "build", "--locked", "--offline"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            cwd: guest::PROBE.into(),
            timeout,
        }
    }
}

impl Sandbox {
    /// Builds the payload and scratch disk, runs `plan` in the slot with
    /// the given honeytokens planted, and analyzes the fake internet's log. No
    /// database access, so the canary test can call it directly.
    ///
    /// # Errors
    ///
    /// Fails if anything but the build itself fails.
    pub async fn execute(
        &self,
        job_id: i64,
        spec: PayloadSpec,
        tokens: &Honeytokens,
        files: &JobFiles,
        plan: &RunPlan,
    ) -> Result<RunReport, Failure> {
        let stats = self.prepare(spec, files).await?;
        let input = job_input(job_id, tokens, files, plan, self.setup.scratch_mib);
        let directories = input.workspace.directories.clone();
        let run = self
            .backend
            .run_job(self.slot, input, plan.timeout + HOST_MARGIN)
            .await
            .map_err(Failure::infrastructure)?;
        let ended = Ended::try_from(&run.end)?;
        let (network, leaked) = analyze_network(&files.network, &tokens.tokens);
        let scratch = scan_scratch(&self.setup, files, &directories, tokens).await;
        let tokens_on_disk = scratch.as_ref().map_or_else(Vec::new, |report| {
            leaks(tokens, report.tokens_found.iter().cloned())
        });
        let values: Vec<&str> = tokens.tokens.iter().map(|t| t.value.as_str()).collect();
        let in_trace = ended.trace.find(&values).into_iter().take(MAX_LISTED);
        let tokens_in_trace = leaks(tokens, in_trace);
        Ok(RunReport {
            scratch,
            tokens_on_disk,
            trace: ended.trace,
            tokens_in_trace,
            network,
            leaked,
            outcome: ended.outcome,
            end: run.end.to_string().chars().take(256).collect(),
            exit: ended.exit,
            restore_ms: u64::try_from(run.restore.as_millis()).unwrap_or(u64::MAX),
            run_ms: u64::try_from(run.run.as_millis()).unwrap_or(u64::MAX),
            stdout_tail: tail(ended.stdout),
            stderr_tail: tail(ended.stderr),
            truncated: ended.truncated,
            payload_files: stats.files,
            payload_bytes: stats.bytes,
            missing_packages: Vec::new(),
        })
    }

    /// Builds the payload and the scratch disk, and clears the network log.
    async fn prepare(&self, spec: PayloadSpec, files: &JobFiles) -> Result<PayloadStats, Failure> {
        // The fake internet appends to its log. One left from an earlier run
        // would mix that run's traffic into this one's.
        remove_file(&files.network).map_err(Failure::infrastructure)?;
        let stats = build_payload(&self.setup, &self.blobs, spec, &files.payload).await?;
        make_scratch(self.setup.scratch_mib, &files.scratch).await?;
        crate::jail::acl::grant_user(&files.scratch, self.backend.slot_uid(self.slot))
            .map_err(Failure::infrastructure)?;
        Ok(stats)
    }
}

/// The environment every job starts with, before its honeytokens.
const BASE_ENV: [(&str, &str); 7] = [
    ("PATH", "/usr/local/bin:/usr/bin:/bin"),
    ("HOME", guest::HOME),
    ("USER", guest::BUILDER_USER),
    ("CARGO_HOME", guest::CARGO_HOME),
    ("CARGO_TARGET_DIR", guest::TARGET),
    ("CARGO_TERM_COLOR", "never"),
    ("LANG", "C.UTF-8"),
];

/// What the agent runs and prepares for `plan`, with the honeytokens planted.
fn job_input(
    job_id: i64,
    tokens: &Honeytokens,
    files: &JobFiles,
    plan: &RunPlan,
    scratch_mib: u64,
) -> JobInput {
    let (mounts, mut directories) = job_mounts(files.warm.is_some());
    directories.extend(tokens.directories.clone());
    let env = BASE_ENV
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .chain(tokens.env.clone())
        .collect();
    JobInput {
        spec: JobSpec {
            job_id,
            wall_clock: now(),
            argv: plan.argv.clone(),
            env,
            cwd: plan.cwd.clone(),
            timeout_secs: u32::try_from(plan.timeout.as_secs()).unwrap_or(u32::MAX),
            output_limit: OUTPUT_LIMIT,
        },
        workspace: Workspace {
            mounts,
            directories,
            files: tokens.files.clone(),
        },
        drives: Some(JobDrives {
            payload: files.payload.clone(),
            scratch: files.scratch.clone(),
            warm: files
                .warm
                .clone()
                .unwrap_or_else(|| files.warm_placeholder.clone()),
        }),
        network_log: Some(files.network.clone()),
        scratch_mib,
    }
}

/// What a run that ended in a result produced.
#[derive(Debug)]
struct Ended<'a> {
    outcome: BuildOutcome,
    exit: Option<ExitStatus>,
    stdout: &'a [u8],
    stderr: &'a [u8],
    truncated: bool,
    trace: TraceSummary,
}

impl Ended<'_> {
    /// A run that ended without the agent's report.
    fn silent(outcome: BuildOutcome) -> Self {
        Self {
            outcome,
            exit: None,
            stdout: &[],
            stderr: &[],
            truncated: false,
            trace: TraceSummary::default(),
        }
    }
}

impl<'a> TryFrom<&'a JobEnd> for Ended<'a> {
    type Error = Failure;

    fn try_from(end: &'a JobEnd) -> Result<Self, Failure> {
        match end {
            JobEnd::Finished(o) => Ok(Self {
                outcome: match o.exit {
                    ExitStatus::Code(0) => BuildOutcome::Succeeded,
                    ExitStatus::TimedOut => BuildOutcome::TimedOut,
                    ExitStatus::Code(_) | ExitStatus::Signal(_) => BuildOutcome::Failed,
                },
                exit: Some(o.exit),
                stdout: &o.stdout,
                stderr: &o.stderr,
                truncated: o.truncated,
                trace: (*o.trace).clone(),
            }),
            JobEnd::HostTimeout => Ok(Self::silent(BuildOutcome::TimedOut)),
            JobEnd::ResourceLimit => Ok(Self::silent(BuildOutcome::ResourceLimit)),
            // Only guest code stops a guest: a result, never retried, so a crate
            // cannot trip the sandbox breaker by crashing its own VM.
            JobEnd::GuestStopped(_) => Ok(Self::silent(BuildOutcome::GuestStopped)),
            JobEnd::VmmCrashed(reason) => {
                Err(Failure::compromise(format!("the VMM crashed: {reason}")))
            }
            JobEnd::DecoyTouched => Err(Failure::compromise(
                "something read the decoy in the jail root",
            )),
            JobEnd::KvmError(reason) => Err(Failure {
                class: FailureClass::Infrastructure,
                message: format!("KVM error: {reason}"),
                escalation: Some(HumanEscalation::KvmError),
            }),
            // A VM that died without a report and without a known reason: ours.
            JobEnd::UnexpectedExit(reason) => Err(Failure::infrastructure(format!(
                "the VM ended unexpectedly: {reason}"
            ))),
        }
    }
}

/// The tokens at the given indexes, each with where it was seen. Indexes
/// that name no token are dropped.
fn leaks(tokens: &Honeytokens, found: impl IntoIterator<Item = (usize, String)>) -> Vec<Leak> {
    found
        .into_iter()
        .filter_map(|(i, via)| {
            tokens.tokens.get(i).map(|t| Leak {
                kind: t.kind.to_owned(),
                via,
            })
        })
        .collect()
}

/// The mounts of a job, and the directories to create before it runs. With
/// `warm`, the warm image's target directory lies under the job's own
/// writable layer at [`guest::TARGET`] (ADR 0006). Without it, the target
/// directory is a plain directory on the scratch disk.
#[must_use]
pub fn job_mounts(warm: bool) -> (Vec<MountSpec>, Vec<PathSpec>) {
    let mut mounts = vec![
        MountSpec {
            device: guest::PAYLOAD_DEVICE.into(),
            target: guest::PAYLOAD.into(),
            fstype: "erofs".into(),
            read_only: true,
            executable: false,
            options: None,
        },
        MountSpec {
            device: guest::SCRATCH_DEVICE.into(),
            target: guest::WORK.into(),
            fstype: "ext4".into(),
            read_only: false,
            executable: false,
            options: None,
        },
    ];
    if !warm {
        return (
            mounts,
            vec![PathSpec {
                path: guest::TARGET.into(),
                owner: guest::BUILDER_UID,
                mode: 0o755,
            }],
        );
    }
    mounts.push(MountSpec {
        device: guest::WARM_DEVICE.into(),
        target: guest::WARM_IMAGE.into(),
        fstype: "erofs".into(),
        read_only: true,
        // Compiled build scripts and proc macros run from here.
        executable: true,
        options: None,
    });
    mounts.push(MountSpec {
        device: "overlay".into(),
        target: guest::TARGET.into(),
        fstype: "overlay".into(),
        read_only: false,
        executable: false,
        options: Some(format!(
            "lowerdir={}/target,upperdir={},workdir={}",
            guest::WARM_IMAGE,
            guest::WARM_UPPER,
            guest::WARM_WORK
        )),
    });
    (mounts, Vec::new())
}

/// Reads the scratch disk in the sandboxed scanner. A failure of the
/// scanner is logged and leaves the report without a scratch section. The
/// job is not failed for it.
async fn scan_scratch(
    setup: &WorkerSetup,
    files: &JobFiles,
    directories: &[PathSpec],
    tokens: &Honeytokens,
) -> Option<ScratchReport> {
    let spec = ScanSpec {
        tokens: tokens.tokens.iter().map(|t| t.value.clone()).collect(),
        planted: tokens.files.iter().map(|f| f.path.path.clone()).collect(),
        created: directories.iter().map(|d| d.path.clone()).collect(),
    };
    let exe = setup.exe.clone();
    let image = files.scratch.clone();
    let result =
        tokio::task::spawn_blocking(move || crate::scratch::scan_in_sandbox(&exe, &image, &spec))
            .await;
    match result {
        Ok(Ok(report)) => Some(report),
        Ok(Err(error)) => {
            tracing::warn!(%error, "scratch disk scan failed");
            None
        }
        Err(error) => {
            tracing::warn!(%error, "scratch disk scan panicked");
            None
        }
    }
}

async fn build_payload(
    setup: &WorkerSetup,
    blobs: &BlobStore,
    spec: PayloadSpec,
    out: &Path,
) -> Result<PayloadStats, Failure> {
    let exe = setup.exe.clone();
    let blobs = blobs.clone();
    let out = out.to_path_buf();
    tokio::task::spawn_blocking(move || build_image(&exe, &spec, &blobs, &out))
        .await
        .map_err(Failure::infrastructure)?
        .map_err(Failure::infrastructure)
}

/// Creates an empty ext4 image. The file is sparse. The tmpfs holds only the
/// blocks the job writes.
async fn make_scratch(mib: u64, path: &Path) -> Result<(), Failure> {
    let file = std::fs::File::create(path).map_err(Failure::infrastructure)?;
    file.set_len(mib * 1024 * 1024)
        .map_err(Failure::infrastructure)?;
    drop(file);
    let status = tokio::process::Command::new("/usr/sbin/mkfs.ext4")
        .args([
            "-q",
            "-F",
            "-m",
            "0",
            "-E",
            "lazy_itable_init=1,lazy_journal_init=1",
        ])
        .arg(path)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .status()
        .await
        .map_err(Failure::infrastructure)?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::infrastructure(format!(
            "mkfs.ext4 exited with {status}"
        )))
    }
}

fn now() -> WallClock {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    WallClock {
        secs: since.as_secs(),
        nanos: since.subsec_nanos(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firecracker::agent::RunOutcome;
    use crateward_fake_internet::server::hex;

    fn finished(exit: ExitStatus) -> JobEnd {
        JobEnd::Finished(RunOutcome {
            exit,
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            truncated: true,
            trace: Box::default(),
        })
    }

    fn setup(work_dir: PathBuf) -> WorkerSetup {
        WorkerSetup {
            exe: PathBuf::from("/nonexistent/exe"),
            work_dir,
            scratch_mib: 64,
            check_timeout: Duration::from_secs(60),
            full_timeout: Duration::from_secs(120),
            warm: Some(PathBuf::from("/nonexistent/warm.erofs")),
            warm_placeholder: PathBuf::from("/nonexistent/none"),
        }
    }

    #[test]
    fn a_finished_run_is_judged_by_its_exit_status() {
        for (exit, outcome) in [
            (ExitStatus::Code(0), BuildOutcome::Succeeded),
            (ExitStatus::Code(101), BuildOutcome::Failed),
            (ExitStatus::Signal(9), BuildOutcome::Failed),
            (ExitStatus::TimedOut, BuildOutcome::TimedOut),
        ] {
            let end = finished(exit);
            let ended = Ended::try_from(&end).unwrap();
            assert_eq!(ended.outcome, outcome);
            assert_eq!(ended.exit, Some(exit));
            assert_eq!(ended.stdout, b"out");
            assert_eq!(ended.stderr, b"err");
            assert!(ended.truncated);
        }
    }

    #[test]
    fn runs_without_a_report_are_results_without_output() {
        for (end, outcome) in [
            (JobEnd::HostTimeout, BuildOutcome::TimedOut),
            (JobEnd::ResourceLimit, BuildOutcome::ResourceLimit),
            (
                JobEnd::GuestStopped("panic".into()),
                BuildOutcome::GuestStopped,
            ),
        ] {
            let ended = Ended::try_from(&end).unwrap();
            assert_eq!(ended.outcome, outcome);
            assert_eq!(ended.exit, None);
            assert!(ended.stdout.is_empty() && ended.stderr.is_empty());
            assert!(!ended.truncated);
        }
    }

    #[test]
    fn a_crashed_vmm_or_a_touched_decoy_is_a_suspected_compromise() {
        for (end, message) in [
            (
                JobEnd::VmmCrashed("SIGSYS".into()),
                "the VMM crashed: SIGSYS",
            ),
            (
                JobEnd::DecoyTouched,
                "something read the decoy in the jail root",
            ),
        ] {
            let failure = Ended::try_from(&end).unwrap_err();
            assert_eq!(failure.class, FailureClass::SuspectedCompromise);
            assert_eq!(failure.message, message);
            assert_eq!(failure.escalation, None);
        }
    }

    #[test]
    fn a_kvm_error_is_ours_and_raises_an_alert() {
        let failure = Ended::try_from(&JobEnd::KvmError("no /dev/kvm".into())).unwrap_err();
        assert_eq!(failure.class, FailureClass::Infrastructure);
        assert_eq!(failure.message, "KVM error: no /dev/kvm");
        assert_eq!(failure.escalation, Some(HumanEscalation::KvmError));
    }

    #[test]
    fn a_vm_that_vanished_without_a_reason_is_ours() {
        let failure = Ended::try_from(&JobEnd::UnexpectedExit("exit 3".into())).unwrap_err();
        assert_eq!(failure.class, FailureClass::Infrastructure);
        assert_eq!(failure.message, "the VM ended unexpectedly: exit 3");
        assert_eq!(failure.escalation, None);
    }

    #[test]
    fn job_files_live_in_the_work_directory_and_can_be_removed() {
        let dir = std::env::temp_dir().join(format!("cw-jobfiles-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let setup = setup(dir.clone());
        let files = JobFiles::named(&setup, "job-7");
        assert_eq!(files.payload, dir.join("job-7.payload"));
        assert_eq!(files.scratch, dir.join("job-7.scratch"));
        assert_eq!(files.network, dir.join("job-7.network"));
        assert_eq!(files.warm, setup.warm);
        assert_eq!(files.warm_placeholder, setup.warm_placeholder);
        std::fs::write(&files.payload, b"x").unwrap();
        std::fs::write(&files.network, b"x").unwrap();
        files.remove();
        assert!(!files.payload.exists() && !files.scratch.exists() && !files.network.exists());
        // Nothing is left to remove the second time, which is fine.
        files.remove();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_job_input_carries_the_plan_the_tokens_and_the_drives() {
        let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
        let plan = RunPlan::check(Duration::from_secs(90));
        let mut files = JobFiles::named(&setup(PathBuf::from("/work")), "job-1");
        files.warm = None;
        let input = job_input(7, &tokens, &files, &plan, 512);
        assert_eq!(input.spec.job_id, 7);
        assert_eq!(input.spec.argv, plan.argv);
        assert_eq!(input.spec.cwd, guest::PROBE);
        assert_eq!(input.spec.timeout_secs, 90);
        assert_eq!(input.spec.output_limit, OUTPUT_LIMIT);
        let (base, planted) = input.spec.env.split_at(BASE_ENV.len());
        assert_eq!(
            base.first(),
            Some(&("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned()))
        );
        assert_eq!(planted, tokens.env);
        assert_eq!(input.workspace.mounts, job_mounts(false).0);
        assert_eq!(
            input.workspace.directories,
            [job_mounts(false).1, tokens.directories.clone()].concat()
        );
        assert_eq!(input.workspace.files, tokens.files);
        let drives = input.drives.unwrap();
        assert_eq!(drives.payload, files.payload);
        assert_eq!(drives.scratch, files.scratch);
        assert_eq!(drives.warm, files.warm_placeholder);
        assert_eq!(input.network_log, Some(files.network));
        assert_eq!(input.scratch_mib, 512);
    }

    #[test]
    fn a_warm_image_is_mounted_and_replaces_the_placeholder() {
        let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
        let plan = RunPlan::full(Duration::from_secs(3600));
        let files = JobFiles::named(&setup(PathBuf::from("/work")), "job-1");
        let input = job_input(1, &tokens, &files, &plan, 512);
        assert_eq!(input.spec.argv[1], "build");
        assert_eq!(input.spec.timeout_secs, 3600);
        assert_eq!(input.workspace.mounts, job_mounts(true).0);
        assert_eq!(input.drives.unwrap().warm, files.warm.unwrap());
    }

    fn network_log(name: &str, contents: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("cw-netlog-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn line(kind: EventKind) -> String {
        serde_json::to_string(&Event { ms: 0, kind }).unwrap()
    }

    fn tcp(dst: &str, sniffed: Sniffed, data: &str, decrypted: Option<&str>) -> EventKind {
        EventKind::Tcp {
            dst: dst.into(),
            sniffed,
            bytes: 10,
            data: hex(data.as_bytes()),
            inner: None,
            decrypted: decrypted.map(|text| hex(text.as_bytes())),
        }
    }

    fn connection(dst: &str, sniffed: Sniffed) -> Connection {
        Connection {
            dst: dst.into(),
            sniffed,
            bytes: 10,
            inner: None,
        }
    }

    fn http(host: Option<&str>) -> Sniffed {
        Sniffed::Http {
            method: "GET".into(),
            target: "/".into(),
            host: host.map(Into::into),
            user_agent: None,
        }
    }

    fn tokens() -> Vec<Token> {
        vec![
            Token {
                kind: "cargo_registry_token",
                value: "cioSECRET".into(),
            },
            Token {
                kind: "ssh_key",
                value: "ssh-SECRET".into(),
            },
        ]
    }

    fn leak(kind: &str, via: &str) -> Leak {
        Leak {
            kind: kind.into(),
            via: via.into(),
        }
    }

    #[test]
    fn the_network_log_becomes_a_summary_and_leaks() {
        let dns = |name: &str, qtype| EventKind::Dns {
            name: name.into(),
            qtype,
        };
        let tls = |sni: Option<&str>| Sniffed::Tls {
            sni: sni.map(Into::into),
        };
        let lines: Vec<String> = [
            dns("a.example", 1),
            dns("a.example", 28),
            dns("cioSECRET.evil.example", 1),
            tcp(
                "10.0.2.1:8080",
                http(Some("h.example")),
                "x cioSECRET x",
                None,
            ),
            tcp(
                "10.0.2.1:8080",
                http(Some("h.example")),
                "x cioSECRET x",
                None,
            ),
            tcp(
                "10.0.2.1:443",
                tls(Some("t.example")),
                "ssh-SECRET",
                Some("cioSECRET"),
            ),
            tcp("1.2.3.4:80", Sniffed::Unknown, "cioSECRET", None),
            tcp("5.6.7.8:80", http(None), "cioSECRET", None),
            tcp("9.9.9.9:443", tls(None), "no token", None),
            EventKind::Udp {
                bytes: 10,
                data: hex(b"ssh-SECRET"),
            },
            EventKind::Packet {
                summary: "icmp echo".into(),
                bytes: 10,
                data: hex(b"cioSECRET"),
            },
            EventKind::PacketLimit,
            EventKind::Refused { dst: "a".into() },
            EventKind::Refused { dst: "b".into() },
            EventKind::Truncated,
        ]
        .into_iter()
        .map(line)
        .collect();
        let path = network_log("summary", lines.join("\n").as_bytes());
        let (summary, leaked) = analyze_network(&path, &tokens());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(summary.dns, ["a.example", "cioSECRET.evil.example"]);
        assert_eq!(
            summary.connections,
            [
                connection("10.0.2.1:8080", http(Some("h.example"))),
                connection("10.0.2.1:8080", http(Some("h.example"))),
                connection("10.0.2.1:443", tls(Some("t.example"))),
                connection("1.2.3.4:80", Sniffed::Unknown),
                connection("5.6.7.8:80", http(None)),
                connection("9.9.9.9:443", tls(None)),
            ]
        );
        assert_eq!(summary.udp_datagrams, 1);
        assert_eq!(summary.refused, 2);
        assert_eq!(summary.packets, ["icmp echo"]);
        assert!(summary.packets_truncated && summary.truncated);
        // A token is named once per route, however often it is seen.
        assert_eq!(
            leaked,
            [
                leak("cargo_registry_token", "cioSECRET.evil.example"),
                leak("cargo_registry_token", "http://h.example"),
                leak("ssh_key", "tls://t.example"),
                leak("cargo_registry_token", "https://t.example"),
                leak("cargo_registry_token", "1.2.3.4:80"),
                leak("cargo_registry_token", "5.6.7.8:80"),
                leak("ssh_key", "udp"),
                leak("cargo_registry_token", "packet"),
            ]
        );
    }

    #[test]
    fn the_lists_of_the_network_summary_are_bounded() {
        let lines: Vec<String> = (0..MAX_LISTED + 50)
            .flat_map(|i| {
                [
                    EventKind::Dns {
                        name: format!("{i}.example"),
                        qtype: 1,
                    },
                    tcp("1.2.3.4:80", Sniffed::Unknown, "", None),
                    EventKind::Packet {
                        summary: format!("packet {i}"),
                        bytes: 1,
                        data: String::new(),
                    },
                ]
            })
            .map(line)
            .collect();
        let path = network_log("bounded", lines.join("\n").as_bytes());
        let (summary, leaked) = analyze_network(&path, &tokens());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(summary.dns.len(), MAX_LISTED);
        assert_eq!(summary.connections.len(), MAX_LISTED);
        assert_eq!(summary.packets.len(), MAX_LISTED);
        assert_eq!(
            summary.dns.last().unwrap(),
            &format!("{}.example", MAX_LISTED - 1)
        );
        assert!(leaked.is_empty());
    }

    #[test]
    fn an_unreadable_network_log_ends_the_summary() {
        let read = |name: &str, contents: &[u8]| {
            let path = network_log(name, contents);
            let (summary, _) = analyze_network(&path, &tokens());
            std::fs::remove_file(&path).unwrap();
            summary
        };
        let dns = |name: &str| {
            line(EventKind::Dns {
                name: name.into(),
                qtype: 1,
            })
        };
        // A line that is no event is skipped.
        let skipped = read(
            "skipped",
            format!("{}\nnot json\n{}\n", dns("a"), dns("b")).as_bytes(),
        );
        assert_eq!(skipped.dns, ["a", "b"]);
        // A line that is no text ends the reading.
        let mut bytes = format!("{}\n", dns("a")).into_bytes();
        bytes.extend_from_slice(b"\xff\xfe\n");
        bytes.extend_from_slice(dns("b").as_bytes());
        assert_eq!(read("binary", &bytes).dns, ["a"]);
        // A missing log is an empty summary.
        let missing = std::env::temp_dir().join("cw-netlog-missing");
        assert_eq!(
            analyze_network(&missing, &tokens()).0,
            NetworkSummary::default()
        );
    }

    #[test]
    fn leaks_name_the_token_and_where_it_was_seen() {
        let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
        let found = leaks(
            &tokens,
            [
                (1, "tls://x.example".to_owned()),
                (usize::MAX, "nowhere".to_owned()),
            ],
        );
        assert_eq!(
            found,
            [Leak {
                kind: tokens.tokens[1].kind.to_owned(),
                via: "tls://x.example".to_owned(),
            }]
        );
    }
}
