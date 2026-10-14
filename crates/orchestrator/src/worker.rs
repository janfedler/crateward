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
use crateward_core::bytes::unhex;
use crateward_core::digest::Sha256Digest;
use crateward_core::escalation::HumanEscalation;
use crateward_core::failure::Failure;
use crateward_core::job::{BuildOutcome, JobEvent, RunKind, Stage};
use crateward_core::name::CrateName;
use crateward_core::paths::{guest, host};
use crateward_core::protocol::{ExitStatus, JobSpec, MountSpec, PathSpec, WallClock, Workspace};
use crateward_core::report::network::{Connection, Leak, NetworkSummary, Sniffed};
use crateward_core::report::run::RunReport;
use crateward_core::report::scratch::ScratchReport;
use crateward_core::report::trace::TraceSummary;
use crateward_core::store::{PauseReason, Policies, Store, StoreError, StoredJob, heartbeat};
use serde::Deserialize;

use crateward_fake_internet::server::{Event, EventKind, MAX_CAPTURE, MAX_EVENTS};

use crate::backend::{FirecrackerBackend, JobEnd, JobInput, VmBackend};
use crate::canary::Canary;
use crate::firecracker::vm::JobDrives;
use crate::honeytokens::{Honeytokens, Token};
use crate::payload::{Package, PayloadSpec, PayloadStats, build_image};
use crate::scratch::ScanSpec;

/// Output kept per stream in the report.
const OUTPUT_TAIL: usize = 16 * 1024;

/// Output the agent forwards per run.
const OUTPUT_LIMIT: u32 = 4 * 1024 * 1024;

/// Extra wall clock the host allows beyond the guest's own timeout.
const HOST_MARGIN: Duration = Duration::from_secs(60);

/// Entries kept per list in the summary.
const MAX_LISTED: usize = 200;

/// Largest network log read back: more than the fake internet writes, with
/// every event at its largest (raw and decrypted data, hex encoded), so the
/// honeytoken search covers all of it.
const MAX_NETWORK_LOG: u64 = MAX_EVENTS as u64 * (4 * MAX_CAPTURE as u64 + 64 * 1024);

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
        let mut reader = BufReader::new(file.take(MAX_NETWORK_LOG));
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
            if let Ok(event) = serde_json::from_slice::<Event>(&line) {
                log.record(event.kind);
            }

            line.clear();
        }

        log.summary.log_cut = reader.get_ref().limit() == 0;
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
                self.search_tcp(&dst, &sniffed, bytes, &data, decrypted.as_deref());

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
            EventKind::Packet {
                summary,
                bytes,
                data,
            } => {
                let data = unhex(&data).unwrap_or_default();
                self.leak(&data, "packet");
                self.cut_if(bytes > data.len() as u64);

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

    /// Searches a TCP connection's data, and its plain text inside TLS.
    fn search_tcp(
        &mut self,
        dst: &str,
        sniffed: &Sniffed,
        bytes: u64,
        data: &str,
        decrypted: Option<&str>,
    ) {
        let via = route(dst, sniffed);
        let data = unhex(data).unwrap_or_default();
        self.leak(&data, &via);
        self.cut_if(bytes > data.len() as u64);

        if let Some(plain) = decrypted.and_then(unhex) {
            self.leak(&plain, &via.replacen("tls://", "https://", 1));
            self.cut_if(plain.len() >= MAX_CAPTURE);
        }
    }

    /// Counts a connection or frame of which only the start was kept.
    fn cut_if(&mut self, cut: bool) {
        if cut {
            self.summary.cut = self.summary.cut.saturating_add(1);
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
        let uid = self.backend.slot_uid(self.slot);
        for drive in [&files.payload, &files.scratch] {
            crate::jail::acl::grant_user(drive, uid).map_err(Failure::infrastructure)?;
        }

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
            wall_clock: WallClock::now(),
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
            JobEnd::KvmError(reason) => {
                Err(Failure::infrastructure(format!("KVM error: {reason}"))
                    .escalate(HumanEscalation::KvmError))
            }

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
        environment: BASE_ENV.iter().map(|(_, v)| (*v).to_owned()).collect(),
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
    let status = tokio::process::Command::new(host::MKFS_EXT4)
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

#[cfg(test)]
mod tests;
