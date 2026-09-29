//! The sandbox stage worker: one per VM slot.
//!
//! For each job it builds the payload image and a scratch disk, plants
//! fresh honeytokens, runs `cargo check` in the slot's microVM, records the
//! run, and deletes the per job files. The job holds its lease for the
//! whole run (`SandboxStarted` keeps it), and a heartbeat renews it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crateward_core::blobs::BlobStore;
use crateward_core::breaker::BreakerState;
use crateward_core::digest::Sha256Digest;
use crateward_core::escalation::HumanEscalation;
use crateward_core::failure::FailureClass;
use crateward_core::job::{BuildOutcome, JobEvent, RunKind, Stage};
use crateward_core::name::CrateName;
use crateward_core::protocol::{ExitStatus, JobSpec, MountSpec, PathSpec, WallClock, Workspace};
use crateward_core::store::{PauseReason, Policies, Store, StoreError, StoredJob, heartbeat};
use serde::{Deserialize, Serialize};

use crateward_fake_internet::server::{Event, EventKind, unhex};
use crateward_fake_internet::sniff::Sniffed;

use crate::backend::{FirecrackerBackend, JobEnd, JobInput, VmBackend};
use crate::firecracker::vm::JobDrives;
use crate::honeytokens::{HOME, Honeytokens};
use crate::payload::{PROBE_DIR, Package, PayloadSpec, PayloadStats, build_image};
use crate::scratch::{ScanSpec, ScratchReport};
use crate::trace::TraceSummary;

/// UID and GID of the guest's `builder` user.
pub(crate) const BUILDER: u32 = 1000;

/// Output kept per stream in the report.
const OUTPUT_TAIL: usize = 16 * 1024;

/// Output the agent forwards per run.
const OUTPUT_LIMIT: u32 = 4 * 1024 * 1024;

/// Extra wall clock the host allows beyond the guest's own timeout.
const HOST_MARGIN: Duration = Duration::from_secs(60);

/// Why a run could not happen. The job is not at fault for any of these.
#[derive(Debug, thiserror::Error)]
#[error("{class:?}: {message}")]
pub struct Failure {
    /// Retry class.
    pub class: FailureClass,
    /// What happened.
    pub message: String,
    /// An alert to raise, beyond what the failure class implies.
    pub escalation: Option<HumanEscalation>,
}

impl Failure {
    fn infrastructure(message: impl std::fmt::Display) -> Self {
        Self {
            class: FailureClass::Infrastructure,
            message: message.to_string(),
            escalation: None,
        }
    }

    fn permanent(message: impl std::fmt::Display) -> Self {
        Self {
            class: FailureClass::Permanent,
            message: message.to_string(),
            escalation: None,
        }
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
fn analyze_network(
    path: &Path,
    tokens: &[crate::honeytokens::Token],
) -> (NetworkSummary, Vec<Leak>) {
    use std::io::{BufRead, Read};
    let mut summary = NetworkSummary::default();
    let mut leaked = Vec::new();
    let Ok(file) = std::fs::File::open(path) else {
        return (summary, leaked);
    };
    let mut leak = |haystack: &[u8], via: &str| {
        for token in Honeytokens::found_in(tokens, haystack) {
            if !leaked
                .iter()
                .any(|l: &Leak| l.kind == token.kind && l.via == via)
            {
                leaked.push(Leak {
                    kind: token.kind.to_owned(),
                    via: via.to_owned(),
                });
            }
        }
    };
    for line in std::io::BufReader::new(file.take(MAX_NETWORK_LOG)).lines() {
        let Ok(line) = line else {
            break;
        };
        let Ok(event) = serde_json::from_str::<Event>(&line) else {
            continue;
        };
        match event.kind {
            EventKind::Dns { name, .. } => {
                leak(name.as_bytes(), &name);
                if !summary.dns.contains(&name) && summary.dns.len() < MAX_LISTED {
                    summary.dns.push(name);
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
                // Every name resolves to the sink, so the name the guest
                // asked for says more than the address.
                let via = match &sniffed {
                    Sniffed::Http {
                        host: Some(host), ..
                    } => format!("http://{host}"),
                    Sniffed::Tls { sni: Some(sni) } => format!("tls://{sni}"),
                    _ => dst.clone(),
                };
                leak(&unhex(&data).unwrap_or_default(), &via);
                if let Some(plain) = decrypted.as_deref().and_then(unhex) {
                    leak(&plain, &via.replacen("tls://", "https://", 1));
                }
                if summary.connections.len() < MAX_LISTED {
                    summary.connections.push(Connection {
                        dst,
                        sniffed,
                        bytes,
                        inner,
                    });
                }
            }
            EventKind::Udp { data, .. } => {
                leak(&unhex(&data).unwrap_or_default(), "udp");
                summary.udp_datagrams = summary.udp_datagrams.saturating_add(1);
            }
            EventKind::Packet {
                summary: what,
                data,
                ..
            } => {
                leak(&unhex(&data).unwrap_or_default(), "packet");
                if summary.packets.len() < MAX_LISTED {
                    summary.packets.push(what);
                }
            }
            EventKind::PacketLimit => summary.packets_truncated = true,
            EventKind::Refused { .. } => summary.refused = summary.refused.saturating_add(1),
            EventKind::Truncated => summary.truncated = true,
        }
    }
    (summary, leaked)
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
    /// The warm build cache jobs mount, if one was built (ADR 0008).
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

    /// Runs both canaries (ADR 0020) in this worker's slot and records the
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
        for canary in crate::canary::ALL {
            let setup = &self.sandbox.setup;
            let files = JobFiles {
                payload: setup.work_dir.join(format!("{}.payload", canary.name)),
                scratch: setup.work_dir.join(format!("{}.scratch", canary.name)),
                network: setup.work_dir.join(format!("{}.network", canary.name)),
                warm: setup.warm.clone(),
                warm_placeholder: setup.warm_placeholder.clone(),
            };
            let result = async {
                let spec = canary
                    .payload(&self.sandbox.blobs)
                    .map_err(Failure::infrastructure)?;
                let tokens = Honeytokens::generate(&mut rand::rng(), BUILDER);
                let plan = RunPlan::check(setup.check_timeout);
                self.sandbox.execute(0, spec, &tokens, &files, &plan).await
            }
            .await;
            for file in [&files.payload, &files.scratch, &files.network] {
                let _ = std::fs::remove_file(file);
            }
            let (passed, detail) = match result {
                Ok(report) => {
                    let problems = canary.check(&report);
                    let detail = serde_json::json!({
                        "problems": problems,
                        "outcome": report.outcome,
                        "run_ms": report.run_ms,
                    });
                    (problems.is_empty(), detail)
                }
                // The run itself failed: that says nothing about verdicts,
                // so it is recorded but not counted as a wrong result.
                Err(failure) => {
                    tracing::warn!(canary = canary.name, %failure, "canary run failed");
                    continue;
                }
            };
            tracing::info!(canary = canary.name, passed, %detail, "canary finished");
            self.store
                .record_canary(canary.name, passed, &detail)
                .await?;
        }
        Ok(())
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
        let worker = self.worker.clone();
        let policies = self.policies.clone();
        self.store
            .complete(job.id, &worker, JobEvent::SandboxStarted, &policies, true)
            .await?;
        let beat = heartbeat(
            Arc::clone(&self.heartbeats),
            job.id,
            worker.clone(),
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
                if let Some(escalation) = &failure.escalation {
                    self.store.raise_alert(escalation).await?;
                    // A KVM error stops the stage at once; the supervisor
                    // probes again after the cooldown.
                    if *escalation == HumanEscalation::KvmError {
                        let now = self.store.now_epoch().await?;
                        self.store
                            .set_breaker(
                                Stage::Sandbox,
                                BreakerState::Open {
                                    since: now,
                                    reopened: 0,
                                },
                            )
                            .await?;
                    }
                }
                JobEvent::StageFailed {
                    class: failure.class,
                }
            }
        };
        self.store
            .complete(job.id, &worker, event, &policies, false)
            .await?;
        Ok(true)
    }

    async fn run(&self, job: &StoredJob) -> Result<RunReport, Failure> {
        let work = &self.sandbox.setup.work_dir;
        let payload = work.join(format!("job-{}.payload", job.id.0));
        let scratch = work.join(format!("job-{}.scratch", job.id.0));
        let network = work.join(format!("job-{}.network", job.id.0));
        let result = self.run_with(job, &payload, &scratch, &network).await;
        for file in [&payload, &scratch, &network] {
            if let Err(error) = std::fs::remove_file(file)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!(file = %file.display(), %error, "cannot remove a job file");
            }
        }
        result
    }

    async fn run_with(
        &self,
        job: &StoredJob,
        payload: &Path,
        scratch: &Path,
        network: &Path,
    ) -> Result<RunReport, Failure> {
        let name = CrateName::parse(&job.name).map_err(Failure::permanent)?;
        let version = semver::Version::parse(&job.version).map_err(Failure::permanent)?;
        let lockfile = self
            .store
            .fetch_lockfile(job.id)
            .await?
            .ok_or_else(|| Failure::permanent("the job has no lockfile"))?;
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
        let spec = PayloadSpec {
            name,
            version,
            lockfile,
            packages,
            extra_probes: Vec::new(),
            files: Vec::new(),
            stubs: Vec::new(),
        };
        let tokens = Honeytokens::generate(&mut rand::rng(), BUILDER);
        self.store
            .record_honeytokens(job.id, &tokens.records())
            .await?;
        let files = JobFiles {
            payload: payload.to_path_buf(),
            scratch: scratch.to_path_buf(),
            network: network.to_path_buf(),
            warm: self.sandbox.setup.warm.clone(),
            warm_placeholder: self.sandbox.setup.warm_placeholder.clone(),
        };
        let setup = &self.sandbox.setup;
        let plan = match job.job.run_kind {
            RunKind::Check => RunPlan::check(setup.check_timeout),
            RunKind::Full => RunPlan::full(setup.full_timeout),
        };
        let mut report = self
            .sandbox
            .execute(job.id.0, spec, &tokens, &files, &plan)
            .await?;
        report.missing_packages = missing;
        if !report.leaked.is_empty() {
            tracing::warn!(job = job.id.0, name = %job.name, version = %job.version, leaked = ?report.leaked, "honeytokens left the VM");
        }
        let outcome = report.outcome;
        let value = serde_json::to_value(&report).map_err(Failure::infrastructure)?;
        let outcome_name = serde_json::to_value(outcome)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        self.store
            .record_run(job.id, job.job.run_kind.name(), &outcome_name, &value)
            .await?;
        Ok(report)
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
    /// The warm build cache to mount, if there is one (ADR 0008).
    pub warm: Option<PathBuf>,
    /// An empty file that stands in for the warm image when there is none.
    pub warm_placeholder: PathBuf,
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
            cwd: PROBE_DIR.into(),
            timeout,
        }
    }

    /// The confirmation run after an escalation (ADR 0021): a full build,
    /// with code generation and linking, in a fresh VM with fresh
    /// honeytokens.
    #[must_use]
    pub fn full(timeout: Duration) -> Self {
        Self {
            argv: ["cargo", "build", "--locked", "--offline"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            cwd: PROBE_DIR.into(),
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
        // The fake internet appends to its log; one left from an earlier run
        // would mix that run's traffic into this one's.
        match std::fs::remove_file(&files.network) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Failure::infrastructure(error)),
        }
        let stats = build_payload(&self.setup, &self.blobs, spec, &files.payload).await?;
        make_scratch(self.setup.scratch_mib, &files.scratch).await?;
        crate::jail::acl::grant_user(&files.scratch, self.backend.slot_uid(self.slot))
            .map_err(Failure::infrastructure)?;

        let (mounts, mut directories) = job_mounts(files.warm.is_some());
        directories.extend(tokens.directories.clone());
        let workspace = Workspace {
            mounts,
            directories: directories.clone(),
            files: tokens.files.clone(),
        };
        let mut env: Vec<(String, String)> = [
            ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ("HOME", HOME),
            ("USER", "builder"),
            ("CARGO_HOME", "/work/home/.cargo"),
            ("CARGO_TARGET_DIR", "/work/target"),
            ("CARGO_TERM_COLOR", "never"),
            ("LANG", "C.UTF-8"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
        env.extend(tokens.env.clone());
        let timeout = plan.timeout;
        let input = JobInput {
            spec: JobSpec {
                job_id,
                wall_clock: now(),
                argv: plan.argv.clone(),
                env,
                cwd: plan.cwd.clone(),
                timeout_secs: u32::try_from(timeout.as_secs()).unwrap_or(u32::MAX),
                output_limit: OUTPUT_LIMIT,
            },
            workspace,
            drives: Some(JobDrives {
                payload: files.payload.clone(),
                scratch: files.scratch.clone(),
                warm: files
                    .warm
                    .clone()
                    .unwrap_or_else(|| files.warm_placeholder.clone()),
            }),
            network_log: Some(files.network.clone()),
            scratch_mib: self.setup.scratch_mib,
        };
        let run = self
            .backend
            .run_job(self.slot, input, timeout + HOST_MARGIN)
            .await
            .map_err(Failure::infrastructure)?;
        let (outcome, exit, stdout, stderr, truncated, trace) = match &run.end {
            JobEnd::Finished(o) => {
                let outcome = match o.exit {
                    ExitStatus::Code(0) => BuildOutcome::Succeeded,
                    ExitStatus::TimedOut => BuildOutcome::TimedOut,
                    ExitStatus::Code(_) | ExitStatus::Signal(_) => BuildOutcome::Failed,
                };
                (
                    outcome,
                    Some(o.exit),
                    o.stdout.as_slice(),
                    o.stderr.as_slice(),
                    o.truncated,
                    (*o.trace).clone(),
                )
            }
            JobEnd::HostTimeout => (
                BuildOutcome::TimedOut,
                None,
                &[][..],
                &[][..],
                false,
                TraceSummary::default(),
            ),
            JobEnd::ResourceLimit => (
                BuildOutcome::ResourceLimit,
                None,
                &[][..],
                &[][..],
                false,
                TraceSummary::default(),
            ),
            // Only guest code stops a guest: a result, never retried, so a crate
            // cannot trip the sandbox breaker by crashing its own VM.
            JobEnd::GuestStopped(_) => (
                BuildOutcome::GuestStopped,
                None,
                &[][..],
                &[][..],
                false,
                TraceSummary::default(),
            ),
            JobEnd::VmmCrashed(reason) => {
                return Err(Failure {
                    class: FailureClass::SuspectedCompromise,
                    message: format!("the VMM crashed: {reason}"),
                    escalation: None,
                });
            }
            JobEnd::DecoyTouched => {
                return Err(Failure {
                    class: FailureClass::SuspectedCompromise,
                    message: "something read the decoy in the jail root".to_owned(),
                    escalation: None,
                });
            }
            JobEnd::KvmError(reason) => {
                return Err(Failure {
                    class: FailureClass::Infrastructure,
                    message: format!("KVM error: {reason}"),
                    escalation: Some(HumanEscalation::KvmError),
                });
            }
            // A VM that died without a report and without a known reason: ours.
            JobEnd::UnexpectedExit(reason) => {
                return Err(Failure::infrastructure(format!(
                    "the VM ended unexpectedly: {reason}"
                )));
            }
        };
        let (network, leaked) = analyze_network(&files.network, &tokens.tokens);
        let scratch = scan_scratch(&self.setup, files, &directories, tokens).await;
        let tokens_on_disk = scratch
            .as_ref()
            .map(|report| {
                report
                    .tokens_found
                    .iter()
                    .filter_map(|(i, path)| {
                        tokens.tokens.get(*i).map(|t| Leak {
                            kind: t.kind.to_owned(),
                            via: path.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let values: Vec<&str> = tokens.tokens.iter().map(|t| t.value.as_str()).collect();
        let tokens_in_trace = trace
            .find(&values)
            .into_iter()
            .filter_map(|(i, via)| {
                tokens.tokens.get(i).map(|t| Leak {
                    kind: t.kind.to_owned(),
                    via,
                })
            })
            .take(MAX_LISTED)
            .collect();
        let report = RunReport {
            scratch,
            tokens_on_disk,
            trace,
            tokens_in_trace,
            network,
            leaked,
            outcome,
            end: format!("{:?}", run.end).chars().take(64).collect(),
            exit,
            restore_ms: u64::try_from(run.restore.as_millis()).unwrap_or(u64::MAX),
            run_ms: u64::try_from(run.run.as_millis()).unwrap_or(u64::MAX),
            stdout_tail: tail(stdout),
            stderr_tail: tail(stderr),
            truncated,
            payload_files: stats.files,
            payload_bytes: stats.bytes,
            missing_packages: Vec::new(),
        };
        Ok(report)
    }
}

/// Where the warm image is mounted in the guest, and the overlay's
/// writable directories, all on the scratch disk.
pub const WARM_IMAGE_DIR: &str = "/work/.warm/image";
const WARM_UPPER: &str = "/work/.warm/upper";
const WARM_WORK: &str = "/work/.warm/work";
/// The target directory, as cargo sees it.
pub const TARGET_DIR: &str = "/work/target";

/// The mounts of a job, and the directories to create before it runs. With
/// `warm`, the warm image's target directory lies under the job's own
/// writable layer at [`TARGET_DIR`] (ADR 0008); without it, the target
/// directory is a plain directory on the scratch disk.
#[must_use]
pub fn job_mounts(warm: bool) -> (Vec<MountSpec>, Vec<PathSpec>) {
    let mut mounts = vec![
        MountSpec {
            device: "/dev/vdb".into(),
            target: crate::payload::MOUNT_POINT.into(),
            fstype: "erofs".into(),
            read_only: true,
            executable: false,
            options: None,
        },
        MountSpec {
            device: "/dev/vdc".into(),
            target: "/work".into(),
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
                path: TARGET_DIR.into(),
                owner: BUILDER,
                mode: 0o755,
            }],
        );
    }
    mounts.push(MountSpec {
        device: "/dev/vdd".into(),
        target: WARM_IMAGE_DIR.into(),
        fstype: "erofs".into(),
        read_only: true,
        // Compiled build scripts and proc macros run from here.
        executable: true,
        options: None,
    });
    mounts.push(MountSpec {
        device: "overlay".into(),
        target: TARGET_DIR.into(),
        fstype: "overlay".into(),
        read_only: false,
        executable: false,
        options: Some(format!(
            "lowerdir={WARM_IMAGE_DIR}/target,upperdir={WARM_UPPER},workdir={WARM_WORK}"
        )),
    });
    (mounts, Vec::new())
}

/// Reads the scratch disk in the sandboxed scanner. A failure of the
/// scanner is logged and leaves the report without a scratch section; the
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

/// Creates an empty ext4 image. The file is sparse; tmpfs holds only the
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
