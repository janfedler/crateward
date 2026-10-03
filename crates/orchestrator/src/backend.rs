//! Running jobs in VM slots, behind a trait the pipeline can fake.
//!
//! [`VmBackend`] is what the sandbox stage talks to: run one job in one slot,
//! and reconcile leftovers at startup. [`FirecrackerBackend`] implements it
//! with jailed Firecracker VMs restored from a snapshot. [`FakeBackend`]
//! returns scripted results, so CI can test everything above this layer
//! without KVM (ADR 0002 names the trait as the seam for another VMM).
//!
//! Every run creates the slot's cgroup, restores a VM into it, applies a
//! host side wall clock, and then removes the VM directory and the cgroup
//! whatever happened. How a run ended is reported as a [`JobEnd`], so that a
//! crate that exhausts memory or time is a result, while a VM that fails to
//! start is an infrastructure error.

use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use crateward_core::protocol::{JobSpec, TracingStatus, Workspace};
use tokio::time::Instant;
use tokio::time::error::Elapsed;

use crate::cgroup::{CgroupError, CgroupTree, SLOT_PREFIX, SlotCgroup, SlotLimits};
use crate::firecracker::agent::{AgentConnection, AgentError, RunOutcome};
use crate::firecracker::vm::{
    BootSpec, Isolation, JailConfig, JobDrives, Launch, Snapshot, TAP, Vm, VmError,
};
use crate::jail::Sinks;

/// How long a freshly booted VM may take until its agent answers.
const BASE_BOOT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a restored VM may take until its agent answers.
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How one run ended, from the host's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobEnd {
    /// The agent reported the job's end (including guest side timeouts).
    Finished(RunOutcome),
    /// The host's wall clock expired. The slot was killed.
    HostTimeout,
    /// The VM hit its cgroup memory or process limit and was killed, or
    /// Firecracker hit its file size or CPU time limit.
    ResourceLimit,
    /// The guest stopped (shut down, restarted, panicked) or its agent
    /// stopped answering before it reported an end. A result about the
    /// crate: only guest code can do that.
    GuestStopped(String),
    /// Firecracker was shut down after a forbidden system call or a fatal
    /// signal. It handles guest input, so this may mean the guest attacked
    /// it: a sandbox escape indicator.
    VmmCrashed(String),
    /// Something read the decoy in the jail root, which only a process
    /// outside the VM can reach (ADR 0008): a sandbox escape indicator.
    DecoyTouched,
    /// KVM refused to run the VM. The host is at fault.
    KvmError(String),
    /// The VM stopped without the agent reporting an end and without a
    /// limit explaining it. The supervisor treats this as a possible escape
    /// indicator.
    UnexpectedExit(String),
}

impl JobEnd {
    /// Whether this end suggests code got out of the VM. Such an end
    /// outranks every later error, so the job is quarantined instead of
    /// retried.
    #[must_use]
    pub fn is_escape_indicator(&self) -> bool {
        matches!(self, Self::VmmCrashed(_) | Self::DecoyTouched)
    }

    /// The lowercase name of the end, without its details.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Finished(_) => "finished",
            Self::HostTimeout => "host_timeout",
            Self::ResourceLimit => "resource_limit",
            Self::GuestStopped(_) => "guest_stopped",
            Self::VmmCrashed(_) => "vmm_crashed",
            Self::DecoyTouched => "decoy_touched",
            Self::KvmError(_) => "kvm_error",
            Self::UnexpectedExit(_) => "unexpected_exit",
        }
    }
}

/// The name, and the reason for ends that have one.
impl std::fmt::Display for JobEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())?;

        match self {
            Self::GuestStopped(reason)
            | Self::VmmCrashed(reason)
            | Self::KvmError(reason)
            | Self::UnexpectedExit(reason) => write!(f, ": {reason}"),
            _ => Ok(()),
        }
    }
}

/// The result of a run once its slot is stopped and cleaned up.
///
/// A touched decoy outranks everything, then an escape indicator the run
/// itself produced. Cleanup errors never hide either, since whatever got out
/// may also have broken the cleanup. A jail root that disappeared is a host
/// fault (another process removed it), never a finding. Otherwise the run's
/// own error comes first, then the first cleanup error.
///
/// # Errors
///
/// Returns the error that decides the run, as above.
pub fn settle(
    slot: u32,
    end: Result<JobEnd, BackendError>,
    decoy: Option<crate::jail::decoy::Decoy>,
    cleanup: Vec<BackendError>,
) -> Result<JobEnd, BackendError> {
    use crate::jail::decoy::Decoy;
    let end = match (decoy, end) {
        (Some(Decoy::Touched), Err(error)) => {
            tracing::warn!(slot, %error, "run error after the decoy was touched");
            JobEnd::DecoyTouched
        }
        (Some(Decoy::Touched), Ok(_)) => JobEnd::DecoyTouched,
        (_, Ok(end)) if end.is_escape_indicator() => end,
        (Some(Decoy::JailGone), _) => {
            return Err(BackendError::Io {
                context: format!("slot {slot}: the jail root disappeared during the run"),
                source: std::io::ErrorKind::NotFound.into(),
            });
        }
        (_, end) => end?,
    };

    let mut cleanup = cleanup.into_iter();
    if end.is_escape_indicator() {
        for error in cleanup {
            tracing::warn!(slot, %error, "cleanup failed after an escape indicator");
        }

        return Ok(end);
    }

    match cleanup.next() {
        Some(error) => {
            for later in cleanup {
                tracing::warn!(slot, error = %later, "cleanup also failed");
            }

            Err(error)
        }
        None => Ok(end),
    }
}

/// Everything one run needs.
#[derive(Debug, Clone)]
pub struct JobInput {
    /// What the agent runs.
    pub spec: JobSpec,
    /// What the agent prepares first.
    pub workspace: Workspace,
    /// The job's payload and scratch drives, if it has any.
    pub drives: Option<JobDrives>,
    /// Where the fake internet writes its events. It runs only if both
    /// this and [`FirecrackerConfig::fake_internet`] are set.
    pub network_log: Option<PathBuf>,
    /// Size of the scratch disk. It lives on tmpfs, and the pages the guest
    /// writes are charged to the slot's cgroup, so its memory limit grows by
    /// this much.
    pub scratch_mib: u64,
}

/// One run with its timings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRun {
    /// How the run ended.
    pub end: JobEnd,
    /// From starting the jail to a ready agent.
    pub restore: Duration,
    /// From sending the job to its end.
    pub run: Duration,
}

/// What reconciliation removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// Slot cgroups killed and removed.
    pub cgroups: Vec<String>,
    /// Slot directories removed.
    pub directories: Vec<String>,
}

/// Why the backend could not run a job at all. These are infrastructure
/// failures. The job itself is not at fault.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The VM could not be started or reached.
    #[error("vm: {0}")]
    Vm(#[from] VmError),
    /// cgroup management failed.
    #[error("cgroup: {0}")]
    Cgroup(#[from] CgroupError),
    /// Filesystem cleanup failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The slot number is outside the configured slots.
    #[error("slot {0} does not exist")]
    NoSuchSlot(u32),
    /// The agent's eBPF tracing did not start, so no base snapshot is
    /// taken: a dynamic run without a trace would look cleaner than it is.
    #[error("guest tracing unavailable: {0}")]
    TracingUnavailable(String),
}

/// What the sandbox stage needs from a VM implementation.
pub trait VmBackend {
    /// Runs one job in `slot` with a host side wall clock limit.
    fn run_job(
        &self,
        slot: u32,
        job: JobInput,
        wall_clock: Duration,
    ) -> impl Future<Output = Result<JobRun, BackendError>> + Send;

    /// Removes everything a crash may have left behind. Called at startup,
    /// before any slot is in use.
    fn reconcile(&self) -> impl Future<Output = Result<Reconciled, BackendError>> + Send;
}

/// Settings of [`FirecrackerBackend`].
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    /// Firecracker binary.
    pub firecracker: PathBuf,
    /// `crateward-vmjail` binary.
    pub launcher: PathBuf,
    /// Parent of the slot directories. Private to the orchestrator.
    pub slots_dir: PathBuf,
    /// Number of slots.
    pub slots: u32,
    /// Slot `n` runs as subordinate UID `uid_base + n`.
    pub uid_base: u32,
    /// Slot `n` runs as subordinate GID `gid_base + n`.
    pub gid_base: u32,
    /// cgroup limits per slot.
    pub limits: SlotLimits,
    /// `RLIMIT_FSIZE` for Firecracker.
    pub max_file_size: u64,
    /// The `crateward_fake_internet` binary, started in every job's jail.
    pub fake_internet: Option<PathBuf>,
    /// The fake internet's TLS authority (certificate and key, PEM).
    pub authority: Option<PathBuf>,
}

/// Runs jobs in jailed Firecracker VMs restored from one snapshot.
#[derive(Debug)]
pub struct FirecrackerBackend {
    config: FirecrackerConfig,
    cgroups: CgroupTree,
    snapshot: Snapshot,
}

impl FirecrackerBackend {
    /// A backend restoring `snapshot`, with slot cgroups under `cgroups`.
    #[must_use]
    pub fn new(config: FirecrackerConfig, cgroups: CgroupTree, snapshot: Snapshot) -> Self {
        Self {
            config,
            cgroups,
            snapshot,
        }
    }

    /// The subordinate UID slot `slot` runs as.
    #[must_use]
    pub fn slot_uid(&self, slot: u32) -> u32 {
        self.config.uid_base + slot
    }

    /// Boots a clean VM in a jail, waits for its agent and writes a full
    /// snapshot to `out`: the base every job restores (ADR 0006, from a
    /// fresh boot, never from a VM that ran crate code). With
    /// `boot.drives`, the snapshot has placeholder drives that jobs replace.
    /// The spare slot number `config.slots` is used, so no job slot is
    /// disturbed.
    ///
    /// # Errors
    ///
    /// Fails if the VM does not boot, its agent does not answer, or the
    /// snapshot cannot be written.
    pub async fn create_base_snapshot(
        config: &FirecrackerConfig,
        boot: &BootSpec,
        out: &std::path::Path,
    ) -> Result<Snapshot, BackendError> {
        let launch = Self::launch(config, config.slots, None, None);
        let vm = Vm::boot(&launch, boot).await?;
        let snapshot = async {
            let mut agent = vm.agent(Instant::now() + BASE_BOOT_TIMEOUT).await?;
            agent.ping().await.map_err(VmError::from)?;

            if let TracingStatus::Unavailable(reason) = &agent.tracing {
                return Err(BackendError::TracingUnavailable(reason.clone()));
            }

            drop(agent);
            Ok(vm.snapshot(&launch, &boot.rootfs, out).await?)
        }
        .await;
        vm.destroy().await?;

        snapshot
    }

    /// The launch description of a slot, in its own cgroup.
    #[must_use]
    pub fn launch(
        config: &FirecrackerConfig,
        slot: u32,
        cgroup: Option<PathBuf>,
        network_log: Option<PathBuf>,
    ) -> Launch {
        let sinks = config
            .fake_internet
            .clone()
            .zip(network_log)
            .map(|(binary, events)| Sinks {
                binary,
                events,
                authority: config.authority.clone(),
            });

        Launch {
            firecracker: config.firecracker.clone(),
            dir: config.slots_dir.join(format!("{SLOT_PREFIX}{slot}")),
            id: format!("{SLOT_PREFIX}{slot}"),
            isolation: Isolation::Jail(JailConfig {
                launcher: config.launcher.clone(),
                vm_uid: config.uid_base + slot,
                vm_gid: config.gid_base + slot,
                tap: Some(TAP.into()),
                sinks,
                cgroup,
                max_file_size: config.max_file_size,
            }),
        }
    }

    async fn run_in_slot(
        &self,
        slot: u32,
        job: JobInput,
        wall_clock: Duration,
        cgroup: &SlotCgroup,
    ) -> Result<JobRun, BackendError> {
        let launch = Self::launch(
            &self.config,
            slot,
            Some(cgroup.path().to_path_buf()),
            job.network_log.clone(),
        );

        let started = Instant::now();
        let mut vm = Vm::restore(&launch, &self.snapshot, job.drives.as_ref()).await?;

        // No crate code has run yet, so a failure up to here is ours.
        let mut agent = match ready_agent(&vm, job.workspace).await {
            Ok(agent) => agent,
            Err(error) => {
                let _ = vm.destroy().await;
                return Err(error.into());
            }
        };

        let restore = started.elapsed();
        let run_started = Instant::now();
        let result = tokio::time::timeout(wall_clock, agent.run(job.spec)).await;
        let run = run_started.elapsed();

        // Errors from here on are kept, not returned: the decoy is checked
        // whatever happened.
        let end = run_end(result, cgroup, &mut vm, &launch).await;
        drop(agent);
        let (decoy, cleanup) = stop_slot(cgroup, vm).await;
        let end = settle(slot, end, decoy, cleanup)?;

        Ok(JobRun { end, restore, run })
    }
}

/// Waits for a restored VM's agent and prepares its workspace.
async fn ready_agent(vm: &Vm, workspace: Workspace) -> Result<AgentConnection, VmError> {
    let mut agent = vm.agent(Instant::now() + AGENT_READY_TIMEOUT).await?;
    agent.prepare(workspace).await.map_err(VmError::from)?;

    Ok(agent)
}

/// How the run ended, from the agent's answer or the host's wall clock.
async fn run_end(
    result: Result<Result<RunOutcome, AgentError>, Elapsed>,
    cgroup: &SlotCgroup,
    vm: &mut Vm,
    launch: &Launch,
) -> Result<JobEnd, BackendError> {
    match result {
        Ok(Ok(outcome)) => Ok(JobEnd::Finished(outcome)),
        Err(_) => {
            cgroup.kill()?;
            Ok(JobEnd::HostTimeout)
        }
        Ok(Err(error)) => broken_agent(&error, cgroup, vm, launch).await,
    }
}

/// The agent stopped answering: a limit of the cgroup explains it, or else
/// the way Firecracker exited.
async fn broken_agent(
    error: &AgentError,
    cgroup: &SlotCgroup,
    vm: &mut Vm,
    launch: &Launch,
) -> Result<JobEnd, BackendError> {
    let oom = cgroup.event("memory.events", "oom_kill ")?;
    let pids = cgroup.event("pids.events", "max ")?;
    if oom > 0 || pids > 0 {
        return Ok(JobEnd::ResourceLimit);
    }

    let status = vm.wait_exit(EXIT_GRACE).await.ok().flatten();

    // The console's last lines usually say why. The guest wrote them, so
    // they are escaped.
    let tail = console_tail(&launch.dir.join("firecracker.log"));

    Ok(classify_exit(status, &format!("{error}; console: {tail}")))
}

/// Stops every process of the slot (Firecracker and the fake internet)
/// before looking at the decoy, so no read can follow the check unseen.
/// Then removes the evidence. Returns the decoy's state and the errors.
async fn stop_slot(
    cgroup: &SlotCgroup,
    mut vm: Vm,
) -> (Option<crate::jail::decoy::Decoy>, Vec<BackendError>) {
    let mut cleanup: Vec<BackendError> = Vec::new();
    if let Err(error) = cgroup.kill_and_wait() {
        cleanup.push(error.into());
    }

    if let Err(error) = vm.kill().await {
        cleanup.push(error.into());
    }

    let decoy = vm.jail_root().map(crate::jail::decoy::inspect);
    if let Err(error) = vm.remove().await {
        cleanup.push(error.into());
    }

    (decoy, cleanup)
}

impl VmBackend for FirecrackerBackend {
    async fn run_job(
        &self,
        slot: u32,
        job: JobInput,
        wall_clock: Duration,
    ) -> Result<JobRun, BackendError> {
        if slot >= self.config.slots {
            return Err(BackendError::NoSuchSlot(slot));
        }

        let mut limits = self.config.limits;
        limits.memory_mib = limits.memory_mib.saturating_add(job.scratch_mib);
        let cgroup = self.cgroups.create_slot(&slot.to_string(), limits)?;
        let result = self.run_in_slot(slot, job, wall_clock, &cgroup).await;

        // The cgroup goes away whatever happened, and with it any process.
        let mut cleanup: Vec<BackendError> = Vec::new();
        if let Err(error) = cgroup.remove() {
            cleanup.push(error.into());
        }

        let dir = self.config.slots_dir.join(format!("{SLOT_PREFIX}{slot}"));
        if dir.exists()
            && let Err(source) = std::fs::remove_dir_all(&dir)
        {
            cleanup.push(BackendError::Io {
                context: format!("removing {}", dir.display()),
                source,
            });
        }

        match result {
            Ok(JobRun { end, restore, run }) => {
                let end = settle(slot, Ok(end), None, cleanup)?;
                Ok(JobRun { end, restore, run })
            }
            Err(error) => {
                for later in cleanup {
                    tracing::warn!(slot, error = %later, "cleanup failed after a failed run");
                }

                Err(error)
            }
        }
    }

    async fn reconcile(&self) -> Result<Reconciled, BackendError> {
        let cgroups = self.cgroups.remove_all_slots()?;
        let mut directories = Vec::new();

        if self.config.slots_dir.exists() {
            let entries =
                std::fs::read_dir(&self.config.slots_dir).map_err(|source| BackendError::Io {
                    context: format!("listing {}", self.config.slots_dir.display()),
                    source,
                })?;
            for entry in entries.filter_map(Result::ok) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(SLOT_PREFIX) {
                    std::fs::remove_dir_all(entry.path()).map_err(|source| BackendError::Io {
                        context: format!("removing {}", entry.path().display()),
                        source,
                    })?;
                    directories.push(name);
                }
            }
        }

        Ok(Reconciled {
            cgroups,
            directories,
        })
    }
}

/// How long to wait for Firecracker to exit after the agent's connection
/// broke, to learn why.
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// Classifies a run that ended without the agent's report, by Firecracker's
/// exit status. Firecracker v1.17 handles fatal signals itself and exits
/// with `FcExitCode` (`src/vmm/src/lib.rs`): 0 when the guest stopped, 1 on
/// errors including KVM faults (logged as `FaultyKvmExit`), 148 after a
/// forbidden system call, 149, 150 and 157 after `SIGBUS`, `SIGSEGV` and
/// `SIGILL`, 151 and 154 after `SIGXFSZ` and `SIGXCPU`, 2 when a signal
/// handler met something impossible.
#[must_use]
pub fn classify_exit(status: Option<std::process::ExitStatus>, detail: &str) -> JobEnd {
    use std::os::unix::process::ExitStatusExt;
    let Some(status) = status else {
        // Firecracker still runs: the guest's agent went away.
        return JobEnd::GuestStopped(format!("the agent stopped answering: {detail}"));
    };

    match (status.code(), status.signal()) {
        (Some(0), _) => JobEnd::GuestStopped(format!("the guest stopped: {detail}")),
        (Some(code @ (2 | 148 | 149 | 150 | 157)), _) => {
            JobEnd::VmmCrashed(format!("firecracker exited with {code}: {detail}"))
        }
        (Some(151 | 154), _) => JobEnd::ResourceLimit,
        (Some(1), _) if detail.contains("FaultyKvmExit") || detail.contains("KVM_RUN") => {
            JobEnd::KvmError(detail.to_owned())
        }
        (_, Some(signal)) => {
            JobEnd::UnexpectedExit(format!("firecracker ended by signal {signal}: {detail}"))
        }
        (code, None) => {
            JobEnd::UnexpectedExit(format!("firecracker exited with {code:?}: {detail}"))
        }
    }
}

/// The last 2 KiB of a VM's log, rendered with escapes.
fn console_tail(path: &std::path::Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return "unavailable".into();
    };

    let len = file.metadata().map_or(0, |m| m.len());
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(2048)));
    let mut tail = Vec::new();
    let _ = file.take(2048).read_to_end(&mut tail);

    // `render` keeps at most 512 bytes per call.
    tail.chunks(512).map(crate::trace::render).collect()
}

/// A scripted backend for tests of the layers above.
#[derive(Debug, Default)]
pub struct FakeBackend {
    script: Mutex<VecDeque<JobEnd>>,
    /// Jobs received, in order.
    pub received: Mutex<Vec<(u32, JobSpec)>>,
}

impl FakeBackend {
    /// A backend that ends the next jobs as scripted, in order. When the
    /// script runs out, jobs end with [`JobEnd::UnexpectedExit`].
    #[must_use]
    pub fn new(script: impl IntoIterator<Item = JobEnd>) -> Self {
        Self {
            script: Mutex::new(script.into_iter().collect()),
            received: Mutex::new(Vec::new()),
        }
    }
}

impl VmBackend for FakeBackend {
    async fn run_job(
        &self,
        slot: u32,
        job: JobInput,
        _wall_clock: Duration,
    ) -> Result<JobRun, BackendError> {
        if let Ok(mut received) = self.received.lock() {
            received.push((slot, job.spec));
        }

        let end = self
            .script
            .lock()
            .ok()
            .and_then(|mut script| script.pop_front())
            .unwrap_or_else(|| JobEnd::UnexpectedExit("script exhausted".into()));

        Ok(JobRun {
            end,
            restore: Duration::ZERO,
            run: Duration::ZERO,
        })
    }

    async fn reconcile(&self) -> Result<Reconciled, BackendError> {
        Ok(Reconciled::default())
    }
}

#[cfg(test)]
mod tests {
    use crateward_core::protocol::{ExitStatus, WallClock};

    use super::*;
    use crate::jail::decoy::Decoy;

    fn failed() -> BackendError {
        BackendError::NoSuchSlot(9)
    }

    #[test]
    fn escape_indicators_outrank_every_error() {
        // A touched decoy wins over the run's error and over cleanup errors.
        let end = settle(0, Err(failed()), Some(Decoy::Touched), vec![failed()]);

        assert_eq!(end.unwrap(), JobEnd::DecoyTouched);

        let end = settle(0, Ok(JobEnd::HostTimeout), Some(Decoy::Touched), vec![]);
        assert_eq!(end.unwrap(), JobEnd::DecoyTouched);

        // A crashed VMM keeps its result when cleanup fails, in both stages.
        let crashed = JobEnd::VmmCrashed("SIGSEGV".into());
        let end = settle(
            0,
            Ok(crashed.clone()),
            Some(Decoy::Untouched),
            vec![failed()],
        );

        assert_eq!(end.unwrap(), crashed);

        let end = settle(0, Ok(crashed.clone()), None, vec![failed(), failed()]);
        assert_eq!(end.unwrap(), crashed);

        // Even when the jail root is gone.
        let end = settle(0, Ok(crashed.clone()), Some(Decoy::JailGone), vec![]);

        assert_eq!(end.unwrap(), crashed);
    }

    #[test]
    fn a_vanished_jail_is_a_host_fault_not_a_finding() {
        let end = settle(
            0,
            Ok(JobEnd::HostTimeout),
            Some(Decoy::JailGone),
            vec![failed()],
        );

        let error = end.unwrap_err().to_string();
        assert!(error.contains("jail root disappeared"), "{error}");
    }

    #[test]
    fn otherwise_the_run_error_then_the_cleanup_error_decide() {
        let end = settle(0, Err(failed()), Some(Decoy::Untouched), vec![]);

        assert!(matches!(end, Err(BackendError::NoSuchSlot(9))));

        let end = settle(
            0,
            Ok(JobEnd::HostTimeout),
            Some(Decoy::Untouched),
            vec![BackendError::NoSuchSlot(1), BackendError::NoSuchSlot(2)],
        );

        assert!(matches!(end, Err(BackendError::NoSuchSlot(1))));

        let end = settle(0, Ok(JobEnd::ResourceLimit), Some(Decoy::Untouched), vec![]);
        assert_eq!(end.unwrap(), JobEnd::ResourceLimit);
    }

    fn spec() -> JobInput {
        JobInput {
            spec: JobSpec {
                job_id: 1,
                wall_clock: WallClock { secs: 0, nanos: 0 },
                argv: vec!["cargo".into(), "check".into()],
                env: vec![],
                cwd: "/work".into(),
                timeout_secs: 60,
                output_limit: 1024,
            },
            workspace: Workspace::default(),
            drives: None,
            network_log: None,
            scratch_mib: 0,
        }
    }

    #[test]
    fn exits_are_classified_by_firecracker_exit_codes() {
        use std::os::unix::process::ExitStatusExt;
        let code = |c: i32| Some(std::process::ExitStatus::from_raw(c << 8));
        let signal = |s: i32| Some(std::process::ExitStatus::from_raw(s));

        assert!(matches!(classify_exit(None, "x"), JobEnd::GuestStopped(_)));
        assert!(matches!(
            classify_exit(code(0), "x"),
            JobEnd::GuestStopped(_)
        ));

        for c in [2, 148, 149, 150, 157] {
            assert!(
                matches!(classify_exit(code(c), "x"), JobEnd::VmmCrashed(_)),
                "{c}"
            );
        }

        assert_eq!(classify_exit(code(151), "x"), JobEnd::ResourceLimit);
        assert!(matches!(
            classify_exit(code(1), "vcpu: FaultyKvmExit(InternalError)"),
            JobEnd::KvmError(_)
        ));
        assert!(matches!(
            classify_exit(code(1), "x"),
            JobEnd::UnexpectedExit(_)
        ));
        assert!(matches!(
            classify_exit(signal(9), "x"),
            JobEnd::UnexpectedExit(_)
        ));
    }

    #[test]
    fn an_end_shows_its_name_and_reason() {
        assert_eq!(JobEnd::HostTimeout.to_string(), "host_timeout");
        assert_eq!(
            JobEnd::VmmCrashed("SIGSEGV".into()).to_string(),
            "vmm_crashed: SIGSEGV"
        );

        let finished = JobEnd::Finished(RunOutcome {
            exit: ExitStatus::Code(1),
            stdout: b"secret".to_vec(),
            stderr: vec![],
            truncated: false,
            trace: Box::default(),
        });

        assert_eq!(finished.to_string(), "finished");
    }

    #[tokio::test]
    async fn fake_backend_follows_its_script() {
        let finished = JobEnd::Finished(RunOutcome {
            exit: ExitStatus::Code(0),
            stdout: vec![],
            stderr: vec![],
            truncated: false,
            trace: Box::default(),
        });

        let backend = FakeBackend::new([finished.clone(), JobEnd::HostTimeout]);
        let d = Duration::from_secs(1);

        assert_eq!(backend.run_job(0, spec(), d).await.unwrap().end, finished);
        assert_eq!(
            backend.run_job(1, spec(), d).await.unwrap().end,
            JobEnd::HostTimeout
        );
        assert!(matches!(
            backend.run_job(2, spec(), d).await.unwrap().end,
            JobEnd::UnexpectedExit(_)
        ));
        assert_eq!(backend.received.lock().unwrap().len(), 3);
    }
}
