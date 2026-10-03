//! Runs jobs in Firecracker microVMs and guarantees their cleanup.
//!
//! Zone: untrusted. This is the only host component that starts code from a
//! crate, and it does so only inside a microVM.
//!
//! Why it looks the way it does:
//!
//! * Firecracker is driven through its API socket and always started in a
//!   rootless jail (ADR 0002): its own subordinate UID, private namespaces,
//!   `pivot_root` into a root with only the needed files, no capabilities.
//!   No process runs as root for the sandbox.
//! * Jobs start by restoring a snapshot of a clean boot. Identity,
//!   honeytokens and the clock are injected after restore, because resuming
//!   one snapshot many times would otherwise repeat entropy and identifiers.
//! * Each slot has its own network namespace whose only route leads to the
//!   fake internet, which has no uplink.
//! * Hard limits cover CPU, memory, disk, processes and wall clock time.
//!   Every host resource is named after its slot, so startup reconciliation
//!   can find and remove anything a crash left behind.
//! * The fake internet's log, tap capture and the scratch disk scan provide
//!   host side ground truth that a compromised guest cannot hide from.
//! * A `VmBackend` trait separates Firecracker from the scheduling logic,
//!   so CI can use a fake backend and another VMM could be added later.

#![forbid(unsafe_code)]

pub mod backend;
pub mod canary;
pub mod cgroup;
pub mod firecracker;
pub mod honeytokens;
pub mod jail;
pub mod payload;
pub mod scratch;
pub mod trace;
pub mod warm;
pub mod worker;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crateward_core::app::{self, ComponentError, Stop, fatal};
use crateward_core::blobs::BlobStore;
use crateward_core::component::Component;
use crateward_core::config::{Config, SandboxConfig, WarmConfig};
use crateward_core::paths::{guest, host};
use crateward_core::store::{Policies, Store, StoreError};
use secrecy::ExposeSecret;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::backend::{FirecrackerBackend, FirecrackerConfig, VmBackend};
use crate::cgroup::{CgroupTree, SlotLimits};
use crate::firecracker::vm::{BootSpec, JobDrives};
use crate::worker::{Sandbox, SandboxWorker, WorkerSetup};

/// The component this package implements.
pub const COMPONENT: Component = Component::Orchestrator;

/// Memory for Firecracker itself on top of guest memory.
const VMM_OVERHEAD_MIB: u64 = 256;

/// Runs the component until SIGTERM or `Ctrl-C`: reconciles leftovers,
/// boots a clean VM for the base snapshot, then runs one worker per slot.
///
/// # Errors
///
/// Returns a [`ComponentError`] if startup or the job store fails.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    // Reconciliation removes every slot's leftovers, so a second instance
    // would tear down the first one's jails. The lock is taken before the
    // runtime exists and dropped after it, when no task runs any more.
    let _instance = lock_instance(&config.sandbox.slots_dir)?;
    let runtime = app::runtime().map_err(fatal)?;
    runtime.block_on(serve(config))
}

async fn serve(config: &Config) -> Result<(), ComponentError> {
    let sandbox = &config.sandbox;
    let booted = boot(config).await?;
    let work = booted.work.clone();
    let mut store = Store::connect(config.database.url.expose_secret())
        .await
        .map_err(fatal)?;
    store.migrate().await.map_err(fatal)?;
    let policies = Policies::from_config(&config.stages).map_err(fatal)?;
    // Installed before the warm build, so a stop request during it ends
    // its VM through reconciliation instead of leaving it behind.
    let stop = Stop::install().map_err(fatal)?;
    let mut template = Sandbox {
        backend: booted.backend.clone(),
        slot: 0,
        setup: WorkerSetup {
            exe: std::env::current_exe().map_err(fatal)?,
            work_dir: work.clone(),
            scratch_mib: sandbox.scratch_mib_per_slot,
            check_timeout: Duration::from_secs(sandbox.check_timeout_secs),
            full_timeout: Duration::from_secs(sandbox.full_timeout_secs),
            warm: None,
            warm_placeholder: work.join("placeholder-warm.img"),
        },
        blobs: BlobStore::open(&config.instance.data_dir.join(host::BLOBS)).map_err(fatal)?,
    };
    if let Some(warm_config) = &sandbox.warm {
        template.setup.warm = warm_cache(&booted, &template, &store, warm_config, &stop).await?;
    }
    if stop.is_requested() {
        return Ok(());
    }
    tokio::spawn(app::reap_loop(store, policies.clone(), stop.clone()));
    for task in spawn_slots(config, &template, &policies, &stop).await? {
        task.await.map_err(fatal)?.map_err(fatal)?;
    }
    tracing::info!("stopping");
    Ok(())
}

/// The base snapshot's backend, and what made it, for the warm build's own.
struct Booted {
    backend: Arc<FirecrackerBackend>,
    work: PathBuf,
    fc: FirecrackerConfig,
    spec: BootSpec,
    cgroups: CgroupTree,
    /// The warm build's VM, from [`warm::machine`].
    warm_machine: Option<(u8, u32)>,
}

/// Clears the leftovers of an earlier run and boots a clean VM for the base
/// snapshot.
async fn boot(config: &Config) -> Result<Booted, ComponentError> {
    let sandbox = &config.sandbox;
    // A deploy switches the guest files by moving a link (ADR 0002).
    // Resolving them once keeps a running orchestrator on the files its
    // base snapshot was made from.
    let kernel = resolve(&sandbox.kernel_image)?;
    let rootfs = resolve(&sandbox.rootfs_image)?;
    let authority = resolve(&sandbox.fake_internet_authority)?;
    let cgroups = CgroupTree::own().map_err(fatal)?;
    let fc = firecracker_config(sandbox, authority);
    check_host(sandbox)?;
    let work = config.instance.run_dir.join(host::ORCHESTRATOR_WORK);
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(fatal)?;
    let boot = boot_spec(sandbox, kernel, rootfs, placeholders(&work)?)?;
    let leftovers = FirecrackerBackend::new(fc.clone(), cgroups.clone(), placeholder_snapshot());
    let reconciled = leftovers.reconcile().await.map_err(fatal)?;
    if !reconciled.cgroups.is_empty() || !reconciled.directories.is_empty() {
        tracing::warn!(?reconciled, "removed leftovers of an earlier run");
    }
    let started = std::time::Instant::now();
    let snapshot = FirecrackerBackend::create_base_snapshot(&fc, &boot, &work.join("snapshot"))
        .await
        .map_err(fatal)?;
    tracing::info!(ms = started.elapsed().as_millis(), "base snapshot ready");
    let backend = FirecrackerBackend::new(fc.clone(), cgroups.clone(), snapshot);
    Ok(Booted {
        backend: Arc::new(backend),
        work,
        fc,
        spec: boot,
        cgroups,
        warm_machine: sandbox
            .warm
            .as_ref()
            .and_then(|w| warm::machine(sandbox, w)),
    })
}

fn resolve(path: &Path) -> Result<PathBuf, ComponentError> {
    std::fs::canonicalize(path).map_err(|e| fatal(format!("{}: {e}", path.display())))
}

fn firecracker_config(sandbox: &SandboxConfig, authority: PathBuf) -> FirecrackerConfig {
    FirecrackerConfig {
        firecracker: sandbox.firecracker_bin.clone(),
        launcher: sandbox.vmjail_bin.clone(),
        slots_dir: sandbox.slots_dir.clone(),
        slots: sandbox.slots,
        uid_base: sandbox.slot_uid_base,
        gid_base: sandbox.slot_gid_base,
        limits: SlotLimits {
            cpus: sandbox.vcpus_per_slot,
            memory_mib: sandbox.memory_mib_per_slot + VMM_OVERHEAD_MIB,
            pids: 64,
        },
        // Firecracker writes the base snapshot's memory file and the
        // scratch disks (a job's, or the larger one of the warm build).
        max_file_size: (sandbox.memory_mib_per_slot + VMM_OVERHEAD_MIB)
            .max(sandbox.scratch_mib_per_slot)
            .max(sandbox.warm.as_ref().map_or(0, warm::scratch_mib))
            .max(
                sandbox
                    .warm
                    .as_ref()
                    .and_then(|w| warm::machine(sandbox, w))
                    .map_or(0, |(_, memory)| u64::from(memory) + VMM_OVERHEAD_MIB),
            )
            << 20,
        fake_internet: Some(sandbox.fake_internet_bin.clone()),
        authority: Some(authority),
    }
}

/// A jail has no dynamic loader, so everything executed in one must be
/// static. Its decoys rely on reads updating the access time (ADR 0008).
fn check_host(sandbox: &SandboxConfig) -> Result<(), ComponentError> {
    let bin = &sandbox.fake_internet_bin;
    let elf = std::fs::read(bin).map_err(|e| fatal(format!("{}: {e}", bin.display())))?;
    if !crateward_core::elf::is_static(&elf).map_err(fatal)? {
        return Err(fatal(format!(
            "{} is dynamically linked: build it for x86_64-unknown-linux-musl",
            bin.display()
        )));
    }
    let slots_dir = &sandbox.slots_dir;
    std::fs::create_dir_all(slots_dir).map_err(fatal)?;
    if !jail::decoy::atime_works(slots_dir).map_err(fatal)? {
        return Err(fatal(format!(
            "reads do not update access times below {}; mount it with relatime or strictatime",
            slots_dir.display()
        )));
    }
    Ok(())
}

/// Empty files that stand in for the job drives in the base snapshot.
fn placeholders(work: &Path) -> Result<JobDrives, ComponentError> {
    let drives = JobDrives {
        payload: work.join("placeholder-payload.img"),
        scratch: work.join("placeholder-scratch.img"),
        warm: work.join("placeholder-warm.img"),
    };
    for file in [&drives.payload, &drives.scratch, &drives.warm] {
        std::fs::File::create(file).map_err(fatal)?;
    }
    Ok(drives)
}

fn boot_spec(
    sandbox: &SandboxConfig,
    kernel: PathBuf,
    rootfs: PathBuf,
    drives: JobDrives,
) -> Result<BootSpec, ComponentError> {
    Ok(BootSpec {
        kernel,
        rootfs,
        boot_args: format!(
            "{} {}",
            BootSpec::default_boot_args(guest::AGENT),
            BootSpec::network_boot_args()
        ),
        vcpus: u8::try_from(sandbox.vcpus_per_slot).map_err(fatal)?,
        memory_mib: u32::try_from(sandbox.memory_mib_per_slot).map_err(fatal)?,
        drives: Some(drives),
        network: true,
    })
}

/// Builds the warm build cache (ADR 0006) and returns its image. Any
/// failure means cold builds, never a failed start. A stop request during
/// the build ends its VM through reconciliation.
async fn warm_cache(
    booted: &Booted,
    slot0: &Sandbox,
    store: &Store,
    config: &WarmConfig,
    stop: &Stop,
) -> Result<Option<PathBuf>, ComponentError> {
    let plan = match warm::plan_from_store(store, config).await {
        Ok(plan) if plan.probes.is_empty() => {
            tracing::info!("nothing qualifies for the warm build cache");
            return Ok(None);
        }
        Ok(plan) => plan,
        Err(error) => {
            tracing::warn!(%error, "cannot plan the warm build cache");
            return Ok(None);
        }
    };
    let snapshot = booted.work.join("warm-snapshot");
    let builder = match warm_builder(booted, slot0, &snapshot).await {
        Ok(builder) => builder,
        Err(error) => {
            tracing::warn!(%error, "the warm build runs in one slot");
            slot0.clone()
        }
    };
    tracing::info!(
        probes = plan.probes.len(),
        units = plan.units,
        packages = plan.packages.len(),
        replayed = %plan.stubs.join(" "),
        "building the warm build cache"
    );
    let built = tokio::select! {
        built = warm::build(slot0, &builder, config, &plan) => Some(built),
        () = stop.wait() => {
            let reconciled = slot0.backend.reconcile().await.map_err(fatal)?;
            tracing::info!(?reconciled, "stopped during the warm build");
            None
        }
    };
    // Its memory file is as large as its guest memory, in tmpfs.
    let _ = std::fs::remove_dir_all(&snapshot);
    match built {
        None => Ok(None),
        Some(Ok(image)) => {
            tracing::info!(image = ?image, "warm build cache ready");
            Ok(image)
        }
        Some(Err(error)) => {
            tracing::warn!(%error, "no warm build cache");
            Ok(None)
        }
    }
}

/// The sandbox the warm build replays in: a VM of the size
/// [`warm::machine`] gives, from its own base snapshot in `snapshot`, or
/// slot 0 when that is not more than one slot.
async fn warm_builder(
    booted: &Booted,
    slot0: &Sandbox,
    snapshot: &Path,
) -> Result<Sandbox, backend::BackendError> {
    let Some((vcpus, memory)) = booted.warm_machine else {
        return Ok(slot0.clone());
    };
    let mut fc = booted.fc.clone();
    fc.limits = SlotLimits {
        cpus: u32::from(vcpus),
        memory_mib: u64::from(memory) + VMM_OVERHEAD_MIB,
        ..fc.limits
    };
    let spec = BootSpec {
        vcpus,
        memory_mib: memory,
        ..booted.spec.clone()
    };
    let started = std::time::Instant::now();
    let base = FirecrackerBackend::create_base_snapshot(&fc, &spec, snapshot).await?;
    tracing::info!(
        ms = started.elapsed().as_millis(),
        vcpus,
        memory_mib = memory,
        "warm build snapshot ready"
    );
    Ok(Sandbox {
        backend: Arc::new(FirecrackerBackend::new(fc, booted.cgroups.clone(), base)),
        ..slot0.clone()
    })
}

type SlotTask = JoinHandle<Result<(), StoreError>>;

async fn spawn_slots(
    config: &Config,
    template: &Sandbox,
    policies: &Policies,
    stop: &Stop,
) -> Result<Vec<SlotTask>, ComponentError> {
    let url = config.database.url.expose_secret();
    let lease = Duration::from_secs(config.stages.sandbox.lease_secs);
    let canary_every = Duration::from_secs(config.sandbox.canary_interval_minutes * 60);
    // No slot claims a job before the first canaries ran on these guest
    // files: a new version must pass them first (ADR 0002). A failure
    // pauses the stage, which the workers then honor.
    let ran = Arc::new(watch::channel(canary_every.is_zero()).0);
    let mut tasks = Vec::new();
    for slot in 0..config.sandbox.slots {
        let store = Store::connect(url).await.map_err(fatal)?;
        let heartbeats = Store::connect(url).await.map_err(fatal)?;
        let sandbox = Sandbox {
            slot,
            ..template.clone()
        };
        let worker = SandboxWorker::new(store, heartbeats, sandbox, policies.clone(), lease);
        let canaries = (slot == 0 && !canary_every.is_zero()).then_some(canary_every);
        let (ran, stop) = (Arc::clone(&ran), stop.clone());
        tasks.push(tokio::spawn(async move {
            slot_loop(worker, canaries, ran, stop)
                .await
                .inspect_err(|error| tracing::error!(slot, %error, "job store failed"))
        }));
    }
    Ok(tasks)
}

/// Runs the jobs of one slot until `stop`. The slot with `canaries` also
/// runs them, first and then on their schedule, between jobs. The others
/// wait for the first run.
async fn slot_loop(
    mut worker: SandboxWorker,
    canaries: Option<Duration>,
    ran: Arc<watch::Sender<bool>>,
    stop: Stop,
) -> Result<(), StoreError> {
    if canaries.is_none() {
        tokio::select! {
            () = canaries_ran(&ran) => {}
            () = stop.wait() => {}
        }
    }
    let mut last_canary: Option<tokio::time::Instant> = None;
    while !stop.is_requested() {
        if let Some(every) = canaries
            && last_canary.is_none_or(|at| at.elapsed() >= every)
        {
            worker.run_canaries().await?;
            last_canary = Some(tokio::time::Instant::now());
            ran.send_replace(true);
        }
        if !worker.run_once().await? {
            stop.sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

async fn canaries_ran(ran: &watch::Sender<bool>) {
    let _ = ran.subscribe().wait_for(|ran| *ran).await;
}

/// Takes the lock that allows one orchestrator per slot directory, the
/// directory reconciliation clears. The file is private to the
/// orchestrator's user, since holding the lock needs only read access.
fn lock_instance(slots_dir: &Path) -> Result<std::fs::File, ComponentError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::create_dir_all(slots_dir)
        .map_err(|e| fatal(format!("{}: {e}", slots_dir.display())))?;
    let path = slots_dir.join("orchestrator.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(&path)
        .map_err(|e| fatal(format!("{}: {e}", path.display())))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(fatal(format!(
            "another orchestrator holds {}; stop it first",
            path.display()
        ))),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(fatal(format!("locking {}: {e}", path.display())))
        }
    }
}

/// A snapshot value for the reconciling backend, which never restores.
fn placeholder_snapshot() -> firecracker::vm::Snapshot {
    firecracker::vm::Snapshot {
        state: PathBuf::new(),
        memory: PathBuf::new(),
        rootfs: PathBuf::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_instance_is_refused_until_the_first_ends() {
        let dir = std::env::temp_dir().join(format!(
            "cw-lock-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        use std::os::unix::fs::PermissionsExt as _;
        let first = lock_instance(&dir).unwrap();
        let mode = first.metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let second = lock_instance(&dir).unwrap_err().to_string();
        assert!(second.contains("another orchestrator"), "{second}");
        drop(first);
        drop(lock_instance(&dir).unwrap());
        // A planted link is not followed.
        let lock = dir.join("orchestrator.lock");
        std::fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), &lock).unwrap();
        assert!(lock_instance(&dir).is_err());
        assert!(!dir.join("elsewhere").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
