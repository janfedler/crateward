//! Runs jobs in Firecracker microVMs and guarantees their cleanup.
//!
//! Zone: untrusted. This is the only host component that starts code from a
//! crate, and it does so only inside a microVM.
//!
//! Why it looks the way it does:
//!
//! * Firecracker is driven through its API socket and always started in a
//!   rootless jail (ADR 0012): its own subordinate UID, private namespaces,
//!   `pivot_root` into a root with only the needed files, no capabilities.
//!   No process runs as root for the sandbox.
//! * Jobs start by restoring a warm snapshot. Identity, honeytokens and the
//!   clock are injected after restore, because resuming one snapshot many
//!   times would otherwise repeat entropy and identifiers.
//! * Each slot has its own network namespace whose only route leads to the
//!   fake internet, which has no uplink.
//! * Hard limits cover CPU, memory, disk, processes and wall clock time.
//!   Every host resource is named after its slot, so startup reconciliation
//!   can find and remove anything a crash left behind.
//! * Tap capture and disk diffs provide host side ground truth that a
//!   compromised guest cannot hide from.
//! * A `VmBackend` trait separates Firecracker from the scheduling logic,
//!   so CI can use a fake backend and another VMM could be added later.
//!
//! The build cache warmer ships as a second binary of this package in M1.5.

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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crateward_core::app::ComponentError;
use crateward_core::blobs::BlobStore;
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::store::{Policies, Store};
use secrecy::ExposeSecret;

use crate::backend::{FirecrackerBackend, FirecrackerConfig, VmBackend};
use crate::cgroup::{CgroupTree, SlotLimits};
use crate::firecracker::vm::{BootSpec, JobDrives};
use crate::worker::{SandboxWorker, WorkerSetup};

/// The component this package implements.
pub const COMPONENT: Component = Component::Orchestrator;

/// Where the guest agent lives in the root filesystem.
const AGENT_PATH: &str = "/usr/sbin/crateward-agent";

/// Memory for Firecracker itself on top of guest memory.
const VMM_OVERHEAD_MIB: u64 = 256;

fn fatal(reason: impl std::fmt::Display) -> ComponentError {
    ComponentError::Fatal {
        component: COMPONENT,
        reason: reason.to_string(),
    }
}

/// Runs the component until SIGTERM or `Ctrl-C`: reconciles leftovers,
/// boots a clean VM for the base snapshot, then runs one worker per slot.
///
/// # Errors
///
/// Returns [`ComponentError::Fatal`] if startup or the job store fails.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    // Reconciliation removes every slot's leftovers, so a second instance
    // would tear down the first one's jails. The lock is taken before the
    // runtime exists and dropped after it, when no task runs any more.
    let _instance = lock_instance(&config.sandbox.slots_dir)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(fatal)?;
    runtime.block_on(async {
        let sandbox = &config.sandbox;
        // A deploy switches the guest files by moving a link (ADR 0024).
        // Resolving them once keeps a running orchestrator on the files its
        // base snapshot was made from.
        let resolve = |path: &std::path::Path| {
            std::fs::canonicalize(path).map_err(|e| fatal(format!("{}: {e}", path.display())))
        };
        let kernel_image = resolve(&sandbox.kernel_image)?;
        let rootfs_image = resolve(&sandbox.rootfs_image)?;
        let authority = resolve(&sandbox.fake_internet_authority)?;
        let cgroups = CgroupTree::own().map_err(fatal)?;
        let memory_mib = u32::try_from(sandbox.memory_mib_per_slot).map_err(fatal)?;
        let fc = FirecrackerConfig {
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
                << 20,
            fake_internet: Some(sandbox.fake_internet_bin.clone()),
            authority: Some(authority),
        };
        // A jail has no dynamic loader, so everything executed in one must
        // be static.
        let fake_internet = std::fs::read(&sandbox.fake_internet_bin)
            .map_err(|e| fatal(format!("{}: {e}", sandbox.fake_internet_bin.display())))?;
        if !crateward_core::elf::is_static(&fake_internet).map_err(fatal)? {
            return Err(fatal(format!(
                "{} is dynamically linked; build it for x86_64-unknown-linux-musl",
                sandbox.fake_internet_bin.display()
            )));
        }
        drop(fake_internet);
        std::fs::create_dir_all(&fc.slots_dir).map_err(fatal)?;
        // The jail decoys rely on reads updating the access time (ADR 0023).
        if !jail::decoy::atime_works(&fc.slots_dir).map_err(fatal)? {
            return Err(fatal(format!(
                "reads do not update access times below {}; mount it with relatime or strictatime",
                fc.slots_dir.display()
            )));
        }
        let work = config.instance.run_dir.join("orchestrator");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).map_err(fatal)?;
        let placeholders = JobDrives {
            payload: work.join("placeholder-payload.img"),
            scratch: work.join("placeholder-scratch.img"),
            warm: work.join("placeholder-warm.img"),
        };
        for file in [
            &placeholders.payload,
            &placeholders.scratch,
            &placeholders.warm,
        ] {
            std::fs::File::create(file).map_err(fatal)?;
        }
        let boot = BootSpec {
            kernel: kernel_image,
            rootfs: rootfs_image,
            boot_args: format!(
                "{} {}",
                BootSpec::default_boot_args(AGENT_PATH),
                BootSpec::network_boot_args()
            ),
            vcpus: u8::try_from(sandbox.vcpus_per_slot).map_err(fatal)?,
            memory_mib,
            drives: Some(placeholders),
            network: true,
        };
        let backend0 = FirecrackerBackend::new(fc.clone(), cgroups.clone(), placeholder_snapshot());
        let reconciled = backend0.reconcile().await.map_err(fatal)?;
        if !reconciled.cgroups.is_empty() || !reconciled.directories.is_empty() {
            tracing::warn!(?reconciled, "removed leftovers of an earlier run");
        }
        let started = std::time::Instant::now();
        let snapshot = FirecrackerBackend::create_base_snapshot(&fc, &boot, &work.join("snapshot"))
            .await
            .map_err(fatal)?;
        tracing::info!(ms = started.elapsed().as_millis(), "base snapshot ready");
        let backend = Arc::new(FirecrackerBackend::new(fc, cgroups, snapshot));

        let url = config.database.url.expose_secret();
        let mut store = Store::connect(url).await.map_err(fatal)?;
        store.migrate().await.map_err(fatal)?;
        let blobs = BlobStore::open(&config.instance.data_dir.join("cas")).map_err(fatal)?;
        let policies = Policies::from_config(&config.stages).map_err(fatal)?;
        // Installed before the warm build, so a stop request during it ends
        // its VM through reconciliation instead of leaving it behind.
        let stop = Arc::new(AtomicBool::new(false));
        let (stopped_tx, stopped) = tokio::sync::watch::channel(false);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(fatal)?;
        let flag = Arc::clone(&stop);
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            flag.store(true, Ordering::SeqCst);
            let _ = stopped_tx.send(true);
        });
        let mut setup = WorkerSetup {
            exe: std::env::current_exe().map_err(fatal)?,
            work_dir: work.clone(),
            scratch_mib: sandbox.scratch_mib_per_slot,
            check_timeout: Duration::from_secs(sandbox.check_timeout_secs),
            full_timeout: Duration::from_secs(sandbox.full_timeout_secs),
            warm: None,
            warm_placeholder: work.join("placeholder-warm.img"),
        };
        // The warm build cache (ADR 0008). Any failure means cold builds,
        // never a failed start.
        if let Some(warm_config) = &sandbox.warm {
            match warm::plan_from_store(&store, warm_config).await {
                Ok(plan) if plan.probes.is_empty() => {
                    tracing::info!("nothing qualifies for the warm build cache");
                }
                Ok(plan) => {
                    tracing::info!(
                        probes = plan.probes.len(),
                        units = plan.units,
                        packages = plan.packages.len(),
                        replayed = %plan.stubs.join(" "),
                        "building the warm build cache"
                    );
                    let mut stopping = stopped.clone();
                    let built = tokio::select! {
                        built = warm::build(&backend, 0, &setup, &blobs, warm_config, &plan) => built,
                        _ = stopping.wait_for(|s| *s) => {
                            let reconciled = backend.reconcile().await.map_err(fatal)?;
                            tracing::info!(?reconciled, "stopped during the warm build");
                            return Ok(());
                        }
                    };
                    match built {
                        Ok(image) => {
                            tracing::info!(image = ?image, "warm build cache ready");
                            setup.warm = image;
                        }
                        Err(error) => tracing::warn!(%error, "no warm build cache"),
                    }
                }
                Err(error) => tracing::warn!(%error, "cannot plan the warm build cache"),
            }
        }
        let lease = Duration::from_secs(config.stages.sandbox.lease_secs);


        let canary_interval = Duration::from_secs(sandbox.canary_interval_minutes * 60);
        // No slot claims a job before the first canaries ran on these guest
        // files: a new version must pass them first (ADR 0024). A failure
        // pauses the stage, which the workers then honor.
        let (canaries_ran, canaries_ran_rx) =
            tokio::sync::watch::channel(canary_interval.is_zero());
        let canaries_ran = Arc::new(canaries_ran);
        let mut tasks = Vec::new();
        for slot in 0..sandbox.slots {
            let store = Store::connect(url).await.map_err(fatal)?;
            let heartbeats = Store::connect(url).await.map_err(fatal)?;
            let mut worker = SandboxWorker::new(
                store,
                heartbeats,
                blobs.clone(),
                Arc::clone(&backend),
                slot,
                setup.clone(),
                policies.clone(),
                lease,
            );
            let stop = Arc::clone(&stop);
            let canaries_ran = Arc::clone(&canaries_ran);
            let mut canaries_ran_rx = canaries_ran_rx.clone();
            tasks.push(tokio::spawn(async move {
                let mut last_reap = tokio::time::Instant::now();
                if slot != 0 {
                    while !*canaries_ran_rx.borrow() && !stop.load(Ordering::SeqCst) {
                        // Wakes on the signal, or every second to see a stop.
                        let _ = tokio::time::timeout(
                            Duration::from_secs(1),
                            canaries_ran_rx.changed(),
                        )
                        .await;
                    }
                }
                // Canaries run first, right after the warm build, then on
                // their schedule, all in slot 0 between jobs.
                let mut last_canary: Option<tokio::time::Instant> = None;
                while !stop.load(Ordering::SeqCst) {
                    let due = last_canary.is_none_or(|at| at.elapsed() >= canary_interval);
                    if slot == 0 && !canary_interval.is_zero() && due {
                        if let Err(error) = worker.run_canaries().await {
                            tracing::error!(slot, %error, "job store failed");
                            return Err(error);
                        }
                        last_canary = Some(tokio::time::Instant::now());
                        canaries_ran.send_replace(true);
                    }
                    if slot == 0 && last_reap.elapsed() >= Duration::from_secs(60) {
                        let policies = worker.policies.clone();
                        match worker.store().reap_expired(&policies).await {
                            Ok(0) => {}
                            Ok(reaped) => tracing::warn!(reaped, "reaped expired leases"),
                            Err(error) => tracing::warn!(%error, "reaping failed"),
                        }
                        last_reap = tokio::time::Instant::now();
                    }
                    match worker.run_once().await {
                        Ok(true) => {}
                        Ok(false) => tokio::time::sleep(Duration::from_secs(1)).await,
                        Err(error) => {
                            tracing::error!(slot, %error, "job store failed");
                            return Err(error);
                        }
                    }
                }
                Ok(())
            }));
        }
        drop(store);
        for task in tasks {
            task.await.map_err(fatal)?.map_err(fatal)?;
        }
        tracing::info!("stopping");
        Ok(())
    })
}

/// Takes the lock that allows one orchestrator per slot directory, the
/// directory reconciliation clears. The file is private to the
/// orchestrator's user, since holding the lock needs only read access.
fn lock_instance(slots_dir: &std::path::Path) -> Result<std::fs::File, ComponentError> {
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
        state: std::path::PathBuf::new(),
        memory: std::path::PathBuf::new(),
        rootfs: std::path::PathBuf::new(),
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
