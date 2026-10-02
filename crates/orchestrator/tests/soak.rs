//! Soak test: many sequential jailed jobs, then a check for leaks.
//!
//! 50 sequential jobs must run without leaks. It needs `/dev/kvm`, the guest images, subordinate IDs
//! and a delegated cgroup, so it only runs through
//!
//! ```sh
//! cargo xtask soak --jobs 50
//! ```
//!
//! which starts it in a systemd user scope with `Delegate=yes`. It checks,
//! against a baseline taken before the first job:
//!
//! * no Firecracker or launcher process is left;
//! * no slot cgroup and no slot directory is left;
//! * no tap device appeared in the host's network namespace;
//! * the test process holds the same number of file descriptors;
//! * the test process's resident memory grew by less than 16 MiB.
//!
//! It also ends one job through the host side wall clock and checks that
//! reconciliation removes a slot left behind by a simulated crash.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crateward_core::protocol::{ExitStatus, JobSpec, WallClock, Workspace};
use crateward_orchestrator::backend::{
    FirecrackerBackend, FirecrackerConfig, JobEnd, JobInput, VmBackend,
};
use crateward_orchestrator::cgroup::{CgroupTree, SlotLimits};
use crateward_orchestrator::firecracker::vm::{BootSpec, Vm};
use tokio::time::Instant;

const SLOTS: u32 = 3;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap()
}

fn now() -> WallClock {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    WallClock {
        secs: since.as_secs(),
        nanos: since.subsec_nanos(),
    }
}

fn job(script: &str) -> JobInput {
    JobInput {
        spec: JobSpec {
            job_id: 1,
            wall_clock: now(),
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            cwd: "/tmp".into(),
            timeout_secs: 60,
            output_limit: 64 * 1024,
        },
        workspace: Workspace::default(),
        drives: None,
        network_log: None,
        scratch_mib: 0,
    }
}

/// Live (not zombie) processes on the host whose command name is one of
/// `names`. Zombies are ignored: they hold no resources, and after a real
/// crash the orchestrator is gone and init reaps them.
fn processes_named(names: &[&str]) -> Vec<String> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .filter_map(|e| std::fs::read_to_string(e.path().join("status")).ok())
        .filter(|status| {
            !status
                .lines()
                .any(|l| l.starts_with("State:") && l.contains('Z'))
        })
        .filter_map(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("Name:"))
                .map(|n| n.trim().to_owned())
        })
        .filter(|name| names.contains(&name.as_str()))
        .collect()
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse().ok())
        .unwrap()
}

fn host_links() -> String {
    let out = std::process::Command::new("/usr/sbin/ip")
        .args(["-br", "link"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() - 1) * p / 100]
}

#[tokio::test]
#[ignore = "run through `cargo xtask soak`"]
async fn sequential_jobs_leave_nothing_behind() {
    let jobs: usize = std::env::var("CRATEWARD_SOAK_JOBS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let work = root()
        .join("target/soak")
        .join(std::process::id().to_string());
    let _ = std::fs::remove_dir_all(&work);
    let slots_dir = work.join("slots");
    std::fs::create_dir_all(&slots_dir).unwrap();
    let out = root().join("target/guest/out");
    let kernel = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "bzImage"))
        .expect("run `cargo xtask guest-kernel` first");
    let spec = BootSpec {
        kernel,
        rootfs: out.join("rootfs.erofs"),
        boot_args: BootSpec::default_boot_args("/usr/sbin/crateward-agent"),
        vcpus: 1,
        memory_mib: 512,
        drives: None,
        network: false,
    };
    let config = FirecrackerConfig {
        firecracker: root().join("target/guest/bin/firecracker"),
        launcher: PathBuf::from(env!("CARGO_BIN_EXE_crateward-vmjail")),
        slots_dir: slots_dir.clone(),
        slots: SLOTS,
        uid_base: 160_010,
        gid_base: 160_010,
        limits: SlotLimits {
            cpus: 1,
            memory_mib: 512 + 256,
            pids: 64,
        },
        max_file_size: 1 << 30,
        fake_internet: None,
        authority: None,
    };
    let cgroups = CgroupTree::own().expect("run through `cargo xtask soak` for a delegated cgroup");

    // The base snapshot: boot once in a jail, wait for the agent, snapshot.
    let base = FirecrackerBackend::launch(&config, SLOTS, None, None);
    let vm = Vm::boot(&base, &spec).await.unwrap();
    let mut agent = vm
        .agent(Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    agent.ping().await.unwrap();
    drop(agent);
    let snapshot = vm
        .snapshot(&base, &spec.rootfs, &work.join("snapshot"))
        .await
        .unwrap();
    vm.destroy().await.unwrap();

    let mut config_with_base_slot = config.clone();
    config_with_base_slot.slots = SLOTS + 1;
    let backend = FirecrackerBackend::new(config_with_base_slot, cgroups.clone(), snapshot);
    backend.reconcile().await.unwrap();

    // Warm up once so lazily allocated runtime state is in the baseline.
    let warmup = backend
        .run_job(0, job("true"), Duration::from_secs(30))
        .await
        .unwrap();
    assert!(matches!(warmup.end, JobEnd::Finished(_)), "{warmup:?}");
    let fds = open_fds();
    let rss = rss_kib();
    let links = host_links();

    let mut restores = Vec::with_capacity(jobs);
    let mut runs = Vec::with_capacity(jobs);
    let started = Instant::now();
    for i in 0..jobs {
        let slot = u32::try_from(i).unwrap() % SLOTS;
        let run = backend
            .run_job(
                slot,
                job("head -c 8388608 /dev/urandom > /tmp/blob && sha256sum /tmp/blob | cut -c1-8"),
                Duration::from_secs(30),
            )
            .await
            .unwrap();
        match &run.end {
            JobEnd::Finished(outcome) => {
                assert_eq!(outcome.exit, ExitStatus::Code(0), "job {i}: {outcome:?}");
                assert_eq!(outcome.stdout.len(), 9, "job {i}: {outcome:?}");
            }
            other => panic!("job {i} ended with {other:?}"),
        }
        restores.push(run.restore);
        runs.push(run.run);
    }
    let total = started.elapsed();

    // The host side wall clock ends a job that would run for a minute.
    let timed_out = backend
        .run_job(1, job("sleep 60"), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(timed_out.end, JobEnd::HostTimeout);

    // Leak checks.
    assert!(cgroups.slots().unwrap().is_empty(), "slot cgroups left");
    let dirs: Vec<_> = std::fs::read_dir(&slots_dir).unwrap().collect();
    assert!(dirs.is_empty(), "slot directories left: {dirs:?}");
    assert_eq!(host_links(), links, "host network interfaces changed");
    assert_eq!(open_fds(), fds, "file descriptors leaked");
    let grown = rss_kib().saturating_sub(rss);
    assert!(grown < 16 * 1024, "resident memory grew by {grown} KiB");

    // Reconciliation removes a slot a crash left behind: a restored VM whose
    // owner is gone, with its directory and cgroup.
    let crashed_cgroup = cgroups.create_slot("2", config.limits).unwrap();
    let crashed =
        FirecrackerBackend::launch(&config, 2, Some(crashed_cgroup.path().to_path_buf()), None);
    let orphan = Vm::restore(&crashed, &backend_snapshot(&work), None)
        .await
        .unwrap();
    std::mem::forget(orphan);
    std::mem::forget(crashed_cgroup);
    let reconciled = backend.reconcile().await.unwrap();
    assert_eq!(reconciled.cgroups, vec!["slot-2".to_owned()]);
    assert_eq!(reconciled.directories, vec!["slot-2".to_owned()]);

    let left = processes_named(&["firecracker", "crateward-vmjai"]);
    assert!(left.is_empty(), "processes left: {left:?}");

    restores.sort();
    runs.sort();
    eprintln!(
        "soak: {jobs} jobs in {total:?}; restore p50 {:?} p95 {:?} max {:?}; run p50 {:?} p95 {:?}; rss growth {grown} KiB",
        percentile(&restores, 50),
        percentile(&restores, 95),
        restores[restores.len() - 1],
        percentile(&runs, 50),
        percentile(&runs, 95),
    );
    std::fs::remove_dir_all(&work).unwrap();
}

/// The snapshot files written by the base VM.
fn backend_snapshot(work: &Path) -> crateward_orchestrator::firecracker::vm::Snapshot {
    let out = root().join("target/guest/out");
    crateward_orchestrator::firecracker::vm::Snapshot {
        state: work.join("snapshot/vm.state"),
        memory: work.join("snapshot/vm.mem"),
        rootfs: out.join("rootfs.erofs"),
    }
}
