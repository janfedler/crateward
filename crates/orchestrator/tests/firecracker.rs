//! Tests against real Firecracker microVMs.
//!
//! They need `/dev/kvm`, the pinned Firecracker binary and the guest images,
//! so they are ignored by default and never run in CI. On the server:
//!
//! ```sh
//! cargo xtask firecracker && cargo xtask guest-kernel && cargo xtask rootfs
//! cargo test -p crateward_orchestrator --test firecracker -- --ignored --test-threads 1
//! ```
//!
//! Only our own guest agent and standard programs of the guest image run
//! here; no crate under analysis is involved.

// Test helpers outside `#[test]` functions are still test code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crateward_core::protocol::{ExitStatus, JobSpec, WallClock};
use crateward_orchestrator::firecracker::vm::{BootSpec, Vm};
use tokio::time::Instant;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap()
}

fn firecracker() -> PathBuf {
    root().join("target/guest/bin/firecracker")
}

fn boot_spec() -> BootSpec {
    let out = root().join("target/guest/out");
    let kernel = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "bzImage"))
        .expect("run `cargo xtask guest-kernel` first");
    BootSpec {
        kernel,
        rootfs: out.join("rootfs.erofs"),
        boot_args: BootSpec::default_boot_args("/usr/sbin/crateward-agent"),
        vcpus: 1,
        memory_mib: 512,
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = root()
        .join("target/vm-tests")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn now() -> WallClock {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    WallClock {
        secs: since.as_secs(),
        nanos: since.subsec_nanos(),
    }
}

fn job(argv: &[&str]) -> JobSpec {
    JobSpec {
        job_id: 1,
        wall_clock: now(),
        argv: argv.iter().map(ToString::to_string).collect(),
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        cwd: "/tmp".into(),
        timeout_secs: 30,
        output_limit: 64 * 1024,
    }
}

#[tokio::test]
#[ignore = "needs /dev/kvm and the guest images"]
async fn boots_runs_a_job_and_shuts_down() {
    let dir = scratch("boot");
    let started = Instant::now();
    let mut vm = Vm::boot(&firecracker(), &dir, "boot-test", &boot_spec())
        .await
        .unwrap();
    let mut agent = vm
        .agent(Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    let boot_time = started.elapsed();

    let outcome = agent.run(job(&["/usr/bin/id"])).await.unwrap();
    let id = String::from_utf8_lossy(&outcome.stdout);
    assert_eq!(outcome.exit, ExitStatus::Code(0));
    assert!(id.contains("uid=1000(builder)"), "{id}");
    assert!(!id.contains("groups=0"), "job kept root's groups: {id}");

    // Snapshot uniqueness relies on the VM generation ID driver reseeding
    // the guest RNG on restore (Firecracker snapshot-support.md).
    // A device must be bound to the vmgenid platform driver, not merely
    // the driver be present.
    let outcome = agent
        .run(job(&[
            "/bin/sh",
            "-c",
            "ls /sys/bus/platform/drivers/vmgenid",
        ]))
        .await
        .unwrap();
    let entries = String::from_utf8_lossy(&outcome.stdout);
    let bound = entries
        .lines()
        .filter(|e| !matches!(*e, "bind" | "unbind" | "uevent" | "module"))
        .count();
    assert!(bound >= 1, "no device bound to vmgenid: {entries:?}");

    let outcome = agent
        .run(job(&["/bin/sh", "-c", "echo out; echo err >&2; exit 7"]))
        .await
        .unwrap();
    assert_eq!(outcome.exit, ExitStatus::Code(7));
    assert_eq!(outcome.stdout, b"out\n");
    assert_eq!(outcome.stderr, b"err\n");

    agent.shutdown().await.unwrap();
    let status = vm.wait_exit(Duration::from_secs(10)).await.unwrap();
    assert!(
        status.is_some(),
        "firecracker did not exit after the guest shut down"
    );
    vm.destroy().await.unwrap();
    eprintln!("boot to agent ready: {boot_time:?}");
}

#[tokio::test]
#[ignore = "needs /dev/kvm and the guest images"]
async fn restores_the_same_snapshot_twice_with_fresh_state() {
    let base_dir = scratch("snap-base");
    let snap_dir = scratch("snap-files");
    let vm = Vm::boot(&firecracker(), &base_dir, "snap-base", &boot_spec())
        .await
        .unwrap();
    let mut agent = vm
        .agent(Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    agent.ping().await.unwrap();
    drop(agent);
    let snapshot = vm.snapshot(&snap_dir).await.unwrap();
    vm.destroy().await.unwrap();

    let mut boot_ids = Vec::new();
    for round in 0..2 {
        let dir = scratch(&format!("restore-{round}"));
        let started = Instant::now();
        let vm = Vm::restore(&firecracker(), &dir, &format!("restore-{round}"), &snapshot)
            .await
            .unwrap();
        let mut agent = vm
            .agent(Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        let restore_time = started.elapsed();
        // A file written by one restored VM must not exist in the next one.
        let outcome = agent
            .run(job(&[
                "/bin/sh",
                "-c",
                "test ! -e /tmp/marker && touch /tmp/marker && cat /proc/sys/kernel/random/uuid",
            ]))
            .await
            .unwrap();
        assert_eq!(
            outcome.exit,
            ExitStatus::Code(0),
            "{}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        boot_ids.push(outcome.stdout);
        // The guest clock follows the host, not the snapshot.
        let outcome = agent.run(job(&["/bin/date", "+%s"])).await.unwrap();
        let guest: u64 = String::from_utf8_lossy(&outcome.stdout)
            .trim()
            .parse()
            .unwrap();
        assert!(
            now().secs.abs_diff(guest) <= 5,
            "guest clock {guest} is off"
        );
        drop(agent);
        vm.destroy().await.unwrap();
        eprintln!("restore {round} to agent ready: {restore_time:?}");
    }
    assert_ne!(
        boot_ids[0], boot_ids[1],
        "restored VMs produced the same random UUID"
    );
    let _ = std::fs::remove_dir_all(&snap_dir);
}
