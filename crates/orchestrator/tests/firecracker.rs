//! Tests against real Firecracker microVMs.
//!
//! They need `/dev/kvm`, the pinned Firecracker binary, the guest images, and
//! subordinate IDs for the jail tests, so they are ignored by default and
//! never run in CI. On the server:
//!
//! ```sh
//! cargo xtask firecracker && cargo xtask guest-kernel && cargo xtask rootfs
//! cargo test -p crateward_orchestrator --test firecracker -- --ignored --test-threads 1
//! ```
//!
//! Only our own guest agent and standard programs of the guest image run
//! here. No crate under analysis is involved.

// Test helpers outside `#[test]` functions are still test code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crateward_core::protocol::{ExitStatus, JobSpec, WallClock};
use crateward_orchestrator::firecracker::vm::{BootSpec, Isolation, JailConfig, Launch, Vm};
use tokio::time::Instant;

/// Subordinate IDs used by the jail tests. Inside the `claude` user's
/// range (`/etc/subuid`), away from its start where image builds map root.
const TEST_SUBID_BASE: u32 = 160_000;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap()
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
        drives: None,
        network: false,
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = root()
        .join("target/vm-tests")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A launch in the given mode. `slot` picks the subordinate ID.
fn launch(name: &str, jailed: bool, slot: u32) -> Launch {
    let isolation = if jailed {
        Isolation::Jail(JailConfig {
            launcher: PathBuf::from(env!("CARGO_BIN_EXE_crateward-vmjail")),
            vm_uid: TEST_SUBID_BASE + slot,
            vm_gid: TEST_SUBID_BASE + slot,
            tap: Some("tap0".into()),
            sinks: None,
            cgroup: None,
            max_file_size: 1 << 30,
        })
    } else {
        Isolation::Direct
    };
    Launch {
        firecracker: root().join("target/guest/bin/firecracker"),
        dir: scratch(name),
        id: name.into(),
        isolation,
    }
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

/// A field of `/proc/<pid>/status`, readable for any process on the host.
fn status_field(pid: u32, field: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

async fn boot_run_shutdown(jailed: bool) {
    let launch = launch(if jailed { "boot-jail" } else { "boot-direct" }, jailed, 0);
    let started = Instant::now();
    let mut vm = Vm::boot(&launch, &boot_spec()).await.unwrap();
    let mut agent = vm
        .agent(Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    let boot_time = started.elapsed();

    if jailed {
        let pid = vm.pid().unwrap();
        let uid = TEST_SUBID_BASE.to_string();
        assert_eq!(status_field(pid, "Uid"), format!("{uid} {uid} {uid} {uid}"));
        assert_eq!(status_field(pid, "CapEff"), "0000000000000000");
        assert_eq!(status_field(pid, "CapPrm"), "0000000000000000");
        assert_eq!(status_field(pid, "NoNewPrivs"), "1");
        // 2 means a seccomp filter is installed (Firecracker's own).
        assert_eq!(status_field(pid, "Seccomp"), "2");
        // The tap device lives only in the jail's network namespace.
        let host_links = std::process::Command::new("/usr/sbin/ip")
            .args(["-br", "link"])
            .output()
            .unwrap();
        assert!(!String::from_utf8_lossy(&host_links.stdout).contains("tap0"));
    }

    let outcome = agent.run(job(&["/usr/bin/id"])).await.unwrap();
    let id = String::from_utf8_lossy(&outcome.stdout);
    assert_eq!(outcome.exit, ExitStatus::Code(0));
    assert!(id.contains("uid=1000(builder)"), "{id}");
    assert!(!id.contains("groups=0"), "job kept root's groups: {id}");

    // Snapshot uniqueness relies on the VM generation ID driver reseeding the
    // guest RNG on restore. A device must be bound to it.
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
    let dir = vm.dir().to_path_buf();
    vm.destroy().await.unwrap();
    assert!(!dir.exists(), "VM directory left behind");
    eprintln!("jailed={jailed}: boot to agent ready: {boot_time:?}");
}

async fn snapshot_and_restore_twice(jailed: bool) {
    let mode = if jailed { "jail" } else { "direct" };
    let base = launch(&format!("snap-base-{mode}"), jailed, 0);
    let snap_dir = scratch(&format!("snap-files-{mode}"));
    let spec = boot_spec();
    let vm = Vm::boot(&base, &spec).await.unwrap();
    let mut agent = vm
        .agent(Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    agent.ping().await.unwrap();
    drop(agent);
    let snapshot = vm.snapshot(&base, &spec.rootfs, &snap_dir).await.unwrap();
    vm.destroy().await.unwrap();

    let mut uuids = Vec::new();
    for round in 0..2 {
        // Each restore runs in its own slot, with its own subordinate UID.
        let launch = launch(&format!("restore-{mode}-{round}"), jailed, round + 1);
        let started = Instant::now();
        let vm = Vm::restore(&launch, &snapshot, None).await.unwrap();
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
        uuids.push(outcome.stdout);
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
        eprintln!("jailed={jailed}: restore {round} to agent ready: {restore_time:?}");
    }
    assert_ne!(
        uuids[0], uuids[1],
        "restored VMs produced the same random UUID"
    );
    std::fs::remove_dir_all(&snap_dir).unwrap();
}

#[tokio::test]
#[ignore = "needs /dev/kvm and the guest images"]
async fn direct_boots_runs_a_job_and_shuts_down() {
    boot_run_shutdown(false).await;
}

#[tokio::test]
#[ignore = "needs /dev/kvm and the guest images"]
async fn direct_restores_the_same_snapshot_twice_with_fresh_state() {
    snapshot_and_restore_twice(false).await;
}

#[tokio::test]
#[ignore = "needs /dev/kvm, the guest images and subordinate IDs"]
async fn jailed_boots_runs_a_job_and_shuts_down() {
    boot_run_shutdown(true).await;
}

#[tokio::test]
#[ignore = "needs /dev/kvm, the guest images and subordinate IDs"]
async fn jailed_restores_the_same_snapshot_twice_with_fresh_state() {
    snapshot_and_restore_twice(true).await;
}

/// The host runs a kernel outside Firecracker's validated matrix (ADR 0003),
/// and Firecracker 1.17 fixed a host kernel specific bug that hid eIBRS from
/// guests. A guest must never report a CPU vulnerability as unmitigated
/// where the host reports a mitigation.
#[tokio::test]
#[ignore = "needs /dev/kvm and the guest images"]
async fn guest_cpu_mitigations_are_not_weaker_than_the_host() {
    let dir = "/sys/devices/system/cpu/vulnerabilities";
    let launch = launch("mitigations", true, 5);
    let vm = Vm::boot(&launch, &boot_spec()).await.unwrap();
    let mut agent = vm
        .agent(Instant::now() + Duration::from_secs(20))
        .await
        .unwrap();
    let outcome = agent
        .run(job(&["/bin/sh", "-c", &format!("cd {dir} && grep . *")]))
        .await
        .unwrap();
    drop(agent);
    vm.destroy().await.unwrap();
    let guest: std::collections::BTreeMap<String, String> =
        String::from_utf8_lossy(&outcome.stdout)
            .lines()
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.to_owned(), v.trim().to_owned()))
            .collect();
    assert!(!guest.is_empty(), "guest reported no vulnerability files");
    let mut weaker = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let host = std::fs::read_to_string(entry.path())
            .unwrap()
            .trim()
            .to_owned();
        let in_guest = guest
            .get(&name)
            .cloned()
            .unwrap_or_else(|| "missing".into());
        eprintln!("{name:28} host: {host:60} guest: {in_guest}");
        if !host.starts_with("Vulnerable") && in_guest.starts_with("Vulnerable") {
            weaker.push(name);
        }
    }
    assert!(
        weaker.is_empty(),
        "guest is weaker than the host for {weaker:?}"
    );
}
