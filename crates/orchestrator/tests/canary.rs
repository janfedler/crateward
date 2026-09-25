//! Canaries: the known bad fixture crate must be caught, the known good
//! one must come out clean (`crateward_orchestrator::canary`).
//!
//! Their sources exist only as strings in the orchestrator: they are packed
//! into a tar, vendored into a payload image and compiled and run **only
//! inside a microVM**, never on the host (the rule in docs/TESTING.md).
//!
//! Needs `/dev/kvm`, the guest images, subordinate IDs and a delegated
//! cgroup, so it runs on the server through `cargo xtask canary`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use crateward_core::blobs::BlobStore;
use crateward_orchestrator::backend::{FirecrackerBackend, FirecrackerConfig};
use crateward_orchestrator::canary;
use crateward_orchestrator::cgroup::{CgroupTree, SlotLimits};
use crateward_orchestrator::firecracker::vm::{BootSpec, JobDrives};
use crateward_orchestrator::honeytokens::Honeytokens;
use crateward_orchestrator::worker::{JobFiles, RunPlan, WorkerSetup, execute};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap()
}

#[tokio::test]
#[ignore = "run through `cargo xtask canary`"]
async fn canaries_give_their_known_results() {
    let work = root()
        .join("target/canary")
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
    let fake_internet =
        root().join("target/x86_64-unknown-linux-musl/release/crateward_fake_internet");
    assert!(
        fake_internet.exists(),
        "build crateward_fake_internet for musl first"
    );
    let config = FirecrackerConfig {
        firecracker: root().join("target/guest/bin/firecracker"),
        launcher: PathBuf::from(env!("CARGO_BIN_EXE_crateward-vmjail")),
        slots_dir,
        slots: 1,
        uid_base: 160_020,
        gid_base: 160_020,
        limits: SlotLimits {
            cpus: 1,
            memory_mib: 2048 + 256,
            pids: 64,
        },
        max_file_size: 3 << 30,
        fake_internet: Some(fake_internet),
        authority: Some(root().join("target/guest/ca/authority.pem")),
    };
    for placeholder in [
        "placeholder-payload.img",
        "placeholder-scratch.img",
        "placeholder-warm.img",
    ] {
        std::fs::File::create(work.join(placeholder)).unwrap();
    }
    let boot = BootSpec {
        kernel,
        rootfs: out.join("rootfs.erofs"),
        boot_args: format!(
            "{} {}",
            BootSpec::default_boot_args("/usr/sbin/crateward-agent"),
            BootSpec::network_boot_args()
        ),
        vcpus: 1,
        memory_mib: 2048,
        drives: Some(JobDrives {
            payload: work.join("placeholder-payload.img"),
            scratch: work.join("placeholder-scratch.img"),
            warm: work.join("placeholder-warm.img"),
        }),
        network: true,
    };
    let snapshot = FirecrackerBackend::create_base_snapshot(&config, &boot, &work.join("snapshot"))
        .await
        .unwrap();
    let cgroups =
        CgroupTree::own().expect("run through `cargo xtask canary` for a delegated cgroup");
    let backend = FirecrackerBackend::new(config, cgroups, snapshot);

    let blobs = BlobStore::open(&work.join("cas")).unwrap();
    let setup = WorkerSetup {
        exe: PathBuf::from(env!("CARGO_BIN_EXE_crateward_orchestrator")),
        work_dir: work.clone(),
        scratch_mib: 2048,
        check_timeout: Duration::from_secs(300),
        warm: None,
        warm_placeholder: work.join("placeholder-warm.img"),
    };
    for canary in canary::ALL {
        let files = JobFiles {
            payload: work.join("job.payload"),
            scratch: work.join("job.scratch"),
            network: work.join("job.network"),
            warm: None,
            warm_placeholder: work.join("placeholder-warm.img"),
        };
        let spec = canary.payload(&blobs).unwrap();
        let tokens = Honeytokens::generate(&mut rand::rng(), 1000);
        let plan = RunPlan::check(Duration::from_secs(300));
        let report = execute(&backend, 0, &setup, &blobs, 1, spec, &tokens, &files, &plan)
            .await
            .unwrap();
        let problems = canary.check(&report);
        assert!(
            problems.is_empty(),
            "{}: {problems:?}\n{}",
            canary.name,
            serde_json::to_string_pretty(&report).unwrap()
        );
        eprintln!("{} passed in {} ms", canary.name, report.run_ms);
    }
    std::fs::remove_dir_all(&work).unwrap();
}
