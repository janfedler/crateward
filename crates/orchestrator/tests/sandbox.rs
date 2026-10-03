//! The orchestrator's sandboxed children, end to end: the scratch disk
//! scanner, the export of the target directory and the image builder.
//!
//! The scratch images are made from inert files by `mkfs.ext4 -d`, and the
//! payload from a tar of a fixture crate. Nothing is mounted or executed.
//! The children enter their sandbox before they read input, so a passing
//! test also shows that the sandbox can be entered. Hosts without
//! unprivileged user namespaces, or without `mkfs.erofs`, skip the tests
//! that need them, unless `CRATEWARD_REQUIRE_SANDBOX` is set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use crateward_core::blobs::BlobStore;
use crateward_core::child::ChildError;
use crateward_core::name::CrateName;
use crateward_core::sandbox;
use crateward_orchestrator::payload::{Package, PayloadError, PayloadSpec, build_image};
use crateward_orchestrator::scratch::{ScanSpec, ScratchReport, export_to_erofs, scan_in_sandbox};

const ORCHESTRATOR: &str = env!("CARGO_BIN_EXE_crateward-orchestrator");
const MKFS_EXT4: &str = "/usr/sbin/mkfs.ext4";
const MKFS_EROFS: &str = "/usr/bin/mkfs.erofs";

/// A fresh directory for one test.
fn workdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sandbox-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    dir
}

/// Whether the test should skip for lack of `tool`.
fn missing(tool: &str) -> bool {
    let missing = !Path::new(tool).exists();
    let required = std::env::var_os("CRATEWARD_REQUIRE_SANDBOX").is_some();
    if missing && !required {
        eprintln!("skipping: {tool} is not installed");
    }

    missing && !required
}

/// An ext4 image of `files`, as the orchestrator formats scratch disks.
fn image(name: &str, files: &[(&str, &[u8], u32)]) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    if missing(MKFS_EXT4) {
        return None;
    }

    let dir = workdir(name);
    let root = dir.join("root");
    for (path, data, mode) in files {
        let file = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, data).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(*mode)).unwrap();
    }

    let image = dir.join("scratch.img");
    let status = Command::new(MKFS_EXT4)
        .args(["-q", "-F", "-d"])
        .arg(&root)
        .arg(&image)
        .arg("8M")
        .status()
        .unwrap();

    assert!(status.success());

    Some(image)
}

/// Whether the file at `path` is an EROFS image, and holds all of `names`.
fn erofs_with(path: &Path, names: &[&str]) -> bool {
    let bytes = std::fs::read(path).unwrap();
    let magic = 0xE0F5_E1E2_u32.to_le_bytes();
    let contains = |name: &str| bytes.windows(name.len()).any(|w| w == name.as_bytes());

    bytes.get(1024..1028) == Some(&magic[..]) && names.iter().all(|name| contains(name))
}

fn scan(image: &Path, spec: &ScanSpec) -> Option<ScratchReport> {
    match scan_in_sandbox(Path::new(ORCHESTRATOR), image, spec) {
        Ok(report) => Some(report),
        Err(error) if sandbox::unavailable(&error) => None,
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn the_scanner_reports_what_a_job_left_behind() {
    let Some(image) = image(
        "scan",
        &[
            ("/target/debug/x", b"build output", 0o644),
            ("/home/.local/bin/dropper", b"\x7fELF payload", 0o755),
        ],
    ) else {
        return;
    };

    let spec = ScanSpec {
        planted: vec!["/work/home/.cargo/credentials.toml".into()],
        ..ScanSpec::default()
    };

    let Some(report) = scan(&image, &spec) else {
        return;
    };

    assert!(report.error.is_none(), "{report:?}");

    let outside: Vec<&str> = report
        .outside_build
        .iter()
        .map(|e| e.path.as_str())
        .collect();

    assert!(
        outside.contains(&"/work/home/.local/bin/dropper"),
        "{outside:?}"
    );
    assert!(
        !outside.iter().any(|p| p.starts_with("/work/target")),
        "{outside:?}"
    );
    assert_eq!(
        report.planted_changed,
        ["/work/home/.cargo/credentials.toml"]
    );
}

#[test]
fn an_image_that_is_no_ext4_becomes_an_error_in_the_report() {
    let path = workdir("garbage").join("scratch.img");
    std::fs::write(&path, vec![0x5a_u8; 1 << 20]).unwrap();
    let Some(report) = scan(&path, &ScanSpec::default()) else {
        return;
    };

    assert!(report.incomplete, "{report:?}");

    let error = report.error.as_deref().unwrap_or_default();
    assert!(error.starts_with("not a readable ext4 image"), "{report:?}");
}

#[test]
fn a_scanner_that_does_not_exist_is_an_error() {
    let error = scan_in_sandbox(
        Path::new("/nonexistent/orchestrator"),
        Path::new("/dev/null"),
        &ScanSpec::default(),
    )
    .unwrap_err();

    assert!(
        error.to_string().starts_with("scratch scanner: starting: "),
        "{error}"
    );
}

#[test]
fn the_export_and_the_builder_make_an_image_of_the_target_directory() {
    if missing(MKFS_EROFS) {
        return;
    }

    let Some(image) = image(
        "export",
        &[
            ("/target/debug/deps/libx-0123.rmeta", b"metadata", 0o644),
            ("/home/.cargo/credentials.toml", b"secret", 0o600),
        ],
    ) else {
        return;
    };

    let out = image.with_file_name("target.erofs");
    match export_to_erofs(Path::new(ORCHESTRATOR), &image, &out, &[]) {
        Ok(()) => {}
        Err(error) if sandbox::unavailable(&error) => return,
        Err(error) => panic!("{error}"),
    }

    assert!(erofs_with(&out, &["libx-0123.rmeta"]));

    // Only the target directory leaves the scratch disk.
    assert!(!erofs_with(&out, &["credentials.toml"]));
}

#[test]
fn an_export_of_something_that_is_no_image_fails_with_its_reason() {
    let path = workdir("bad-export").join("scratch.img");
    std::fs::write(&path, vec![0x5a_u8; 1 << 20]).unwrap();
    let out = path.with_file_name("target.erofs");
    let error = export_to_erofs(Path::new(ORCHESTRATOR), &path, &out, &[]).unwrap_err();
    if sandbox::unavailable(&error) {
        return;
    }

    assert!(
        matches!(&error, ChildError::Failed { child: "scratch export", stderr, .. }
            if stderr.contains("not a readable ext4 image")),
        "{error}"
    );
}

fn payload(dir: &Path) -> (BlobStore, PayloadSpec) {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(10);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "demo-1.0.0/Cargo.toml", &b"[package]\n"[..])
        .unwrap();
    let blobs = BlobStore::open(&dir.join("cas")).unwrap();
    let blob = blobs.put(&builder.into_inner().unwrap()).unwrap();
    let spec = PayloadSpec {
        name: CrateName::parse("demo").unwrap(),
        version: "1.0.0".parse().unwrap(),
        lockfile: "# lock\n".into(),
        packages: vec![Package {
            name: "demo".into(),
            version: "1.0.0".into(),
            checksum: "ab".repeat(32),
            blake3: blob.blake3,
        }],
        extra_probes: Vec::new(),
        files: Vec::new(),
        stubs: Vec::new(),
    };

    (blobs, spec)
}

#[test]
fn the_payload_image_holds_the_probe_and_the_vendored_crate() {
    if missing(MKFS_EROFS) {
        return;
    }

    let dir = workdir("payload");
    let (blobs, spec) = payload(&dir);
    let out = dir.join("payload.erofs");
    match build_image(Path::new(ORCHESTRATOR), &spec, &blobs, &out) {
        Ok(stats) => assert_eq!(stats.files, 6),
        Err(error) if sandbox::unavailable(&error) => return,
        Err(error) => panic!("{error}"),
    }

    assert!(erofs_with(
        &out,
        &["probe", "vendor", "demo-1.0.0", "Cargo.toml"]
    ));
}

#[test]
fn a_builder_that_fails_is_reported_instead_of_the_broken_pipe() {
    let dir = workdir("failing-builder");
    let (blobs, spec) = payload(&dir);
    let error = build_image(
        Path::new("/bin/false"),
        &spec,
        &blobs,
        &dir.join("payload.erofs"),
    )
    .unwrap_err();

    assert!(
        matches!(&error, PayloadError::Child(ChildError::Failed { status, .. })
            if status.code() == Some(1)),
        "{error}"
    );
}
