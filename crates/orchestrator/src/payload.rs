//! The job payload: a read only EROFS image with the consumer probe and
//! every locked crate, mounted at `/cw` in the guest.
//!
//! ```text
//! /cw/probe/Cargo.toml          the probe the fetcher resolved (ADR 0014)
//! /cw/probe/Cargo.lock          the lockfile it produced
//! /cw/probe/lib.rs              empty
//! /cw/probe/.cargo/config.toml  crates.io replaced by /cw/vendor, offline
//! /cw/vendor/<name>-<version>/  each locked crate, from the blob store
//! ```
//!
//! The warm build (ADR 0008) adds further probes under `/cw/probes/<n>/`
//! and a script that runs them.
//!
//! Crate archives are never extracted on the host (ADR 0014). The
//! orchestrator writes a new tar from the stored blobs, with its own
//! headers (root owned, fixed modes and times), and streams it into
//! `mkfs.erofs --tar=f`, which runs in a sandboxed child: no network,
//! Landlock limited to the system directories and the output directory.

use std::error::Error;
use std::io::{BufWriter, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use crateward_core::blobs::BlobStore;
use crateward_core::child::{self, Child, ChildError};
use crateward_core::cratesio::probe_manifest;
use crateward_core::name::CrateName;
use crateward_core::sandbox::{self, FsAccess, Limits};

/// Where the payload is mounted in the guest.
pub const MOUNT_POINT: &str = "/cw";
/// The probe directory in the guest, the job's working directory.
pub const PROBE_DIR: &str = "/cw/probe";

/// First argument of the image building child.
pub const MKFS: &str = "sandbox-mkfs";

/// The image building child in error messages.
const NAME: &str = "image builder";

/// `mkfs.erofs` from Debian's `erofs-utils`.
const MKFS_EROFS: &str = "/usr/bin/mkfs.erofs";

/// What the image builder may use.
const LIMITS: Limits = Limits {
    address_space: 4 << 30,
    cpu_seconds: 600,
    // No file size limit: erofs-utils 1.8.6 writes past 1 TiB (sparse) while
    // it builds even a one file image, measured on 2026-09-25. The image is
    // bounded by the tar this process's parent writes, and by the tmpfs it
    // lands on.
    file_size: u64::MAX,
    open_files: 64,
};

/// Largest unpacked tar read from the blob store per crate.
const MAX_BLOB_BYTES: u64 = 1024 * 1024 * 1024;

const CARGO_CONFIG: &str = "[source.crates-io]\n\
replace-with = \"vendored\"\n\n\
[source.vendored]\n\
directory = \"/cw/vendor\"\n\n\
[net]\n\
offline = true\n";

/// Why a payload could not be built. All of these are infrastructure
/// failures.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// Reading a blob or writing the tar failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A blob does not hold the crate it should.
    #[error("blob of {0} does not match its crate")]
    Mismatch(String),
    /// The image builder failed.
    #[error(transparent)]
    Child(#[from] ChildError),
}

fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> PayloadError {
    let context = context.into();
    move |source| PayloadError::Io { context, source }
}

/// One locked crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Name as published.
    pub name: String,
    /// Version.
    pub version: String,
    /// SHA-256 of the `.crate` file, hex, as in the lockfile.
    pub checksum: String,
    /// BLAKE3 naming the stored blob.
    pub blake3: String,
}

/// What goes into a payload.
#[derive(Debug, Clone)]
pub struct PayloadSpec {
    /// The crate under analysis.
    pub name: CrateName,
    /// Its version.
    pub version: semver::Version,
    /// The lockfile from the fetch stage.
    pub lockfile: String,
    /// Every locked crate, the target included.
    pub packages: Vec<Package>,
    /// Further probes, written to `probes/<n>/` (the warm build).
    pub extra_probes: Vec<ProbeSpec>,
    /// Further files at the payload's root, with their contents.
    pub files: Vec<(String, Vec<u8>)>,
    /// Packages (`<name>-<version>`) written as stubs: their manifest with
    /// the build script, binaries and other targets removed, and an empty
    /// library. The warm build (ADR 0008) replays a job's dependency build
    /// this way without compiling the crate under analysis.
    pub stubs: Vec<String>,
}

/// A consumer probe: a crate version and the lockfile resolved for it.
#[derive(Debug, Clone)]
pub struct ProbeSpec {
    /// The crate.
    pub name: CrateName,
    /// Its version.
    pub version: semver::Version,
    /// The lockfile from the fetch stage.
    pub lockfile: String,
}

/// Size of a written payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PayloadStats {
    /// Files written.
    pub files: u64,
    /// Bytes of file contents.
    pub bytes: u64,
}

fn header(size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    header
}

fn append<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    mode: u32,
    data: &[u8],
    stats: &mut PayloadStats,
) -> Result<(), PayloadError> {
    builder
        .append_data(&mut header(data.len() as u64, mode), path, data)
        .map_err(io(format!("writing {path}")))?;
    stats.files += 1;
    stats.bytes += data.len() as u64;
    Ok(())
}

/// A published manifest reduced to its dependencies and features: no build
/// script, no `links`, one empty library (keeping its crate type), no other
/// targets. Cargo then resolves dependencies and features exactly as for
/// the real crate, and compiles nothing of it.
///
/// # Errors
///
/// Fails if the manifest is not valid TOML.
pub fn stub_manifest(original: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(original).map_err(|e| e.to_string())?;
    let mut manifest: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
    if let Some(package) = manifest
        .get_mut("package")
        .and_then(toml::Value::as_table_mut)
    {
        for key in ["build", "links", "autolib", "default-run"] {
            package.remove(key);
        }
        for key in ["autobins", "autoexamples", "autotests", "autobenches"] {
            package.insert(key.into(), toml::Value::Boolean(false));
        }
    }
    for key in ["bin", "example", "test", "bench"] {
        manifest.remove(key);
    }
    let mut lib = toml::Table::new();
    if let Some(original) = manifest.get("lib").and_then(toml::Value::as_table) {
        for key in ["name", "crate-type", "proc-macro"] {
            if let Some(value) = original.get(key) {
                lib.insert(key.into(), value.clone());
            }
        }
    }
    lib.insert("path".into(), toml::Value::String("src/lib.rs".into()));
    manifest.insert("lib".into(), toml::Value::Table(lib));
    toml::to_string(&manifest).map_err(|e| e.to_string())
}

/// Writes the payload as a tar stream.
///
/// # Errors
///
/// Fails if a blob is missing, corrupt or does not match its crate, or if
/// writing fails.
pub fn write_tar<W: Write>(
    spec: &PayloadSpec,
    blobs: &BlobStore,
    out: W,
) -> Result<PayloadStats, PayloadError> {
    let mut builder = tar::Builder::new(out);
    let mut stats = PayloadStats::default();
    let first = ProbeSpec {
        name: spec.name.clone(),
        version: spec.version.clone(),
        lockfile: spec.lockfile.clone(),
    };
    let probes = std::iter::once(("probe".to_owned(), &first)).chain(
        spec.extra_probes
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("probes/{i}"), p)),
    );
    for (dir, probe) in probes {
        let manifest = probe_manifest(&probe.name, &probe.version);
        for (file, data) in [
            ("Cargo.toml", manifest.as_bytes()),
            ("Cargo.lock", probe.lockfile.as_bytes()),
            ("lib.rs", b"".as_slice()),
            (".cargo/config.toml", CARGO_CONFIG.as_bytes()),
        ] {
            append(
                &mut builder,
                &format!("{dir}/{file}"),
                0o644,
                data,
                &mut stats,
            )?;
        }
    }
    for (path, data) in &spec.files {
        append(&mut builder, path, 0o644, data, &mut stats)?;
    }
    for package in &spec.packages {
        let dir = format!("{}-{}", package.name, package.version);
        let stub = spec.stubs.contains(&dir);
        let tar = blobs
            .get(&package.blake3, MAX_BLOB_BYTES)
            .map_err(|e| PayloadError::Io {
                context: format!("reading the blob of {dir}"),
                source: std::io::Error::other(e),
            })?;
        let mut archive = tar::Archive::new(tar.as_slice());
        for entry in archive.entries().map_err(io(format!("reading {dir}")))? {
            let mut entry = entry.map_err(io(format!("reading {dir}")))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(io(format!("reading {dir}")))?
                .to_string_lossy()
                .into_owned();
            let Some(rest) = path
                .strip_prefix(dir.as_str())
                .and_then(|r| r.strip_prefix('/'))
            else {
                return Err(PayloadError::Mismatch(dir));
            };
            // Cargo trusts this file for vendored sources; only ours counts.
            if rest == ".cargo-checksum.json" || (stub && rest != "Cargo.toml") {
                continue;
            }
            let executable = entry.header().mode().is_ok_and(|m| m & 0o111 != 0);
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(io(format!("reading {path}")))?;
            let mode = if executable { 0o755 } else { 0o644 };
            if stub {
                let manifest = stub_manifest(&data)
                    .map_err(|e| PayloadError::Mismatch(format!("{dir}: {e}")))?;
                append(
                    &mut builder,
                    &format!("vendor/{path}"),
                    0o644,
                    manifest.as_bytes(),
                    &mut stats,
                )?;
                append(
                    &mut builder,
                    &format!("vendor/{dir}/src/lib.rs"),
                    0o644,
                    b"",
                    &mut stats,
                )?;
                continue;
            }
            append(
                &mut builder,
                &format!("vendor/{path}"),
                mode,
                &data,
                &mut stats,
            )?;
        }
        // Directory sources need a checksum file; `package` must match the
        // lockfile. File hashes are left out: the payload is read only.
        let checksum = format!("{{\"files\":{{}},\"package\":\"{}\"}}", package.checksum);
        append(
            &mut builder,
            &format!("vendor/{dir}/.cargo-checksum.json"),
            0o644,
            checksum.as_bytes(),
            &mut stats,
        )?;
    }
    builder
        .into_inner()
        .and_then(|mut w| w.flush())
        .map_err(io("finishing the tar"))?;
    Ok(stats)
}

/// Starts the image building child, which reads a tar from `stdin` and
/// writes the image at `out`. `exe` is the orchestrator binary.
///
/// # Errors
///
/// Fails if the child cannot start.
pub fn spawn_mkfs(exe: &Path, out: &Path, stdin: impl Into<Stdio>) -> Result<Child, ChildError> {
    let mut command = child::command(exe);
    command
        .arg(MKFS)
        .arg(out)
        .stdin(stdin)
        .stdout(Stdio::null());
    Child::spawn(NAME, command)
}

/// Builds the payload image at `out` through the sandboxed child. `exe`
/// is the orchestrator binary.
///
/// # Errors
///
/// Fails if the tar cannot be written or `mkfs.erofs` fails.
pub fn build_image(
    exe: &Path,
    spec: &PayloadSpec,
    blobs: &BlobStore,
    out: &Path,
) -> Result<PayloadStats, PayloadError> {
    let mut child = spawn_mkfs(exe, out, Stdio::piped())?;
    let written = write_tar(spec, blobs, BufWriter::new(child.stdin()?));
    // A child that dies breaks the pipe. Its own failure says why, so it
    // wins over the write error.
    child.finish(None)?;
    written
}

/// Runs the image building child if `args` names it.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    (args.get(1).map(String::as_str) == Some(MKFS)).then(|| child::exit(serve(args.get(2))))
}

/// Enters the sandbox and becomes `mkfs.erofs`, which reads the tar from
/// the inherited stdin. Returns only when that fails.
fn serve(out: Option<&String>) -> Result<(), Box<dyn Error>> {
    let out = Path::new(out.ok_or("usage: sandbox-mkfs <image>")?);
    let dir = out.parent().ok_or("the image needs a parent directory")?;
    let access = FsAccess {
        read: ["/usr", "/lib", "/lib64", "/etc"]
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect(),
        write: vec![dir.to_path_buf()],
    };
    sandbox::enter(LIMITS, &access)?;
    let error = child::command(MKFS_EROFS)
        .args(["--tar=f", "-T0", "--quiet"])
        .arg(out)
        .exec();
    Err(format!("exec {MKFS_EROFS}: {error}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob_tar(files: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data, mode) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_cksum();
            builder.append_data(&mut h, path, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn setup(files: &[(&str, &[u8], u32)]) -> (PathBuf, BlobStore, PayloadSpec) {
        let dir =
            std::env::temp_dir().join(format!("cw-payload-{}-{}", std::process::id(), files.len()));
        let _ = std::fs::remove_dir_all(&dir);
        let blobs = BlobStore::open(&dir.join("cas")).unwrap();
        let blob = blobs.put(&blob_tar(files)).unwrap();
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
        (dir, blobs, spec)
    }

    #[test]
    fn the_tar_holds_the_probe_and_vendored_crates() {
        let (dir, blobs, spec) = setup(&[
            ("demo-1.0.0/Cargo.toml", b"[package]", 0o644),
            ("demo-1.0.0/build.sh", b"#!/bin/sh", 0o755),
            ("demo-1.0.0/.cargo-checksum.json", b"{\"forged\":1}", 0o644),
        ]);
        let mut tar = Vec::new();
        let stats = write_tar(&spec, &blobs, &mut tar).unwrap();
        let mut entries = std::collections::BTreeMap::new();
        for entry in tar::Archive::new(tar.as_slice()).entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mode = entry.header().mode().unwrap();
            let mut data = String::new();
            entry.read_to_string(&mut data).unwrap();
            entries.insert(path, (mode, data));
        }
        assert!(
            entries["probe/Cargo.toml"]
                .1
                .contains("version = \"=1.0.0\"")
        );
        assert!(
            entries["probe/.cargo/config.toml"]
                .1
                .contains("directory = \"/cw/vendor\"")
        );
        assert_eq!(entries["vendor/demo-1.0.0/build.sh"].0, 0o755);
        assert_eq!(
            entries["vendor/demo-1.0.0/.cargo-checksum.json"].1,
            format!("{{\"files\":{{}},\"package\":\"{}\"}}", "ab".repeat(32))
        );
        assert_eq!(stats.files, 7);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_blob_of_another_crate_is_refused() {
        let (dir, blobs, spec) = setup(&[("other-2.0.0/Cargo.toml", b"", 0o644)]);
        assert!(matches!(
            write_tar(&spec, &blobs, Vec::new()),
            Err(PayloadError::Mismatch(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stub_keeps_dependencies_and_features_only() {
        let original = br#"
[package]
name = "evil"
version = "1.0.0"
edition = "2021"
build = "build.rs"
links = "evil"
default-run = "evil-cli"

[lib]
name = "evil"
path = "src/evil.rs"
proc-macro = true

[[bin]]
name = "evil-cli"
path = "src/main.rs"

[dependencies.serde]
version = "1"
features = ["derive"]

[build-dependencies]
cc = "1"

[features]
default = ["std"]
std = []
"#;
        let stub: toml::Table = stub_manifest(original).unwrap().parse().unwrap();
        let package = stub["package"].as_table().unwrap();
        assert!(package.get("build").is_none() && package.get("links").is_none());
        assert!(package.get("default-run").is_none());
        assert_eq!(package["autobins"].as_bool(), Some(false));
        assert!(stub.get("bin").is_none());
        let lib = stub["lib"].as_table().unwrap();
        assert_eq!(lib["path"].as_str(), Some("src/lib.rs"));
        assert_eq!(lib["proc-macro"].as_bool(), Some(true));
        assert!(
            stub["dependencies"]["serde"]["features"]
                .as_array()
                .is_some()
        );
        assert!(stub.get("features").is_some());
        assert!(stub_manifest(b"not [toml").is_err());
    }
}
