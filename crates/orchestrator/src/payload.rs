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
//! Crate archives are never extracted on the host (ADR 0014). The
//! orchestrator writes a new tar from the stored blobs, with its own
//! headers (root owned, fixed modes and times), and streams it into
//! `mkfs.erofs --tar=f`, which runs in a sandboxed child: no network,
//! Landlock limited to the system directories and the output directory.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crateward_core::blobs::BlobStore;
use crateward_core::cratesio::probe_manifest;
use crateward_core::name::CrateName;
use crateward_core::sandbox::{self, FsAccess, Limits};

/// Where the payload is mounted in the guest.
pub const MOUNT_POINT: &str = "/cw";
/// The probe directory in the guest, the job's working directory.
pub const PROBE_DIR: &str = "/cw/probe";

/// First argument of the image building child.
pub const MKFS: &str = "sandbox-mkfs";

/// `mkfs.erofs` from Debian's `erofs-utils`.
const MKFS_EROFS: &str = "/usr/bin/mkfs.erofs";

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
    #[error("mkfs.erofs: {0}")]
    Mkfs(String),
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
    let manifest = probe_manifest(&spec.name, &spec.version);
    append(
        &mut builder,
        "probe/Cargo.toml",
        0o644,
        manifest.as_bytes(),
        &mut stats,
    )?;
    append(
        &mut builder,
        "probe/Cargo.lock",
        0o644,
        spec.lockfile.as_bytes(),
        &mut stats,
    )?;
    append(&mut builder, "probe/lib.rs", 0o644, b"", &mut stats)?;
    append(
        &mut builder,
        "probe/.cargo/config.toml",
        0o644,
        CARGO_CONFIG.as_bytes(),
        &mut stats,
    )?;
    for package in &spec.packages {
        let dir = format!("{}-{}", package.name, package.version);
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
            if rest == ".cargo-checksum.json" {
                continue;
            }
            let executable = entry.header().mode().is_ok_and(|m| m & 0o111 != 0);
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(io(format!("reading {path}")))?;
            let mode = if executable { 0o755 } else { 0o644 };
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
    let mut child = Command::new(exe)
        .arg(MKFS)
        .arg(out)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io("starting the image builder"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| PayloadError::Mkfs("no stderr".into()))?;
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_string(&mut text);
        text
    });
    let written = match child.stdin.take() {
        Some(stdin) => write_tar(spec, blobs, std::io::BufWriter::new(stdin)),
        None => Err(PayloadError::Mkfs("no stdin".into())),
    };
    let status = child.wait().map_err(io("waiting for the image builder"))?;
    let errors = errors.join().unwrap_or_default();
    if !status.success() {
        return Err(PayloadError::Mkfs(format!("{status}: {}", errors.trim())));
    }
    written
}

/// Runs the image building child if `args` names it.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<std::process::ExitCode> {
    if args.get(1).map(String::as_str) != Some(MKFS) {
        return None;
    }
    let fail = |message: &str| {
        eprintln!("crateward sandbox: {message}");
        std::process::ExitCode::FAILURE
    };
    let Some(out) = args.get(2).map(PathBuf::from) else {
        return Some(fail("usage: sandbox-mkfs <image>"));
    };
    let Some(dir) = out.parent().map(Path::to_path_buf) else {
        return Some(fail("the image needs a parent directory"));
    };
    let entered = sandbox::isolate_network()
        .and_then(|()| {
            sandbox::limit(Limits {
                address_space: 4 << 30,
                cpu_seconds: 600,
                // No file size limit: erofs-utils 1.8.6 writes past 1 TiB
                // (sparse) while it builds even a one file image, measured
                // on 2026-09-25. The image is bounded by the tar this
                // process's parent writes, and by the tmpfs it lands on.
                file_size: u64::MAX,
                open_files: 64,
            })
        })
        .and_then(|()| {
            sandbox::restrict_fs(&FsAccess {
                read: ["/usr", "/lib", "/lib64", "/etc"]
                    .iter()
                    .map(PathBuf::from)
                    .filter(|p| p.exists())
                    .collect(),
                write: vec![dir],
            })
        });
    if let Err(error) = entered {
        return Some(fail(&error.to_string()));
    }
    // Replaces this process; the tar arrives on the inherited stdin.
    let error = Command::new(MKFS_EROFS)
        .args(["--tar=f", "-T0", "--quiet"])
        .arg(&out)
        .env_clear()
        .exec();
    Some(fail(&format!("exec {MKFS_EROFS}: {error}")))
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
}
