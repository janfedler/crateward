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

use crateward_core::blobs::{BlobError, BlobStore};
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
    /// Reading a crate's archive or writing the tar failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A blob could not be read.
    #[error("reading the blob of {package}: {source}")]
    Blob {
        /// The package directory, `<name>-<version>`.
        package: String,
        /// Why the blob store refused.
        source: BlobError,
    },
    /// A blob does not hold the crate it should.
    #[error("blob of {0} does not match its crate")]
    Mismatch(String),
    /// A manifest could not be reduced to a stub.
    #[error("the manifest of {package}: {source}")]
    Manifest {
        /// The package directory, `<name>-<version>`.
        package: String,
        /// What is wrong with it.
        source: ManifestError,
    },
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

/// Why a manifest could not be reduced to a stub.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The manifest is not UTF-8.
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    /// The manifest is not valid TOML.
    #[error(transparent)]
    Parse(#[from] toml::de::Error),
    /// The stub did not serialize.
    #[error(transparent)]
    Write(#[from] toml::ser::Error),
}

/// A published manifest reduced to its dependencies and features: no build
/// script, no `links`, one empty library (keeping its crate type), no other
/// targets. Cargo then resolves dependencies and features exactly as for
/// the real crate, and compiles nothing of it.
///
/// # Errors
///
/// Fails if the manifest is not valid TOML.
pub fn stub_manifest(original: &[u8]) -> Result<String, ManifestError> {
    let mut manifest: toml::Table = std::str::from_utf8(original)?.parse()?;
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
    Ok(toml::to_string(&manifest)?)
}

/// A tar stream that counts what goes into it.
struct TarWriter<W: Write> {
    builder: tar::Builder<W>,
    stats: PayloadStats,
}

impl<W: Write> TarWriter<W> {
    fn append(&mut self, path: &str, mode: u32, data: &[u8]) -> Result<(), PayloadError> {
        self.builder
            .append_data(&mut header(data.len() as u64, mode), path, data)
            .map_err(io(format!("writing {path}")))?;
        self.stats.files += 1;
        self.stats.bytes += data.len() as u64;
        Ok(())
    }

    fn probe(&mut self, dir: &str, probe: &ProbeSpec) -> Result<(), PayloadError> {
        let manifest = probe_manifest(&probe.name, &probe.version);
        for (file, data) in [
            ("Cargo.toml", manifest.as_bytes()),
            ("Cargo.lock", probe.lockfile.as_bytes()),
            ("lib.rs", b"".as_slice()),
            (".cargo/config.toml", CARGO_CONFIG.as_bytes()),
        ] {
            self.append(&format!("{dir}/{file}"), 0o644, data)?;
        }
        Ok(())
    }

    /// The files of one locked crate from its blob, then our checksum file.
    fn package(
        &mut self,
        package: &Package,
        blobs: &BlobStore,
        stubs: &[String],
    ) -> Result<(), PayloadError> {
        let dir = format!("{}-{}", package.name, package.version);
        let stub = stubs.contains(&dir);
        let tar = blobs
            .get(&package.blake3, MAX_BLOB_BYTES)
            .map_err(|source| PayloadError::Blob {
                package: dir.clone(),
                source,
            })?;
        let mut archive = tar::Archive::new(tar.as_slice());
        for entry in archive.entries().map_err(io(format!("reading {dir}")))? {
            let entry = entry.map_err(io(format!("reading {dir}")))?;
            self.entry(entry, &dir, stub)?;
        }
        // Directory sources need a checksum file; `package` must match the
        // lockfile. File hashes are left out: the payload is read only.
        let checksum = format!("{{\"files\":{{}},\"package\":\"{}\"}}", package.checksum);
        let path = format!("vendor/{dir}/.cargo-checksum.json");
        self.append(&path, 0o644, checksum.as_bytes())
    }

    fn entry(
        &mut self,
        mut entry: tar::Entry<'_, &[u8]>,
        dir: &str,
        stub: bool,
    ) -> Result<(), PayloadError> {
        if !entry.header().entry_type().is_file() {
            return Ok(());
        }
        let path = entry
            .path()
            .map_err(io(format!("reading {dir}")))?
            .to_string_lossy()
            .into_owned();
        let Some(rest) = path.strip_prefix(dir).and_then(|r| r.strip_prefix('/')) else {
            return Err(PayloadError::Mismatch(dir.to_owned()));
        };
        // Cargo trusts this file for vendored sources; only ours counts.
        if rest == ".cargo-checksum.json" || (stub && rest != "Cargo.toml") {
            return Ok(());
        }
        let executable = entry.header().mode().is_ok_and(|m| m & 0o111 != 0);
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(io(format!("reading {path}")))?;
        if stub {
            return self.stub_files(dir, &path, &data);
        }
        let mode = if executable { 0o755 } else { 0o644 };
        self.append(&format!("vendor/{path}"), mode, &data)
    }

    /// The reduced manifest of a stubbed crate and its empty library.
    fn stub_files(&mut self, dir: &str, path: &str, manifest: &[u8]) -> Result<(), PayloadError> {
        let stub = stub_manifest(manifest).map_err(|source| PayloadError::Manifest {
            package: dir.to_owned(),
            source,
        })?;
        self.append(&format!("vendor/{path}"), 0o644, stub.as_bytes())?;
        self.append(&format!("vendor/{dir}/src/lib.rs"), 0o644, b"")
    }

    fn finish(self) -> Result<PayloadStats, PayloadError> {
        self.builder
            .into_inner()
            .and_then(|mut w| w.flush())
            .map_err(io("finishing the tar"))?;
        Ok(self.stats)
    }
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
    let mut tar = TarWriter {
        builder: tar::Builder::new(out),
        stats: PayloadStats::default(),
    };
    let first = ProbeSpec {
        name: spec.name.clone(),
        version: spec.version.clone(),
        lockfile: spec.lockfile.clone(),
    };
    tar.probe("probe", &first)?;
    for (i, probe) in spec.extra_probes.iter().enumerate() {
        tar.probe(&format!("probes/{i}"), probe)?;
    }
    for (path, data) in &spec.files {
        tar.append(path, 0o644, data)?;
    }
    for package in &spec.packages {
        tar.package(package, blobs, &spec.stubs)?;
    }
    tar.finish()
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
            if path.ends_with('/') {
                h.set_entry_type(tar::EntryType::Directory);
            }
            h.set_cksum();
            builder.append_data(&mut h, path, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn setup(files: &[(&str, &[u8], u32)]) -> (PathBuf, BlobStore, PayloadSpec) {
        let dir = std::env::temp_dir().join(format!(
            "cw-payload-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
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
    fn the_tar_has_a_fixed_order_with_extra_probes_files_and_stubs() {
        let (dir, blobs, mut spec) = setup(&[
            ("demo-1.0.0/", b"", 0o755),
            ("demo-1.0.0/Cargo.toml", b"[package]", 0o644),
            ("demo-1.0.0/src/lib.rs", b"// lib", 0o600),
            ("demo-1.0.0/build.sh", b"#!/bin/sh", 0o755),
            ("demo-1.0.0/.cargo-checksum.json", b"{}", 0o644),
        ]);
        let dep_manifest: &[u8] = b"[package]\nname = \"dep\"\nbuild = \"build.rs\"\n";
        let dep = blobs
            .put(&blob_tar(&[
                ("dep-0.3.0/Cargo.toml", dep_manifest, 0o644),
                ("dep-0.3.0/src/lib.rs", b"pub fn f() {}", 0o644),
                ("dep-0.3.0/README.md", b"read me", 0o644),
            ]))
            .unwrap();
        spec.packages.push(Package {
            name: "dep".into(),
            version: "0.3.0".into(),
            checksum: "cd".repeat(32),
            blake3: dep.blake3,
        });
        spec.stubs = vec!["dep-0.3.0".into()];
        spec.extra_probes = vec![ProbeSpec {
            name: CrateName::parse("extra").unwrap(),
            version: "0.2.0".parse().unwrap(),
            lockfile: "# extra\n".into(),
        }];
        spec.files = vec![("run.sh".into(), b"echo".to_vec())];

        let mut tar = Vec::new();
        let stats = write_tar(&spec, &blobs, &mut tar).unwrap();
        let mut listing = Vec::new();
        let mut bytes = 0;
        for entry in tar::Archive::new(tar.as_slice()).entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mode = entry.header().mode().unwrap();
            let mut data = String::new();
            entry.read_to_string(&mut data).unwrap();
            bytes += data.len() as u64;
            listing.push(format!("{path} {mode:o} {data}"));
        }

        let probe = |name: &str, version: &str| {
            probe_manifest(&CrateName::parse(name).unwrap(), &version.parse().unwrap())
        };
        let checksum =
            |digit: &str| format!("{{\"files\":{{}},\"package\":\"{}\"}}", digit.repeat(32));
        let expected = [
            format!("probe/Cargo.toml 644 {}", probe("demo", "1.0.0")),
            "probe/Cargo.lock 644 # lock\n".to_owned(),
            "probe/lib.rs 644 ".to_owned(),
            format!("probe/.cargo/config.toml 644 {CARGO_CONFIG}"),
            format!("probes/0/Cargo.toml 644 {}", probe("extra", "0.2.0")),
            "probes/0/Cargo.lock 644 # extra\n".to_owned(),
            "probes/0/lib.rs 644 ".to_owned(),
            format!("probes/0/.cargo/config.toml 644 {CARGO_CONFIG}"),
            "run.sh 644 echo".to_owned(),
            "vendor/demo-1.0.0/Cargo.toml 644 [package]".to_owned(),
            "vendor/demo-1.0.0/src/lib.rs 644 // lib".to_owned(),
            "vendor/demo-1.0.0/build.sh 755 #!/bin/sh".to_owned(),
            format!(
                "vendor/demo-1.0.0/.cargo-checksum.json 644 {}",
                checksum("ab")
            ),
            format!(
                "vendor/dep-0.3.0/Cargo.toml 644 {}",
                stub_manifest(dep_manifest).unwrap()
            ),
            "vendor/dep-0.3.0/src/lib.rs 644 ".to_owned(),
            format!(
                "vendor/dep-0.3.0/.cargo-checksum.json 644 {}",
                checksum("cd")
            ),
        ];
        assert_eq!(listing, expected);
        assert_eq!(stats.files, expected.len() as u64);
        assert_eq!(stats.bytes, bytes);
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
        assert!(matches!(
            stub_manifest(b"not [toml"),
            Err(ManifestError::Parse(_))
        ));
        assert!(matches!(
            stub_manifest(b"\xff"),
            Err(ManifestError::Utf8(_))
        ));
    }

    #[test]
    fn a_stub_of_a_broken_manifest_names_its_package() {
        let (dir, blobs, mut spec) = setup(&[("demo-1.0.0/Cargo.toml", b"not [toml", 0o644)]);
        spec.stubs = vec!["demo-1.0.0".into()];
        let error = write_tar(&spec, &blobs, Vec::new()).unwrap_err();
        assert!(
            matches!(&error, PayloadError::Manifest { package, .. } if package == "demo-1.0.0"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .starts_with("the manifest of demo-1.0.0: ")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_blob_that_is_not_stored_names_its_package() {
        let (dir, blobs, mut spec) = setup(&[("demo-1.0.0/Cargo.toml", b"[package]", 0o644)]);
        spec.packages[0].blake3 = "0".repeat(64);
        let error = write_tar(&spec, &blobs, Vec::new()).unwrap_err();
        assert!(
            matches!(&error, PayloadError::Blob { package, .. } if package == "demo-1.0.0"),
            "{error}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
