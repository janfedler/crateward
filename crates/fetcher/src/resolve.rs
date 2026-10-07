//! Dependency resolution through a consumer probe (ADR 0004).
//!
//! For a version under analysis, the fetcher writes a small package that
//! depends on exactly that version, the way a victim would pull it in, and
//! lets `cargo generate-lockfile` resolve it in the sandbox. Cargo reads
//! only configuration Crateward wrote: the crate's own `.cargo/config.toml`
//! is never consulted, because the crate is a registry dependency, not the
//! workspace. The lockfile lists every package for every target, with
//! checksums. The fetcher then fetches those crates itself.

use std::path::Path;
use std::process::Stdio;

use crateward_core::child::ChildError;
use crateward_core::cratesio::probe_manifest;
use crateward_core::name::CrateName;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::proxy::{self, Index, Target};
use crate::sandboxed::{RESOLVE, ResolveOutcome};

/// The resolution child in error messages.
const CHILD: &str = "resolution child";

/// Why resolution could not be attempted. A crate whose dependencies do
/// not resolve is not an error. See [`Resolution::Failed`].
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Preparing the work directory or reading the lockfile failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The child did not run, failed or gave a bad answer.
    #[error(transparent)]
    Child(#[from] ChildError),
}

fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> ResolveError {
    move |source| ResolveError::Io { context, source }
}

/// The result of resolving one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The lockfile text.
    Locked(String),
    /// Cargo could not resolve the dependencies. The message says why.
    Failed(String),
}

/// A package from a lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPackage {
    /// Package name.
    pub name: String,
    /// Version.
    pub version: String,
    /// SHA-256 of the `.crate` file.
    pub checksum: String,
}

#[derive(Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockEntry>,
}

#[derive(Deserialize)]
struct LockEntry {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// Why a lockfile is not accepted.
#[derive(Debug, thiserror::Error)]
pub enum LockfileError {
    /// The text is not a lockfile.
    #[error(transparent)]
    Parse(#[from] toml::de::Error),
    /// A package comes from another source than the crates.io registry.
    #[error("{package} comes from {origin}")]
    ForeignSource {
        /// The package, as `name version`.
        package: String,
        /// Where the lockfile takes it from.
        origin: String,
    },
    /// A registry package has no checksum. The payload is `name version`.
    #[error("{0} has no checksum")]
    NoChecksum(String),
}

/// The registry packages of a lockfile. Packages without a source (the
/// probe itself) are skipped. A package from anywhere but the crates.io
/// registry is returned as an error, since crates.io does not allow them.
///
/// # Errors
///
/// Fails if the lockfile does not parse or names another source.
pub fn locked_packages(lockfile: &str) -> Result<Vec<LockedPackage>, LockfileError> {
    let parsed: Lockfile = toml::from_str(lockfile)?;
    let mut packages = Vec::new();

    for entry in parsed.package {
        let Some(origin) = entry.source else { continue };
        let package = format!("{} {}", entry.name, entry.version);
        if origin != "registry+https://github.com/rust-lang/crates.io-index" {
            return Err(LockfileError::ForeignSource { package, origin });
        }

        let checksum = entry.checksum.ok_or(LockfileError::NoChecksum(package))?;
        packages.push(LockedPackage {
            name: entry.name,
            version: entry.version,
            checksum,
        });
    }

    Ok(packages)
}

/// Resolves one version in a sandboxed child. `work` must be empty or
/// missing. It is removed afterwards.
///
/// # Errors
///
/// Fails if the child cannot run. Unresolvable dependencies are a
/// [`Resolution::Failed`] result instead.
pub async fn resolve(
    exe: &Path,
    cargo: &Path,
    work: &Path,
    index: Index,
    name: &CrateName,
    version: &semver::Version,
) -> Result<Resolution, ResolveError> {
    let _ = tokio::fs::remove_dir_all(work).await;
    let result = resolve_in(exe, cargo, work, index, name, version).await;
    let _ = tokio::fs::remove_dir_all(work).await;

    result
}

async fn resolve_in(
    exe: &Path,
    cargo: &Path,
    work: &Path,
    index: Index,
    name: &CrateName,
    version: &semver::Version,
) -> Result<Resolution, ResolveError> {
    let probe = work.join("probe");
    tokio::fs::create_dir_all(&probe)
        .await
        .map_err(io("creating the work directory"))?;
    tokio::fs::write(probe.join("Cargo.toml"), probe_manifest(name, version))
        .await
        .map_err(io("writing the probe manifest"))?;
    tokio::fs::write(probe.join("lib.rs"), "")
        .await
        .map_err(io("writing the probe source"))?;
    let socket = probe.join("proxy.sock");
    let target = Target {
        index_path: name.index_path(),
        version: version.to_string(),
    };

    let server = proxy::serve(&socket, index, target).map_err(io("starting the index proxy"))?;
    let output = Command::new(exe)
        .arg(RESOLVE)
        .arg(&probe)
        .arg(&socket)
        .arg(cargo)
        .env_clear()
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await;

    server.abort();

    let output = output.map_err(ChildError::io(CHILD, "running"))?;
    if !output.status.success() {
        return Err(ChildError::Failed {
            child: CHILD,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        }
        .into());
    }

    let outcome: ResolveOutcome =
        serde_json::from_slice(&output.stdout).map_err(|e| ChildError::answer(CHILD, e))?;
    if !outcome.ok {
        return Ok(Resolution::Failed(outcome.message));
    }

    tokio::fs::read_to_string(probe.join("Cargo.lock"))
        .await
        .map(Resolution::Locked)
        .map_err(io("reading the lockfile"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_packages_skip_the_probe_and_keep_checksums() {
        let lock = r#"
version = 4

[[package]]
name = "crateward-probe"
version = "0.0.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba"
"#;

        let packages = locked_packages(lock).unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "serde");
    }

    #[test]
    fn foreign_sources_are_rejected() {
        let lock = "[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nsource = \"git+https://example.com/x\"\n";

        assert!(matches!(
            locked_packages(lock),
            Err(LockfileError::ForeignSource { package, origin })
                if package == "x 1.0.0" && origin == "git+https://example.com/x"
        ));
    }

    #[test]
    fn a_registry_package_needs_a_checksum() {
        let lock = "[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";

        assert!(matches!(
            locked_packages(lock),
            Err(LockfileError::NoChecksum(package)) if package == "x 1.0.0"
        ));
    }

    #[test]
    fn text_that_is_no_lockfile_is_refused() {
        assert!(matches!(
            locked_packages("package = 3"),
            Err(LockfileError::Parse(_))
        ));
    }

    #[test]
    fn the_probe_depends_on_exactly_one_version() {
        let manifest = probe_manifest(
            &CrateName::parse("Inflector").unwrap(),
            &semver::Version::parse("0.11.4").unwrap(),
        );

        assert!(manifest.contains(r#"target = { package = "Inflector", version = "=0.11.4" }"#));
    }
}
