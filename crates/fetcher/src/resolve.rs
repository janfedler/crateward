//! Dependency resolution through a consumer probe (ADR 0014).
//!
//! For a version under analysis, the fetcher writes a small package that
//! depends on exactly that version, the way a victim would pull it in, and
//! lets `cargo generate-lockfile` resolve it in the sandbox. Cargo reads
//! only configuration Crateward wrote: the crate's own `.cargo/config.toml`
//! is never consulted, because the crate is a registry dependency, not the
//! workspace. The lockfile lists every package for every target, with
//! checksums; the fetcher then fetches those crates itself.

use std::path::Path;
use std::process::Stdio;

use crateward_core::http::PoliteClient;
use crateward_core::name::CrateName;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::proxy::{self, IndexCache, Target};
use crate::sandboxed::{RESOLVE, ResolveOutcome};

/// Why resolution could not be attempted. A crate whose dependencies do
/// not resolve is not an error; see [`Resolution::Failed`].
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Preparing the work directory or running the child failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The child's output did not parse.
    #[error("resolution child: {0}")]
    Child(String),
}

fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> ResolveError {
    move |source| ResolveError::Io { context, source }
}

/// The result of resolving one version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The lockfile text.
    Locked(String),
    /// Cargo could not resolve the dependencies; the message says why.
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

/// The registry packages of a lockfile. Packages without a source (the
/// probe itself) are skipped; a package from anywhere but the crates.io
/// registry is returned as an error, since crates.io does not allow them.
///
/// # Errors
///
/// Fails if the lockfile does not parse or names another source.
pub fn locked_packages(lockfile: &str) -> Result<Vec<LockedPackage>, String> {
    let parsed: Lockfile = toml::from_str(lockfile).map_err(|e| e.to_string())?;
    let mut packages = Vec::new();
    for entry in parsed.package {
        let Some(source) = entry.source else { continue };
        if source != "registry+https://github.com/rust-lang/crates.io-index" {
            return Err(format!(
                "{} {} comes from {source}",
                entry.name, entry.version
            ));
        }
        let checksum = entry
            .checksum
            .ok_or_else(|| format!("{} {} has no checksum", entry.name, entry.version))?;
        packages.push(LockedPackage {
            name: entry.name,
            version: entry.version,
            checksum,
        });
    }
    Ok(packages)
}

/// The probe's manifest. The dependency is renamed to a fixed key so that
/// no crate name is ever interpreted as manifest syntax beyond a quoted
/// string.
fn probe_manifest(name: &CrateName, version: &semver::Version) -> String {
    format!(
        "[package]\nname = \"crateward-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n\
         [lib]\npath = \"lib.rs\"\n\n\
         [dependencies]\ntarget = {{ package = \"{name}\", version = \"={version}\" }}\n"
    )
}

/// Resolves one version in a sandboxed child. `work` must be empty or
/// missing; it is removed afterwards.
///
/// # Errors
///
/// Fails if the child cannot run. Unresolvable dependencies are a
/// [`Resolution::Failed`] result instead.
#[allow(clippy::too_many_arguments)]
pub async fn resolve(
    exe: &Path,
    cargo: &Path,
    work: &Path,
    client: PoliteClient,
    index_root: &str,
    cache: IndexCache,
    name: &CrateName,
    version: &semver::Version,
) -> Result<Resolution, ResolveError> {
    let _ = tokio::fs::remove_dir_all(work).await;
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
    let server = proxy::serve(&socket, client, index_root, cache, target)
        .map_err(io("starting the index proxy"))?;
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
    let result = (|| {
        let output = output.map_err(io("running the resolution child"))?;
        if !output.status.success() {
            return Err(ResolveError::Child(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let outcome: ResolveOutcome = serde_json::from_slice(&output.stdout)
            .map_err(|e| ResolveError::Child(e.to_string()))?;
        if outcome.ok {
            std::fs::read_to_string(probe.join("Cargo.lock"))
                .map(Resolution::Locked)
                .map_err(io("reading the lockfile"))
        } else {
            Ok(Resolution::Failed(outcome.message))
        }
    })();
    let _ = tokio::fs::remove_dir_all(work).await;
    result
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
        assert!(locked_packages(lock).is_err());
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
