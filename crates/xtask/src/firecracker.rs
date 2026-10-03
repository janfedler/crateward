//! Downloads the pinned Firecracker release and verifies it.
//!
//! The release archive's SHA-256 is pinned in `guest/firecracker.toml`.
//! Only after the digest matches is the `firecracker` binary extracted to
//! `target/guest/bin`. Crateward does not use Firecracker's jailer
//! (ADR 0002).

use std::path::Path;

use crateward_core::paths::{build, repo};
use serde::Deserialize;

use crate::images::download;
use crate::{TaskError, io, read_toml, run_in};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    version: String,
    url: String,
    sha256: String,
}

/// Downloads, verifies and extracts the pinned release.
///
/// # Errors
///
/// Fails if the download fails or the digest does not match the pin.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let pin: Pin = read_toml(root, repo::FIRECRACKER_PIN)?;

    let dir = root.join(build::GUEST_BIN);
    let name = format!("firecracker-{}.tgz", pin.version);
    let archive = download(&dir, &name, &pin.url, &pin.sha256)?;
    let archive_str = archive.to_string_lossy();

    let release = format!("release-{}-x86_64", pin.version);
    let member = format!("{release}/firecracker-{}-x86_64", pin.version);
    let from = dir.join(&member);
    run_in(&dir, "tar", &["-xzf", &archive_str, &member], &[])?;
    std::fs::rename(&from, root.join(build::FIRECRACKER)).map_err(io(&from))?;
    let _ = std::fs::remove_dir_all(dir.join(&release));

    eprintln!(
        "xtask: firecracker {} verified in {}",
        pin.version,
        dir.display()
    );

    Ok(())
}
