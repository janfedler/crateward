//! Downloads the pinned Firecracker release and verifies it.
//!
//! The release archive's SHA-256 is pinned in `guest/firecracker.toml`.
//! Only after the digest matches is the `firecracker` binary extracted to
//! `target/guest/bin`. Crateward does not use Firecracker's jailer
//! (ADR 0002).

use std::path::Path;

use serde::Deserialize;

use crate::{TaskError, run_in};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    version: String,
    url: String,
    sha256: String,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> TaskError + '_ {
    move |e| TaskError::Io(path.to_path_buf(), e)
}

/// Downloads, verifies and extracts the pinned release.
///
/// # Errors
///
/// Fails if the download fails or the digest does not match the pin.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let pin_path = root.join("guest").join("firecracker.toml");
    let pin: Pin = toml::from_str(&std::fs::read_to_string(&pin_path).map_err(io(&pin_path))?)
        .map_err(|e| TaskError::Check(format!("guest/firecracker.toml: {e}")))?;
    let dir = root.join("target").join("guest").join("bin");
    std::fs::create_dir_all(&dir).map_err(io(&dir))?;
    let archive = dir.join(format!("firecracker-{}.tgz", pin.version));
    let archive_str = archive.to_string_lossy().into_owned();
    if !archive.exists() {
        run_in(
            &dir,
            "curl",
            &["-sSfL", "--proto", "=https", "-o", &archive_str, &pin.url],
            &[],
        )?;
    }
    let digest = crate::images::sha256_file(&archive)?;
    if digest != pin.sha256 {
        std::fs::remove_file(&archive).map_err(io(&archive))?;
        return Err(TaskError::Check(format!(
            "firecracker archive has SHA-256 {digest}, pinned {}; deleted it",
            pin.sha256
        )));
    }
    let release = format!("release-{}-x86_64", pin.version);
    let member = format!("{release}/firecracker-{}-x86_64", pin.version);
    run_in(&dir, "tar", &["-xzf", &archive_str, &member], &[])?;
    let from = dir.join(&member);
    let to = dir.join("firecracker");
    std::fs::rename(&from, &to).map_err(io(&from))?;
    let _ = std::fs::remove_dir_all(dir.join(&release));
    eprintln!(
        "xtask: firecracker {} verified in {}",
        pin.version,
        dir.display()
    );
    Ok(())
}
