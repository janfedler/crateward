//! `crateward integrity`: record and check the host manifest (ADR 0008).

use std::path::Path;

use clap::Subcommand;
use crateward_core::config::Config;
use crateward_core::integrity;
use crateward_core::paths::host;

use crate::error::{CliError, io};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Record the digests of the trusted files, after a deploy.
    Record,
    /// Compare the trusted files with the manifest.
    Check,
}

/// Records or checks the manifest in `instance.data_dir`. The Crateward
/// binaries are the ones next to this tool.
pub fn run(config: &Config, command: &Command) -> Result<(), CliError> {
    let manifest = config.instance.data_dir.join(host::INTEGRITY_MANIFEST);

    match command {
        Command::Record => record_manifest(config, &manifest),
        Command::Check => check_manifest(&manifest),
    }
}

fn record_manifest(config: &Config, manifest: &Path) -> Result<(), CliError> {
    let exe = std::env::current_exe().map_err(CliError::ToolPath)?;
    let dir = exe.parent().ok_or(CliError::NoToolDirectory)?;
    let files = integrity::covered(config, dir)?;
    let text = integrity::record(&files)?;
    let temporary = manifest.with_extension("tmp");
    std::fs::write(&temporary, text).map_err(io(&temporary))?;
    std::fs::rename(&temporary, manifest).map_err(io(manifest))?;
    out!("recorded {} files in {}", files.len(), manifest.display());

    Ok(())
}

fn check_manifest(manifest: &Path) -> Result<(), CliError> {
    let text = std::fs::read_to_string(manifest).map_err(io(manifest))?;
    let recorded = integrity::parse(&text)?;
    let mismatches = integrity::verify(&recorded);
    for m in &mismatches {
        out!("MISMATCH {}: {}", m.path.display(), m.reason);
    }

    if !mismatches.is_empty() {
        return Err(CliError::Differ(mismatches.len()));
    }

    out!("{} files match", recorded.len());

    Ok(())
}
