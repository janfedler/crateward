//! Runs every fuzz target in `fuzz/` for a fixed time.
//!
//! The package has its own workspace and toolchain file (a pinned nightly,
//! which the sanitizer flags of `cargo fuzz` need). CI runs each target
//! briefly from an empty corpus as a smoke test. Before a release every
//! target runs for at least 150 seconds from the seed corpus (TESTING.md).

use std::path::Path;

use crateward_core::paths::repo;

use crate::{TaskError, io, nested_cargo, run_command};

/// Type checks every target. The package is its own workspace, so the
/// workspace checks do not build it.
///
/// # Errors
///
/// Fails if a target does not compile.
pub fn check(root: &Path) -> Result<(), TaskError> {
    run_command(nested_cargo(&root.join(repo::FUZZ)).args(["check", "--locked", "--bins"]))
}

/// Runs each target for `seconds`.
///
/// # Errors
///
/// Fails if `cargo fuzz` cannot run or a target finds a crash, a leak, a
/// timeout or an allocation above 2 GiB.
pub fn run(root: &Path, seconds: u32) -> Result<(), TaskError> {
    let targets_dir = root.join(repo::FUZZ_TARGETS);
    let mut targets = Vec::new();

    for entry in std::fs::read_dir(&targets_dir).map_err(io(&targets_dir))? {
        let path = entry.map_err(io(&targets_dir))?.path();
        if path.extension().is_some_and(|e| e == "rs")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            targets.push(stem.to_owned());
        }
    }

    targets.sort();
    let max_time = format!("-max_total_time={seconds}");
    let mut failed = Vec::new();

    for target in &targets {
        let args = [
            "fuzz",
            "run",
            "-O",
            target.as_str(),
            "--",
            max_time.as_str(),
            "-rss_limit_mb=2048",
            "-max_len=1048576",
        ];

        if let Err(error) = run_command(nested_cargo(&root.join(repo::FUZZ)).args(args)) {
            eprintln!("xtask: {error}");
            failed.push(target.clone());
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        Err(TaskError::Check(format!(
            "fuzz targets failed: {}; inputs are in fuzz/artifacts",
            failed.join(", ")
        )))
    }
}
