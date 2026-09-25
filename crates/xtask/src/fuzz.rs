//! Runs every fuzz target in `fuzz/` for a fixed time.
//!
//! The package has its own workspace and toolchain file (a pinned nightly,
//! which the sanitizer flags of `cargo fuzz` need). CI runs each target
//! briefly from an empty corpus as a smoke test; before a release every
//! target runs for at least 150 seconds from the seed corpus (TESTING.md).

use std::path::Path;
use std::process::Command;

use crate::TaskError;

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> TaskError + '_ {
    move |e| TaskError::Io(path.to_path_buf(), e)
}

/// Runs each target for `seconds`.
///
/// # Errors
///
/// Fails if `cargo fuzz` cannot run or a target finds a crash, a leak, a
/// timeout or an allocation above 2 GiB.
pub fn run(root: &Path, seconds: u32) -> Result<(), TaskError> {
    let fuzz = root.join("fuzz");
    let targets_dir = fuzz.join("fuzz_targets");
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
        eprintln!("xtask: running cargo {} in fuzz", args.join(" "));
        // The outer cargo exports its toolchain; removing it lets the
        // package's own rust-toolchain.toml choose.
        let status = Command::new("cargo")
            .args(args)
            .current_dir(&fuzz)
            .env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("RUSTC")
            .env_remove("RUSTDOC")
            .env_remove("CARGO")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .status()
            .map_err(|e| TaskError::Command(format!("cannot start cargo fuzz: {e}")))?;
        if !status.success() {
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
