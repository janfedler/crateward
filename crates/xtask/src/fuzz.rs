//! Runs the fuzz targets in `fuzz/` with libFuzzer or AFL++.
//!
//! The package has its own workspace and toolchain file (a pinned nightly,
//! which the sanitizer flags of `cargo fuzz` need). Every target builds for
//! both engines (see `fuzz/src/lib.rs`). `cargo xtask ci` type checks them
//! for both.
//!
//! With libFuzzer, `cargo xtask fuzz` runs each target briefly. Before a
//! release every target runs for at least 150 seconds from the seed corpus
//! (TESTING.md).
//!
//! With AFL++, it fuzzes the targets in turn, one round of `--seconds` each,
//! until interrupted. Each target keeps its state in `fuzz/afl/<target>`,
//! so every round and every new run resumes where the last one stopped.
//! The fuzzers run at the lowest priority and are not bound to a core, so
//! they yield to the microVMs of a production host.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crateward_core::paths::repo;

use crate::{TaskError, io, nested, nested_cargo, run_command};

/// A fuzzing engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Engine {
    /// libFuzzer through `cargo fuzz`, for a fixed time.
    Libfuzzer,
    /// AFL++ through `cargo afl`, until interrupted.
    Afl,
}

/// Largest input either engine generates.
const MAX_INPUT_BYTES: u32 = 1024 * 1024;

/// Memory limit of one target process, in MiB.
const MEMORY_LIMIT_MIB: u32 = 2048;

/// Type checks every target for both engines. The package is its own
/// workspace, so the workspace checks do not build it.
///
/// # Errors
///
/// Fails if a target does not compile.
pub fn check(root: &Path) -> Result<(), TaskError> {
    let fuzz = root.join(repo::FUZZ);
    run_command(nested_cargo(&fuzz).args(["check", "--locked", "--bins"]))?;

    run_command(nested_cargo(&fuzz).args([
        "check",
        "--locked",
        "--bins",
        "--no-default-features",
        "--features",
        "afl",
    ]))
}

/// Runs `only`, or every target when it is empty, with `engine`.
///
/// # Errors
///
/// Fails if a target is unknown or the engine cannot run. With libFuzzer it
/// also fails if a target finds a crash, a leak, a timeout or an allocation
/// above the memory limit. AFL++ runs until interrupted and only reports
/// what it found.
pub fn run(
    root: &Path,
    engine: Engine,
    seconds: Option<u32>,
    only: &[String],
    jobs: u32,
) -> Result<(), TaskError> {
    let targets = targets(root, only)?;
    match engine {
        Engine::Libfuzzer => run_libfuzzer(root, &targets, seconds.unwrap_or(30)),
        Engine::Afl => run_afl(root, &targets, seconds.unwrap_or(3600), jobs.max(1)),
    }
}

/// The names of the targets in `fuzz/fuzz_targets`, sorted, or `only` if
/// each of them exists.
fn targets(root: &Path, only: &[String]) -> Result<Vec<String>, TaskError> {
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

    if let Some(unknown) = only.iter().find(|name| !targets.contains(name)) {
        return Err(TaskError::Check(format!(
            "unknown fuzz target {unknown}, known: {}",
            targets.join(", ")
        )));
    }

    if only.is_empty() {
        Ok(targets)
    } else {
        Ok(only.to_vec())
    }
}

fn run_libfuzzer(root: &Path, targets: &[String], seconds: u32) -> Result<(), TaskError> {
    let max_time = format!("-max_total_time={seconds}");
    let rss_limit = format!("-rss_limit_mb={MEMORY_LIMIT_MIB}");
    let max_len = format!("-max_len={MAX_INPUT_BYTES}");
    let mut failed = Vec::new();

    for target in targets {
        let args = [
            "fuzz",
            "run",
            "-O",
            target.as_str(),
            "--",
            max_time.as_str(),
            rss_limit.as_str(),
            max_len.as_str(),
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

/// Builds every target with `cargo afl`, then fuzzes `targets` in turn
/// forever, `seconds` each round with `jobs` instances.
fn run_afl(root: &Path, targets: &[String], seconds: u32, jobs: u32) -> Result<(), TaskError> {
    run_command(nested_cargo(&root.join(repo::FUZZ)).args([
        "afl",
        "build",
        "--release",
        "--locked",
        "--bins",
        "--no-default-features",
        "--features",
        "afl",
    ]))?;

    for round in 1.. {
        for target in targets {
            eprintln!("xtask: round {round}, {target}");
            afl_round(root, target, seconds, jobs)?;

            let out = root.join(repo::FUZZ_AFL).join(target).join("out");
            let crashes = crashes(&out)?;
            if crashes > 0 {
                eprintln!(
                    "xtask: {target} has {crashes} crashing inputs in {}/*/crashes",
                    out.display()
                );
            }
        }
    }

    Ok(())
}

/// One round of AFL++ on `target`: a main instance in the foreground and
/// `jobs - 1` secondary instances without output, all stopping after
/// `seconds`.
fn afl_round(root: &Path, target: &str, seconds: u32, jobs: u32) -> Result<(), TaskError> {
    let seeds = seeds(root, target)?;
    let dir = root.join(repo::FUZZ_AFL).join(target);
    std::fs::create_dir_all(&dir).map_err(io(&dir))?;

    let mut secondaries = Vec::new();

    for index in 1..jobs {
        let mut command = afl_fuzz(root, target, &seeds, seconds, &format!("-Ss{index}"));
        command
            .env("AFL_NO_UI", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command
            .spawn()
            .map_err(|error| TaskError::Command(format!("cannot start afl-fuzz: {error}")))?;

        secondaries.push(child);
    }

    let main = run_command(&mut afl_fuzz(root, target, &seeds, seconds, "-Mmain"));
    stop(secondaries, main.is_err());

    main
}

/// `afl-fuzz` for one instance of `target`, through `cargo afl` at the
/// lowest priority. `role` is `-M<name>` or `-S<name>`.
fn afl_fuzz(root: &Path, target: &str, seeds: &Path, seconds: u32, role: &str) -> Command {
    let out = root.join(repo::FUZZ_AFL).join(target).join("out");
    let binary = root.join(repo::FUZZ_AFL_BINARIES).join(target);
    let mut command = nested("nice", &root.join(repo::FUZZ));
    command
        .args(["-n", "19", "cargo", "afl", "fuzz", "-i"])
        .arg(seeds)
        .arg("-o")
        .arg(out)
        .args(["-V", &seconds.to_string()])
        .args(["-m", &MEMORY_LIMIT_MIB.to_string()])
        .args([role, "--"])
        .arg(binary)
        // Resume from the state in the output directory.
        .env("AFL_AUTORESUME", "1")
        // Changing the CPU frequency governor needs root.
        .env("AFL_SKIP_CPUFREQ", "1")
        // Leave every core to the scheduler, so the microVMs come first.
        .env("AFL_NO_AFFINITY", "1");

    command
}

/// Waits for the secondary instances, killing them first if the main
/// instance failed.
fn stop(secondaries: Vec<Child>, kill: bool) {
    for mut child in secondaries {
        if kill && let Err(error) = child.kill() {
            eprintln!("xtask: cannot stop afl-fuzz: {error}");
        }

        if let Err(error) = child.wait() {
            eprintln!("xtask: cannot wait for afl-fuzz: {error}");
        }
    }
}

/// The seed directory of `target`: its corpus in `fuzz/corpus`, or a single
/// empty input when that has no file, since AFL++ needs at least one.
fn seeds(root: &Path, target: &str) -> Result<PathBuf, TaskError> {
    let corpus = root.join(repo::FUZZ_CORPUS).join(target);
    if has_files(&corpus)? {
        return Ok(corpus);
    }

    let seeds = root.join(repo::FUZZ_AFL).join(target).join("seeds");
    std::fs::create_dir_all(&seeds).map_err(io(&seeds))?;

    let empty = seeds.join("empty");
    std::fs::write(&empty, b"\n").map_err(io(&empty))?;

    Ok(seeds)
}

fn has_files(dir: &Path) -> Result<bool, TaskError> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => Ok(entries.next().is_some()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io(dir)(error)),
    }
}

/// How many crashing inputs the instances in `out` saved.
fn crashes(out: &Path) -> Result<usize, TaskError> {
    let mut count = 0;

    for instance in std::fs::read_dir(out).map_err(io(out))? {
        let dir = instance.map_err(io(out))?.path().join("crashes");
        if !dir.is_dir() {
            continue;
        }

        for entry in std::fs::read_dir(&dir).map_err(io(&dir))? {
            if entry.map_err(io(&dir))?.file_name() != "README.txt" {
                count += 1;
            }
        }
    }

    Ok(count)
}
