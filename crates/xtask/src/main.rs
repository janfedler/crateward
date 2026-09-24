//! Developer tasks for Crateward, run as `cargo xtask <task>`.
//!
//! Keeping these in Rust instead of shell scripts follows the project rule
//! that everything except kernel configuration, root filesystem scripts and
//! third party binaries is Rust. It also makes the tasks testable: the
//! documentation checks below run as part of `cargo test`.

#![forbid(unsafe_code)]

mod diagram;
mod docs_lint;
mod elf;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

/// `EX_UNAVAILABLE` from `sysexits.h`.
const EXIT_UNAVAILABLE: u8 = 69;

/// Target of the guest agent.
const GUEST_TARGET: &str = "x86_64-unknown-linux-musl";

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "Crateward developer tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Run every check CI runs, in the same order.
    Ci,
    /// Check the writing style of all documentation.
    DocsLint,
    /// Check or rewrite the generated state diagram in docs/ARCHITECTURE.md.
    StateDiagram {
        /// Rewrite the diagram instead of checking it.
        #[arg(long)]
        write: bool,
    },
    /// Build the guest agent for the musl target and verify it is static.
    GuestAgent,
    /// Vendor all dependencies into a reproducible tarball for a release.
    Vendor,
    /// Build the guest kernel (milestone M1).
    GuestKernel,
    /// Build the guest root filesystem (milestone M1).
    Rootfs,
    /// Run sequential jobs and check for leaked resources (milestone M1).
    Soak,
}

/// Why a task failed.
#[derive(Debug)]
enum TaskError {
    /// A command exited unsuccessfully or could not start.
    Command(String),
    /// A check found problems.
    Check(String),
    /// Reading or writing a file failed.
    Io(PathBuf, std::io::Error),
    /// The task belongs to a later milestone.
    NotImplemented(&'static str),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command(message) | Self::Check(message) => f.write_str(message),
            Self::Io(path, error) => write!(f, "{}: {error}", path.display()),
            Self::NotImplemented(milestone) => {
                write!(f, "not implemented yet (planned for milestone {milestone})")
            }
        }
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().task {
        Task::Ci => ci(),
        Task::DocsLint => docs_lint(),
        Task::StateDiagram { write } => diagram::run(&workspace_root(), write),
        Task::GuestAgent => guest_agent(),
        Task::Vendor => vendor(),
        Task::GuestKernel | Task::Rootfs | Task::Soak => Err(TaskError::NotImplemented("M1")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error @ TaskError::NotImplemented(_)) => {
            eprintln!("xtask: {error}");
            ExitCode::from(EXIT_UNAVAILABLE)
        }
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The workspace root, derived from this package's manifest directory.
fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf)
}

fn run(program: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<(), TaskError> {
    let rendered = format!("{program} {}", args.join(" "));
    eprintln!("xtask: running {rendered}");
    let status = Command::new(program)
        .args(args)
        .envs(envs.iter().copied())
        .current_dir(workspace_root())
        .status()
        .map_err(|error| TaskError::Command(format!("cannot start {rendered}: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(TaskError::Command(format!(
            "{rendered} failed with {status}"
        )))
    }
}

fn ci() -> Result<(), TaskError> {
    run("cargo", &["fmt", "--all", "--check"], &[])?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        &[],
    )?;
    run(
        "cargo",
        &["test", "--workspace", "--all-features", "--locked"],
        &[],
    )?;
    run(
        "cargo",
        &[
            "doc",
            "--workspace",
            "--no-deps",
            "--all-features",
            "--locked",
        ],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    guest_agent()?;
    docs_lint()?;
    diagram::run(&workspace_root(), false)?;
    run("cargo", &["deny", "--locked", "check"], &[])?;
    run("cargo", &["audit"], &[])?;
    run("cargo", &["vet", "--locked"], &[])?;
    eprintln!("xtask: all checks passed");
    Ok(())
}

fn docs_lint() -> Result<(), TaskError> {
    let violations = docs_lint::lint_workspace(&workspace_root())?;
    if violations.is_empty() {
        eprintln!("xtask: documentation style is clean");
        return Ok(());
    }
    for violation in &violations {
        eprintln!("{violation}");
    }
    Err(TaskError::Check(format!(
        "{} writing style violation(s); see the writing style section of docs/TESTING.md",
        violations.len()
    )))
}

fn guest_agent() -> Result<(), TaskError> {
    run(
        "cargo",
        &[
            "build",
            "--package",
            "crateward_guest_agent",
            "--release",
            "--locked",
            "--target",
            GUEST_TARGET,
        ],
        &[],
    )?;
    let binary = workspace_root()
        .join("target")
        .join(GUEST_TARGET)
        .join("release")
        .join("crateward_guest_agent");
    let bytes = std::fs::read(&binary).map_err(|error| TaskError::Io(binary.clone(), error))?;
    match elf::is_static(&bytes) {
        Ok(true) => {
            eprintln!("xtask: {} is statically linked", binary.display());
            Ok(())
        }
        Ok(false) => Err(TaskError::Check(format!(
            "{} requests a dynamic loader",
            binary.display()
        ))),
        Err(message) => Err(TaskError::Check(format!("{}: {message}", binary.display()))),
    }
}

fn vendor() -> Result<(), TaskError> {
    let out = "target/release-vendor";
    run(
        "cargo",
        &[
            "vendor",
            "--locked",
            "--versioned-dirs",
            &format!("{out}/vendor"),
        ],
        &[],
    )?;
    // Deterministic archive: sorted names, fixed owner and timestamps.
    run(
        "tar",
        &[
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-C",
            out,
            "-czf",
            "target/crateward-vendor.tar.gz",
            "vendor",
        ],
        &[("GZIP", "-n")],
    )?;
    eprintln!("xtask: wrote target/crateward-vendor.tar.gz");
    Ok(())
}
