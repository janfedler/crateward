//! Developer tasks for Crateward, run as `cargo xtask <task>`.
//!
//! Keeping these in Rust instead of shell scripts follows the project rule
//! that everything except kernel configuration, root filesystem scripts and
//! third party binaries is Rust. It also makes the tasks testable: the
//! documentation checks below run as part of `cargo test`.

#![forbid(unsafe_code)]

mod deploy;
mod diagram;
mod docs_lint;
mod firecracker;
mod fuzz;
mod guest_ebpf;
mod guest_kernel;
mod images;
mod release;
mod rootfs;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

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
    /// Build the guest's eBPF programs with the pinned nightly and linker.
    GuestEbpf,
    /// Vendor all dependencies into a reproducible tarball for a release.
    Vendor,
    /// Build the release bundle for `deploy/ansible`: binaries, guest
    /// images, SBOM, vendored sources and checksums.
    Release,
    /// Download and verify the pinned Firecracker release.
    Firecracker,
    /// Build the guest kernel from the pinned source in guest/kernel.
    GuestKernel,
    /// Build the guest root filesystem image from the pins in guest/rootfs.
    Rootfs,
    /// Move the root filesystem's Debian snapshot pin to today (image
    /// refresh, ADR 0024).
    BumpDebianSnapshot,
    /// Run sequential jailed jobs on this host and check for leaked resources.
    Soak {
        /// Number of sequential jobs.
        #[arg(long, default_value_t = 50)]
        jobs: u32,
    },
    /// Run every fuzz target for a while (needs `cargo fuzz`).
    Fuzz {
        /// Seconds per target.
        #[arg(long, default_value_t = 30)]
        seconds: u32,
    },
    /// Run the canary: a fixture crate that steals a honeytoken inside a
    /// microVM must be caught.
    Canary,
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
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command(message) | Self::Check(message) => f.write_str(message),
            Self::Io(path, error) => write!(f, "{}: {error}", path.display()),
        }
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().task {
        Task::Ci => ci(),
        Task::DocsLint => docs_lint(),
        Task::StateDiagram { write } => diagram::run(&workspace_root(), write),
        Task::GuestAgent => guest_agent(),
        Task::GuestEbpf => guest_ebpf::run(&workspace_root()),
        Task::Vendor => vendor(),
        Task::Release => release::run_release(&workspace_root()),
        Task::Firecracker => firecracker::run(&workspace_root()),
        Task::GuestKernel => guest_kernel::run(&workspace_root()),
        Task::Rootfs => rootfs::run(&workspace_root()),
        Task::BumpDebianSnapshot => rootfs::bump_snapshot(&workspace_root()),
        Task::Soak { jobs } => soak(jobs),
        Task::Canary => canary(),
        Task::Fuzz { seconds } => fuzz::run(&workspace_root(), seconds),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
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
    run_in(&workspace_root(), program, args, envs)
}

/// Runs a command in `dir` and fails unless it exits successfully.
fn run_in(
    dir: &Path,
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<(), TaskError> {
    let rendered = format!("{program} {}", args.join(" "));
    eprintln!("xtask: running {rendered}");
    let status = Command::new(program)
        .args(args)
        .envs(envs.iter().copied())
        .current_dir(dir)
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
    guest_ebpf::run(&workspace_root())?;
    docs_lint()?;
    diagram::run(&workspace_root(), false)?;
    run("cargo", &["deny", "--locked", "check"], &[])?;
    // The eBPF package has its own lockfile; the root deny.toml applies.
    run(
        "cargo",
        &[
            "deny",
            "--manifest-path",
            "crates/guest_ebpf/Cargo.toml",
            "--locked",
            "check",
        ],
        &[],
    )?;
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
    match crateward_core::elf::is_static(&bytes) {
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

/// Runs the soak test in a systemd user scope with `Delegate=yes`, which
/// gives it a cgroup subtree for the slot limits. Needs `/dev/kvm`, the
/// guest images and subordinate IDs, so it only runs on the server.
fn soak(jobs: u32) -> Result<(), TaskError> {
    let jobs = jobs.to_string();
    run(
        "systemd-run",
        &[
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "Delegate=yes",
            "cargo",
            "test",
            "--release",
            "--locked",
            "--package",
            "crateward_orchestrator",
            "--test",
            "soak",
            "--",
            "--ignored",
            "--nocapture",
        ],
        &[("CRATEWARD_SOAK_JOBS", jobs.as_str())],
    )
}

/// The C compiler for musl targets: `musl-gcc` when installed, otherwise
/// the host `gcc`.
fn musl_cc() -> &'static str {
    if Path::new("/usr/bin/musl-gcc").exists() {
        "musl-gcc"
    } else {
        "gcc"
    }
}

/// Runs the canary test: a fixture crate that steals a honeytoken inside a
/// microVM must be caught. Builds the static fake internet first. Needs the
/// same environment as the soak test.
fn canary() -> Result<(), TaskError> {
    run(
        "cargo",
        &[
            "build",
            "--release",
            "--locked",
            "--target",
            GUEST_TARGET,
            "--package",
            "crateward_fake_internet",
        ],
        // ring compiles a little C and assembly. Without `musl-tools` there
        // is no musl C compiler; the host gcc works for ring's freestanding
        // code. Installing `musl-tools` is the proper fix.
        &[("CC_x86_64_unknown_linux_musl", musl_cc())],
    )?;
    run(
        "systemd-run",
        &[
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "Delegate=yes",
            "cargo",
            "test",
            "--release",
            "--locked",
            "--package",
            "crateward_orchestrator",
            "--test",
            "canary",
            "--",
            "--ignored",
            "--nocapture",
        ],
        &[],
    )
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
            // `gzip -n` leaves the name and time out of the header.
            "--use-compress-program=gzip -n",
            "-cf",
            "target/crateward-vendor.tar.gz",
            "vendor",
        ],
        &[],
    )?;
    eprintln!("xtask: wrote target/crateward-vendor.tar.gz");
    Ok(())
}
