//! Developer tasks for Crateward, run as `cargo xtask <task>`.

#![forbid(unsafe_code)]

mod coverage;
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
#[cfg(test)]
mod testing;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use crateward_core::paths::{build, repo};
use serde::de::DeserializeOwned;

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
    /// Build the release bundle and its tarball: binaries, guest images,
    /// playbooks, `install.sh`, SBOM, vendored sources and checksums.
    Release,
    /// Pack a release bundle directory again, for example after adding
    /// `SHA256SUMS.sig`.
    Pack {
        /// The bundle directory under `target/release-bundle`.
        bundle: PathBuf,
    },
    /// Download and verify the pinned Firecracker release.
    Firecracker,
    /// Build the guest kernel from the pinned source in guest/kernel.
    GuestKernel,
    /// Build the guest root filesystem image from the pins in guest/rootfs.
    Rootfs,
    /// Move the root filesystem's Debian snapshot pin to today (image
    /// refresh, ADR 0002).
    BumpDebianSnapshot,
    /// Run sequential jailed jobs on this host and check for leaked resources.
    Soak {
        /// Number of sequential jobs.
        #[arg(long, default_value_t = 50)]
        jobs: u32,
    },
    /// Check deploy/: playbook syntax, unit files, firewall rules. Needs
    /// `ansible-playbook`, `systemd-analyze`, `nft` and `unshare`.
    DeployCheck,
    /// Run every fuzz target for a while (needs `cargo fuzz`).
    Fuzz {
        /// Seconds per target.
        #[arg(long, default_value_t = 30)]
        seconds: u32,
    },
    /// Run the canary: a fixture crate that steals a honeytoken inside a
    /// microVM must be caught.
    Canary,
    /// Measure the line coverage of the workspace tests (needs
    /// `cargo llvm-cov`).
    Coverage,
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
        Task::Pack { bundle } => release::pack(&bundle).map(|archive| {
            eprintln!("xtask: wrote {}", archive.display());
        }),
        Task::Firecracker => firecracker::run(&workspace_root()),
        Task::GuestKernel => guest_kernel::run(&workspace_root()),
        Task::Rootfs => rootfs::run(&workspace_root()),
        Task::BumpDebianSnapshot => rootfs::bump_snapshot(&workspace_root()),
        Task::Soak { jobs } => soak(jobs),
        Task::Canary => canary(),
        Task::Coverage => coverage::run_coverage(&workspace_root()),
        Task::DeployCheck => deploy::run(&workspace_root()),
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

/// Maps an I/O error to a task error that names `path`.
fn io(path: &Path) -> impl FnOnce(std::io::Error) -> TaskError + '_ {
    move |e| TaskError::Io(path.to_path_buf(), e)
}

/// Reads a text file.
fn read(path: &Path) -> Result<String, TaskError> {
    std::fs::read_to_string(path).map_err(io(path))
}

/// Copies a file with `mode`, creating the target's directory.
fn copy(from: &Path, to: &Path, mode: u32) -> Result<(), TaskError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !from.is_file() {
        return Err(TaskError::Check(format!("{} is missing", from.display())));
    }

    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(io(parent))?;
    }

    std::fs::copy(from, to).map_err(io(to))?;

    std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode)).map_err(io(to))
}

/// Reads and parses a TOML file at `path` under `root`.
fn read_toml<T: DeserializeOwned>(root: &Path, path: &str) -> Result<T, TaskError> {
    let file = root.join(path);
    let text = std::fs::read_to_string(&file).map_err(io(&file))?;

    toml::from_str(&text).map_err(|e| TaskError::Check(format!("{path}: {e}")))
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
    let mut command = Command::new(program);
    command
        .args(args)
        .envs(envs.iter().copied())
        .current_dir(dir);

    run_command(&mut command)
}

/// Runs `command` and fails unless it exits successfully.
fn run_command(command: &mut Command) -> Result<(), TaskError> {
    let args: Vec<_> = command.get_args().map(|a| a.to_string_lossy()).collect();
    let rendered = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        args.join(" ")
    );

    eprintln!("xtask: running {rendered}");

    let status = command
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

/// Runs a command in `dir` and returns its trimmed standard output.
fn output(dir: &Path, program: &str, args: &[&str]) -> Result<String, TaskError> {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| TaskError::Command(format!("cannot start {program}: {e}")))?;
    if !out.status.success() {
        return Err(TaskError::Command(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// `cargo` in `dir`, for a package with its own workspace and toolchain
/// file. The outer cargo exports its toolchain. Removing it lets the
/// package's own `rust-toolchain.toml` choose.
fn nested_cargo(dir: &Path) -> Command {
    let mut command = Command::new("cargo");
    command.current_dir(dir);

    for name in [
        "RUSTUP_TOOLCHAIN",
        "RUSTC",
        "RUSTDOC",
        "CARGO",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        command.env_remove(name);
    }

    command
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
    fuzz::check(&workspace_root())?;
    docs_lint()?;
    diagram::run(&workspace_root(), false)?;
    run("cargo", &["deny", "--locked", "check"], &[])?;

    // The eBPF package has its own lockfile. The root deny.toml applies, so
    // its ignores of host advisories match nothing there.
    run(
        "cargo",
        &[
            "deny",
            "--manifest-path",
            repo::GUEST_EBPF_MANIFEST,
            "--locked",
            "check",
            "--allow",
            "advisory-not-detected",
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
        "{} writing style violation(s), see the writing style section of docs/TESTING.md",
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
            build::GUEST_TARGET,
        ],
        &[],
    )?;
    let binary = workspace_root().join(build::GUEST_AGENT);
    let bytes = std::fs::read(&binary).map_err(io(&binary))?;

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

/// Runs the soak test. Needs the same environment as [`vm_test`].
fn soak(jobs: u32) -> Result<(), TaskError> {
    vm_test("soak", &[("CRATEWARD_SOAK_JOBS", &jobs.to_string())])
}

/// Runs an ignored microVM test of the orchestrator in a systemd user scope
/// with `Delegate=yes`, which gives it a cgroup subtree for the slot limits,
/// and under the units' `UMask=0027`, so a file a VM cannot open fails here
/// as it would in production. Needs `/dev/kvm`, the guest images and
/// subordinate IDs, so it only runs on the server.
fn vm_test(test: &str, env: &[(&str, &str)]) -> Result<(), TaskError> {
    run(
        "sh",
        &[
            "-c",
            "umask 0027 && exec \"$@\"",
            "sh",
            "systemd-run",
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
            test,
            "--",
            "--ignored",
            "--nocapture",
        ],
        env,
    )
}

/// The C compiler for musl targets: `musl-gcc` when installed, otherwise
/// the host `gcc`.
fn musl_cc() -> &'static str {
    if Path::new(build::MUSL_GCC).exists() {
        "musl-gcc"
    } else {
        "gcc"
    }
}

/// Runs the canary test: a fixture crate that steals a honeytoken inside a
/// microVM must be caught. Builds the static fake internet first. Needs the
/// same environment as [`vm_test`].
fn canary() -> Result<(), TaskError> {
    run(
        "cargo",
        &[
            "build",
            "--release",
            "--locked",
            "--target",
            build::GUEST_TARGET,
            "--package",
            "crateward_fake_internet",
        ],
        // ring compiles a little C and assembly. Without `musl-tools` there
        // is no musl C compiler. The host gcc works for ring's freestanding
        // code. Installing `musl-tools` is the proper fix.
        &[("CC_x86_64_unknown_linux_musl", musl_cc())],
    )?;

    vm_test("canary", &[])
}

fn vendor() -> Result<(), TaskError> {
    run(
        "cargo",
        &[
            "vendor",
            "--locked",
            "--versioned-dirs",
            &format!("{}/vendor", build::VENDOR_DIR),
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
            build::VENDOR_DIR,
            // `gzip -n` leaves the name and time out of the header.
            "--use-compress-program=gzip -n",
            "-cf",
            build::VENDOR_ARCHIVE,
            "vendor",
        ],
        &[],
    )?;
    eprintln!("xtask: wrote {}", build::VENDOR_ARCHIVE);

    Ok(())
}
