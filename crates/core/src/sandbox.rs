//! Process sandboxing for host side workers that handle hostile input.
//!
//! A worker that parses crate archives or runs `cargo` on untrusted
//! metadata enters a sandbox before touching the input:
//!
//! * A new user namespace mapping only the caller's own user, and a new
//!   network namespace with only loopback, so it cannot reach the network.
//! * Resource limits on memory, CPU time, file size and open files.
//! * A Landlock ruleset that allows only the listed paths.
//! * `no_new_privs`.
//!
//! [`enter`] runs the whole sequence, and [`crate::child`] starts the children
//! that call it. The rootless jail of the orchestrator uses the same
//! `unshare` wrapper. This module holds the project's only `unsafe` block,
//! documented below.
//!
//! Enabled with the `sandbox` feature.

#![allow(unsafe_code)]

use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    path_beneath_rules,
};
use rustix::process::{Resource, Rlimit};
use rustix::thread::UnshareFlags;

/// The namespace sets a sandbox creates, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespaces {
    /// A new user namespace, created first and alone so that its ID maps can
    /// be written before anything else happens.
    User,
    /// New mount, network, IPC and UTS namespaces, owned by the new user
    /// namespace.
    Isolation,
    /// Only a new network namespace.
    Network,
}

impl Namespaces {
    fn flags(self) -> UnshareFlags {
        match self {
            Self::User => UnshareFlags::NEWUSER,
            Self::Isolation => {
                UnshareFlags::NEWNS
                    | UnshareFlags::NEWNET
                    | UnshareFlags::NEWIPC
                    | UnshareFlags::NEWUTS
            }
            Self::Network => UnshareFlags::NEWNET,
        }
    }
}

/// Moves the calling process into new namespaces.
///
/// # Errors
///
/// Returns the `errno` of `unshare(2)`.
pub fn unshare(namespaces: Namespaces) -> std::io::Result<()> {
    let flags = namespaces.flags();
    debug_assert!(!flags.contains(UnshareFlags::FILES));
    // SAFETY: `flags` never contains `UnshareFlags::FILES` (see `flags`),
    // which is the only reason `unshare_unsafe` is unsafe: unsharing the
    // file descriptor table could invalidate descriptors other threads use.
    // Callers are single threaded launchers or run this before starting
    // any thread.
    unsafe { rustix::thread::unshare_unsafe(flags) }.map_err(std::io::Error::from)
}

/// Why a sandbox could not be entered.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// A system call failed.
    #[error("{step}: {source}")]
    Io {
        /// The step.
        step: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Landlock could not be enforced.
    #[error("landlock: {0}")]
    Landlock(String),
}

fn io(step: &'static str) -> impl FnOnce(std::io::Error) -> SandboxError {
    move |source| SandboxError::Io { step, source }
}

/// Enters a user namespace in which the caller is root (mapped to its own
/// user outside), plus a network namespace with only a loopback device.
/// Afterwards nothing outside the host's loopback of the new namespace is
/// reachable. Must run before any thread is started.
///
/// # Errors
///
/// Fails if the kernel refuses unprivileged user namespaces.
pub fn isolate_network() -> Result<(), SandboxError> {
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    unshare(Namespaces::User).map_err(io("unsharing the user namespace"))?;
    std::fs::write("/proc/self/setgroups", "deny").map_err(io("denying setgroups"))?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).map_err(io("writing uid_map"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).map_err(io("writing gid_map"))?;
    unshare(Namespaces::Network).map_err(io("unsharing the network namespace"))?;
    Ok(())
}

/// Resource limits of a sandboxed worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Address space in bytes.
    pub address_space: u64,
    /// CPU time in seconds.
    pub cpu_seconds: u64,
    /// Largest file the process may write, in bytes.
    pub file_size: u64,
    /// Open file descriptors.
    pub open_files: u64,
}

/// Applies hard resource limits.
///
/// # Errors
///
/// Fails if a limit cannot be set.
pub fn limit(limits: Limits) -> Result<(), SandboxError> {
    for (resource, value) in [
        (Resource::As, limits.address_space),
        (Resource::Cpu, limits.cpu_seconds),
        (Resource::Fsize, limits.file_size),
        (Resource::Nofile, limits.open_files),
    ] {
        rustix::process::setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(|e| SandboxError::Io {
            step: "setting a resource limit",
            source: e.into(),
        })?;
    }
    Ok(())
}

/// Filesystem access a sandboxed worker keeps.
#[derive(Debug, Clone, Default)]
pub struct FsAccess {
    /// Paths that may be read (and executed).
    pub read: Vec<PathBuf>,
    /// Paths that may be read and written.
    pub write: Vec<PathBuf>,
}

/// Restricts the filesystem with Landlock and sets `no_new_privs`. Paths
/// not listed become inaccessible, including for child processes.
///
/// # Errors
///
/// Fails if Landlock is not enforced at all by the running kernel.
pub fn restrict_fs(access: &FsAccess) -> Result<(), SandboxError> {
    let abi = ABI::V5;
    let landlock = |e: landlock::RulesetError| SandboxError::Landlock(e.to_string());
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(landlock)?
        .create()
        .map_err(landlock)?
        .add_rules(path_beneath_rules(&access.read, AccessFs::from_read(abi)))
        .map_err(landlock)?
        .add_rules(path_beneath_rules(&access.write, AccessFs::from_all(abi)))
        .map_err(landlock)?
        .restrict_self()
        .map_err(landlock)?;
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Landlock("not enforced by this kernel".into()));
    }
    Ok(())
}

/// The messages of the steps of [`enter`] that a host without unprivileged
/// user namespaces refuses. On Ubuntu 24.04, AppArmor lets `unshare` create
/// a user namespace without capabilities, so the `setgroups` write fails
/// instead.
const REFUSED_STEPS: [&str; 6] = [
    "unsharing the user namespace",
    "denying setgroups",
    "writing uid_map",
    "writing gid_map",
    "unsharing the network namespace",
    "landlock",
];

/// For tests of sandboxed children: whether `error` only says that this host
/// refuses the sandbox, so the test should skip. Never true when
/// `CRATEWARD_REQUIRE_SANDBOX` is set, which the server's own runs do.
#[must_use]
pub fn unavailable(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    let refused = REFUSED_STEPS.iter().any(|step| message.contains(step));
    let required = std::env::var_os("CRATEWARD_REQUIRE_SANDBOX").is_some();
    if refused && !required {
        eprintln!("skipping: {message}");
    }
    refused && !required
}

/// Enters the sandbox of a worker child: no network, then `limits`, then
/// Landlock with `access`. The order matters, because Landlock comes last and
/// takes away the `/proc` writes of [`isolate_network`]. Call it before the
/// child reads any input. Nothing hostile may be parsed outside the sandbox.
///
/// # Errors
///
/// Fails at the first step the kernel refuses.
pub fn enter(limits: Limits, access: &FsAccess) -> Result<(), SandboxError> {
    isolate_network()?;
    limit(limits)?;
    restrict_fs(access)
}
