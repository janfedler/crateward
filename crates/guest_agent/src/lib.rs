//! Agent inside the microVM.
//!
//! Zone: guest. Everything in the guest, this agent included, is assumed to
//! be under the control of the crate being analyzed once its code runs. The
//! host therefore treats every byte from the agent as hostile input
//! (`crateward_core::protocol`).
//!
//! Why it looks the way it does:
//!
//! * It ships as a static musl binary and runs as PID 1, so it depends on
//!   neither the guest's C library nor an init system that a crate could
//!   tamper with, and boot takes as little time as possible.
//! * It listens on one vsock port. The host opens the only connection after
//!   the VM starts or is restored, so a listening socket, which survives
//!   snapshot restore, is all the guest needs. The host never listens for
//!   guest initiated vsock connections.
//! * Everything specific to a job arrives after restore: the workspace
//!   (drives, directories, honeytokens), the job specification and the wall
//!   clock. Nothing unique lives in the snapshot.
//! * Jobs run as an unprivileged user in their own process group, with a
//!   cleared environment, bounded output and a guest side timeout. The host
//!   enforces its own limits independently.
//! * eBPF programs (ADR 0007), loaded at boot, trace every process
//!   of the job. They live in a separate package because they build for
//!   the BPF target with a pinned nightly toolchain.

#![forbid(unsafe_code)]

pub mod btf;
pub mod init;
pub mod runner;
pub mod server;
pub mod trace;
pub mod workspace;

use crateward_core::component::Component;

/// The component this package implements.
pub const COMPONENT: Component = Component::GuestAgent;

/// Why the agent failed.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// A system call failed.
    #[error("{context}: {source}")]
    Io {
        /// What the agent was doing.
        context: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The host sent something the agent cannot handle.
    #[error("protocol: {0}")]
    Protocol(#[from] crateward_core::protocol::ProtocolError),
}

impl AgentError {
    /// Wraps an I/O error with context.
    pub fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io { context, source }
    }
}
