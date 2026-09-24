//! Runs jobs in Firecracker microVMs and guarantees their cleanup.
//!
//! Zone: untrusted. This is the only host component that starts code from a
//! crate, and it does so only inside a microVM.
//!
//! Why it looks the way it does:
//!
//! * Firecracker is driven through its API socket and always started in a
//!   rootless jail (ADR 0012): its own subordinate UID, private namespaces,
//!   `pivot_root` into a root with only the needed files, no capabilities.
//!   No process runs as root for the sandbox.
//! * Jobs start by restoring a warm snapshot. Identity, honeytokens and the
//!   clock are injected after restore, because resuming one snapshot many
//!   times would otherwise repeat entropy and identifiers.
//! * Each slot has its own network namespace whose only route leads to the
//!   fake internet, which has no uplink.
//! * Hard limits cover CPU, memory, disk, processes and wall clock time.
//!   Every host resource is named after its slot, so startup reconciliation
//!   can find and remove anything a crash left behind.
//! * Tap capture and disk diffs provide host side ground truth that a
//!   compromised guest cannot hide from.
//! * A `VmBackend` trait separates Firecracker from the scheduling logic,
//!   so CI can use a fake backend and another VMM could be added later.
//!
//! The build cache warmer ships as a second binary of this package in M1.5.

#![forbid(unsafe_code)]

pub mod backend;
pub mod cgroup;
pub mod firecracker;
pub mod jail;

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::Orchestrator;

/// Runs the component until shutdown.
///
/// # Errors
///
/// Returns [`ComponentError::NotImplemented`] until milestone M1.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(ComponentError::NotImplemented {
        component: COMPONENT,
        milestone: "M1",
    })
}
