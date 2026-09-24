//! Downloads, verifies, safely extracts and vendors crates.
//!
//! Zone: trusted. The fetcher is the only component with real internet
//! access, and nftables restricts even that to the crates.io hosts.
//!
//! Why it looks the way it does:
//!
//! * Every `.crate` file is checked against the SHA-256 from the index
//!   before any other code touches it.
//! * Extraction runs in a sandboxed subprocess and rejects path traversal,
//!   links, device files and special files, and caps size, file count,
//!   depth and compression ratio. A rejected archive is a finding, not an
//!   error.
//! * Dependencies are vendored for all targets by generating a small
//!   consumer package that depends on the exact version under analysis.
//!   This mirrors how a victim would pull the crate in, and it means cargo
//!   never reads configuration shipped inside the crate. The vendoring
//!   subprocess reaches only a local registry proxy, never the internet.
//! * Blobs are stored content addressed and zstd compressed, so shared
//!   dependencies are stored once.
//!
//! No crate code is ever executed here.

#![forbid(unsafe_code)]

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::Fetcher;

/// Runs the component until shutdown.
///
/// # Errors
///
/// Returns [`ComponentError::NotImplemented`] until milestone M2.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(ComponentError::NotImplemented {
        component: COMPONENT,
        milestone: "M2",
    })
}
