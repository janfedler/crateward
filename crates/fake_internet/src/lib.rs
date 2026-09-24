//! DNS, HTTP and HTTPS sinks that stand in for the internet.
//!
//! Zone: untrusted. The sinks run unprivileged in a network namespace that
//! has no uplink at all, so even a compromise of this component gives a
//! crate no path to the real internet.
//!
//! Why it looks the way it does:
//!
//! * Every connection attempt from a guest is redirected here and logged
//!   with its intended destination, recovered with `SO_ORIGINAL_DST`.
//! * Responses are plausible enough to keep a downloader talking, so the
//!   next stage of an attack becomes visible.
//! * HTTPS is terminated with a certificate authority baked into the guest
//!   image; its private key never leaves the host.
//! * Parsers of guest traffic are fuzz targets, because the guest controls
//!   every byte they see.

#![forbid(unsafe_code)]

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::FakeInternet;

/// Runs the component until shutdown.
///
/// # Errors
///
/// Returns [`ComponentError::NotImplemented`] until milestone M4.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(ComponentError::NotImplemented {
        component: COMPONENT,
        milestone: "M4",
    })
}
