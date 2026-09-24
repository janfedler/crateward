//! Dashboard and read only API.
//!
//! Zone: control plane. The admin view is reachable only through WireGuard
//! and requires a passkey. The public view is a static export pushed to
//! GitHub Pages; this server never serves the public.
//!
//! Why it looks the way it does:
//!
//! * Server rendered HTML with htmx and server sent events needs no
//!   JavaScript build chain and allows a strict Content Security Policy.
//! * Templates escape by default, and crate supplied text such as READMEs
//!   is never rendered as raw HTML.
//! * The database role is read only.

#![forbid(unsafe_code)]

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::Api;

/// Runs the component until shutdown.
///
/// # Errors
///
/// Returns [`ComponentError::NotImplemented`] until milestone M6.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(ComponentError::NotImplemented {
        component: COMPONENT,
        milestone: "M6",
    })
}
