//! Scores runs and stores behavior profiles.
//!
//! Zone: control plane. It reads data the other zones already parsed and
//! validated, and never talks to a guest.
//!
//! Why it looks the way it does:
//!
//! * The risk score combines static findings, dynamic events and the diff
//!   against the previous version, and every point of the score links to
//!   its evidence.
//! * Behavior is stored as a compact profile per version. When behavior is
//!   unchanged, only the diff against the previous version is stored.
//! * The analyzer decides whether a `cargo check` run escalates to a full
//!   build and test, at most once per job.

#![forbid(unsafe_code)]

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::Analyzer;

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
