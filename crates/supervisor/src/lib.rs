//! Keeps the pipeline healthy without a human.
//!
//! Zone: control plane.
//!
//! Why it looks the way it does: autonomy means every failure class has an
//! automated response before anyone is paged. The supervisor owns those
//! responses:
//!
//! * health checks and a circuit breaker per stage, so persistent
//!   infrastructure trouble pauses only the affected stage;
//! * startup reconciliation of VMs, tap devices, overlays and disk space;
//! * hourly canaries with a known good and a known bad inert crate;
//! * the weekly image refresh, promoted only when canaries pass;
//! * retention jobs and disk usage alerts;
//! * quarantine, which pauses the whole pipeline;
//! * alerts through the notifier (ntfy) for the closed list of escalations
//!   in `crateward_core::escalation`, deduplicated and rate limited;
//! * the heartbeat to healthchecks.io, which alerts when this server stops.

#![forbid(unsafe_code)]

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::Supervisor;

/// Runs the component until shutdown.
///
/// # Errors
///
/// Returns [`ComponentError::NotImplemented`] until milestone M5.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(ComponentError::NotImplemented {
        component: COMPONENT,
        milestone: "M5",
    })
}
