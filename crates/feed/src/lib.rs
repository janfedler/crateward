//! Discovers new crates.io versions and creates their jobs.
//!
//! Zone: trusted. The feed reads public metadata only and never downloads
//! crate files.
//!
//! Why it looks the way it does: the crates.io data access policy asks
//! clients to prefer the sparse index, feeds and database dump over the API,
//! so the feed combines three sources, each used for what it is best at:
//!
//! * The RSS feeds (`updates.xml`, `crates.xml`) are polled every few
//!   minutes as a cheap trigger. They cover the last 60 minutes.
//! * The sparse index file of each crate is the source of truth for the
//!   checksum, dependencies, features, publish time and yank status. It is
//!   fetched with conditional requests.
//! * The daily database dump reconciles anything the feeds missed and
//!   provides the reverse dependency graph and download counts that drive
//!   priorities.
//!
//! Enqueueing is idempotent: a crate name and version pair maps to exactly
//! one job, however often it is seen.

#![forbid(unsafe_code)]

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::Feed;

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
