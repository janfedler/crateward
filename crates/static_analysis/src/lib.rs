//! Parses crate sources without executing them and produces findings.
//!
//! Zone: trusted. Input is hostile source code, so analysis runs in a
//! separate process with rlimits, Landlock and seccomp.
//!
//! Why it looks the way it does:
//!
//! * `syn` parses every file without evaluating `cfg`, so Linux, Windows and
//!   macOS code paths are all visible. Module resolution follows `#[path]`
//!   and `cfg_attr` across every branch for the same reason.
//! * Detectors look for network access, process spawning, downloader
//!   patterns, obfuscated strings, credential and environment access,
//!   `unsafe` usage, build scripts and proc macros. YARA-X rules complement
//!   them, and a diff against the previous version highlights what changed.
//! * Every finding carries file and line evidence, so a verdict can always
//!   be explained.
//! * The stage ends with the triage decision: whether the version needs a
//!   microVM run at all.

#![forbid(unsafe_code)]

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::StaticAnalysis;

/// Runs the component until shutdown.
///
/// # Errors
///
/// Returns [`ComponentError::NotImplemented`] until milestone M3.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(ComponentError::NotImplemented {
        component: COMPONENT,
        milestone: "M3",
    })
}
