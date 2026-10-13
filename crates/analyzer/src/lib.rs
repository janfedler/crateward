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
//! * Behavior is stored as a compact profile per version. Behavior that is
//!   new against the previous version's profile scores again.
//! * The analyzer decides whether a `cargo check` run escalates to a full
//!   build and test, at most once per job.
//! * Finalize writes the job's CycloneDX SBOM. Idle time writes those of
//!   older jobs and completes SBOMs whose data has arrived since.

#![forbid(unsafe_code)]

pub mod score;

pub mod worker;

use std::time::Duration;

use crateward_core::app::{self, ComponentError, Stop, fatal};
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::store::{Policies, Store};
use secrecy::ExposeSecret;

use crate::worker::Analyzer;

/// The component this package implements.
pub const COMPONENT: Component = Component::Analyzer;

/// Runs the analysis and finalize stages until SIGTERM or `Ctrl-C`.
///
/// # Errors
///
/// Returns a [`ComponentError`] if startup or the job store fails.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = app::runtime().map_err(fatal)?;

    runtime.block_on(async {
        let mut store = Store::connect(config.database.url.expose_secret())
            .await
            .map_err(fatal)?;

        store.migrate().await.map_err(fatal)?;
        let policies = Policies::from_config(&config.stages).map_err(fatal)?;
        let mut analyzer = Analyzer::new(
            store,
            policies,
            format!("analyzer-{}", std::process::id()),
            Duration::from_secs(config.stages.analysis.lease_secs),
        );

        let stop = Stop::install().map_err(fatal)?;
        while !stop.is_requested() {
            let analyzed = analyzer.analyze_once().await.map_err(fatal)?;
            let finalized = analyzer.finalize_once().await.map_err(fatal)?;
            let idle = if analyzed || finalized {
                0
            } else {
                match analyzer.rescore_some().await.map_err(fatal)? {
                    0 => analyzer.refresh_sboms().await.map_err(fatal)?,
                    rescored => rescored,
                }
            };

            if !analyzed && !finalized && idle == 0 {
                stop.sleep(Duration::from_secs(1)).await;
            }
        }

        tracing::info!("stopping");
        Ok(())
    })
}
