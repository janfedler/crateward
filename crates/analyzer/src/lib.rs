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

pub mod score;

pub mod worker;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::store::{Policies, Store};
use secrecy::ExposeSecret;

use crate::worker::Analyzer;

/// The component this package implements.
pub const COMPONENT: Component = Component::Analyzer;

fn fatal(reason: impl std::fmt::Display) -> ComponentError {
    ComponentError::Fatal {
        component: COMPONENT,
        reason: reason.to_string(),
    }
}

/// Runs the analysis and finalize stages until SIGTERM or `Ctrl-C`.
///
/// # Errors
///
/// Returns [`ComponentError::Fatal`] if startup or the job store fails.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(fatal)?;
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
        let stop = Arc::new(AtomicBool::new(false));
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(fatal)?;
        let flag = Arc::clone(&stop);
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            flag.store(true, Ordering::SeqCst);
        });
        while !stop.load(Ordering::SeqCst) {
            let analyzed = analyzer.analyze_once().await.map_err(fatal)?;
            let finalized = analyzer.finalize_once().await.map_err(fatal)?;
            let rescored = if analyzed || finalized {
                0
            } else {
                analyzer.rescore_some().await.map_err(fatal)?
            };
            if !analyzed && !finalized && rescored == 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        tracing::info!("stopping");
        Ok(())
    })
}
