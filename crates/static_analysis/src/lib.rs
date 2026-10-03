//! Parses crate sources without executing them and produces findings.
//!
//! Zone: trusted. Input is hostile source code, so analysis runs in a
//! separate process without network, without filesystem access (Landlock)
//! and under resource limits (see [`sandboxed`]).
//!
//! Why it looks the way it does:
//!
//! * `syn` parses every Rust file in the archive without evaluating `cfg`,
//!   so Linux, Windows and macOS code paths are all visible, and `#[path]`
//!   tricks cannot hide a file.
//! * Detectors look for network access, process spawning, downloader
//!   patterns, obfuscated strings, credential and environment access,
//!   `unsafe` usage, build scripts and proc macros. YARA-X rules complement
//!   them, and a diff against the previous version highlights what changed.
//! * Every finding carries file and line evidence, so a verdict can always
//!   be explained.
//! * The stage ends with the triage decision: whether the version needs a
//!   microVM run at all.

#![forbid(unsafe_code)]

pub mod analyze;
pub mod diff;
pub mod findings;
pub mod manifest;
pub mod rust;
pub mod sandboxed;
pub mod triage;
pub mod worker;
pub mod yara;

use std::error::Error;
use std::time::Duration;

use crateward_core::app::{self, ComponentError, Stop, fatal};
use crateward_core::blobs::BlobStore;
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::paths::host;
use crateward_core::store::{Policies, Store};
use secrecy::ExposeSecret;

use crate::worker::Analyzer;

/// The component this package implements.
pub const COMPONENT: Component = Component::StaticAnalysis;

async fn start(config: &Config) -> Result<Analyzer, Box<dyn Error>> {
    let url = config.database.url.expose_secret();
    let mut store = Store::connect(url).await?;
    store.migrate().await?;
    let heartbeats = Store::connect(url).await?;
    let blobs = BlobStore::open(&config.instance.data_dir.join(host::BLOBS))?;
    let policies = Policies::from_config(&config.stages)?;
    Ok(Analyzer::new(
        store,
        heartbeats,
        blobs,
        std::env::current_exe()?,
        (
            i64::from(config.triage.popular_min_reverse_dependencies),
            i64::try_from(config.triage.popular_min_downloads).unwrap_or(i64::MAX),
        ),
        policies,
        Duration::from_secs(config.stages.static_analysis.lease_secs),
    ))
}

/// Runs the component until SIGTERM or `Ctrl-C`. A job in progress finishes
/// first, so no lease is left to expire.
///
/// # Errors
///
/// Returns a [`ComponentError`] if startup or the job store fails.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = app::runtime().map_err(fatal)?;
    runtime.block_on(async {
        let mut analyzer = start(config).await.map_err(fatal)?;
        let stop = Stop::install().map_err(fatal)?;
        let reaper = Store::connect(config.database.url.expose_secret())
            .await
            .map_err(fatal)?;
        tokio::spawn(app::reap_loop(
            reaper,
            analyzer.policies.clone(),
            stop.clone(),
        ));
        while !stop.is_requested() {
            // Idle time goes to reports an older analyzer wrote.
            if !analyzer.run_once().await.map_err(fatal)?
                && analyzer.refresh_some().await.map_err(fatal)? == 0
            {
                stop.sleep(Duration::from_secs(1)).await;
            }
        }
        tracing::info!("stopping");
        Ok(())
    })
}
