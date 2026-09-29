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

pub mod archive;
pub mod proxy;
pub mod resolve;
pub mod sandboxed;
pub mod worker;

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::http::{ClientConfig, Fetched, PoliteClient};
use crateward_core::store::{Policies, Store};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::worker::{Fetcher, FetcherSetup};
use crateward_core::blobs::BlobStore;

/// The component this package implements.
pub const COMPONENT: Component = Component::Fetcher;

fn fatal(reason: impl std::fmt::Display) -> ComponentError {
    ComponentError::Fatal {
        component: COMPONENT,
        reason: reason.to_string(),
    }
}

/// The index's `config.json`, as far as the fetcher reads it.
#[derive(Deserialize)]
struct IndexConfig {
    dl: String,
}

/// The download template from the index's `config.json`.
async fn download_template(index: &PoliteClient, root: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("{root}config.json");
    let Fetched::Body { body, .. } = index.get(&url, None, 64 * 1024).await? else {
        return Err("index config.json is not available".into());
    };
    let config: IndexConfig =
        serde_json::from_slice(&body).map_err(|e| format!("index config.json: {e}"))?;
    Ok(config.dl)
}

async fn start(config: &Config) -> Result<Fetcher, Box<dyn Error>> {
    let c = &config.crates_io;
    let client = |rate| ClientConfig {
        user_agent: c.user_agent.clone(),
        requests_per_second: rate,
        timeout: Duration::from_secs(120),
        allow_plain_http: false,
    };
    let downloads = PoliteClient::new(&client(c.static_requests_per_second))?;
    let index = PoliteClient::new(&client(c.index_requests_per_second))?;
    let mut index_root = c.index_url.to_string();
    if !index_root.ends_with('/') {
        index_root.push('/');
    }
    let dl = download_template(&index, &index_root).await?;
    let url = config.database.url.expose_secret();
    let mut store = Store::connect(url).await?;
    store.migrate().await?;
    let heartbeats = Store::connect(url).await?;
    let data = &config.instance.data_dir;
    let blobs = BlobStore::open(&data.join("cas"))?;
    let work_root = config.instance.run_dir.join("fetch");
    std::fs::create_dir_all(&work_root).map_err(|e| format!("{}: {e}", work_root.display()))?;
    let setup = FetcherSetup {
        exe: std::env::current_exe()?,
        cargo: config.fetcher.cargo_bin.clone(),
        work_root,
        originals: config
            .fetcher
            .keep_originals
            .then(|| data.join("originals")),
        dl,
        index_root,
    };
    let policies = Policies::from_config(&config.stages)?;
    let worker = format!("fetcher-{}", std::process::id());
    let lease = Duration::from_secs(config.stages.fetch.lease_secs);
    Ok(Fetcher::new(
        store, heartbeats, downloads, index, blobs, setup, policies, worker, lease,
    ))
}

/// Runs the fetch stage until SIGTERM or SIGINT.
///
/// # Errors
///
/// Returns [`ComponentError::Fatal`] if the fetcher cannot start or the
/// store fails; systemd restarts it.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(fatal)?;
    runtime.block_on(async {
        let mut fetcher = start(config).await.map_err(fatal)?;
        // A signal stops the loop between jobs: a job in progress finishes,
        // so no lease is left to expire.
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
        let mut last_reap = tokio::time::Instant::now();
        while !stop.load(Ordering::SeqCst) {
            if last_reap.elapsed() >= Duration::from_secs(60) {
                let policies = fetcher.policies.clone();
                let reaped = fetcher
                    .store()
                    .reap_expired(&policies)
                    .await
                    .map_err(fatal)?;
                if reaped > 0 {
                    tracing::warn!(reaped, "reaped expired leases");
                }
                last_reap = tokio::time::Instant::now();
            }
            let worked = fetcher.run_once().await.map_err(fatal)?;
            if worked {
                continue;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        tracing::info!("stopping");
        Ok(())
    })
}
