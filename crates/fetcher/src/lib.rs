//! Downloads, verifies and validates crates and resolves their dependencies.
//!
//! Zone: trusted. The fetcher and the feed are the only components with
//! real internet access, and nftables restricts even that to the crates.io
//! hosts.
//!
//! Why it looks the way it does:
//!
//! * Every `.crate` file is checked against the SHA-256 from the index
//!   before any other code touches it. Its SHA-512 is recorded for SBOMs
//!   (ADR 0012), and while there is no job the fetcher downloads files
//!   fetched before that again to add it.
//! * Archives are validated in a sandboxed subprocess without being
//!   extracted. Path traversal, links, device files and special files are
//!   findings, and size, file count, depth and compression ratio are
//!   capped. A rejected archive is a finding, not an error.
//! * Dependencies are resolved for all targets by generating a small
//!   consumer package that depends on the exact version under analysis.
//!   This mirrors how a victim would pull the crate in, and it means cargo
//!   never reads configuration shipped inside the crate. The resolving
//!   subprocess reaches only a local registry proxy, never the internet.
//!   The fetcher then fetches and validates every locked crate itself.
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
use std::time::Duration;

use crateward_core::app::{self, ComponentError, Stop, fatal};
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::http::{ClientConfig, Fetched, PoliteClient};
use crateward_core::paths::host;
use crateward_core::store::{Policies, Store};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::proxy::Index;
use crate::worker::{Fetcher, FetcherSetup};
use crateward_core::blobs::BlobStore;

/// The component this package implements.
pub const COMPONENT: Component = Component::Fetcher;

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
    let index_client = PoliteClient::new(&client(c.index_requests_per_second))?;
    let mut index_root = c.index_url.to_string();
    if !index_root.ends_with('/') {
        index_root.push('/');
    }

    let dl = download_template(&index_client, &index_root).await?;
    let index = Index::new(index_client, &index_root);
    let url = config.database.url.expose_secret();
    let mut store = Store::connect(url).await?;
    store.migrate().await?;
    let heartbeats = Store::connect(url).await?;
    let data = &config.instance.data_dir;
    let blobs = BlobStore::open(&data.join(host::BLOBS))?;
    let work_root = config.instance.run_dir.join(host::FETCH_WORK);
    std::fs::create_dir_all(&work_root).map_err(|e| format!("{}: {e}", work_root.display()))?;
    let setup = FetcherSetup {
        exe: std::env::current_exe()?,
        cargo: config.fetcher.cargo_bin.clone(),
        work_root,
        originals: config
            .fetcher
            .keep_originals
            .then(|| data.join(host::ORIGINALS)),
        dl,
        blobs,
    };

    let policies = Policies::from_config(&config.stages)?;
    let lease = Duration::from_secs(config.stages.fetch.lease_secs);

    Ok(Fetcher::new(
        store, heartbeats, downloads, index, setup, policies, lease,
    ))
}

/// Runs the fetch stage until SIGTERM or SIGINT.
///
/// # Errors
///
/// Returns a [`ComponentError`] if the fetcher cannot start or the
/// store fails, and systemd restarts it.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = app::runtime().map_err(fatal)?;

    runtime.block_on(async {
        let mut fetcher = start(config).await.map_err(fatal)?;
        let stop = Stop::install().map_err(fatal)?;
        let reaper = Store::connect(config.database.url.expose_secret())
            .await
            .map_err(fatal)?;

        tokio::spawn(app::reap_loop(
            reaper,
            fetcher.policies.clone(),
            stop.clone(),
        ));

        while !stop.is_requested() {
            if !fetcher.run_once().await.map_err(fatal)?
                && !fetcher.hash_one().await.map_err(fatal)?
            {
                stop.sleep(Duration::from_secs(1)).await;
            }
        }

        tracing::info!("stopping");
        Ok(())
    })
}
