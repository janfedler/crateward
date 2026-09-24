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

pub mod poller;

use std::time::Duration;

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::http::{ClientConfig, PoliteClient};
use crateward_core::store::Store;
use secrecy::ExposeSecret;

use crate::poller::{Feed, FeedError, Urls};

/// The component this package implements.
pub const COMPONENT: Component = Component::Feed;

fn fatal(reason: impl std::fmt::Display) -> ComponentError {
    ComponentError::Fatal {
        component: COMPONENT,
        reason: reason.to_string(),
    }
}

async fn start(config: &Config) -> Result<Feed, FeedError> {
    let c = &config.crates_io;
    let client = |rate| ClientConfig {
        user_agent: c.user_agent.clone(),
        requests_per_second: rate,
        timeout: Duration::from_secs(60),
        allow_plain_http: false,
    };
    let rss = PoliteClient::new(&client(c.static_requests_per_second))?;
    let index = PoliteClient::new(&client(c.index_requests_per_second))?;
    let mut store = Store::connect(config.database.url.expose_secret()).await?;
    store.migrate().await?;
    let mut index_root = c.index_url.to_string();
    if !index_root.ends_with('/') {
        index_root.push('/');
    }
    let urls = Urls {
        rss_updates: c.rss_updates_url.to_string(),
        rss_new_crates: c.rss_new_crates_url.to_string(),
        index_root,
    };
    Ok(Feed::new(rss, index, urls, store))
}

/// Runs the feed until SIGTERM or SIGINT.
///
/// # Errors
///
/// Returns [`ComponentError::Fatal`] if the feed cannot start or hits a
/// permanent error; systemd restarts it.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(fatal)?;
    runtime.block_on(async {
        let mut feed = start(config).await.map_err(fatal)?;
        let interval = Duration::from_secs(config.crates_io.rss_poll_interval_secs);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(fatal)?;
        loop {
            match feed.poll_once().await {
                Ok(report) => tracing::info!(?report, "poll finished"),
                Err(error) if error.is_transient() => {
                    tracing::warn!(%error, "poll failed; retrying at the next interval");
                }
                Err(error) => return Err(fatal(error)),
            }
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                _ = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }
        tracing::info!("stopping");
        Ok(())
    })
}
