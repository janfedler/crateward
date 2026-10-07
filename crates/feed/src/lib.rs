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

pub mod dump;
pub mod poller;

use std::time::Duration;

use crateward_core::app::{self, ComponentError, Stop, fatal};
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::http::{ClientConfig, PoliteClient};
use crateward_core::store::Store;
use secrecy::ExposeSecret;

use crate::poller::{Feed, FeedError, Urls};

/// The component this package implements.
pub const COMPONENT: Component = Component::Feed;

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

    let mut feed = Feed::new(rss, index, urls, store);
    feed.popular_threshold = i64::from(config.triage.popular_min_reverse_dependencies);

    Ok(feed)
}

/// Refreshes crate popularity from the dump now and then every
/// `db_dump_refresh_hours`, on its own connection.
fn spawn_dump_refresh(config: &Config) -> Result<(), ComponentError> {
    let c = &config.crates_io;
    let client = PoliteClient::new(&ClientConfig {
        user_agent: c.user_agent.clone(),
        requests_per_second: c.static_requests_per_second,
        timeout: Duration::from_secs(3600),
        allow_plain_http: false,
    })
    .map_err(fatal)?;

    let url = c.db_dump_url.to_string();
    let every = Duration::from_secs(c.db_dump_refresh_hours * 3600);
    let database = config.database.url.expose_secret().to_owned();
    tokio::spawn(async move {
        loop {
            let started = tokio::time::Instant::now();
            let result = match Store::connect(&database).await {
                Ok(store) => dump::refresh(&client, &url, &store).await,
                Err(error) => Err(error.into()),
            };

            match result {
                Ok(crates) => tracing::info!(
                    crates,
                    seconds = started.elapsed().as_secs(),
                    "dump statistics refreshed"
                ),
                Err(error) => {
                    tracing::warn!(%error, "dump refresh failed, retrying at the next interval");
                }
            }

            tokio::time::sleep(every).await;
        }
    });

    Ok(())
}

/// Runs the feed until SIGTERM or SIGINT.
///
/// # Errors
///
/// Returns a [`ComponentError`] if the feed cannot start or hits a
/// permanent error, and systemd restarts it.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = app::runtime().map_err(fatal)?;

    runtime.block_on(async {
        let mut feed = start(config).await.map_err(fatal)?;
        spawn_dump_refresh(config)?;
        let interval = Duration::from_secs(config.crates_io.rss_poll_interval_secs);
        let stop = Stop::install().map_err(fatal)?;
        while !stop.is_requested() {
            match feed.poll_once().await {
                Ok(report) => tracing::info!(?report, "poll finished"),
                Err(error) if error.is_transient() => {
                    tracing::warn!(%error, "poll failed, retrying at the next interval");
                }
                Err(error) => return Err(fatal(error)),
            }

            stop.sleep(interval).await;
        }

        tracing::info!("stopping");
        Ok(())
    })
}
