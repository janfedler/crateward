//! Polling crates.io and turning new versions into jobs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use crateward_core::cratesio::{self, IndexEntry, ParseError};
use crateward_core::http::{Fetched, HttpError, PoliteClient, Validators};
use crateward_core::name::CrateName;
use crateward_core::store::{NewJob, Store, StoreError};
use tokio::time::Instant;

/// Largest `config.json` of the index.
const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// How long a version may stay missing from its index file before the feed
/// gives up on it. The CDN caches index files for ten minutes
/// (`cache-control: max-age=600`), so a fresh version can lag behind the
/// feed for a while. The daily dump reconciles anything given up here.
const GIVE_UP_AFTER: Duration = Duration::from_secs(2 * 60 * 60);

/// Upper bound of versions waiting for their index entry.
const MAX_PENDING: usize = 50_000;

/// Why a poll failed.
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    /// A request failed.
    #[error("http: {0}")]
    Http(#[from] HttpError),
    /// The job store failed.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// crates.io sent something that does not parse.
    #[error("parse: {0}")]
    Parse(#[from] ParseError),
    /// The index configuration is unusable.
    #[error("index config.json: {0}")]
    IndexConfig(String),
}

impl FeedError {
    /// Whether the next poll may succeed without intervention.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Http(error) => error.is_transient(),
            Self::Store(_) => true,
            Self::Parse(_) | Self::IndexConfig(_) => false,
        }
    }
}

/// Where the feed reads from.
#[derive(Debug, Clone)]
pub struct Urls {
    /// `updates.xml`.
    pub rss_updates: String,
    /// `crates.xml`.
    pub rss_new_crates: String,
    /// Sparse index root, ending in `/`.
    pub index_root: String,
}

/// A version seen in a feed, waiting for its index entry.
#[derive(Debug, Clone)]
struct Pending {
    name: CrateName,
    version: semver::Version,
    new_crate: bool,
    first_seen: Instant,
    next_try: Instant,
}

/// What one poll did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PollReport {
    /// Valid items in the feeds that changed.
    pub feed_items: usize,
    /// Feed items dropped as invalid.
    pub rejected: usize,
    /// Jobs created.
    pub enqueued: usize,
    /// Versions that were already known.
    pub already_known: usize,
    /// Versions still waiting for their index entry.
    pub waiting: usize,
    /// Versions given up on after waiting too long.
    pub gave_up: usize,
    /// Versions whose crate no longer exists.
    pub missing: usize,
}

/// Priority of a new job. Higher runs first. Signals of code that runs at
/// build time and of new crates (a common shape of typosquatting) come
/// first; popularity from the database dump is added later.
#[must_use]
pub fn priority(entry: &IndexEntry, new_crate: bool) -> i16 {
    let mut score = 0;
    if new_crate {
        score += 40;
    }
    if entry.links.is_some() || entry.has_build_dependencies() {
        score += 20;
    }
    score
}

/// The feed: RSS as the trigger, the sparse index as the source of truth.
#[derive(Debug)]
pub struct Feed {
    rss: PoliteClient,
    index: PoliteClient,
    urls: Urls,
    store: Store,
    feed_validators: HashMap<String, Validators>,
    pending: BTreeMap<(String, String), Pending>,
    /// Delay before looking up a lagging version again.
    pub index_retry: Duration,
}

impl Feed {
    /// A feed with explicit clients and URLs.
    #[must_use]
    pub fn new(rss: PoliteClient, index: PoliteClient, urls: Urls, store: Store) -> Self {
        Self {
            rss,
            index,
            urls,
            store,
            feed_validators: HashMap::new(),
            pending: BTreeMap::new(),
            index_retry: Duration::from_secs(60),
        }
    }

    /// The `dl` template from the index's `config.json`.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be fetched or has no `dl` string.
    pub async fn download_template(&self) -> Result<String, FeedError> {
        let url = format!("{}config.json", self.urls.index_root);
        match self.index.get(&url, None, MAX_CONFIG_BYTES).await? {
            Fetched::Body { body, .. } => {
                let json: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|e| FeedError::IndexConfig(e.to_string()))?;
                json.get("dl")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .ok_or_else(|| FeedError::IndexConfig("no dl string".into()))
            }
            Fetched::NotModified | Fetched::Missing => {
                Err(FeedError::IndexConfig("not available".into()))
            }
        }
    }

    async fn read_feed(&mut self, url: &str) -> Result<Option<cratesio::Feed>, FeedError> {
        let validators = self.feed_validators.get(url).cloned();
        match self
            .rss
            .get(url, validators.as_ref(), cratesio::MAX_FEED_BYTES)
            .await?
        {
            Fetched::Body { body, validators } => {
                let text = String::from_utf8_lossy(&body);
                let feed = cratesio::parse_feed(&text)?;
                self.feed_validators.insert(url.to_owned(), validators);
                Ok(Some(feed))
            }
            Fetched::NotModified => Ok(None),
            Fetched::Missing => Err(FeedError::Http(HttpError::Status(404))),
        }
    }

    /// Polls both feeds once and resolves every pending version that is
    /// due.
    ///
    /// # Errors
    ///
    /// Fails if a feed cannot be read or the store fails. Versions already
    /// queued stay pending for the next poll.
    pub async fn poll_once(&mut self) -> Result<PollReport, FeedError> {
        let mut report = PollReport::default();
        let mut new_crates = HashSet::new();
        let new_url = self.urls.rss_new_crates.clone();
        if let Some(feed) = self.read_feed(&new_url).await? {
            report.rejected += feed.rejected;
            for item in &feed.items {
                new_crates.insert(item.name.canonical());
            }
            self.queue(feed.items, &new_crates, &mut report).await?;
        }
        let updates_url = self.urls.rss_updates.clone();
        if let Some(feed) = self.read_feed(&updates_url).await? {
            report.rejected += feed.rejected;
            self.queue(feed.items, &new_crates, &mut report).await?;
        }
        self.resolve_due(&mut report).await?;
        report.waiting = self.pending.len();
        Ok(report)
    }

    async fn queue(
        &mut self,
        items: Vec<cratesio::FeedItem>,
        new_crates: &HashSet<String>,
        report: &mut PollReport,
    ) -> Result<(), FeedError> {
        let now = Instant::now();
        for item in items {
            report.feed_items += 1;
            let key = (item.name.canonical(), item.version.to_string());
            if self.pending.contains_key(&key) {
                continue;
            }
            if self.store.contains(&item.name, &key.1).await? {
                report.already_known += 1;
                continue;
            }
            if self.pending.len() >= MAX_PENDING {
                tracing::warn!("pending versions at the limit; the dump will reconcile the rest");
                break;
            }
            let new_crate = new_crates.contains(&key.0);
            self.pending.insert(
                key,
                Pending {
                    name: item.name,
                    version: item.version,
                    new_crate,
                    first_seen: now,
                    next_try: now,
                },
            );
        }
        Ok(())
    }

    async fn resolve_due(&mut self, report: &mut PollReport) -> Result<(), FeedError> {
        let now = Instant::now();
        let due: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, p)| p.next_try <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in due {
            let Some(pending) = self.pending.get(&key).cloned() else {
                continue;
            };
            let url = format!("{}{}", self.urls.index_root, pending.name.index_path());
            let text = match self
                .index
                .get(&url, None, cratesio::MAX_INDEX_FILE_BYTES)
                .await?
            {
                Fetched::Body { body, .. } => String::from_utf8_lossy(&body).into_owned(),
                Fetched::Missing => {
                    // Deleted crates vanish from the index.
                    self.pending.remove(&key);
                    report.missing += 1;
                    continue;
                }
                Fetched::NotModified => continue,
            };
            let versions = text.lines().filter(|l| !l.trim().is_empty()).count();
            match cratesio::find_version(&text, &pending.version)? {
                Some((entry, raw)) => {
                    let new_crate = pending.new_crate || versions == 1;
                    let job = NewJob {
                        priority: priority(&entry, new_crate),
                        name: entry.name.clone(),
                        version: entry.version.clone(),
                        cksum: entry.cksum,
                        published_at: entry.published,
                        index_entry: raw,
                    };
                    match self.store.enqueue(&job).await? {
                        Some(id) => {
                            report.enqueued += 1;
                            tracing::info!(
                                job = id.0,
                                name = %entry.name,
                                version = %entry.version,
                                priority = job.priority,
                                "enqueued"
                            );
                        }
                        None => report.already_known += 1,
                    }
                    self.pending.remove(&key);
                }
                None if now.duration_since(pending.first_seen) >= GIVE_UP_AFTER => {
                    self.pending.remove(&key);
                    report.gave_up += 1;
                    tracing::warn!(name = %pending.name, version = %pending.version, "gave up waiting for the index");
                }
                None => {
                    if let Some(p) = self.pending.get_mut(&key) {
                        p.next_try = now + self.index_retry;
                    }
                }
            }
        }
        Ok(())
    }
}
