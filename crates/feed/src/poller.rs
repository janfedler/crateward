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

/// Index files fetched at the same time.
const INDEX_CONCURRENCY: usize = 8;

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
    /// An index lookup task panicked or was cancelled.
    #[error("index lookup: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl FeedError {
    /// Whether the next poll may succeed without intervention.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Http(error) => error.is_transient(),
            Self::Store(_) => true,
            Self::Parse(_) | Self::IndexConfig(_) | Self::Task(_) => false,
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

/// A pending version: the canonical crate name and the version text.
type Key = (String, String);

/// A version seen in a feed, waiting for its index entry.
#[derive(Debug, Clone)]
struct Pending {
    name: CrateName,
    version: semver::Version,
    new_crate: bool,
    first_seen: Instant,
    next_try: Instant,
}

impl Pending {
    /// Whether the feed has waited long enough for the index entry.
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.first_seen) >= GIVE_UP_AFTER
    }
}

/// A pending version with what its index file said.
type Lookup = (Key, Pending, Result<Fetched, HttpError>);

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

/// Priority of a new job. Higher runs first: new crates (a common shape of
/// typosquatting), updates to popular crates (a compromise reaches many
/// users), and signals of code that runs at build time.
#[must_use]
pub fn priority(entry: &IndexEntry, new_crate: bool, popular: bool) -> i16 {
    let mut score = 0;
    if new_crate {
        score += 40;
    }

    if popular {
        score += 30;
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
    pending: BTreeMap<Key, Pending>,
    /// Delay before looking up a lagging version again.
    pub index_retry: Duration,
    /// Reverse dependencies from which a crate counts as popular.
    pub popular_threshold: i64,
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
            popular_threshold: 100,
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
            // New crate items carry no version. Their first version arrives
            // through `updates.xml`.
            let Some(version) = item.version else {
                continue;
            };

            report.feed_items += 1;

            let key = (item.name.canonical(), version.to_string());
            if self.pending.contains_key(&key) {
                continue;
            }

            if self.store.contains(&item.name, &key.1).await? {
                report.already_known += 1;
                continue;
            }

            if self.pending.len() >= MAX_PENDING {
                tracing::warn!("pending versions at the limit, the dump will reconcile the rest");
                break;
            }

            let new_crate = new_crates.contains(&key.0);
            self.pending.insert(
                key,
                Pending {
                    name: item.name,
                    version,
                    new_crate,
                    first_seen: now,
                    next_try: now,
                },
            );
        }

        Ok(())
    }

    /// Looks up every version that is due in its index file.
    async fn resolve_due(&mut self, report: &mut PollReport) -> Result<(), FeedError> {
        let now = Instant::now();
        for (key, pending, fetched) in self.fetch_due(now).await? {
            let text = match fetched? {
                Fetched::Body { body, .. } => String::from_utf8_lossy(&body).into_owned(),
                Fetched::Missing => {
                    // Deleted crates vanish from the index.
                    self.pending.remove(&key);
                    report.missing += 1;
                    continue;
                }
                Fetched::NotModified => continue,
            };

            self.settle(&key, &pending, &text, now, report).await?;
        }

        Ok(())
    }

    /// Fetches the index files of the versions that are due, several at a
    /// time. The client's pacer still bounds the request rate. Freshly
    /// published index files often miss the CDN cache, so latency, not rate,
    /// dominates.
    async fn fetch_due(&self, now: Instant) -> Result<Vec<Lookup>, FeedError> {
        let mut fetches = tokio::task::JoinSet::new();
        let mut results = Vec::new();

        for (key, pending) in self.pending.iter().filter(|(_, p)| p.next_try <= now) {
            if fetches.len() >= INDEX_CONCURRENCY
                && let Some(done) = fetches.join_next().await
            {
                results.push(done?);
            }

            let url = format!("{}{}", self.urls.index_root, pending.name.index_path());
            let client = self.index.clone();
            let (key, pending) = (key.clone(), pending.clone());
            fetches.spawn(async move {
                let fetched = client.get(&url, None, cratesio::MAX_INDEX_FILE_BYTES).await;
                (key, pending, fetched)
            });
        }

        while let Some(done) = fetches.join_next().await {
            results.push(done?);
        }

        Ok(results)
    }

    /// Enqueues the version if its index file has it, else waits or gives up.
    async fn settle(
        &mut self,
        key: &Key,
        pending: &Pending,
        text: &str,
        now: Instant,
        report: &mut PollReport,
    ) -> Result<(), FeedError> {
        let Some((entry, raw)) = cratesio::find_version(text, &pending.version)? else {
            self.wait_or_give_up(key, pending, now, report);
            return Ok(());
        };

        let versions = text.lines().filter(|l| !l.trim().is_empty()).count();
        let new_crate = pending.new_crate || versions == 1;
        let popular = self
            .store
            .reverse_dependencies(&entry.name)
            .await?
            .is_some_and(|n| n >= self.popular_threshold);
        let job = NewJob {
            priority: priority(&entry, new_crate, popular),
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

        self.pending.remove(key);

        Ok(())
    }

    /// The index does not have the version yet: look again later, or give up.
    fn wait_or_give_up(
        &mut self,
        key: &Key,
        pending: &Pending,
        now: Instant,
        report: &mut PollReport,
    ) {
        if pending.expired(now) {
            self.pending.remove(key);
            report.gave_up += 1;
            tracing::warn!(name = %pending.name, version = %pending.version, "gave up waiting for the index");
        } else if let Some(p) = self.pending.get_mut(key) {
            p.next_try = now + self.index_retry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_since(first_seen: Instant) -> Pending {
        Pending {
            name: CrateName::parse("demo").unwrap(),
            version: semver::Version::new(1, 0, 0),
            new_crate: false,
            first_seen,
            next_try: first_seen,
        }
    }

    #[test]
    fn a_version_expires_after_two_hours_and_not_before() {
        let seen = Instant::now();
        let pending = pending_since(seen);
        let hours = |h: u64| seen + Duration::from_secs(h * 3600);

        assert!(!pending.expired(seen));
        assert!(!pending.expired(hours(1)));
        assert!(!pending.expired(hours(2) - Duration::from_millis(1)));
        assert!(pending.expired(hours(2)));
        assert!(pending.expired(hours(3)));
    }
}
