//! The feed against a mock crates.io and a real PostgreSQL.
//!
//! The mock serves the two RSS feeds, sparse index files and `config.json`
//! over plain HTTP on localhost, answers conditional requests with 304, and
//! counts requests per path. The database setup is
//! `crateward_core::testing`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use crateward_core::http::{ClientConfig, HttpError, PoliteClient};
use crateward_core::job::{JobId, Stage};
use crateward_core::testing::TestDb;
use crateward_feed::poller::{Feed, FeedError, Urls};
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

#[derive(Default)]
struct MockState {
    files: HashMap<String, String>,
    /// Paths that answer with a server error.
    broken: HashSet<String>,
    hits: HashMap<String, usize>,
    not_modified: usize,
}

type Shared = Arc<Mutex<MockState>>;

fn etag(body: &str) -> String {
    format!(
        "\"{}-{}\"",
        body.len(),
        body.bytes().map(u32::from).sum::<u32>()
    )
}

async fn serve(
    state: Shared,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_owned();
    let mut s = state.lock().unwrap();
    *s.hits.entry(path.clone()).or_default() += 1;

    if s.broken.contains(&path) {
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::default())
            .unwrap());
    }

    let Some(body) = s.files.get(&path).cloned() else {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::default())
            .unwrap());
    };

    let tag = etag(&body);

    if req
        .headers()
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        == Some(tag.as_str())
    {
        s.not_modified += 1;
        return Ok(Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Full::default())
            .unwrap());
    }

    Ok(Response::builder()
        .header("etag", tag)
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn start_mock(state: Shared) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| serve(Arc::clone(&state), req));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

fn rss(items: &[(&str, &str)]) -> String {
    let items: String = items
        .iter()
        .map(|(n, v)| {
            // `crates.xml` items carry no version, like the real feed.
            let version = if v.is_empty() {
                String::new()
            } else {
                format!("<crates:version>{v}</crates:version>")
            };

            format!("<item><crates:name>{n}</crates:name>{version}</item>")
        })
        .collect();
    format!(
        r#"<?xml version="1.0"?><rss xmlns:crates="https://crates.io/"><channel>{items}</channel></rss>"#
    )
}

fn index_line(name: &str, version: &str, extra: &str) -> String {
    format!(
        r#"{{"name":"{name}","vers":"{version}","deps":[],"cksum":"{}","features":{{}},"yanked":false{extra}}}"#,
        "ab".repeat(32)
    )
}

fn client() -> PoliteClient {
    PoliteClient::new(&ClientConfig {
        user_agent: "crateward-test/0 (+https://example.com)".into(),
        requests_per_second: 1000.0,
        timeout: Duration::from_secs(5),
        allow_plain_http: true,
    })
    .unwrap()
}

#[tokio::test]
async fn new_versions_become_prioritized_jobs_exactly_once() {
    let Some(db) = TestDb::new("feed").await else {
        return;
    };

    let store = db.migrated().await;
    let state: Shared = Arc::default();
    let base = start_mock(Arc::clone(&state)).await;
    {
        let mut s = state.lock().unwrap();
        s.files.insert(
            "/index/config.json".into(),
            format!(r#"{{"dl":"{base}/crates"}}"#),
        );
        s.files
            .insert("/rss/crates.xml".into(), rss(&[("brand-new", "")]));
        s.files.insert(
            "/rss/updates.xml".into(),
            rss(&[
                ("brand-new", "0.1.0"),
                ("Popular", "2.0.0"),
                ("lagging", "1.1.0"),
                ("../evil", "1.0.0"),
            ]),
        );
        s.files.insert(
            "/index/br/an/brand-new".into(),
            index_line("brand-new", "0.1.0", r#","links":"z""#),
        );
        s.files.insert(
            "/index/po/pu/popular".into(),
            format!(
                "{}\n{}\n",
                index_line("Popular", "1.0.0", ""),
                index_line("Popular", "2.0.0", "")
            ),
        );

        // The CDN has not caught up with 1.1.0 yet.
        s.files.insert(
            "/index/la/gg/lagging".into(),
            index_line("lagging", "1.0.0", ""),
        );
    }

    let urls = Urls {
        rss_updates: format!("{base}/rss/updates.xml"),
        rss_new_crates: format!("{base}/rss/crates.xml"),
        index_root: format!("{base}/index/"),
    };

    let mut feed = Feed::new(client(), client(), urls, store);
    feed.index_retry = Duration::ZERO;

    assert_eq!(
        feed.download_template().await.unwrap(),
        format!("{base}/crates")
    );

    let first = feed.poll_once().await.unwrap();
    assert_eq!(first.enqueued, 2, "{first:?}");
    assert_eq!(first.rejected, 1, "{first:?}");
    assert_eq!(first.waiting, 1, "{first:?}");

    // The lagging version appears in the index. The feeds did not change.
    state.lock().unwrap().files.insert(
        "/index/la/gg/lagging".into(),
        format!(
            "{}\n{}\n",
            index_line("lagging", "1.0.0", ""),
            index_line("lagging", "1.1.0", "")
        ),
    );
    let second = feed.poll_once().await.unwrap();

    assert_eq!(second.enqueued, 1, "{second:?}");
    assert_eq!(
        second.feed_items, 0,
        "unchanged feeds were read again: {second:?}"
    );
    assert_eq!(second.waiting, 0);
    assert_eq!(
        state.lock().unwrap().not_modified,
        2,
        "feeds were not fetched conditionally"
    );

    // Nothing is enqueued twice, even when the feeds change and repeat items.
    state.lock().unwrap().files.insert(
        "/rss/updates.xml".into(),
        rss(&[("brand-new", "0.1.0"), ("Popular", "2.0.0")]),
    );
    let third = feed.poll_once().await.unwrap();

    assert_eq!(third.enqueued, 0, "{third:?}");
    assert_eq!(third.already_known, 2, "{third:?}");

    // The new crate with a native link comes first. The name keeps its
    // published casing from the index, not the feed's.
    let check = db.store().await;
    let first_claim = check
        .claim(Stage::Fetch, "t", Duration::from_secs(30))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(first_claim.name, "brand-new");
    assert_eq!(first_claim.priority, 60);

    let popular = check
        .get(JobId(first_claim.id.0 + 1))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(popular.name, "Popular");
    assert_eq!(popular.priority, 0);
    assert_eq!(
        check.count_by_state().await.unwrap().get("Discovered"),
        Some(&3)
    );

    db.drop().await;
}

/// A feed against the mock, in a schema of its own.
struct World {
    state: Shared,
    feed: Feed,
    db: TestDb,
}

impl World {
    /// The feeds are empty and the retry delay is zero.
    async fn new(test: &str) -> Option<Self> {
        let db = TestDb::new(&format!("feed_{test}")).await?;
        let store = db.migrated().await;
        let state: Shared = Arc::default();
        let base = start_mock(Arc::clone(&state)).await;
        let urls = Urls {
            rss_updates: format!("{base}/rss/updates.xml"),
            rss_new_crates: format!("{base}/rss/crates.xml"),
            index_root: format!("{base}/index/"),
        };

        let mut feed = Feed::new(client(), client(), urls, store);
        feed.index_retry = Duration::ZERO;
        let world = Self { state, feed, db };
        world.serve("/rss/crates.xml", rss(&[]));
        world.serve("/rss/updates.xml", rss(&[]));
        Some(world)
    }

    fn serve(&self, path: &str, body: String) {
        self.state.lock().unwrap().files.insert(path.into(), body);
    }

    fn hits(&self, path: &str) -> usize {
        let state = self.state.lock().unwrap();
        state.hits.get(path).copied().unwrap_or(0)
    }

    /// The queued jobs as name and priority, sorted by name.
    async fn jobs(&self) -> Vec<(String, i16)> {
        let store = self.db.store().await;
        let mut jobs = Vec::new();

        while let Some(job) = store
            .claim(Stage::Fetch, "t", Duration::from_secs(30))
            .await
            .unwrap()
        {
            jobs.push((job.name, job.priority));
        }

        jobs.sort();
        jobs
    }

    async fn finish(self) {
        self.db.drop().await;
    }
}

#[tokio::test]
async fn deleted_crates_are_dropped_and_lagging_versions_wait_for_their_turn() {
    let Some(mut world) = World::new("waiting").await else {
        return;
    };

    world.serve(
        "/rss/updates.xml",
        rss(&[("ghost", "1.0.0"), ("lagging", "1.1.0")]),
    );
    world.serve("/index/la/gg/lagging", index_line("lagging", "1.0.0", ""));
    world.feed.index_retry = Duration::from_secs(3600);

    let first = world.feed.poll_once().await.unwrap();
    assert_eq!(first.feed_items, 2, "{first:?}");
    assert_eq!(first.missing, 1, "{first:?}");
    assert_eq!(first.waiting, 1, "{first:?}");
    assert_eq!(first.enqueued, 0, "{first:?}");

    // The lagging version is not due again for an hour. The deleted crate
    // is not looked up again at all.
    let second = world.feed.poll_once().await.unwrap();

    assert_eq!(second.feed_items, 0, "{second:?}");
    assert_eq!(second.missing, 0, "{second:?}");
    assert_eq!(second.waiting, 1, "{second:?}");
    assert_eq!(world.hits("/index/gh/os/ghost"), 1);
    assert_eq!(world.hits("/index/la/gg/lagging"), 1);
    assert!(world.jobs().await.is_empty());

    world.finish().await;
}

#[tokio::test]
async fn priority_adds_new_crates_popularity_and_build_time_signals() {
    let Some(mut world) = World::new("priority").await else {
        return;
    };

    world
        .db
        .store()
        .await
        .upsert_crate_stats(&[
            ("busy".into(), 5000, 100),
            ("quiet".into(), 10, 99),
            ("both".into(), 1, 500),
        ])
        .await
        .unwrap();
    world.serve(
        "/rss/updates.xml",
        rss(&[
            ("solo", "1.0.0"),
            ("busy", "2.0.0"),
            ("quiet", "2.0.0"),
            ("linked", "2.0.0"),
            ("both", "1.0.0"),
        ]),
    );
    let two = |name: &str, extra: &str| {
        format!(
            "{}\n{}\n",
            index_line(name, "1.0.0", ""),
            index_line(name, "2.0.0", extra)
        )
    };

    let links = r#","links":"z""#;

    // The index file of a crate with one version marks a new crate.
    world.serve("/index/so/lo/solo", index_line("solo", "1.0.0", ""));
    world.serve("/index/bu/sy/busy", two("busy", ""));
    world.serve("/index/qu/ie/quiet", two("quiet", ""));
    world.serve("/index/li/nk/linked", two("linked", links));
    world.serve("/index/bo/th/both", index_line("both", "1.0.0", links));

    let report = world.feed.poll_once().await.unwrap();
    assert_eq!(report.enqueued, 5, "{report:?}");

    let expected = [
        ("both", 90),
        ("busy", 30),
        ("linked", 20),
        ("quiet", 0),
        ("solo", 40),
    ];

    assert_eq!(
        world.jobs().await,
        expected.map(|(name, priority)| (name.to_owned(), priority))
    );

    world.finish().await;
}

#[tokio::test]
async fn a_failing_index_fetch_fails_the_poll_and_the_version_stays_queued() {
    let Some(mut world) = World::new("failing").await else {
        return;
    };

    world.serve("/rss/updates.xml", rss(&[("flaky", "1.0.0")]));
    world.serve("/index/fl/ak/flaky", index_line("flaky", "1.0.0", ""));
    let broken = "/index/fl/ak/flaky".to_owned();
    world.state.lock().unwrap().broken.insert(broken.clone());

    let error = world.feed.poll_once().await.unwrap_err();
    assert!(
        matches!(error, FeedError::Http(HttpError::Server(500))),
        "{error}"
    );
    assert!(error.is_transient());
    assert!(world.jobs().await.is_empty());

    // The feeds did not change, so only the queued version can bring the job.
    world.state.lock().unwrap().broken.remove(&broken);
    let report = world.feed.poll_once().await.unwrap();

    assert_eq!(report.feed_items, 0, "{report:?}");
    assert_eq!(report.enqueued, 1, "{report:?}");
    assert_eq!(report.waiting, 0, "{report:?}");
    assert_eq!(world.jobs().await, [("flaky".to_owned(), 40)]);

    world.finish().await;
}

#[tokio::test]
async fn an_index_file_that_does_not_parse_is_a_permanent_error() {
    let Some(mut world) = World::new("garbled").await else {
        return;
    };

    world.serve("/rss/updates.xml", rss(&[("garbled", "1.0.0")]));
    world.serve("/index/ga/rb/garbled", "this is not json\n".into());

    let error = world.feed.poll_once().await.unwrap_err();
    assert!(matches!(error, FeedError::Parse(_)), "{error}");
    assert!(!error.is_transient());
    assert!(world.jobs().await.is_empty());

    world.finish().await;
}
