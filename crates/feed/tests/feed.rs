//! The feed against a mock crates.io and a real PostgreSQL.
//!
//! The mock serves the two RSS feeds, sparse index files and `config.json`
//! over plain HTTP on localhost, answers conditional requests with 304, and
//! counts requests per path. Needs `CRATEWARD_TEST_DATABASE_URL` (see the
//! store tests in `crateward_core`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use crateward_core::http::{ClientConfig, PoliteClient};
use crateward_core::job::{JobId, Stage};
use crateward_core::store::Store;
use crateward_feed::poller::{Feed, Urls};
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

#[derive(Default)]
struct MockState {
    files: HashMap<String, String>,
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
            let state = state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| serve(state.clone(), req));
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

async fn test_store(schema: &str) -> Option<Store> {
    let Ok(config) = std::env::var("CRATEWARD_TEST_DATABASE_URL") else {
        assert!(
            std::env::var("CRATEWARD_REQUIRE_DB").is_err(),
            "database required"
        );
        eprintln!("skipping: CRATEWARD_TEST_DATABASE_URL is not set");
        return None;
    };
    let (client, connection) = tokio_postgres::connect(&config, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    client
        .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema}; SET search_path TO {schema}"))
        .await
        .unwrap();
    let mut store = Store::from_client(client);
    store.migrate().await.unwrap();
    Some(store)
}

fn client() -> PoliteClient {
    PoliteClient::new(&ClientConfig {
        user_agent: "crateward-test/0 (+https://crateward.com)".into(),
        requests_per_second: 1000.0,
        timeout: Duration::from_secs(5),
        allow_plain_http: true,
    })
    .unwrap()
}

#[tokio::test]
async fn new_versions_become_prioritized_jobs_exactly_once() {
    let schema = format!("feed_test_{}", std::process::id());
    let Some(store) = test_store(&schema).await else {
        return;
    };
    let state: Shared = Arc::default();
    let base = start_mock(state.clone()).await;
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

    // The lagging version appears in the index; the feeds did not change.
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

    // The new crate with a native link comes first; the name keeps its
    // published casing from the index, not the feed's.
    let (client, connection) = tokio_postgres::connect(
        &std::env::var("CRATEWARD_TEST_DATABASE_URL").unwrap(),
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(connection);
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let check = Store::from_client(client);
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
}
