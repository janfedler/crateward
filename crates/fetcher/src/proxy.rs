//! A registry index proxy for one resolution (ADR 0014).
//!
//! `cargo generate-lockfile` runs in a sandbox whose only network path is a
//! relay to this proxy's Unix socket. The proxy serves:
//!
//! * `/index/config.json`, pointing downloads nowhere: resolution never
//!   downloads crates, and the fetcher fetches locked crates itself;
//! * `/index/<path>`, the crates.io sparse index file, passed through
//!   unchanged except that the version under analysis is marked as not
//!   yanked, so that cargo resolves versions that were yanked after
//!   publishing (malware often is).
//!
//! Index files are cached for ten minutes, matching the CDN's own cache,
//! so dependencies shared by many jobs are not fetched again and again.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use crateward_core::cratesio::MAX_INDEX_FILE_BYTES;
use crateward_core::http::{Fetched, PoliteClient};
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;

/// How long a cached index file is served without asking crates.io again.
const CACHE_TTL: Duration = Duration::from_secs(600);

/// Cached index files by path: when fetched, and the body (`None` for a
/// crate that does not exist).
type CacheMap = HashMap<String, (Instant, Option<Bytes>)>;

/// Index files shared by all resolutions of one fetcher process.
#[derive(Debug, Clone, Default)]
pub struct IndexCache {
    entries: Arc<Mutex<CacheMap>>,
}

/// The version whose yanked flag the proxy clears.
#[derive(Debug, Clone)]
pub struct Target {
    /// Lowercase index path of the crate, for example `se/rd/serde`.
    pub index_path: String,
    /// The version.
    pub version: String,
}

/// Clears `"yanked": true` on the target version's line.
fn unyank(body: &[u8], version: &str) -> Bytes {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(mut value) if value.get("vers").and_then(|v| v.as_str()) == Some(version) => {
                if let Some(yanked) = value.get_mut("yanked") {
                    *yanked = serde_json::Value::Bool(false);
                }
                out.push_str(&value.to_string());
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    Bytes::from(out)
}

async fn index_file(
    client: &PoliteClient,
    root: &str,
    cache: &IndexCache,
    path: &str,
) -> Result<Option<Bytes>, StatusCode> {
    if let Ok(entries) = cache.entries.lock()
        && let Some((at, body)) = entries.get(path)
        && at.elapsed() < CACHE_TTL
    {
        return Ok(body.clone());
    }
    let url = format!("{root}{path}");
    let body = match client.get(&url, None, MAX_INDEX_FILE_BYTES).await {
        Ok(Fetched::Body { body, .. }) => Some(body),
        Ok(Fetched::Missing) => None,
        Ok(Fetched::NotModified) | Err(_) => return Err(StatusCode::BAD_GATEWAY),
    };
    if let Ok(mut entries) = cache.entries.lock() {
        entries.insert(path.to_owned(), (Instant::now(), body.clone()));
    }
    Ok(body)
}

/// Whether a request path is a well formed index path: lowercase crate name
/// characters and slashes only, no traversal.
fn valid_index_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 80
        && !path.contains("..")
        && path.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'/' | b'-' | b'_')
        })
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    client: PoliteClient,
    root: Arc<str>,
    cache: IndexCache,
    target: Arc<Target>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let respond = |status: StatusCode, body: Bytes| {
        Response::builder()
            .status(status)
            .body(Full::new(body))
            .unwrap_or_else(|_| Response::new(Full::default()))
    };
    let Some(path) = req.uri().path().strip_prefix("/index/") else {
        return Ok(respond(StatusCode::NOT_FOUND, Bytes::new()));
    };
    if path == "config.json" {
        let config = r#"{"dl":"http://127.0.0.1:9/crateward-no-downloads"}"#;
        return Ok(respond(
            StatusCode::OK,
            Bytes::from_static(config.as_bytes()),
        ));
    }
    if !valid_index_path(path) {
        return Ok(respond(StatusCode::NOT_FOUND, Bytes::new()));
    }
    Ok(match index_file(&client, &root, &cache, path).await {
        Ok(Some(body)) if path == target.index_path => {
            respond(StatusCode::OK, unyank(&body, &target.version))
        }
        Ok(Some(body)) => respond(StatusCode::OK, body),
        Ok(None) => respond(StatusCode::NOT_FOUND, Bytes::new()),
        Err(status) => respond(status, Bytes::new()),
    })
}

/// Serves the proxy on a Unix socket until the returned task is aborted.
///
/// # Errors
///
/// Fails if the socket cannot be bound.
pub fn serve(
    socket: &Path,
    client: PoliteClient,
    index_root: &str,
    cache: IndexCache,
    target: Target,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = UnixListener::bind(socket)?;
    let root: Arc<str> = Arc::from(index_root);
    let target = Arc::new(target);
    Ok(tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (client, root, cache, target) =
                (client.clone(), root.clone(), cache.clone(), target.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| {
                    handle(
                        req,
                        client.clone(),
                        root.clone(),
                        cache.clone(),
                        target.clone(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_target_version_is_unyanked() {
        let body = b"{\"name\":\"x\",\"vers\":\"1.0.0\",\"yanked\":true}\n{\"name\":\"x\",\"vers\":\"1.0.1\",\"yanked\":true}\n";
        let out = String::from_utf8(unyank(body, "1.0.1").to_vec()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains("\"yanked\":true"));
        assert!(lines[1].contains("\"yanked\":false"));
    }

    #[test]
    fn index_paths_are_restricted() {
        assert!(valid_index_path("se/rd/serde"));
        assert!(valid_index_path("3/a/abc"));
        assert!(!valid_index_path("../../etc"));
        assert!(!valid_index_path("Se/rd/serde"));
        assert!(!valid_index_path(""));
    }
}
