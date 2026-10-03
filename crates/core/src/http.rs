//! A polite HTTP client for crates.io.
//!
//! The crates.io data access policy asks clients to identify themselves
//! with a user agent that includes contact details, and to keep API use to
//! one request per second. Crateward avoids the API, but applies the same
//! courtesy everywhere: every client has a request rate limit, conditional
//! requests avoid downloading unchanged index files, `Retry-After` on HTTP
//! 429 is honored, and response bodies have a hard size limit, since a CDN
//! or a proxy in the path could misbehave.
//!
//! Enabled with the `http` feature.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Why a request failed.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The request could not be sent or the response not read. Transient.
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
    /// The server asked us to slow down. Transient, after the given delay.
    #[error("rate limited by the server, retry after {0:?}")]
    RateLimited(Duration),
    /// A server error. Transient.
    #[error("server error {0}")]
    Server(u16),
    /// A status that retrying will not change. Permanent.
    #[error("unexpected status {0}")]
    Status(u16),
    /// The body exceeded the limit for this request.
    #[error("response exceeds {0} bytes")]
    TooLarge(usize),
}

impl HttpError {
    /// Whether retrying later may succeed.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Transport(_) | Self::RateLimited(_) | Self::Server(_)
        )
    }
}

/// Validators from a previous response, for a conditional request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    /// The `ETag` header.
    pub etag: Option<String>,
    /// The `Last-Modified` header.
    pub last_modified: Option<String>,
}

/// Result of a GET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The resource, with validators for the next conditional request.
    Body {
        /// The body.
        body: Bytes,
        /// Validators of this response.
        validators: Validators,
    },
    /// The resource did not change since the validators were issued.
    NotModified,
    /// The resource does not exist (404, 410 or 451, as the Cargo registry
    /// documentation defines for missing crates).
    Missing,
}

/// Settings of one client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// The user agent. Must identify Crateward and its operator.
    pub user_agent: String,
    /// Upper bound on the request rate.
    pub requests_per_second: f64,
    /// Timeout of one request, including reading the body.
    pub timeout: Duration,
    /// Permit plain HTTP. Only the mock crates.io of the tests uses it.
    /// Configuration validation requires https for every real URL.
    pub allow_plain_http: bool,
}

/// Spaces requests out to at most a configured rate.
#[derive(Debug)]
struct Pacer {
    interval: Duration,
    next: Mutex<Instant>,
}

impl Pacer {
    fn new(requests_per_second: f64) -> Self {
        let rate = if requests_per_second.is_finite() && requests_per_second > 0.0 {
            requests_per_second
        } else {
            1.0
        };
        Self {
            interval: Duration::from_secs_f64(1.0 / rate),
            next: Mutex::new(Instant::now()),
        }
    }

    /// Waits for the next slot.
    async fn wait(&self) {
        let slot = {
            let mut next = self.next.lock().await;
            let slot = (*next).max(Instant::now());
            *next = slot + self.interval;
            slot
        };
        tokio::time::sleep_until(slot).await;
    }

    /// Pushes the next slot back, for example after HTTP 429.
    async fn back_off(&self, delay: Duration) {
        let mut next = self.next.lock().await;
        *next = (*next).max(Instant::now() + delay);
    }
}

/// A rate limited HTTP client.
#[derive(Debug, Clone)]
pub struct PoliteClient {
    client: reqwest::Client,
    pacer: Arc<Pacer>,
}

/// `Retry-After` in seconds, bounded to one hour. HTTP dates fall back to a
/// minute.
fn retry_after(response: &reqwest::Response) -> Duration {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(Duration::from_secs(60), |secs| {
            Duration::from_secs(secs.min(3600))
        })
}

fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

impl PoliteClient {
    /// A client with the given settings.
    ///
    /// # Errors
    ///
    /// Fails if the TLS backend cannot be initialized.
    pub fn new(config: &ClientConfig) -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .timeout(config.timeout)
            .https_only(!config.allow_plain_http)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()?;
        Ok(Self {
            client,
            pacer: Arc::new(Pacer::new(config.requests_per_second)),
        })
    }

    /// Sends a GET, conditional if validators are given, and reads at most
    /// `max_bytes` of body.
    ///
    /// # Errors
    ///
    /// See [`HttpError`]. [`HttpError::is_transient`] tells whether to retry.
    pub async fn get(
        &self,
        url: &str,
        validators: Option<&Validators>,
        max_bytes: usize,
    ) -> Result<Fetched, HttpError> {
        self.pacer.wait().await;
        let mut request = self.client.get(url);
        if let Some(v) = validators {
            if let Some(etag) = &v.etag {
                request = request.header(reqwest::header::IF_NONE_MATCH, etag);
            } else if let Some(modified) = &v.last_modified {
                request = request.header(reqwest::header::IF_MODIFIED_SINCE, modified);
            }
        }
        let mut response = request.send().await?;
        let status = response.status().as_u16();
        match status {
            200 => {}
            304 => return Ok(Fetched::NotModified),
            404 | 410 | 451 => return Ok(Fetched::Missing),
            429 => {
                let delay = retry_after(&response);
                self.pacer.back_off(delay).await;
                return Err(HttpError::RateLimited(delay));
            }
            500..=599 => return Err(HttpError::Server(status)),
            other => return Err(HttpError::Status(other)),
        }
        if response
            .content_length()
            .is_some_and(|len| len > u64::try_from(max_bytes).unwrap_or(u64::MAX))
        {
            return Err(HttpError::TooLarge(max_bytes));
        }
        let validators = Validators {
            etag: header(&response, reqwest::header::ETAG),
            last_modified: header(&response, reqwest::header::LAST_MODIFIED),
        };
        let mut body = BytesMut::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > max_bytes {
                return Err(HttpError::TooLarge(max_bytes));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Fetched::Body {
            body: body.freeze(),
            validators,
        })
    }

    /// Starts a GET for streaming a large body, such as a crate file. The
    /// caller reads chunks and enforces its own limit.
    ///
    /// # Errors
    ///
    /// Fails like [`PoliteClient::get`] for any status other than 200.
    pub async fn stream(&self, url: &str) -> Result<Option<reqwest::Response>, HttpError> {
        self.pacer.wait().await;
        let response = self.client.get(url).send().await?;
        match response.status().as_u16() {
            200 => Ok(Some(response)),
            404 | 410 | 451 => Ok(None),
            429 => {
                let delay = retry_after(&response);
                self.pacer.back_off(delay).await;
                Err(HttpError::RateLimited(delay))
            }
            s @ 500..=599 => Err(HttpError::Server(s)),
            other => Err(HttpError::Status(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn pacer_spaces_requests_out() {
        let pacer = Pacer::new(4.0);
        let start = Instant::now();
        for _ in 0..5 {
            pacer.wait().await;
        }
        // Five requests at 4 per second: the fifth starts after one second.
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn back_off_delays_the_next_request() {
        let pacer = Pacer::new(100.0);
        pacer.back_off(Duration::from_secs(30)).await;
        let start = Instant::now();
        pacer.wait().await;
        assert_eq!(start.elapsed(), Duration::from_secs(30));
    }

    #[test]
    fn transient_errors_are_classified() {
        assert!(HttpError::Server(503).is_transient());
        assert!(HttpError::RateLimited(Duration::ZERO).is_transient());
        assert!(!HttpError::Status(403).is_transient());
        assert!(!HttpError::TooLarge(1).is_transient());
    }
}
