//! Protections every response and request goes through.
//!
//! * **Host check.** A page on another site could point its own name at the
//!   dashboard's address (DNS rebinding) and read responses as same origin.
//!   Requests are answered only when `Host` is the address the dashboard
//!   listens on.
//! * **Cross site writes.** A page the maintainer has open elsewhere could
//!   post forms to the dashboard. Every request other than `GET` and `HEAD`
//!   must come from the dashboard itself: `Sec-Fetch-Site: same-origin`, or
//!   an `Origin` equal to the dashboard's own.
//! * **Headers.** A Content Security Policy that allows only the
//!   dashboard's own scripts and styles (ADR 0005), no framing, no referrer,
//!   no sniffing, no caching of pages.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The Content Security Policy of every response.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; \
    base-uri 'none'";

/// Whether a request may proceed, given the dashboard's own host
/// (`address:port`).
///
/// # Errors
///
/// Names the reason a request is refused.
pub fn allowed(method: &Method, headers: &HeaderMap, host: &str) -> Result<(), &'static str> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if header("host") != Some(host) {
        return Err("unexpected Host");
    }
    if matches!(*method, Method::GET | Method::HEAD) {
        return Ok(());
    }
    let same_site = header("sec-fetch-site") == Some("same-origin");
    let same_origin = header("origin").is_some_and(|o| o == format!("http://{host}"));
    if same_site || same_origin {
        Ok(())
    } else {
        Err("cross site request")
    }
}

/// Middleware: rejects what [`allowed`] refuses and adds the headers.
pub async fn guard(host: String, request: Request<Body>, next: Next) -> Response {
    if let Err(reason) = allowed(request.method(), request.headers(), &host) {
        tracing::warn!(reason, method = %request.method(), "request refused");
        return (StatusCode::FORBIDDEN, reason).into_response();
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    const HOST: &str = "10.77.0.1:8080";

    #[test]
    fn reads_need_the_right_host() {
        assert!(allowed(&Method::GET, &headers(&[("host", HOST)]), HOST).is_ok());
        assert!(allowed(&Method::GET, &headers(&[("host", "evil.example")]), HOST).is_err());
        assert!(allowed(&Method::GET, &headers(&[]), HOST).is_err());
    }

    #[test]
    fn writes_need_the_same_origin() {
        let post = Method::POST;
        assert!(allowed(&post, &headers(&[("host", HOST)]), HOST).is_err());
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("sec-fetch-site", "cross-site")]),
                HOST
            )
            .is_err()
        );
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("sec-fetch-site", "same-origin")]),
                HOST
            )
            .is_ok()
        );
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("origin", "http://10.77.0.1:8080")]),
                HOST
            )
            .is_ok()
        );
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("origin", "http://evil.example")]),
                HOST
            )
            .is_err()
        );
    }
}
