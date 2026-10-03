//! Protections every response and request goes through.
//!
//! * **Host check.** A page on another site could point its own name at the
//!   dashboard's address (DNS rebinding) and read responses as same origin.
//!   The dashboard listens on loopback and is reached through an SSH tunnel
//!   (ADR 0009), so requests are answered only when `Host` is a loopback
//!   name with the dashboard's port.
//! * **Cross site writes.** A page the maintainer has open elsewhere could
//!   post forms to the dashboard. Every request other than `GET` and `HEAD`
//!   must come from the dashboard itself: `Sec-Fetch-Site: same-origin`, or
//!   an `Origin` equal to the dashboard's own.
//! * **Headers.** A Content Security Policy that allows only the
//!   dashboard's own scripts and styles (ADR 0009), no framing, no referrer,
//!   no sniffing, no caching of pages.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The Content Security Policy of every response.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    font-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; \
    frame-ancestors 'none'; base-uri 'none'";

/// Whether a request may proceed, given the port the dashboard listens on.
///
/// # Errors
///
/// Names the reason a request is refused.
pub fn allowed(method: &Method, headers: &HeaderMap, port: u16) -> Result<(), &'static str> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let names = [
        format!("localhost:{port}"),
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
    ];

    let Some(host) = header("host").filter(|h| names.iter().any(|n| n == h)) else {
        return Err("unexpected Host");
    };

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
pub async fn guard(port: u16, request: Request<Body>, next: Next) -> Response {
    if let Err(reason) = allowed(request.method(), request.headers(), port) {
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

    const HOST: &str = "localhost:8080";
    const PORT: u16 = 8080;

    #[test]
    fn reads_need_a_loopback_host() {
        for host in ["localhost:8080", "127.0.0.1:8080", "[::1]:8080"] {
            assert!(
                allowed(&Method::GET, &headers(&[("host", host)]), PORT).is_ok(),
                "{host}"
            );
        }

        for host in ["evil.example", "localhost:9999", "10.77.0.1:8080"] {
            assert!(
                allowed(&Method::GET, &headers(&[("host", host)]), PORT).is_err(),
                "{host}"
            );
        }

        assert!(allowed(&Method::GET, &headers(&[]), PORT).is_err());
    }

    #[test]
    fn writes_need_the_same_origin() {
        let post = Method::POST;

        assert!(allowed(&post, &headers(&[("host", HOST)]), PORT).is_err());
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("sec-fetch-site", "cross-site")]),
                PORT
            )
            .is_err()
        );
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("sec-fetch-site", "same-origin")]),
                PORT
            )
            .is_ok()
        );
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("origin", "http://localhost:8080")]),
                PORT
            )
            .is_ok()
        );
        assert!(
            allowed(
                &post,
                &headers(&[("host", HOST), ("origin", "http://evil.example")]),
                PORT
            )
            .is_err()
        );
    }
}
