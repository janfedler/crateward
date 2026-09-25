//! Dashboard (M6).
//!
//! Zone: control plane. The admin view is reachable only through WireGuard;
//! the public view is a static export (`crate::export`), never served here.
//!
//! Why it looks the way it does:
//!
//! * Server rendered HTML with htmx and server sent events needs no
//!   JavaScript build chain and allows a strict Content Security Policy
//!   (ADR 0005). htmx and its server sent events extension are vendored
//!   and pinned by SHA-256.
//! * Templates escape by default at compile time (askama), and crate
//!   supplied text is never rendered as HTML.
//! * Page queries run on a read only session; one second connection makes
//!   the only write, the review decision.
//! * Every request passes the protections in [`security`]: a Host check
//!   against DNS rebinding, same origin checks for writes, strict headers.

#![forbid(unsafe_code)]

pub mod export;
pub mod security;
pub mod views;

use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use crateward_core::app::ComponentError;
use crateward_core::breaker::BreakerState;
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::job::{JobId, Stage};
use crateward_core::store::{JobFilter, Review, Store, StoreError};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::views::{
    EvidenceView, FindingView, InboxPage, JobPage, JobsPage, OverviewBody, OverviewData,
    OverviewPage, Row, ago,
};

/// The component this package implements.
pub const COMPONENT: Component = Component::Api;

/// Vendored files, served under `/static/`, with their SHA-256.
pub const STATIC: [(&str, &str, &[u8], &str); 3] = [
    (
        "htmx-2.0.11.min.js",
        "text/javascript",
        include_bytes!("../static/htmx-2.0.11.min.js"),
        "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717",
    ),
    (
        "sse-2.2.4.min.js",
        "text/javascript",
        include_bytes!("../static/sse-2.2.4.min.js"),
        "98a46496de0c3605fbffdce9167ba427bdd9553184f83f149c261891a92c0136",
    ),
    (
        "crateward.css",
        "text/css",
        include_bytes!("../static/crateward.css"),
        "",
    ),
];

/// Largest pretty printed run report shown on a job page.
const MAX_REPORT_TEXT: usize = 256 * 1024;

fn fatal(reason: impl std::fmt::Display) -> ComponentError {
    ComponentError::Fatal {
        component: COMPONENT,
        reason: reason.to_string(),
    }
}

/// Connections of the dashboard.
#[derive(Debug)]
pub struct AppState {
    /// Read only session for pages.
    pub reader: Store,
    /// The connection for review decisions.
    pub writer: Store,
}

/// Errors shown as a plain 500; details go to the log only.
#[derive(Debug)]
pub struct AppError(String);

impl From<StoreError> for AppError {
    fn from(error: StoreError) -> Self {
        Self(error.to_string())
    }
}

impl From<askama::Error> for AppError {
    fn from(error: askama::Error) -> Self {
        Self(error.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!(error = %self.0, "request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    }
}

type Page = Result<Html<String>, AppError>;

async fn overview_data(store: &Store) -> Result<OverviewData, StoreError> {
    let o = store.overview().await?;
    let now = store.now_epoch().await?;
    let breakers = store.breakers().await?;
    let dynamic_share = if o.done_24h > 0 {
        format!("{}%", o.dynamic_24h * 100 / o.done_24h)
    } else {
        "0%".into()
    };
    Ok(OverviewData {
        pending_reviews: o.pending_reviews,
        done_24h: o.done_24h,
        dynamic_share,
        alerts_waiting: store.pending_alerts(1000).await?.len(),
        pauses: store
            .pauses()
            .await?
            .into_iter()
            .map(|p| format!("{} ({}, {})", p.reason.name(), p.detail, ago(now - p.since)))
            .collect(),
        breakers: Stage::ALL
            .iter()
            .map(|s| {
                let state = breakers.get(s).copied().unwrap_or(BreakerState::Closed);
                (s.name().to_owned(), state.name().to_owned())
            })
            .collect(),
        canaries: store
            .latest_canaries()
            .await?
            .into_iter()
            .map(|(name, passed, at)| (name, passed, ago(now - at)))
            .collect(),
        states: o.states,
        levels: o.levels,
        updated: "just now".into(),
    })
}

async fn overview(State(state): State<Arc<AppState>>) -> Page {
    let o = overview_data(&state.reader).await?;
    Ok(Html(OverviewPage { o }.render()?))
}

async fn events(
    State(state): State<Arc<AppState>>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = futures_util::stream::unfold(state, |state| async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let html = match overview_data(&state.reader).await {
            Ok(o) => OverviewBody { o }.render().unwrap_or_default(),
            Err(error) => {
                tracing::warn!(%error, "overview update failed");
                String::new()
            }
        };
        Some((Ok(Event::default().event("overview").data(html)), state))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn inbox(State(state): State<Arc<AppState>>) -> Page {
    let rows = state
        .reader
        .inbox()
        .await?
        .into_iter()
        .map(Row::from)
        .collect();
    Ok(Html(InboxPage { rows }.render()?))
}

/// The job list's filters.
#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    #[serde(default)]
    name: String,
    #[serde(default)]
    level: String,
}

const LEVELS: [&str; 5] = ["none", "low", "medium", "high", "critical"];

async fn jobs(State(state): State<Arc<AppState>>, Query(q): Query<JobsQuery>) -> Page {
    let name: String = q.name.chars().take(64).collect();
    let level = LEVELS
        .iter()
        .find(|l| **l == q.level)
        .map(|l| (*l).to_owned());
    let filter = JobFilter {
        name: (!name.is_empty()).then(|| name.clone()),
        level: level.clone(),
        review: None,
    };
    let rows = state
        .reader
        .jobs(&filter, 200)
        .await?
        .into_iter()
        .map(Row::from)
        .collect();
    Ok(Html(
        JobsPage {
            rows,
            name,
            level: level.unwrap_or_default(),
            levels: LEVELS.iter().map(|l| (*l).to_owned()).collect(),
        }
        .render()?,
    ))
}

fn findings(report: &serde_json::Value) -> Vec<FindingView> {
    let text = |v: &serde_json::Value, key: &str| {
        v.get(key)
            .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
            .unwrap_or_default()
    };
    report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(300)
        .map(|f| {
            let kind = match f.get("rule").and_then(serde_json::Value::as_str) {
                Some(rule) => format!("{} {rule}", text(f, "kind")),
                None => text(f, "kind"),
            };
            let line = f.get("line").and_then(serde_json::Value::as_u64);
            FindingView {
                severity: text(f, "severity"),
                kind,
                context: text(f, "context"),
                location: match line {
                    Some(l) => format!("{}:{l}", text(f, "file")),
                    None => text(f, "file"),
                },
                evidence: text(f, "evidence"),
            }
        })
        .collect()
}

async fn job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let store = &state.reader;
    let Some(job) = store.get(JobId(id)).await? else {
        return Ok((StatusCode::NOT_FOUND, "no such job").into_response());
    };
    let verdict = store.verdict(job.id).await?;
    let static_report = store.static_report(&job.cksum).await?;
    let now = std::time::SystemTime::now();
    let timeline = store
        .events(job.id)
        .await?
        .into_iter()
        .map(|e| {
            let secs = now
                .duration_since(e.at)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            let event = e
                .event
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?")
                .to_owned();
            (ago(secs), e.from, e.to, event, e.worker)
        })
        .collect();
    let runs = store
        .job_runs(job.id)
        .await?
        .into_iter()
        .map(|(kind, report)| {
            let mut text = serde_json::to_string_pretty(&report).unwrap_or_default();
            if text.len() > MAX_REPORT_TEXT {
                let mut cut = MAX_REPORT_TEXT;
                while !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                text.truncate(cut);
                text.push_str("\n… (cut)");
            }
            (kind, text)
        })
        .collect();
    let (score, level, review, evidence, profile, new_behavior) = match verdict {
        Some((v, review)) => (
            v.score.to_string(),
            v.level.name().to_owned(),
            review.name().to_owned(),
            v.evidence
                .into_iter()
                .map(|e| EvidenceView {
                    points: e.points,
                    signal: e.signal,
                    source: format!("{:?}", e.source).to_lowercase(),
                    package: e.package.unwrap_or_default(),
                    location: e.location.unwrap_or_default(),
                    summary: e.summary,
                })
                .collect(),
            v.profile,
            v.new_behavior,
        ),
        None => Default::default(),
    };
    let page = JobPage {
        id,
        name: job.name,
        version: job.version,
        state: job.job.state.name().to_owned(),
        coverage: job
            .job
            .coverage
            .map(|c| c.label().to_owned())
            .unwrap_or_default(),
        score,
        level,
        review,
        evidence,
        new_behavior,
        profile,
        findings: static_report.map(|(_, r)| findings(&r)).unwrap_or_default(),
        timeline,
        runs,
    };
    Ok(Html(page.render()?).into_response())
}

/// A review decision from the job page.
#[derive(Debug, Deserialize)]
pub struct ReviewForm {
    decision: String,
}

async fn review(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Form(form): Form<ReviewForm>,
) -> Result<Response, AppError> {
    let decision = match form.decision.as_str() {
        "confirmed" => Review::Confirmed,
        "false_positive" => Review::FalsePositive,
        _ => return Ok((StatusCode::BAD_REQUEST, "unknown decision").into_response()),
    };
    if !state.writer.set_review(JobId(id), decision, None).await? {
        return Ok((StatusCode::NOT_FOUND, "no verdict").into_response());
    }
    tracing::info!(job = id, decision = decision.name(), "review recorded");
    Ok(Redirect::to(&format!("/jobs/{id}")).into_response())
}

async fn asset(Path(file): Path<String>) -> Response {
    match STATIC.iter().find(|(name, ..)| *name == file) {
        Some((_, content_type, bytes, _)) => (
            [
                (header::CONTENT_TYPE, *content_type),
                (header::CACHE_CONTROL, "public, max-age=86400"),
            ],
            *bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no such file").into_response(),
    }
}

/// The dashboard's routes, behind the protections of [`security`].
pub fn router(state: Arc<AppState>, host: String) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/events", get(events))
        .route("/inbox", get(inbox))
        .route("/jobs", get(jobs))
        .route("/jobs/{id}", get(job))
        .route("/jobs/{id}/review", post(review))
        .route("/static/{file}", get(asset))
        .with_state(state)
        .layer(middleware::from_fn(move |request, next| {
            security::guard(host.clone(), request, next)
        }))
}

/// Runs the dashboard until shutdown.
///
/// # Errors
///
/// Fails if the database or the listening socket cannot be set up.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(fatal)?;
    runtime.block_on(async {
        let url = config.database.url.expose_secret();
        let reader = Store::connect(url).await.map_err(fatal)?;
        reader.make_read_only().await.map_err(fatal)?;
        let writer = Store::connect(url).await.map_err(fatal)?;
        // The public export runs next to the dashboard, on its own
        // read only connection.
        let exporter = Store::connect(url).await.map_err(fatal)?;
        exporter.make_read_only().await.map_err(fatal)?;
        let export_dir = config.instance.run_dir.join("export");
        let export_config = config.export.clone();
        tokio::spawn(async move {
            export::run(&exporter, export_dir, export_config.as_ref()).await;
        });
        let state = Arc::new(AppState { reader, writer });
        let listen = config.web.listen;
        let listener = tokio::net::TcpListener::bind(listen).await.map_err(fatal)?;
        tracing::info!(%listen, "dashboard listening");
        axum::serve(listener, router(state, listen.to_string()))
            .with_graceful_shutdown(async {
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(mut terminate) => {
                        tokio::select! {
                            _ = terminate.recv() => {}
                            _ = tokio::signal::ctrl_c() => {}
                        }
                    }
                    Err(_) => {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                }
            })
            .await
            .map_err(fatal)
    })
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::*;

    #[test]
    fn vendored_files_match_their_pins() {
        for (name, _, bytes, pin) in STATIC {
            if pin.is_empty() {
                continue;
            }
            let digest = sha2::Sha256::digest(bytes);
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, pin, "{name}");
        }
    }

    #[test]
    fn templates_escape_guest_text() {
        let page = InboxPage {
            rows: vec![Row {
                id: 1,
                name: "<script>alert(1)</script>".into(),
                version: "1.0.0".into(),
                state: "Done".into(),
                score: "90".into(),
                level: "critical\" onmouseover=\"x".into(),
                review: "pending".into(),
                evidence: "\"><img src=x onerror=alert(1)>".into(),
                age: "now".into(),
            }],
        };
        let html = page.render().unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("\" onmouseover"));
    }
}
