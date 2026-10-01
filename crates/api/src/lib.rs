//! Dashboard (M6).
//!
//! Zone: control plane. The admin view listens on loopback and is reached
//! through an SSH tunnel (ADR 0009);
//! the public view is a static export (`crate::export`), never served here.
//!
//! Why it looks the way it does:
//!
//! * Server rendered HTML with htmx and server sent events needs no
//!   JavaScript build chain and allows a strict Content Security Policy
//!   (ADR 0009). htmx and its server sent events extension are vendored
//!   and pinned by SHA-256.
//! * Templates escape by default at compile time (askama), and crate
//!   supplied text is never rendered as HTML.
//! * Page queries run on a read only session; one second connection makes
//!   the only write, the review decision.
//! * Every request passes the protections in [`security`]: a Host check
//!   against DNS rebinding, same origin checks for writes, strict headers.

#![forbid(unsafe_code)]

pub mod export;
pub mod run_view;
pub mod security;
pub mod views;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use crateward_core::app::{self, ComponentError, Stop};
use crateward_core::breaker::BreakerState;
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::job::{JobId, Stage};
use crateward_core::store::{Disclosure, JobFilter, Review, Store, StoreError, StoredEvent};
use crateward_core::verdict::{Evidence, Verdict};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::views::{
    EvidenceView, FindingView, InboxPage, JobPage, JobsPage, OverviewBody, OverviewData,
    OverviewPage, Row, VerdictView, ago,
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

/// A hash of the stylesheet, added to its URL so that a browser fetches it
/// again when it changed instead of using its cached copy.
#[must_use]
pub fn stylesheet_version() -> &'static str {
    static VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        include_bytes!("../static/crateward.css").hash(&mut hasher);
        format!("{:012x}", hasher.finish() & 0xffff_ffff_ffff)
    });
    &VERSION
}

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
    /// Ends the live updates, so a shutdown does not wait for open pages.
    pub stop: Stop,
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
        state.stop.sleep(Duration::from_secs(5)).await;
        if state.stop.is_requested() {
            return None;
        }
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

fn text(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
        .unwrap_or_default()
}

/// A file of a crate version in the crates.io code viewer, at the line when
/// there is one. Everything but unreserved characters and the path
/// separator is percent encoded.
fn code_url(name: &str, version: &str, file: &str, line: Option<u64>) -> String {
    let encode = |text: &str| {
        text.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                    char::from(b).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    let anchor = line.map(|l| format!("#L{l}")).unwrap_or_default();
    format!(
        "https://crates.io/crates/{}/{}/code/{}{anchor}",
        encode(name),
        encode(version).replace('/', "%2F"),
        encode(file.trim_start_matches('/'))
    )
}

/// A finding's place in the crates.io code viewer.
fn finding_url(f: &serde_json::Value, name: &str, version: &str) -> String {
    let line = f.get("line").and_then(serde_json::Value::as_u64);
    code_url(name, version, &text(f, "file"), line)
}

/// A finding's file and line, as evidence names its location.
fn finding_location(f: &serde_json::Value) -> String {
    match f.get("line").and_then(serde_json::Value::as_u64) {
        Some(l) => format!("{}:{l}", text(f, "file")),
        None => text(f, "file"),
    }
}

/// A finding's signal name, as static evidence names it.
fn finding_signal(f: &serde_json::Value) -> String {
    match f.get("rule").and_then(serde_json::Value::as_str) {
        Some(rule) => format!("static:yara:{rule}"),
        None => format!("static:{}", text(f, "kind")),
    }
}

fn report_findings(report: &serde_json::Value) -> &[serde_json::Value] {
    report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn findings(report: &serde_json::Value, name: &str, version: &str) -> Vec<FindingView> {
    report_findings(report)
        .iter()
        .take(300)
        .map(|f| {
            let kind = match f.get("rule").and_then(serde_json::Value::as_str) {
                Some(rule) => format!("{} {rule}", text(f, "kind")),
                None => text(f, "kind"),
            };
            FindingView {
                severity: text(f, "severity"),
                kind,
                context: text(f, "context"),
                location: finding_location(f),
                evidence: text(f, "evidence"),
                code_url: finding_url(f, name, version),
            }
        })
        .collect()
}

/// Links each piece of static evidence to its code in the crates.io code
/// viewer, at the line of the finding of the same kind at the same place,
/// or in the same file when the verdict predates line numbers for that
/// kind.
fn attach_links(
    evidence: &mut [EvidenceView],
    report: &serde_json::Value,
    name: &str,
    version: &str,
) {
    let findings = report_findings(report);
    for e in evidence
        .iter_mut()
        .filter(|e| e.source == "static" || e.signal == "new_high_finding")
    {
        let same_kind = |f: &&serde_json::Value| {
            e.signal == "new_high_finding" || finding_signal(f) == e.signal
        };
        let found = findings
            .iter()
            .filter(same_kind)
            .find(|f| finding_location(f) == e.location)
            .or_else(|| {
                findings
                    .iter()
                    .filter(same_kind)
                    .find(|f| text(f, "file") == e.location)
            });
        if let Some(f) = found {
            e.code_url = finding_url(f, name, version);
        }
    }
}

fn disclosure_rows(d: Disclosure) -> Vec<(String, String)> {
    let dash = |v: Option<String>| v.unwrap_or_else(|| "-".to_owned());
    [
        ("Kind", d.kind.name().to_owned()),
        (
            "Reported",
            format!("{} to {}", d.reported_on, d.reported_to),
        ),
        ("Reference", dash(d.reference)),
        ("Resolved", dash(d.resolved_on)),
        ("Published", dash(d.published_on)),
        ("Page", dash(d.slug)),
        ("Note", dash(d.note)),
    ]
    .into_iter()
    .map(|(label, value)| (label.to_owned(), value))
    .collect()
}

fn timeline_row(e: StoredEvent, now: SystemTime) -> (String, String, String, String, String) {
    let secs = now
        .duration_since(e.at)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let kind = e.event.get("kind").and_then(serde_json::Value::as_str);
    (
        ago(secs),
        e.from,
        e.to,
        kind.unwrap_or("?").to_owned(),
        e.worker,
    )
}

fn evidence_view(e: Evidence) -> EvidenceView {
    EvidenceView {
        points: e.points,
        signal: e.signal,
        source: e.source.name().to_owned(),
        package: e.package.unwrap_or_default(),
        location: e.location.unwrap_or_default(),
        summary: e.summary,
        code_url: String::new(),
    }
}

fn verdict_view((verdict, review): (Verdict, Review)) -> VerdictView {
    VerdictView {
        score: verdict.score.to_string(),
        level: verdict.level.name().to_owned(),
        review: review.name().to_owned(),
        evidence: verdict.evidence.into_iter().map(evidence_view).collect(),
        profile: verdict.profile,
        new_behavior: verdict.new_behavior,
    }
}

async fn job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let store = &state.reader;
    let Some(job) = store.get(JobId(id)).await? else {
        return Ok((StatusCode::NOT_FOUND, "no such job").into_response());
    };
    let verdict = store.verdict(job.id).await?.map(verdict_view);
    let mut verdict = verdict.unwrap_or_default();
    let static_report = store.static_report(&job.cksum).await?.map(|(_, r)| r);
    if let Some(report) = &static_report {
        attach_links(&mut verdict.evidence, report, &job.name, &job.version);
    }
    let findings = static_report
        .as_ref()
        .map(|r| findings(r, &job.name, &job.version))
        .unwrap_or_default();
    let disclosure = store.disclosure(job.id).await?;
    let events = store.events(job.id).await?;
    let runs = store.job_runs(job.id).await?;
    let now = SystemTime::now();
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
        score: verdict.score,
        level: verdict.level,
        review: verdict.review,
        evidence: verdict.evidence,
        new_behavior: verdict.new_behavior,
        profile: verdict.profile,
        findings,
        timeline: events.into_iter().map(|e| timeline_row(e, now)).collect(),
        runs: run_view::run_views(id, &runs),
        disclosure: disclosure.map(disclosure_rows).unwrap_or_default(),
    };
    Ok(Html(page.render()?).into_response())
}

/// A run report as a file, for tools and archives.
async fn run_report(
    State(state): State<Arc<AppState>>,
    Path((id, file)): Path<(i64, String)>,
) -> Result<Response, AppError> {
    let runs = state.reader.job_runs(JobId(id)).await?;
    let wanted = file.strip_suffix(".json");
    let Some((kind, report)) = runs
        .into_iter()
        .find(|(kind, _)| Some(kind.as_str()) == wanted)
    else {
        return Ok((StatusCode::NOT_FOUND, "no such run").into_response());
    };
    let body = serde_json::to_vec_pretty(&report).unwrap_or_default();
    // The kind is one of the orchestrator's own names, but keep the header
    // safe whatever the database holds.
    let kind: String = kind.chars().filter(char::is_ascii_alphanumeric).collect();
    let disposition = format!("attachment; filename=\"crateward-job-{id}-{kind}.json\"");
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
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
pub fn router(state: Arc<AppState>, port: u16) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/events", get(events))
        .route("/inbox", get(inbox))
        .route("/jobs", get(jobs))
        .route("/jobs/{id}", get(job))
        .route("/jobs/{id}/review", post(review))
        .route("/jobs/{id}/runs/{file}", get(run_report))
        .route("/static/{file}", get(asset))
        .with_state(state)
        .layer(middleware::from_fn(move |request, next| {
            security::guard(port, request, next)
        }))
}

/// Runs the dashboard until shutdown.
///
/// # Errors
///
/// Fails if the database or the listening socket cannot be set up.
pub fn run(config: &Config) -> Result<(), ComponentError> {
    let runtime = app::runtime().map_err(fatal)?;
    runtime.block_on(async {
        let url = config.database.url.expose_secret();
        let reader = Store::connect(url).await.map_err(fatal)?;
        reader.make_read_only().await.map_err(fatal)?;
        let mut writer = Store::connect(url).await.map_err(fatal)?;
        // Like every service, the dashboard brings the schema up to date, so
        // it never queries a table that a later migration adds.
        writer.migrate().await.map_err(fatal)?;
        // The public export runs next to the dashboard, on its own
        // read only connection.
        let exporter = Store::connect(url).await.map_err(fatal)?;
        exporter.make_read_only().await.map_err(fatal)?;
        let export_dir = config.instance.run_dir.join("export");
        let export_config = config.export.clone();
        tokio::spawn(async move {
            export::run(&exporter, export_dir, export_config.as_ref()).await;
        });
        let stop = Stop::install().map_err(fatal)?;
        let state = Arc::new(AppState {
            reader,
            writer,
            stop: stop.clone(),
        });
        let listen = config.web.listen;
        let listener = tokio::net::TcpListener::bind(listen).await.map_err(fatal)?;
        tracing::info!(%listen, "dashboard listening");
        axum::serve(listener, router(state, listen.port()))
            .with_graceful_shutdown(async move { stop.wait().await })
            .await
            .map_err(fatal)
    })
}

#[cfg(test)]
mod tests {
    use crateward_core::digest::Sha256Digest;
    use sha2::Digest;

    use super::*;

    #[test]
    fn vendored_files_match_their_pins() {
        for (name, _, bytes, pin) in STATIC {
            if pin.is_empty() {
                continue;
            }
            let digest = Sha256Digest::from_bytes(sha2::Sha256::digest(bytes).into());
            assert_eq!(digest.to_string(), pin, "{name}");
        }
    }

    #[test]
    fn pages_ask_for_the_current_stylesheet() {
        let page = InboxPage { rows: Vec::new() }.render().unwrap();
        let version = stylesheet_version();
        assert_eq!(version.len(), 12);
        assert!(page.contains(&format!("/static/crateward.css?v={version}\"")));
    }

    #[test]
    fn code_links_encode_what_the_crate_controls() {
        assert_eq!(
            code_url("masler", "0.1.0-alpha.4", "src/macros.rs", None),
            "https://crates.io/crates/masler/0.1.0-alpha.4/code/src/macros.rs"
        );
        assert_eq!(
            code_url("hegeltest", "0.47.4", "build.rs", Some(4)),
            "https://crates.io/crates/hegeltest/0.47.4/code/build.rs#L4"
        );
        assert_eq!(
            code_url("a", "1.0.0+meta", "/odd dir/x\"?#%.rs", None),
            "https://crates.io/crates/a/1.0.0%2Bmeta/code/odd%20dir/x%22%3F%23%25.rs"
        );
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
