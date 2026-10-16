//! Dashboard.
//!
//! Zone: control plane. The admin view listens on loopback and is reached
//! through an SSH tunnel (ADR 0009).
//! The public view is a static export (`crate::export`), never served here.
//!
//! Why it looks the way it does:
//!
//! * Server rendered HTML with htmx and server sent events needs no
//!   JavaScript build chain and allows a strict Content Security Policy
//!   (ADR 0009). htmx and its server sent events extension are vendored
//!   and pinned by SHA-256.
//! * Templates escape by default at compile time (askama), and crate
//!   supplied text is never rendered as HTML.
//! * Page queries run on a read only session. One second connection makes
//!   the only write, the review decision.
//! * Every request passes the protections in [`security`]: a Host check
//!   against DNS rebinding, same origin checks for writes, strict headers.

#![forbid(unsafe_code)]

pub mod archive;
pub mod diff;
pub mod export;
pub mod job_detail;
pub mod jobs_list;
pub mod run_view;
pub mod sbom;
pub mod security;
pub mod selection;
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
use crateward_core::app::{self, ComponentError, Stop, fatal};
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::job::{JobId, Stage};
use crateward_core::paths::host;
use crateward_core::store::{PauseReason, Review, Store, StoreError};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::job_detail::{job_href, job_page};
use crate::jobs_list::{Backlog, jobs};
use crate::views::{InboxPage, OverviewBody, OverviewData, OverviewPage, Row, ago};

/// The component this package implements.
pub const COMPONENT: Component = Component::Api;

/// The dashboard stylesheet: the design system's tokens, then its own rules.
pub(crate) const DASHBOARD_CSS: &str = concat!(
    include_str!("../static/brand.css"),
    include_str!("../static/crateward.css")
);

/// The webfonts of the design system (`static/OFL.txt`), with their SHA-256.
pub const FONTS: [(&str, &[u8], &str); 3] = [
    (
        "lobster-latin-400.woff2",
        include_bytes!("../static/lobster-latin-400.woff2"),
        "aed68c73817364906ff95d97be87246d106bd38d5e4397e4866ec831ee22f7ba",
    ),
    (
        "dm-sans-latin-wght.woff2",
        include_bytes!("../static/dm-sans-latin-wght.woff2"),
        "9fea608a947e67020c33cad9a6fe3d60c54119dfb8cff87768a8117a15ed7543",
    ),
    (
        "jetbrains-mono-latin-wght.woff2",
        include_bytes!("../static/jetbrains-mono-latin-wght.woff2"),
        "18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e",
    ),
];

/// Vendored files, served under `/static/`, with their SHA-256.
pub const STATIC: [(&str, &str, &[u8], &str); 6] = [
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
    ("crateward.css", "text/css", DASHBOARD_CSS.as_bytes(), ""),
    (
        "lobster-latin-400.woff2",
        "font/woff2",
        FONTS[0].1,
        FONTS[0].2,
    ),
    (
        "dm-sans-latin-wght.woff2",
        "font/woff2",
        FONTS[1].1,
        FONTS[1].2,
    ),
    (
        "jetbrains-mono-latin-wght.woff2",
        "font/woff2",
        FONTS[2].1,
        FONTS[2].2,
    ),
];

/// A hash of the stylesheet, added to its URL so that a browser fetches it
/// again when it changed instead of using its cached copy.
#[must_use]
pub fn stylesheet_version() -> &'static str {
    static VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        use std::hash::{DefaultHasher, Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        DASHBOARD_CSS.hash(&mut hasher);
        format!("{:012x}", hasher.finish() & 0xffff_ffff_ffff)
    });

    &VERSION
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
    /// The jobs page's reprocessing backlog.
    pub backlog: Backlog,
}

/// Errors shown as a plain 500. Details go to the log only.
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
                let state = breakers.get(s).copied().unwrap_or_default();
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
    let rows = state.reader.inbox().await?;
    let unreported = state.reader.unreported().await?;

    Ok(Html(
        InboxPage {
            rows: rows.into_iter().map(Row::from).collect(),
            unreported: unreported.into_iter().map(Row::from).collect(),
        }
        .render()?,
    ))
}

/// Percent encodes everything but unreserved characters and the path
/// separator.
fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The comparison of job `id` with `against`, or with the version before
/// it. `None` if there is no such job or nothing to compare with.
///
/// # Errors
///
/// Fails on database errors.
pub async fn diff_page(
    store: &Store,
    id: i64,
    against: Option<i64>,
    archive: bool,
) -> Result<Option<views::DiffPage>, StoreError> {
    let versions = store.analyzed_versions(JobId(id)).await?;
    let Some(other) = diff::counterpart(&versions, id, against) else {
        return Ok(None);
    };

    let (Some(now), Some(before)) = (
        diff::Side::load(store, id).await?,
        diff::Side::load(store, other.id.0).await?,
    ) else {
        return Ok(None);
    };

    let package = store
        .job_static(JobId(id))
        .await?
        .and_then(|(_, _, diff)| diff);

    let (package, package_note) = match diff::package_rows(package.as_ref(), &before.version) {
        Ok(rows) => (rows, String::new()),
        Err(note) => (Vec::new(), note),
    };

    let head = |side: &diff::Side| views::DiffHead {
        version: side.version.clone(),
        href: job_href(side.id, archive),
        score: side.score.clone(),
        level: side.level.clone(),
    };

    let links = if archive {
        Vec::new()
    } else {
        versions
            .iter()
            .filter(|v| v.id.0 != id)
            .map(|v| views::VersionLink {
                version: v.version.clone(),
                href: format!("/jobs/{id}/diff?against={}", v.id.0),
                selected: v.id == other.id,
            })
            .collect()
    };

    Ok(Some(views::DiffPage {
        archive,
        name: now.name.clone(),
        now: head(&now),
        before: head(&before),
        source_url: diff::source_url(&now.name, &before.version, &now.version),
        versions: links,
        package,
        package_note,
        c: diff::compare(&now, &before),
    }))
}

/// Which version the comparison is against.
#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    against: Option<i64>,
}

async fn diff_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<DiffQuery>,
) -> Result<Response, AppError> {
    match diff_page(&state.reader, id, q.against, false).await? {
        Some(page) => Ok(Html(page.render()?).into_response()),
        None => Ok((StatusCode::NOT_FOUND, "nothing to compare with").into_response()),
    }
}

async fn job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    match job_page(&state.reader, id, false).await? {
        Some(page) => Ok(Html(page.render()?).into_response()),
        None => Ok((StatusCode::NOT_FOUND, "no such job").into_response()),
    }
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

/// The SBOM of a job (ADR 0012).
async fn sbom_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    document(&state, id, |d| (d.sbom_file(), &d.sbom)).await
}

/// The findings document of a job, which points into its SBOM.
async fn vex_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    document(&state, id, |d| (d.vex_file(), &d.vex)).await
}

/// One of a job's CycloneDX documents as a download.
async fn document(
    state: &AppState,
    id: i64,
    pick: impl FnOnce(&sbom::Documents) -> (String, &serde_json::Value),
) -> Result<Response, AppError> {
    let Some(documents) = sbom::documents(&state.reader, id).await? else {
        return Ok((StatusCode::NOT_FOUND, "no SBOM for this job yet").into_response());
    };

    let (file, value) = pick(&documents);
    let body = serde_json::to_vec_pretty(value).unwrap_or_default();
    let disposition = format!("attachment; filename=\"{file}\"");

    Ok((
        [
            (header::CONTENT_TYPE, sbom::MEDIA_TYPE.to_owned()),
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

/// The burst mode switch: `start` or `stop`.
#[derive(Debug, Deserialize)]
pub struct BurstForm {
    action: String,
}

/// Starts or stops burst mode: VM runs wait, and their cores reprocess
/// finished jobs.
async fn burst(
    State(state): State<Arc<AppState>>,
    Form(form): Form<BurstForm>,
) -> Result<Response, AppError> {
    match form.action.as_str() {
        "start" => {
            let detail = "VM runs wait while finished jobs are reprocessed";
            state.writer.pause(PauseReason::Burst, None, detail).await?;
        }
        "stop" => {
            state.writer.lift_pause(PauseReason::Burst).await?;
        }
        _ => return Ok((StatusCode::BAD_REQUEST, "unknown action").into_response()),
    }

    tracing::info!(action = %form.action, "burst mode");

    Ok(Redirect::to("/jobs").into_response())
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
        .route("/jobs/{id}/diff", get(diff_handler))
        .route("/jobs/{id}/review", post(review))
        .route("/jobs/{id}/runs/{file}", get(run_report))
        .route("/jobs/{id}/sbom.cdx.json", get(sbom_file))
        .route("/jobs/{id}/vex.cdx.json", get(vex_file))
        .route("/burst", post(burst))
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
        let export_dir = config.instance.run_dir.join(host::EXPORT_WORK);
        let export_config = config.export.clone();
        tokio::spawn(async move {
            export::run(&exporter, export_dir, export_config.as_ref()).await;
        });
        let stop = Stop::install().map_err(fatal)?;
        let state = Arc::new(AppState {
            reader,
            writer,
            stop: stop.clone(),
            backlog: Backlog::default(),
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
    fn the_stylesheet_loads_only_served_fonts() {
        let urls: Vec<&str> = DASHBOARD_CSS
            .split("url(")
            .skip(1)
            .filter_map(|rest| rest.split_once(')').map(|(url, _)| url))
            .collect();

        assert_eq!(urls.len(), FONTS.len());

        for url in urls {
            assert!(STATIC.iter().any(|(name, ..)| *name == url), "{url}");
        }
    }

    #[test]
    fn pages_ask_for_the_current_stylesheet() {
        let page = InboxPage {
            rows: Vec::new(),
            unreported: Vec::new(),
        }
        .render()
        .unwrap();

        let version = stylesheet_version();

        assert_eq!(version.len(), 12);
        assert!(page.contains(&format!("/static/crateward.css?v={version}\"")));
    }

    #[test]
    fn templates_escape_guest_text() {
        let row = Row {
            id: 1,
            name: "<script>alert(1)</script>".into(),
            version: "1.0.0".into(),
            state: "Done".into(),
            score: "90".into(),
            level: "critical\" onmouseover=\"x".into(),
            review: "pending".into(),
            evidence: "\"><img src=x onerror=alert(1)>".into(),
            age: "now".into(),
            reported: false,
        };

        let page = InboxPage {
            rows: vec![row.clone()],
            unreported: vec![Row {
                review: "confirmed".into(),
                ..row
            }],
        };

        let html = page.render().unwrap();
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("\" onmouseover"));
    }
}
