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
use crateward_core::app::{self, ComponentError, Stop, fatal};
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::job::{JobId, JobState, Stage};
use crateward_core::paths::host;
use crateward_core::store::{
    Disclosure, JobFilter, PauseReason, Review, Store, StoreError, StoredEvent,
};
use crateward_core::verdict::{Evidence, Verdict};
use secrecy::ExposeSecret;
use serde::Deserialize;

use crate::views::{
    EvidenceView, FindingGroup, FindingItem, InboxPage, JobPage, JobsPage, OverviewBody,
    OverviewData, OverviewPage, PageLink, Row, SeverityCount, StateCount, VerdictView, ago,
};

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

/// The job list's filters.
#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    #[serde(default)]
    name: String,
    #[serde(default)]
    level: String,
    #[serde(default)]
    review: String,
    #[serde(default)]
    state: String,
    /// `rescore`: only finished jobs waiting for the current static analysis
    /// or scoring.
    #[serde(default)]
    verdict: String,
    /// Page number, from 1.
    page: Option<i64>,
    /// Jobs per page, one of [`PER_PAGE`].
    per: Option<i64>,
}

/// The choices of jobs per page.
const PER_PAGE: [i64; 4] = [10, 25, 50, 100];

/// Jobs per page unless chosen.
const DEFAULT_PER_PAGE: i64 = 10;

const LEVELS: [&str; 5] = ["none", "low", "medium", "high", "critical"];

/// The verdict filter's value for verdicts waiting for the current
/// analyzer.
const RESCORE: &str = "rescore";

/// The review filter's values and labels. `unreported` is a confirmed job
/// whose report was not recorded yet.
const REVIEWS: [(&str, &str); 4] = [
    ("pending", "waiting for review"),
    ("confirmed", "confirmed"),
    ("unreported", "confirmed, not reported"),
    ("false_positive", "false positive"),
];

/// The job list's filters, each one of its allowed values or empty.
struct Selection {
    name: String,
    level: &'static str,
    review: &'static str,
    state: &'static str,
    rescore: bool,
}

/// `value` if it is one of `allowed`, or empty.
fn allowed(mut allowed: impl Iterator<Item = &'static str>, value: &str) -> &'static str {
    allowed.find(|a| *a == value).unwrap_or_default()
}

impl Selection {
    fn parse(q: &JobsQuery) -> Self {
        Self {
            name: q.name.chars().take(64).collect(),
            level: allowed(LEVELS.into_iter(), &q.level),
            review: allowed(REVIEWS.iter().map(|(value, _)| *value), &q.review),
            state: allowed(JobState::ALL.iter().map(|s| s.name()), &q.state),
            rescore: q.verdict == RESCORE,
        }
    }

    fn filter(&self) -> JobFilter {
        let some = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        let unreported = self.review == "unreported";

        JobFilter {
            name: some(&self.name),
            level: some(self.level),
            review: some(if unreported { "confirmed" } else { self.review }),
            unreported,
            rescore: self.rescore,
            state: some(self.state),
        }
    }

    /// The job list with these filters but `state`, at `page` of `per` jobs.
    fn href(&self, state: &str, page: i64, per: i64) -> String {
        let page = if page > 1 {
            page.to_string()
        } else {
            String::new()
        };

        let per = if per == DEFAULT_PER_PAGE {
            String::new()
        } else {
            per.to_string()
        };

        jobs_href(&[
            ("name", &self.name),
            ("level", self.level),
            ("review", self.review),
            ("verdict", if self.rescore { RESCORE } else { "" }),
            ("state", state),
            ("per", &per),
            ("page", &page),
        ])
    }
}

/// Which part of `total` jobs is shown.
struct Paging {
    page: i64,
    pages: i64,
    per: i64,
    offset: i64,
}

impl Paging {
    fn new(total: i64, page: Option<i64>, per: Option<i64>) -> Self {
        let per = per
            .filter(|p| PER_PAGE.contains(p))
            .unwrap_or(DEFAULT_PER_PAGE);

        let pages = ((total + per - 1) / per).max(1);
        let page = page.unwrap_or(1).clamp(1, pages);

        Self {
            page,
            pages,
            per,
            offset: (page - 1) * per,
        }
    }
}

async fn jobs(State(state): State<Arc<AppState>>, Query(q): Query<JobsQuery>) -> Page {
    let selection = Selection::parse(&q);
    let filter = selection.filter();

    let counts = state.reader.job_states(&filter).await?;
    let total: i64 = counts
        .iter()
        .filter(|(s, _)| selection.state.is_empty() || s == selection.state)
        .map(|(_, n)| n)
        .sum();

    let paging = Paging::new(total, q.page, q.per);
    let rows = state
        .reader
        .jobs(&filter, paging.offset, paging.per)
        .await?;

    let backlog = state.reader.rescore_backlog().await?;

    let at = |page: i64| selection.href(selection.state, page, paging.per);

    Ok(Html(
        JobsPage {
            states: state_links(&selection, &counts, paging.per),
            all_href: selection.href("", 1, paging.per),
            total,
            first: if rows.is_empty() {
                0
            } else {
                paging.offset + 1
            },
            last: paging.offset + rows.len() as i64,
            pager: pager(paging.page, paging.pages, &at),
            sizes: size_links(&selection, paging.offset, paging.per),
            rows: rows.into_iter().map(Row::from).collect(),
            name: selection.name.clone(),
            level: selection.level.to_owned(),
            levels: LEVELS.iter().map(|l| (*l).to_owned()).collect(),
            review: selection.review.to_owned(),
            reviews: REVIEWS.to_vec(),
            state: selection.state.to_owned(),
            rescore: selection.rescore,
            backlog,
            backlog_href: jobs_href(&[("verdict", RESCORE)]),
            bursting: state.reader.bursting().await?,
        }
        .render()?,
    ))
}

/// A link per job state with its count of matching jobs.
fn state_links(selection: &Selection, counts: &[(String, i64)], per: i64) -> Vec<StateCount> {
    counts
        .iter()
        .map(|(s, n)| StateCount {
            href: selection.href(s, 1, per),
            selected: selection.state == s,
            name: s.clone(),
            n: *n,
        })
        .collect()
}

/// A link per page size, each starting at the page that holds the first
/// job shown now.
fn size_links(selection: &Selection, offset: i64, per: i64) -> Vec<PageLink> {
    PER_PAGE
        .iter()
        .map(|&p| PageLink {
            label: p.to_string(),
            title: format!("{p} jobs per page"),
            href: selection.href(selection.state, offset / p + 1, p),
            class: if p == per { "current" } else { "" },
        })
        .collect()
}

/// Pages shown on each side of the current one, besides the first and last.
const PAGE_SPREAD: i64 = 2;

/// The page numbers to show: the first, the last and those near `page`,
/// with `None` for a gap of more than one page.
fn page_numbers(page: i64, pages: i64) -> Vec<Option<i64>> {
    let near = (page - PAGE_SPREAD).max(1)..=(page + PAGE_SPREAD).min(pages);
    let mut shown: Vec<i64> = [1, pages].into_iter().chain(near).collect();
    shown.sort_unstable();
    shown.dedup();

    let mut out = Vec::new();
    let mut prev = 0;
    for p in shown {
        match p - prev {
            1 => {}
            2 => out.push(Some(p - 1)),
            _ => out.push(None),
        }

        out.push(Some(p));
        prev = p;
    }

    out
}

/// Links to the first, previous, nearby, next and last page.
fn pager(page: i64, pages: i64, at: &dyn Fn(i64) -> String) -> Vec<PageLink> {
    let arrow = |label: &str, title: &str, to: i64, enabled: bool| PageLink {
        label: label.to_owned(),
        title: title.to_owned(),
        href: if enabled { at(to) } else { String::new() },
        class: if enabled { "" } else { "disabled" },
    };

    let numbers = page_numbers(page, pages).into_iter().map(|p| match p {
        Some(p) if p == page => PageLink {
            label: p.to_string(),
            title: format!("page {p}, shown"),
            href: String::new(),
            class: "current",
        },
        Some(p) => PageLink {
            label: p.to_string(),
            title: format!("page {p}"),
            href: at(p),
            class: "",
        },
        None => PageLink {
            label: "…".to_owned(),
            title: String::new(),
            href: String::new(),
            class: "gap",
        },
    });

    [
        arrow("«", "first page", 1, page > 1),
        arrow("‹", "previous page", page - 1, page > 1),
    ]
    .into_iter()
    .chain(numbers)
    .chain([
        arrow("›", "next page", page + 1, page < pages),
        arrow("»", "last page", pages, page < pages),
    ])
    .collect()
}

/// The job list with these filters, leaving out empty ones.
fn jobs_href(params: &[(&str, &str)]) -> String {
    let query: Vec<String> = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", encode(v).replace('/', "%2F")))
        .collect();

    if query.is_empty() {
        "/jobs".to_owned()
    } else {
        format!("/jobs?{}", query.join("&"))
    }
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

fn text(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
        .unwrap_or_default()
}

/// A file of a crate version in the crates.io code viewer, at the line when
/// there is one.
fn code_url(name: &str, version: &str, file: &str, line: Option<u64>) -> String {
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

/// Places listed per evidence before the rest is counted.
const PLACES: usize = 50;

/// A severity as the filter and the colors know it.
fn severity_tone(severity: &str) -> &'static str {
    match severity {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" => "info",
        _ => "other",
    }
}

fn severity_rank(tone: &str) -> u8 {
    match tone {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// The findings grouped by severity, kind and context, and inside a group
/// by evidence, severe and frequent groups first.
fn finding_groups(report: &serde_json::Value, name: &str, version: &str) -> Vec<FindingGroup> {
    let mut groups: Vec<FindingGroup> = Vec::new();
    for f in report_findings(report) {
        let severity = text(f, "severity");
        let kind = match f.get("rule").and_then(serde_json::Value::as_str) {
            Some(rule) => format!("{} {rule}", text(f, "kind")),
            None => text(f, "kind"),
        };

        let context = text(f, "context");
        let same = |g: &&mut FindingGroup| {
            g.severity == severity && g.kind == kind && g.context == context
        };

        let group = match groups.iter_mut().position(|g| same(&g)) {
            Some(i) => groups.get_mut(i),
            None => {
                groups.push(FindingGroup {
                    tone: severity_tone(&severity),
                    severity: severity.clone(),
                    kind: kind.clone(),
                    context: context.clone(),
                    count: 0,
                    items: Vec::new(),
                });
                groups.last_mut()
            }
        };

        let Some(group) = group else { continue };
        group.count += 1;

        let evidence = text(f, "evidence");
        let item = match group.items.iter().position(|i| i.evidence == evidence) {
            Some(i) => group.items.get_mut(i),
            None => {
                group.items.push(FindingItem {
                    evidence,
                    places: Vec::new(),
                    more: 0,
                });
                group.items.last_mut()
            }
        };

        let Some(item) = item else { continue };

        let place = finding_location(f);
        if item.places.len() < PLACES {
            item.places.push((place, finding_url(f, name, version)));
        } else {
            item.more += 1;
        }
    }

    groups.sort_by(|a, b| {
        (severity_rank(a.tone), std::cmp::Reverse(a.count), &a.kind).cmp(&(
            severity_rank(b.tone),
            std::cmp::Reverse(b.count),
            &b.kind,
        ))
    });

    groups
}

/// Findings per severity, in the groups' order.
fn severity_counts(groups: &[FindingGroup]) -> Vec<SeverityCount> {
    let mut counts: Vec<SeverityCount> = Vec::new();
    for g in groups {
        match counts.iter_mut().find(|c| c.tone == g.tone) {
            Some(c) => c.count += g.count,
            None => counts.push(SeverityCount {
                tone: g.tone,
                count: g.count,
            }),
        }
    }

    counts
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
        ("Reported", d.reported()),
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

/// An event as when, from, to, kind and worker. When is an age on the
/// dashboard and a date in the archive, where ages go stale.
fn timeline_row(
    e: StoredEvent,
    now: SystemTime,
    archive: bool,
) -> (String, String, String, String, String) {
    let when = if archive {
        let at =
            e.at.duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());

        export::format_utc(i64::try_from(at).unwrap_or(i64::MAX))
    } else {
        let secs = now
            .duration_since(e.at)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));

        ago(secs)
    };

    let kind = e.event.get("kind").and_then(serde_json::Value::as_str);

    (when, e.from, e.to, kind.unwrap_or("?").to_owned(), e.worker)
}

fn evidence_view(e: Evidence) -> EvidenceView {
    EvidenceView {
        points: e.points,
        signal: e.signal,
        source: e.source.name().to_owned(),
        package: e.package.unwrap_or_default(),
        location: e
            .location
            .as_deref()
            .map(run_view::address)
            .unwrap_or_default(),
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

/// A job's page, for the dashboard or, with `archive`, as a static file
/// of `crateward archive`: without the review decision and run downloads,
/// with dates instead of ages. `None` if there is no such job.
///
/// # Errors
///
/// Fails on database errors.
pub async fn job_page(
    store: &Store,
    id: i64,
    archive: bool,
) -> Result<Option<JobPage>, StoreError> {
    let Some(job) = store.get(JobId(id)).await? else {
        return Ok(None);
    };

    let verdict = store.verdict(job.id).await?.map(verdict_view);
    let mut verdict = verdict.unwrap_or_default();
    let static_report = store.static_report(&job.cksum).await?.map(|(_, r)| r);
    if let Some(report) = &static_report {
        attach_links(&mut verdict.evidence, report, &job.name, &job.version);
    }

    let groups = static_report
        .as_ref()
        .map(|r| finding_groups(r, &job.name, &job.version))
        .unwrap_or_default();

    let findings_dropped = static_report
        .as_ref()
        .and_then(|r| r.get("findings_dropped"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let (evidence, quiet) = verdict.evidence.into_iter().partition(|e| e.points > 0);
    let crate_url = format!(
        "https://crates.io/crates/{}/{}",
        encode(&job.name),
        encode(&job.version).replace('/', "%2F")
    );

    let disclosure = store.disclosure(job.id).await?;
    let slug = disclosure
        .as_ref()
        .and_then(|d| d.published_on.as_ref().and(d.slug.clone()))
        .unwrap_or_default();

    let events = store.events(job.id).await?;
    let runs = store.job_runs(job.id).await?;
    let now = SystemTime::now();

    Ok(Some(JobPage {
        id,
        archive,
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
        evidence,
        quiet,
        new_behavior: verdict.new_behavior,
        profile: verdict.profile,
        severities: severity_counts(&groups),
        finding_total: groups.iter().map(|g| g.count).sum(),
        findings_dropped,
        groups,
        crate_url,
        timeline: events
            .into_iter()
            .map(|e| timeline_row(e, now, archive))
            .collect(),
        runs: run_view::run_views(id, &runs),
        disclosure: disclosure.map(disclosure_rows).unwrap_or_default(),
        finding_url: if slug.is_empty() {
            String::new()
        } else {
            format!("https://{}/findings/{}/", export::DOMAIN, encode(&slug))
        },
    }))
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
        .route("/jobs/{id}/review", post(review))
        .route("/jobs/{id}/runs/{file}", get(run_report))
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
    fn page_numbers_show_the_ends_and_the_neighborhood() {
        let shown = |page, pages| {
            page_numbers(page, pages)
                .iter()
                .map(|p| p.map_or("…".to_owned(), |p| p.to_string()))
                .collect::<Vec<_>>()
                .join(" ")
        };

        assert_eq!(shown(1, 1), "1");
        assert_eq!(shown(1, 5), "1 2 3 4 5");
        assert_eq!(shown(1, 9), "1 2 3 … 9");
        assert_eq!(shown(5, 11), "1 2 3 4 5 6 7 … 11");
        assert_eq!(shown(6, 11), "1 … 4 5 6 7 8 … 11");
        assert_eq!(shown(11, 11), "1 … 9 10 11");
    }

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
