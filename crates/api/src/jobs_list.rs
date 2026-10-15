//! The job list: its filters, state counts and pages.

use std::sync::Arc;
use std::time::{Duration, Instant};

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Html;
use crateward_core::job::JobState;
use crateward_core::store::{JobFilter, Store, StoreError};
use serde::Deserialize;

use crate::views::{JobsPage, PageLink, Row, StateCount};
use crate::{AppState, Page, encode};

/// How long the jobs page shows the same reprocessing backlog. Counting it
/// reads every verdict, and it only changes when a new analyzer ships or a
/// burst makes progress.
const BACKLOG_TTL: Duration = Duration::from_secs(60);

/// The reprocessing backlog, counted at most once a minute.
/// Requests that arrive while it is counted wait for that count.
#[derive(Debug, Default)]
pub struct Backlog(tokio::sync::Mutex<Option<(Instant, i64)>>);

impl Backlog {
    async fn count(&self, store: &Store) -> Result<i64, StoreError> {
        let mut cached = self.0.lock().await;
        if let Some((at, count)) = *cached
            && at.elapsed() < BACKLOG_TTL
        {
            return Ok(count);
        }

        let count = store.rescore_backlog().await?;
        *cached = Some((Instant::now(), count));

        Ok(count)
    }
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

pub(crate) async fn jobs(State(state): State<Arc<AppState>>, Query(q): Query<JobsQuery>) -> Page {
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

    let backlog = state.backlog.count(&state.reader).await?;

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

#[cfg(test)]
mod tests {
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
}
