//! The archive: chosen job pages as static files (`crateward archive`).
//!
//! The dashboard ends with the server. The archive keeps what it showed:
//! each chosen job's page as the dashboard renders it, without the review
//! decision and the run downloads, plus an index with the aggregate
//! numbers. The files need no server and no script, so any static host
//! serves them.
//!
//! The archive names crates, so it holds only what may be published:
//! [`ArchiveCandidate::refusal`] keeps out verdicts nobody reviewed yet and
//! confirmed findings before their publication (DISCLOSURE.md).
//! Honeytokens are redacted like in an evidence pack.

use std::path::Path;

use askama::Template;
use crateward_core::store::{ArchiveCandidate, PublicStats, Store, StoreError};
use crateward_core::text::redact;

use crate::export::format_utc;
use crate::{FONTS, job_page};

/// The file that marks a directory as an archive, so writing again may
/// replace it.
pub const SELECTION: &str = "selection.json";

/// Why the archive could not be written.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A template did not render.
    #[error(transparent)]
    Template(#[from] askama::Error),
    /// The selection did not serialize.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A file could not be written.
    #[error("cannot write the archive: {0}")]
    Files(#[from] std::io::Error),
    /// A chosen job is not finished and scored.
    #[error("job {0} is not a finished, scored job")]
    NotCandidate(i64),
    /// A chosen job must not be published.
    #[error("job {id} may not be archived: {reason}")]
    Refused {
        /// The job.
        id: i64,
        /// Why not.
        reason: &'static str,
    },
    /// The directory holds other files.
    #[error("{0} is not empty and holds no earlier archive")]
    NotEmpty(String),
}

/// A job in the archive's index.
#[derive(Debug, Clone)]
pub struct ArchiveRow {
    /// Job ID, the page's name.
    pub id: i64,
    /// Crate name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Score.
    pub score: i32,
    /// Risk level.
    pub level: String,
    /// Review.
    pub review: String,
    /// Coverage in words.
    pub coverage: String,
    /// Strongest evidence, or empty.
    pub evidence: String,
}

impl From<&ArchiveCandidate> for ArchiveRow {
    fn from(c: &ArchiveCandidate) -> Self {
        Self {
            id: c.id.0,
            name: c.name.clone(),
            version: c.version.clone(),
            score: c.score,
            level: c.level.clone(),
            review: c.review.clone(),
            coverage: coverage_label(&c.coverage).to_owned(),
            evidence: c.top_evidence.clone(),
        }
    }
}

/// A coverage kind in a few words.
#[must_use]
pub fn coverage_label(kind: &str) -> &str {
    match kind {
        "dynamic_linux" => "VM run",
        "static_only" => "static only",
        "not_applicable_on_linux" => "not for Linux",
        other => other,
    }
}

/// A level and how many archived jobs have it, for the filter.
#[derive(Debug, Clone)]
pub struct LevelCount {
    /// Level name.
    pub level: String,
    /// Archived jobs.
    pub archived: usize,
    /// Verdicts in the whole dataset.
    pub total: i64,
}

/// The archive's front page.
#[derive(Template)]
#[template(path = "archive.html")]
pub struct ArchiveIndex {
    /// The archived jobs, highest score first.
    pub rows: Vec<ArchiveRow>,
    /// Levels, severe first, with their counts.
    pub levels: Vec<LevelCount>,
    /// Versions Crateward has seen.
    pub versions: i64,
    /// Versions with a verdict.
    pub finished: i64,
    /// Share of those built and traced in a VM.
    pub dynamic_share: String,
    /// Days with finished versions, first and last.
    pub period: String,
    /// When the archive was made.
    pub generated: String,
}

const LEVELS: [&str; 5] = ["critical", "high", "medium", "low", "none"];

impl ArchiveIndex {
    /// The index of `chosen`, with the numbers of the whole dataset.
    #[must_use]
    pub fn new(chosen: &[ArchiveCandidate], stats: &PublicStats, generated: String) -> Self {
        let dynamic: i64 = stats
            .coverage
            .iter()
            .filter(|(kind, _)| kind == "dynamic_linux")
            .map(|(_, n)| n)
            .sum();

        let period = match (stats.daily.last(), stats.daily.first()) {
            (Some((first, _)), Some((last, _))) if first != last => format!("{first} to {last}"),
            (Some((day, _)), _) => day.clone(),
            _ => String::new(),
        };

        Self {
            rows: chosen.iter().map(ArchiveRow::from).collect(),
            levels: LEVELS
                .iter()
                .map(|&level| LevelCount {
                    level: level.to_owned(),
                    archived: chosen.iter().filter(|c| c.level == level).count(),
                    total: stats
                        .levels
                        .iter()
                        .find(|(l, _)| l == level)
                        .map_or(0, |(_, n)| *n),
                })
                .collect(),
            versions: stats.versions,
            finished: stats.finished,
            dynamic_share: format!("{}%", dynamic * 100 / stats.finished.max(1)),
            period,
            generated,
        }
    }
}

/// `text` as askama escapes it, so a honeytoken is found in rendered HTML.
fn escaped(text: &str) -> String {
    text.replace('&', "&#38;")
        .replace('<', "&#60;")
        .replace('>', "&#62;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// Removes every form of the honeytokens from a rendered page.
fn redact_page(html: &str, tokens: &[String]) -> String {
    let forms: Vec<String> = tokens
        .iter()
        .flat_map(|t| [escaped(t), t.clone()])
        .collect();

    redact(html, &forms)
}

/// Checks that `dir` is new, empty, or an earlier archive, and removes the
/// earlier archive's job pages.
fn prepare(dir: &Path) -> Result<(), ArchiveError> {
    match std::fs::read_dir(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(mut entries) => {
            if dir.join(SELECTION).is_file() {
                match std::fs::remove_dir_all(dir.join("jobs")) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        return Err(error.into());
                    }
                    _ => {}
                }
            } else if entries.next().is_some() {
                return Err(ArchiveError::NotEmpty(dir.display().to_string()));
            }
        }
    }

    std::fs::create_dir_all(dir.join("jobs"))?;
    std::fs::create_dir_all(dir.join("static"))?;

    Ok(())
}

/// The chosen jobs as candidates, or why one cannot be archived.
async fn chosen(store: &Store, ids: &[i64]) -> Result<Vec<ArchiveCandidate>, ArchiveError> {
    let found = store.archive_candidates(Some(ids)).await?;

    for id in ids {
        let candidate = found
            .iter()
            .find(|c| c.id.0 == *id)
            .ok_or(ArchiveError::NotCandidate(*id))?;

        if let Some(reason) = candidate.refusal() {
            return Err(ArchiveError::Refused { id: *id, reason });
        }
    }

    Ok(found)
}

/// Writes the archive of the jobs `ids` into `dir`: `index.html`, a page per
/// job under `jobs/`, the stylesheet and fonts under `static/`, and
/// `selection`, which says how the jobs were chosen. Nothing is written if a
/// job may not be archived. Returns the number of job pages.
///
/// # Errors
///
/// Fails if a job may not be archived, on database and template errors,
/// and if a file cannot be written.
pub async fn write(
    store: &Store,
    ids: &[i64],
    dir: &Path,
    selection: &serde_json::Value,
) -> Result<usize, ArchiveError> {
    let mut chosen = chosen(store, ids).await?;
    prepare(dir)?;

    for c in &mut chosen {
        let Some(page) = job_page(store, c.id.0, true).await? else {
            return Err(ArchiveError::NotCandidate(c.id.0));
        };

        let tokens = store.honeytoken_values(c.id).await?;
        let html = redact_page(&page.render()?, &tokens);
        std::fs::write(dir.join("jobs").join(format!("{}.html", c.id.0)), html)?;

        // The index shows the strongest evidence too.
        c.top_evidence = redact(&c.top_evidence, &tokens);
    }

    let stats = store.public_stats().await?;
    let generated = format_utc(store.now_epoch().await?);
    let index = ArchiveIndex::new(&chosen, &stats, generated).render()?;
    std::fs::write(dir.join("index.html"), index)?;

    std::fs::write(
        dir.join("static").join("crateward.css"),
        crate::DASHBOARD_CSS,
    )?;

    for (name, bytes, _) in FONTS {
        std::fs::write(dir.join("static").join(name), bytes)?;
    }

    std::fs::write(
        dir.join("static").join("OFL.txt"),
        include_bytes!("../static/OFL.txt"),
    )?;

    std::fs::write(
        dir.join(SELECTION),
        serde_json::to_string_pretty(selection)? + "\n",
    )?;

    // Static hosts such as GitHub Pages serve the files as they are.
    std::fs::write(dir.join(".nojekyll"), "")?;

    Ok(chosen.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honeytokens_are_redacted_raw_and_escaped() {
        let tokens = vec!["ghp_a\"b&c".to_owned(), "AKIA123".to_owned()];
        let html = "<p>ghp_a&#34;b&#38;c and AKIA123 and ghp_a\"b&c</p>";

        assert_eq!(
            redact_page(html, &tokens),
            "<p>[honeytoken] and [honeytoken] and [honeytoken]</p>"
        );
    }

    #[test]
    fn coverage_kinds_are_short_words() {
        assert_eq!(coverage_label("dynamic_linux"), "VM run");
        assert_eq!(coverage_label("odd"), "odd");
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("crateward-archive-{name}-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&dir);

        dir
    }

    #[test]
    fn only_new_empty_or_earlier_archives_are_written_to() {
        let dir = scratch("prepare");
        prepare(&dir).unwrap();
        std::fs::write(dir.join("jobs").join("1.html"), "old").unwrap();
        std::fs::write(dir.join(SELECTION), "{}").unwrap();

        prepare(&dir).unwrap();
        assert!(!dir.join("jobs").join("1.html").exists());

        let other = scratch("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("notes.txt"), "mine").unwrap();
        assert!(matches!(prepare(&other), Err(ArchiveError::NotEmpty(_))));

        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(other).unwrap();
    }
}
