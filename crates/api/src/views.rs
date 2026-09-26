//! Page templates. askama escapes every value at compile time (ADR 0005);
//! nothing here marks text as safe HTML.

use askama::Template;
use crateward_core::store::JobRow;

/// Seconds as a short relative time.
#[must_use]
pub fn ago(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s} s ago"),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 86_400 => format!("{} h ago", s / 3600),
        s => format!("{} d ago", s / 86_400),
    }
}

/// A job row as shown.
#[derive(Debug, Clone)]
pub struct Row {
    /// Job ID.
    pub id: i64,
    /// Crate name.
    pub name: String,
    /// Version.
    pub version: String,
    /// State.
    pub state: String,
    /// Score, or empty.
    pub score: String,
    /// Level, or empty.
    pub level: String,
    /// Review, or empty.
    pub review: String,
    /// Strongest evidence, or empty.
    pub evidence: String,
    /// Relative age.
    pub age: String,
}

impl From<JobRow> for Row {
    fn from(r: JobRow) -> Self {
        Self {
            id: r.id.0,
            name: r.name,
            version: r.version,
            state: r.state,
            score: r.score.map(|s| s.to_string()).unwrap_or_default(),
            level: r.level.unwrap_or_default(),
            review: r.review.unwrap_or_default(),
            evidence: r.top_evidence.unwrap_or_default(),
            age: ago(r.age_secs),
        }
    }
}

/// The overview's live part.
#[derive(Debug, Clone, Default)]
pub struct OverviewData {
    /// Verdicts waiting for review.
    pub pending_reviews: i64,
    /// Finished in 24 hours.
    pub done_24h: i64,
    /// Share of those with a VM run.
    pub dynamic_share: String,
    /// Alerts not yet delivered.
    pub alerts_waiting: usize,
    /// Active pauses, described.
    pub pauses: Vec<String>,
    /// Stage and breaker state.
    pub breakers: Vec<(String, String)>,
    /// Canary, passed, when.
    pub canaries: Vec<(String, bool, String)>,
    /// Jobs per state.
    pub states: Vec<(String, i64)>,
    /// Verdicts per level.
    pub levels: Vec<(String, i64)>,
    /// When this was read.
    pub updated: String,
}

/// The overview page.
#[derive(Template)]
#[template(path = "overview.html")]
pub struct OverviewPage {
    /// Its data.
    pub o: OverviewData,
}

/// The overview's live part, sent over server sent events.
#[derive(Template)]
#[template(path = "overview_body.html")]
pub struct OverviewBody {
    /// Its data.
    pub o: OverviewData,
}

/// The inbox.
#[derive(Template)]
#[template(path = "inbox.html")]
pub struct InboxPage {
    /// Pending verdicts.
    pub rows: Vec<Row>,
}

/// The job list.
#[derive(Template)]
#[template(path = "jobs.html")]
pub struct JobsPage {
    /// Matching jobs.
    pub rows: Vec<Row>,
    /// The name filter.
    pub name: String,
    /// The level filter.
    pub level: String,
    /// Every level, for the select.
    pub levels: Vec<String>,
}

/// One piece of evidence as shown.
#[derive(Debug, Clone)]
pub struct EvidenceView {
    /// Points.
    pub points: u32,
    /// Signal.
    pub signal: String,
    /// Source.
    pub source: String,
    /// Package, or empty.
    pub package: String,
    /// Location, or empty.
    pub location: String,
    /// Summary.
    pub summary: String,
}

/// One static finding as shown.
#[derive(Debug, Clone)]
pub struct FindingView {
    /// Severity.
    pub severity: String,
    /// Kind.
    pub kind: String,
    /// Code context.
    pub context: String,
    /// File and line.
    pub location: String,
    /// Evidence.
    pub evidence: String,
}

/// A job's page.
#[derive(Template)]
#[template(path = "job.html")]
pub struct JobPage {
    /// Job ID.
    pub id: i64,
    /// Crate name.
    pub name: String,
    /// Version.
    pub version: String,
    /// State.
    pub state: String,
    /// Coverage label, or empty.
    pub coverage: String,
    /// Score, or empty when not scored.
    pub score: String,
    /// Level, or empty.
    pub level: String,
    /// Review, or empty.
    pub review: String,
    /// Evidence, strongest first.
    pub evidence: Vec<EvidenceView>,
    /// Behavior new against the previous version.
    pub new_behavior: Vec<String>,
    /// Behavior profile.
    pub profile: Vec<String>,
    /// Static findings of the crate's own file.
    pub findings: Vec<FindingView>,
    /// When, from, to, event, worker.
    pub timeline: Vec<(String, String, String, String, String)>,
    /// Run kind and its report, pretty printed.
    pub runs: Vec<(String, String)>,
    /// The disclosure record as label and value, empty without a report.
    pub disclosure: Vec<(String, String)>,
}
