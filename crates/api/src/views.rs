//! Page templates. askama escapes every value at compile time (ADR 0009).
//! Nothing here marks text as safe HTML.

use askama::Template;
use crateward_core::attack::Technique;
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
    /// Whether a report was recorded.
    pub reported: bool,
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
            reported: r.reported,
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
    /// Confirmed verdicts without a recorded report.
    pub unreported: Vec<Row>,
}

/// The number of matching jobs in one state, linking to them.
#[derive(Debug, Clone)]
pub struct StateCount {
    /// State name.
    pub name: String,
    /// Matching jobs in it.
    pub n: i64,
    /// The job list filtered to it.
    pub href: String,
    /// Whether the list is filtered to it.
    pub selected: bool,
}

/// A link in the pager.
#[derive(Debug, Clone)]
pub struct PageLink {
    /// Shown text.
    pub label: String,
    /// Tooltip, or empty.
    pub title: String,
    /// Target, or empty for no link.
    pub href: String,
    /// `current`, `disabled`, `gap` or empty.
    pub class: &'static str,
}

/// The job list.
#[derive(Template)]
#[template(path = "jobs.html")]
pub struct JobsPage {
    /// Matching jobs per state, in pipeline order.
    pub states: Vec<StateCount>,
    /// The job list without the state filter.
    pub all_href: String,
    /// Matching jobs, in the selected state if any.
    pub total: i64,
    /// The position of the first job shown, from 1, or 0 when none is.
    pub first: i64,
    /// The position of the last job shown.
    pub last: i64,
    /// Links to other pages.
    pub pager: Vec<PageLink>,
    /// Links to the same jobs with another page size.
    pub sizes: Vec<PageLink>,
    /// Matching jobs on this page.
    pub rows: Vec<Row>,
    /// The name filter.
    pub name: String,
    /// The level filter.
    pub level: String,
    /// Every level, for the select.
    pub levels: Vec<String>,
    /// The review filter.
    pub review: String,
    /// Every review filter, value and label.
    pub reviews: Vec<(&'static str, &'static str)>,
    /// The state filter.
    pub state: String,
    /// Only finished jobs waiting for the current static analysis or scoring.
    pub rescore: bool,
    /// How many finished jobs wait for it.
    pub backlog: i64,
    /// The job list of those jobs.
    pub backlog_href: String,
    /// Whether burst mode is on.
    pub bursting: bool,
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
    /// The file in the crates.io code viewer, or empty.
    pub code_url: String,
    /// ATT&CK techniques it is consistent with.
    pub techniques: Vec<Technique>,
}

/// The parts of a job page that come from its verdict.
#[derive(Debug, Default)]
pub struct VerdictView {
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
    /// The file in the crates.io code viewer, or empty.
    pub code_url: String,
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
    /// ATT&CK techniques of all evidence, the supply chain compromise
    /// first once a human confirmed the verdict.
    pub techniques: Vec<Technique>,
    /// The ATT&CK release the techniques follow.
    pub attack_version: &'static str,
    /// Static findings of the crate's own file.
    pub findings: Vec<FindingView>,
    /// When, from, to, event, worker.
    pub timeline: Vec<(String, String, String, String, String)>,
    /// The VM runs shown.
    pub runs: Vec<crate::run_view::RunView>,
    /// The disclosure record as label and value, empty without a report.
    pub disclosure: Vec<(String, String)>,
}
