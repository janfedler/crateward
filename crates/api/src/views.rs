//! Page templates. askama escapes every value at compile time (ADR 0009).
//! Nothing here marks text as safe HTML.

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

impl OverviewData {
    /// Verdicts in all, the scale of the level bars.
    #[must_use]
    pub fn verdicts(&self) -> i64 {
        self.levels.iter().map(|(_, n)| n).sum::<i64>().max(1)
    }

    /// Jobs in all, the scale of the state bars.
    #[must_use]
    pub fn jobs(&self) -> i64 {
        self.states.iter().map(|(_, n)| n).sum::<i64>().max(1)
    }
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
}

impl EvidenceView {
    /// How much the points weigh: `bad`, `warn` or `low`.
    #[must_use]
    pub fn tone(&self) -> &'static str {
        match self.points {
            30.. => "bad",
            10.. => "warn",
            _ => "low",
        }
    }
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

/// Static findings of one severity, kind and context.
#[derive(Debug, Clone)]
pub struct FindingGroup {
    /// Severity as the report names it.
    pub severity: String,
    /// `critical`, `high`, `medium`, `low`, `info` or `other`, for the
    /// filter and the colors.
    pub tone: &'static str,
    /// Kind, with the YARA rule.
    pub kind: String,
    /// Code context.
    pub context: String,
    /// How many findings.
    pub count: usize,
    /// The findings by evidence.
    pub items: Vec<FindingItem>,
}

impl FindingGroup {
    /// Shown open: the severe ones.
    #[must_use]
    pub fn open(&self) -> bool {
        matches!(self.tone, "critical" | "high")
    }
}

/// Findings with the same evidence, and where they are.
#[derive(Debug, Clone)]
pub struct FindingItem {
    /// Evidence.
    pub evidence: String,
    /// File and line, and the place in the crates.io code viewer.
    pub places: Vec<(String, String)>,
    /// Places not listed.
    pub more: usize,
}

/// How many static findings have a severity, for the filter.
#[derive(Debug, Clone)]
pub struct SeverityCount {
    /// The filter's tone, as in [`FindingGroup::tone`].
    pub tone: &'static str,
    /// Findings.
    pub count: usize,
}

/// A job's page.
#[derive(Template)]
#[template(path = "job.html")]
pub struct JobPage {
    /// Job ID.
    pub id: i64,
    /// A static page of `crateward archive` instead of the dashboard's.
    pub archive: bool,
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
    /// Evidence with points, strongest first.
    pub evidence: Vec<EvidenceView>,
    /// Evidence without points.
    pub quiet: Vec<EvidenceView>,
    /// Behavior new against the previous version.
    pub new_behavior: Vec<String>,
    /// Behavior profile.
    pub profile: Vec<String>,
    /// Static findings of the crate's own file, grouped, severe first.
    pub groups: Vec<FindingGroup>,
    /// Findings per severity, severe first.
    pub severities: Vec<SeverityCount>,
    /// Static findings in all.
    pub finding_total: usize,
    /// Findings the analysis dropped over its limit.
    pub findings_dropped: u64,
    /// The crate version on crates.io.
    pub crate_url: String,
    /// When, from, to, event, worker.
    pub timeline: Vec<(String, String, String, String, String)>,
    /// The VM runs shown.
    pub runs: Vec<crate::run_view::RunView>,
    /// The disclosure record as label and value, empty without a report.
    pub disclosure: Vec<(String, String)>,
    /// The published finding page on the public site, or empty.
    pub finding_url: String,
    /// The comparison with the previous version, or empty.
    pub compare_href: String,
    /// The previous version, or empty.
    pub compare_version: String,
    /// The SBOM's link, empty when the job has none yet.
    pub sbom_href: String,
    /// The findings document's link, empty with the SBOM's.
    pub vex_href: String,
}

/// Another analyzed version of the crate, to compare with.
#[derive(Debug, Clone)]
pub struct VersionLink {
    /// Version.
    pub version: String,
    /// The comparison with it.
    pub href: String,
    /// It is the one compared.
    pub selected: bool,
}

/// The comparison of a job with another version of its crate (ADR 0011).
#[derive(Template)]
#[template(path = "diff.html")]
pub struct DiffPage {
    /// A static page of `crateward archive` instead of the dashboard's.
    pub archive: bool,
    /// Crate name.
    pub name: String,
    /// The newer side.
    pub now: DiffHead,
    /// The side compared with.
    pub before: DiffHead,
    /// The two versions on diff.rs.
    pub source_url: String,
    /// Other versions to compare with, empty in the archive.
    pub versions: Vec<VersionLink>,
    /// The package changes the static analysis recorded.
    pub package: Vec<(String, String)>,
    /// Why there are none, or empty.
    pub package_note: String,
    /// The changes.
    pub c: crate::diff::Comparison,
}

/// One side in the head of a comparison.
#[derive(Debug, Clone)]
pub struct DiffHead {
    /// Version.
    pub version: String,
    /// Its job page.
    pub href: String,
    /// Score, or empty.
    pub score: String,
    /// Level, or empty.
    pub level: String,
}
