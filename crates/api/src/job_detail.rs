//! The job page: verdict, evidence, findings grouped by severity, the
//! disclosure, the timeline and the runs.

use std::time::SystemTime;

use crateward_core::job::JobId;
use crateward_core::store::{Disclosure, Review, Store, StoreError, StoredEvent};
use crateward_core::verdict::{Evidence, Verdict};

use crate::views::{
    EvidenceView, FindingGroup, FindingItem, JobPage, SeverityCount, VerdictView, ago,
};
use crate::{diff, encode, export, run_view};

/// A field of a stored JSON object as text, empty when it is missing.
pub(crate) fn text(v: &serde_json::Value, key: &str) -> String {
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

pub(crate) fn report_findings(report: &serde_json::Value) -> &[serde_json::Value] {
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
pub(crate) fn finding_groups(
    report: &serde_json::Value,
    name: &str,
    version: &str,
) -> Vec<FindingGroup> {
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

pub(crate) fn verdict_view((verdict, review): (Verdict, Review)) -> VerdictView {
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
    let verdict_missing = verdict.is_none();
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
    let has_documents = store.job_sbom(job.id).await?.is_some() && !verdict_missing;
    let now = SystemTime::now();

    // The archive links a comparison only if it holds both versions.
    let previous = if archive {
        None
    } else {
        let versions = store.analyzed_versions(job.id).await?;
        diff::counterpart(&versions, id, None).map(|v| v.version.clone())
    };

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
        compare_href: previous
            .as_ref()
            .map(|_| format!("/jobs/{id}/diff"))
            .unwrap_or_default(),
        compare_version: previous.unwrap_or_default(),
        sbom_href: if has_documents {
            sbom_href(id, archive)
        } else {
            String::new()
        },
        vex_href: if has_documents {
            vex_href(id, archive)
        } else {
            String::new()
        },
    }))
}

/// A job's SBOM: the dashboard's download, or the archive's file name.
pub(crate) fn sbom_href(id: i64, archive: bool) -> String {
    if archive {
        format!("{id}.cdx.json")
    } else {
        format!("/jobs/{id}/sbom.cdx.json")
    }
}

/// A job's findings document, as [`sbom_href`].
pub(crate) fn vex_href(id: i64, archive: bool) -> String {
    if archive {
        format!("{id}.vex.cdx.json")
    } else {
        format!("/jobs/{id}/vex.cdx.json")
    }
}

/// A job's page, by its ID: the dashboard's, or the archive's file name.
pub(crate) fn job_href(id: i64, archive: bool) -> String {
    if archive {
        format!("{id}.html")
    } else {
        format!("/jobs/{id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
