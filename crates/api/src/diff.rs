//! What changed between two versions of a crate (ADR 0011).
//!
//! The comparison reads stored data only: the verdicts, the static reports,
//! the VM runs and the static analysis' package diff. It is computed when
//! the page is shown, so it always uses the current views. [`compare`] is
//! pure and needs no database.
//!
//! Things are compared by what stays the same between builds, never by
//! process IDs, times or line numbers: evidence by signal and package,
//! findings by severity, kind, context, file and evidence, processes by
//! their place in the folded tree, files by program and path.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crateward_core::job::JobId;
use crateward_core::store::{AnalyzedVersion, Store, StoreError};
use serde_json::{Value, json};

use crate::run_view::{self, ConnectionRow, ProcessRow, RunView, build_package};
use crate::views::{EvidenceView, FindingGroup};
use crate::{encode, finding_groups, report_findings, text, verdict_view};

/// Process lines shown per list before the rest is counted.
const LINES: usize = 400;

/// One side of a comparison, as stored.
#[derive(Debug, Clone, Default)]
pub struct Side {
    /// Job ID.
    pub id: i64,
    /// Crate name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Score, or empty.
    pub score: String,
    /// Level, or empty.
    pub level: String,
    /// Every piece of evidence.
    pub evidence: Vec<EvidenceView>,
    /// Behavior profile.
    pub profile: Vec<String>,
    /// The static report, or `null`.
    pub report: Value,
    /// VM runs by kind.
    pub runs: Vec<(String, Value)>,
}

impl Side {
    /// The side of `job`, or `None` if there is no such job.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn load(store: &Store, job: i64) -> Result<Option<Self>, StoreError> {
        let Some(stored) = store.get(JobId(job)).await? else {
            return Ok(None);
        };

        let verdict = store
            .verdict(stored.id)
            .await?
            .map(verdict_view)
            .unwrap_or_default();

        let report = store
            .static_report(&stored.cksum)
            .await?
            .map_or(Value::Null, |(_, r)| r);

        Ok(Some(Self {
            id: job,
            name: stored.name,
            version: stored.version,
            score: verdict.score,
            level: verdict.level,
            evidence: verdict.evidence,
            profile: verdict.profile,
            report,
            runs: store.job_runs(stored.id).await?,
        }))
    }
}

/// A piece of evidence that is new, gone or weighs differently.
#[derive(Debug, Clone)]
pub struct EvidenceChange {
    /// `added`, `removed` or `changed`.
    pub change: &'static str,
    /// Signal.
    pub signal: String,
    /// Package, or empty.
    pub package: String,
    /// Points before, or empty when it is new.
    pub before: String,
    /// Points now, or empty when it is gone.
    pub after: String,
    /// The summary, of the newer side that has it.
    pub summary: String,
    /// `bad`, `warn` or `low`, by the points it adds.
    pub tone: &'static str,
}

/// A process of a tree, shown because it is new or gone, or as the
/// ancestor of one that is.
#[derive(Debug, Clone)]
pub struct TreeLine {
    /// The process.
    pub row: ProcessRow,
    /// Shown only for its place in the tree.
    pub context: bool,
}

/// A file a run touched.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileChange {
    /// `secret read`, `written` or the scratch disk's reason.
    pub what: String,
    /// The program, or empty.
    pub program: String,
    /// The path.
    pub path: String,
}

/// The comparison of two VM runs of the same kind.
#[derive(Debug, Clone, Default)]
pub struct RunDiff {
    /// `check` or `full`.
    pub kind: String,
    /// Why the processes cannot be compared, or empty.
    pub trimmed: String,
    /// The newer tree's new processes, with their ancestors.
    pub new_processes: Vec<TreeLine>,
    /// The older tree's processes that are gone, with their ancestors.
    pub gone_processes: Vec<TreeLine>,
    /// New process rows.
    pub added: usize,
    /// Gone process rows.
    pub removed: usize,
    /// Process rows in both.
    pub same: usize,
    /// Lines not shown over the limit.
    pub more: usize,
    /// New lookups.
    pub dns_added: Vec<String>,
    /// Lookups that are gone.
    pub dns_removed: Vec<String>,
    /// New connections.
    pub connections_added: Vec<ConnectionRow>,
    /// Connections that are gone.
    pub connections_removed: Vec<ConnectionRow>,
    /// Lookups and connections in both.
    pub network_same: usize,
    /// New file accesses and scratch entries.
    pub files_added: Vec<FileChange>,
    /// File accesses and scratch entries that are gone.
    pub files_removed: Vec<FileChange>,
    /// File accesses and scratch entries in both.
    pub files_same: usize,
}

impl RunDiff {
    /// Process changes.
    #[must_use]
    pub fn process_changes(&self) -> usize {
        self.added + self.removed
    }

    /// Network changes.
    #[must_use]
    pub fn network_changes(&self) -> usize {
        self.dns_added.len()
            + self.dns_removed.len()
            + self.connections_added.len()
            + self.connections_removed.len()
    }

    /// File changes.
    #[must_use]
    pub fn file_changes(&self) -> usize {
        self.files_added.len() + self.files_removed.len()
    }

    /// Every change.
    #[must_use]
    pub fn changes(&self) -> usize {
        self.process_changes() + self.network_changes() + self.file_changes()
    }
}

/// Everything that changed between two versions.
#[derive(Debug, Clone, Default)]
pub struct Comparison {
    /// Evidence that is new, gone or weighs differently, new first.
    pub evidence: Vec<EvidenceChange>,
    /// Evidence that is the same.
    pub evidence_same: usize,
    /// New findings, grouped like the job page.
    pub added_groups: Vec<FindingGroup>,
    /// Findings that are gone, grouped.
    pub removed_groups: Vec<FindingGroup>,
    /// New findings.
    pub findings_added: usize,
    /// Findings that are gone.
    pub findings_removed: usize,
    /// Findings in both.
    pub findings_same: usize,
    /// The runs compared, the full run first.
    pub runs: Vec<RunDiff>,
    /// Why no runs are compared, or empty.
    pub runs_note: String,
    /// New behavior.
    pub profile_added: Vec<String>,
    /// Behavior that is gone.
    pub profile_removed: Vec<String>,
    /// Behavior in both.
    pub profile_same: usize,
}

impl Comparison {
    /// Evidence changes.
    #[must_use]
    pub fn evidence_changes(&self) -> usize {
        self.evidence.len()
    }

    /// Finding changes.
    #[must_use]
    pub fn finding_changes(&self) -> usize {
        self.findings_added + self.findings_removed
    }

    /// Behavior changes.
    #[must_use]
    pub fn profile_changes(&self) -> usize {
        self.profile_added.len() + self.profile_removed.len()
    }
}

fn tone(points: u32) -> &'static str {
    match points {
        30.. => "bad",
        10.. => "warn",
        _ => "low",
    }
}

/// Evidence by signal and package: the points summed, the summary of the
/// strongest.
fn evidence_by_key(evidence: &[EvidenceView]) -> BTreeMap<(String, String), (u32, String)> {
    let mut keyed: BTreeMap<(String, String), (u32, String, u32)> = BTreeMap::new();
    for e in evidence {
        let entry = keyed
            .entry((e.signal.clone(), e.package.clone()))
            .or_insert((0, String::new(), 0));

        entry.0 += e.points;

        if entry.1.is_empty() || e.points > entry.2 {
            entry.1.clone_from(&e.summary);
            entry.2 = e.points;
        }
    }

    keyed
        .into_iter()
        .map(|(k, (points, summary, _))| (k, (points, summary)))
        .collect()
}

fn evidence_changes(now: &[EvidenceView], before: &[EvidenceView]) -> (Vec<EvidenceChange>, usize) {
    let now = evidence_by_key(now);
    let before = evidence_by_key(before);
    let mut changes = Vec::new();
    let mut same = 0;

    for (key, (points, summary)) in &now {
        let change = match before.get(key) {
            None => "added",
            Some((old, _)) if old != points => "changed",
            Some(_) => {
                same += 1;
                continue;
            }
        };

        let old = before.get(key).map(|(p, _)| *p);
        changes.push(EvidenceChange {
            change,
            signal: key.0.clone(),
            package: key.1.clone(),
            before: old.map(|p| p.to_string()).unwrap_or_default(),
            after: points.to_string(),
            summary: summary.clone(),
            tone: tone(points.saturating_sub(old.unwrap_or(0))),
        });
    }

    for (key, (points, summary)) in before.iter().filter(|(k, _)| !now.contains_key(*k)) {
        changes.push(EvidenceChange {
            change: "removed",
            signal: key.0.clone(),
            package: key.1.clone(),
            before: points.to_string(),
            after: String::new(),
            summary: summary.clone(),
            tone: "low",
        });
    }

    let rank = |c: &EvidenceChange| match c.change {
        "added" => 0,
        "changed" => 1,
        _ => 2,
    };

    let weight = |c: &EvidenceChange| {
        std::cmp::Reverse(
            c.after
                .parse::<u32>()
                .unwrap_or(0)
                .max(c.before.parse().unwrap_or(0)),
        )
    };

    changes.sort_by_key(|c| (rank(c), weight(c), c.signal.clone()));

    (changes, same)
}

/// What makes a finding the same in another version. Lines move with any
/// edit, so they do not count.
fn finding_key(f: &Value) -> String {
    let rule = f.get("rule").map(Value::to_string).unwrap_or_default();

    [
        text(f, "severity"),
        text(f, "kind"),
        rule,
        text(f, "context"),
        text(f, "file"),
        text(f, "evidence"),
    ]
    .join("\u{1f}")
}

/// The findings of `report` whose key is not in `other`, `n` times for a
/// key `other` has `n` fewer times.
fn new_findings(report: &Value, other: &Value) -> Vec<Value> {
    let mut left: HashMap<String, usize> = HashMap::new();
    for f in report_findings(other) {
        *left.entry(finding_key(f)).or_default() += 1;
    }

    report_findings(report)
        .iter()
        .filter(|f| match left.get_mut(&finding_key(f)) {
            Some(n) if *n > 0 => {
                *n -= 1;
                false
            }
            _ => true,
        })
        .cloned()
        .collect()
}

/// A process's place in its tree: the programs of its ancestors, then its
/// own program, exit and whether it became root. Build scripts count by
/// package, since cargo names their directory with a hash.
fn tree_keys(rows: &[ProcessRow]) -> Vec<String> {
    let mut stack: Vec<(usize, String)> = Vec::new();

    rows.iter()
        .map(|row| {
            while stack.last().is_some_and(|(n, _)| *n >= row.nesting) {
                stack.pop();
            }

            let program = format!("{}:{}", row.role, row.label());
            let path: Vec<&str> = stack.iter().map(|(_, p)| p.as_str()).collect();
            let key = format!("{}/{program}:{}:{}", path.join("/"), row.exit, row.root);
            stack.push((row.nesting, program));

            key
        })
        .collect()
}

/// Which rows of `rows` have no counterpart in `other`.
fn unmatched(rows: &[ProcessRow], other: &[ProcessRow]) -> Vec<bool> {
    let mut left: HashMap<String, usize> = HashMap::new();
    for key in tree_keys(other) {
        *left.entry(key).or_default() += 1;
    }

    tree_keys(rows)
        .into_iter()
        .map(|key| match left.get_mut(&key) {
            Some(n) if *n > 0 => {
                *n -= 1;
                false
            }
            _ => true,
        })
        .collect()
}

/// The changed rows with their ancestors, in tree order, at most [`LINES`].
/// Returns the lines and how many were left out.
fn tree_lines(rows: &[ProcessRow], changed: &[bool]) -> (Vec<TreeLine>, usize) {
    let mut shown = vec![false; rows.len()];

    for (i, _) in changed.iter().enumerate().filter(|(_, c)| **c) {
        if let Some(s) = shown.get_mut(i) {
            *s = true;
        }

        // Ancestors: each earlier row less deep than the last one found.
        let mut nesting = rows.get(i).map_or(0, |r| r.nesting);
        for j in (0..i).rev() {
            let Some(row) = rows.get(j) else { break };
            if row.nesting < nesting {
                if shown.get(j) == Some(&true) && changed.get(j) == Some(&true) {
                    break;
                }

                if let Some(s) = shown.get_mut(j) {
                    *s = true;
                }

                nesting = row.nesting;

                if nesting == 0 {
                    break;
                }
            }
        }
    }

    let mut lines: Vec<TreeLine> = rows
        .iter()
        .zip(shown.iter().zip(changed))
        .filter(|(_, (shown, _))| **shown)
        .map(|(row, (_, changed))| TreeLine {
            row: row.clone(),
            context: !changed,
        })
        .collect();

    let more = lines.len().saturating_sub(LINES);
    lines.truncate(LINES);

    (lines, more)
}

/// The rows of `a` not in `b`, and how many of `a` are in `b`.
fn set_difference<T: Clone + Ord>(a: &[T], b: &[T]) -> (Vec<T>, usize) {
    let b: BTreeSet<&T> = b.iter().collect();
    let (gone, kept): (Vec<&T>, Vec<&T>) = a.iter().partition(|x| !b.contains(x));

    (gone.into_iter().cloned().collect(), kept.len())
}

fn files(view: &RunView) -> Vec<FileChange> {
    let program = |exe: &str| build_package(exe).unwrap_or(exe).to_owned();
    let access = |what: &str, rows: &[run_view::AccessRow]| -> Vec<FileChange> {
        rows.iter()
            .map(|a| FileChange {
                what: what.to_owned(),
                program: program(&a.exe),
                path: a.path.clone(),
            })
            .collect()
    };

    let mut all = access("secret read", &view.sensitive);
    all.extend(access("written", &view.writes));
    all.extend(view.entries.iter().map(|e| FileChange {
        what: e.why.to_owned(),
        program: String::new(),
        path: e.path.clone(),
    }));
    all.sort();
    all.dedup();

    all
}

/// A connection as compared: where, how and what was sent, not how much.
fn connection_key(c: &ConnectionRow) -> (String, String, String) {
    (c.dst.clone(), c.protocol.clone(), c.detail.clone())
}

fn connections(a: &[ConnectionRow], b: &[ConnectionRow]) -> (Vec<ConnectionRow>, usize) {
    let b: BTreeSet<_> = b.iter().map(connection_key).collect();
    let mut seen = BTreeSet::new();
    let mut same = 0;
    let mut gone = Vec::new();

    for c in a {
        let key = connection_key(c);
        if !seen.insert(key.clone()) {
            continue;
        }

        if b.contains(&key) {
            same += 1;
        } else {
            gone.push(c.clone());
        }
    }

    (gone, same)
}

fn run_diff(kind: &str, now: &Value, before: &Value) -> RunDiff {
    let now = run_view::run_view(0, kind, now);
    let before = run_view::run_view(0, kind, before);
    let mut diff = RunDiff {
        kind: kind.to_owned(),
        ..RunDiff::default()
    };

    if now.trimmed || before.trimmed {
        diff.trimmed = "Retention removed the process list of a run, so processes are not compared. The network and files still are.".to_owned();
    } else {
        let added = unmatched(&now.processes, &before.processes);
        let removed = unmatched(&before.processes, &now.processes);
        diff.added = added.iter().filter(|a| **a).count();
        diff.removed = removed.iter().filter(|r| **r).count();
        diff.same = now.processes.len() - diff.added;

        let (new, more_new) = tree_lines(&now.processes, &added);
        let (gone, more_gone) = tree_lines(&before.processes, &removed);
        diff.new_processes = new;
        diff.gone_processes = gone;
        diff.more = more_new + more_gone;
    }

    let (dns_added, dns_same) = set_difference(&now.dns, &before.dns);
    diff.dns_added = dns_added;
    diff.dns_removed = set_difference(&before.dns, &now.dns).0;
    let (added, connections_same) = connections(&now.connections, &before.connections);
    diff.connections_added = added;
    diff.connections_removed = connections(&before.connections, &now.connections).0;
    diff.network_same = dns_same + connections_same;

    let (now_files, before_files) = (files(&now), files(&before));
    let (files_added, files_same) = set_difference(&now_files, &before_files);
    diff.files_added = files_added;
    diff.files_removed = set_difference(&before_files, &now_files).0;
    diff.files_same = files_same;

    diff
}

/// The runs both versions have, the full run first.
fn run_diffs(now: &Side, before: &Side) -> (Vec<RunDiff>, String) {
    let report = |side: &Side, kind: &str| {
        side.runs
            .iter()
            .find(|(k, _)| k == kind)
            .map(|(_, r)| r.clone())
    };

    let runs: Vec<RunDiff> = ["full", "check"]
        .into_iter()
        .filter_map(|kind| Some(run_diff(kind, &report(now, kind)?, &report(before, kind)?)))
        .take(1)
        .collect();

    let note = match (now.runs.is_empty(), before.runs.is_empty()) {
        _ if !runs.is_empty() => String::new(),
        (true, true) => "Neither version was built in a VM.".to_owned(),
        (true, false) => format!("{} was not built in a VM.", now.version),
        (false, true) => format!("{} was not built in a VM.", before.version),
        (false, false) => "The versions have no VM run of the same kind.".to_owned(),
    };

    (runs, note)
}

/// Compares `now` with `before`.
#[must_use]
pub fn compare(now: &Side, before: &Side) -> Comparison {
    let (evidence, evidence_same) = evidence_changes(&now.evidence, &before.evidence);

    let added = new_findings(&now.report, &before.report);
    let removed = new_findings(&before.report, &now.report);
    let total = report_findings(&now.report).len();
    let groups = |findings: &[Value], side: &Side| {
        finding_groups(&json!({ "findings": findings }), &side.name, &side.version)
    };

    let (profile_added, profile_same) = set_difference(&now.profile, &before.profile);
    let (runs, runs_note) = run_diffs(now, before);

    Comparison {
        evidence,
        evidence_same,
        added_groups: groups(&added, now),
        removed_groups: groups(&removed, before),
        findings_added: added.len(),
        findings_removed: removed.len(),
        findings_same: total - added.len(),
        runs,
        runs_note,
        profile_added,
        profile_removed: set_difference(&before.profile, &now.profile).0,
        profile_same,
    }
}

/// The version to compare `job` with: `against` if it is another analyzed
/// version of the crate, or else the newest one before `job`.
#[must_use]
pub fn counterpart(
    versions: &[AnalyzedVersion],
    job: i64,
    against: Option<i64>,
) -> Option<&AnalyzedVersion> {
    if let Some(against) = against.filter(|a| *a != job) {
        return versions.iter().find(|v| v.id.0 == against);
    }

    versions.iter().skip_while(|v| v.id.0 != job).nth(1)
}

/// The package changes the static analysis recorded, as label and value,
/// when they compare with `version`.
///
/// # Errors
///
/// Says why there are none to show.
pub fn package_rows(diff: Option<&Value>, version: &str) -> Result<Vec<(String, String)>, String> {
    let Some(diff) = diff.filter(|d| d.is_object()) else {
        return Err("The static analysis recorded no package diff for this version.".to_owned());
    };

    let previous = text(diff, "previous_version");
    if previous != version {
        return Err(format!(
            "The static analysis compared this version with {previous}, so its package diff is not shown here."
        ));
    }

    let flag = |key: &str, yes: &str| {
        if diff.get(key).and_then(Value::as_bool) == Some(true) {
            yes.to_owned()
        } else {
            "no change".to_owned()
        }
    };

    let dependencies: Vec<&str> = diff
        .get("new_dependencies")
        .and_then(Value::as_array)
        .map(|d| d.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    Ok(vec![
        (
            "Build script".to_owned(),
            flag("build_script_added", "added"),
        ),
        (
            "Proc macro".to_owned(),
            flag("proc_macro_added", "became one"),
        ),
        ("links".to_owned(), flag("links_changed", "changed")),
        (
            "New dependencies".to_owned(),
            if dependencies.is_empty() {
                "none".to_owned()
            } else {
                dependencies.join(", ")
            },
        ),
    ])
}

/// The two versions on diff.rs, which compares their source files.
#[must_use]
pub fn source_url(name: &str, before: &str, now: &str) -> String {
    let version = |v: &str| encode(v).replace('/', "%2F");

    format!(
        "https://diff.rs/{}/{}/{}/",
        encode(name),
        version(before),
        version(now)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(signal: &str, points: u32, summary: &str) -> EvidenceView {
        EvidenceView {
            points,
            signal: signal.to_owned(),
            source: "trace".to_owned(),
            package: String::new(),
            location: String::new(),
            summary: summary.to_owned(),
            code_url: String::new(),
        }
    }

    fn process(pid: u64, ppid: Option<u64>, exe: &str, role: &str) -> Value {
        json!({"pid": pid, "ppid": ppid, "exe": exe, "argv": [exe, format!("arg{pid}")], "role": role, "started_ms": pid})
    }

    /// A full run with a cargo, a build script under a hashed directory and
    /// what the build script started.
    fn report(hash: &str, children: &[&str], extra: Value) -> Value {
        let script = format!("/w/target/debug/build/evil-{hash}/build-script-build");
        let mut processes = vec![
            process(1, None, "/usr/bin/cargo", "cargo"),
            process(2, Some(1), &script, "build_script"),
        ];

        for (i, exe) in children.iter().enumerate() {
            processes.push(process(10 + i as u64, Some(2), exe, "other"));
        }

        let mut report = json!({
            "outcome": "succeeded",
            "trace": {"complete": true, "processes": processes,
                      "sensitive_opens": [], "writes_outside_work": [], "sockets": [], "tamper": []},
            "network": {"dns": [], "connections": []},
        });

        if let (Some(r), Some(e)) = (report.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                r.insert(k.clone(), v.clone());
            }
        }

        report
    }

    fn side(
        id: i64,
        version: &str,
        evidence: Vec<EvidenceView>,
        findings: Value,
        runs: Vec<(String, Value)>,
    ) -> Side {
        Side {
            id,
            name: "evil".to_owned(),
            version: version.to_owned(),
            score: "0".to_owned(),
            level: "none".to_owned(),
            evidence,
            profile: Vec::new(),
            report: json!({ "findings": findings }),
            runs,
        }
    }

    #[test]
    fn evidence_is_new_gone_or_weighs_differently() {
        let (changes, same) = evidence_changes(
            &[
                evidence("honeytoken_left_vm", 60, "a token went out"),
                evidence("exec_curl", 10, "ran curl"),
                evidence("exec_curl", 5, "ran curl again"),
                evidence("same", 3, "unchanged"),
            ],
            &[
                evidence("exec_curl", 10, "ran curl"),
                evidence("same", 3, "unchanged"),
                evidence("timeout", 3, "ended late"),
            ],
        );

        let shown: Vec<String> = changes
            .iter()
            .map(|c| {
                format!(
                    "{} {} {}->{} {}",
                    c.change, c.signal, c.before, c.after, c.tone
                )
            })
            .collect();

        assert_eq!(
            shown,
            [
                "added honeytoken_left_vm ->60 bad",
                "changed exec_curl 10->15 low",
                "removed timeout 3-> low",
            ]
        );
        assert_eq!(same, 1);
    }

    #[test]
    fn findings_that_only_moved_are_the_same() {
        let now = json!([
            {"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": 40, "evidence": "curl"},
            {"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": 41, "evidence": "wget"},
            {"severity": "info", "kind": "filler", "file": "src/a.rs", "line": 1, "evidence": "x"},
        ]);

        let before = json!([
            {"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": 12, "evidence": "curl"},
            {"severity": "low", "kind": "unsafe_block", "file": "src/lib.rs", "evidence": "unsafe"},
            {"severity": "info", "kind": "filler", "file": "src/a.rs", "line": 1, "evidence": "x"},
            {"severity": "info", "kind": "filler", "file": "src/a.rs", "line": 2, "evidence": "x"},
        ]);

        let c = compare(
            &side(2, "0.2.0", vec![], now, vec![]),
            &side(1, "0.1.0", vec![], before, vec![]),
        );

        assert_eq!(
            (c.findings_added, c.findings_removed, c.findings_same),
            (1, 2, 2)
        );
        let added = c.added_groups.first().unwrap();
        assert_eq!(added.kind, "build_script net_call");
        assert_eq!(added.items.first().unwrap().evidence, "wget");
        assert!(
            added
                .items
                .first()
                .unwrap()
                .places
                .first()
                .unwrap()
                .1
                .contains("/evil/0.2.0/")
        );
        assert!(c.removed_groups.iter().any(|g| g.kind == "unsafe_block"));
        assert!(
            c.removed_groups
                .first()
                .unwrap()
                .items
                .first()
                .unwrap()
                .places
                .first()
                .unwrap()
                .1
                .contains("/evil/0.1.0/")
        );
    }

    #[test]
    fn new_processes_show_with_their_ancestors_and_build_hashes_do_not_matter() {
        let now = report("aaaa1111", &["/usr/bin/cc", "/tmp/payload"], json!({}));
        let before = report("bbbb2222", &["/usr/bin/cc", "/usr/bin/git"], json!({}));
        let c = compare(
            &side(
                2,
                "0.2.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), now)],
            ),
            &side(
                1,
                "0.1.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), before)],
            ),
        );

        let run = c.runs.first().unwrap();
        let lines = |l: &[TreeLine]| -> Vec<String> {
            l.iter()
                .map(|t| {
                    format!(
                        "{}{}{}",
                        if t.context { "~" } else { "+" },
                        "  ".repeat(t.row.nesting),
                        t.row.label()
                    )
                })
                .collect()
        };

        assert_eq!(
            lines(&run.new_processes),
            ["~/usr/bin/cargo", "~  evil", "+    /tmp/payload"]
        );
        assert_eq!(
            lines(&run.gone_processes),
            ["~/usr/bin/cargo", "~  evil", "+    /usr/bin/git"]
        );
        assert_eq!((run.added, run.removed, run.same), (1, 1, 3));
        assert!(c.runs_note.is_empty());
    }

    #[test]
    fn a_whole_new_subtree_is_new_and_network_and_files_are_sets() {
        let extra = |dns: &[&str], host: &str, secret: &str| {
            json!({
                "network": {"dns": dns, "connections": [{"dst": "10.0.2.1:443", "protocol": "tls", "sni": host, "bytes_out": 10}]},
                "trace": {"complete": true,
                          "processes": [{"pid": 1, "exe": "/usr/bin/cargo", "role": "cargo"}],
                          "sensitive_opens": [{"exe": "/w/target/debug/build/evil-ab12/build-script-build", "path": secret, "ms": 3, "flags": 0}],
                          "writes_outside_work": [], "sockets": [], "tamper": []},
            })
        };

        let now = report(
            "a1",
            &[],
            extra(
                &["evil.example", "crates.io"],
                "evil.example",
                "/root/.ssh/id_rsa",
            ),
        );

        let before = report(
            "b2",
            &[],
            extra(&["crates.io"], "crates.io", "/root/.ssh/id_rsa"),
        );

        let c = compare(
            &side(
                2,
                "0.2.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), now)],
            ),
            &side(
                1,
                "0.1.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), before)],
            ),
        );

        let run = c.runs.first().unwrap();
        assert_eq!(run.dns_added, ["evil.example"]);
        assert!(run.dns_removed.is_empty());
        assert_eq!(run.connections_added.len(), 1);
        assert_eq!(run.connections_removed.len(), 1);
        assert_eq!(run.network_same, 1);
        assert_eq!(run.file_changes(), 0);
        assert_eq!(run.files_same, 1);
    }

    #[test]
    fn trimmed_runs_and_missing_runs_are_named() {
        let trimmed = report("a1", &["/usr/bin/cc"], json!({"trimmed": true}));
        let full = report("b2", &[], json!({}));
        let c = compare(
            &side(
                2,
                "0.2.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), full.clone())],
            ),
            &side(
                1,
                "0.1.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), trimmed)],
            ),
        );

        let run = c.runs.first().unwrap();
        assert!(run.trimmed.starts_with("Retention removed"));
        assert!(run.new_processes.is_empty() && run.added == 0);

        let c = compare(
            &side(
                2,
                "0.2.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), full)],
            ),
            &side(1, "0.1.0", vec![], json!([]), vec![]),
        );
        assert_eq!(c.runs_note, "0.1.0 was not built in a VM.");

        let any = report("c3", &[], json!({}));
        let c = compare(
            &side(
                2,
                "0.2.0",
                vec![],
                json!([]),
                vec![("full".to_owned(), any.clone())],
            ),
            &side(
                1,
                "0.1.0",
                vec![],
                json!([]),
                vec![("check".to_owned(), any)],
            ),
        );
        assert_eq!(c.runs_note, "The versions have no VM run of the same kind.");
    }

    #[test]
    fn the_counterpart_is_the_version_before_or_the_chosen_one() {
        let v = |id: i64, version: &str| AnalyzedVersion {
            id: JobId(id),
            version: version.to_owned(),
            score: 0,
            level: "none".to_owned(),
        };

        let versions = [v(9, "1.0.0"), v(3, "0.10.0"), v(7, "0.9.1")];

        assert_eq!(counterpart(&versions, 3, None).unwrap().id, JobId(7));
        assert!(counterpart(&versions, 7, None).is_none());
        assert_eq!(counterpart(&versions, 7, Some(9)).unwrap().id, JobId(9));
        assert_eq!(counterpart(&versions, 9, Some(9)).unwrap().id, JobId(3));
        assert!(counterpart(&versions, 9, Some(42)).is_none());
    }

    #[test]
    fn the_package_diff_shows_only_against_its_version() {
        let diff = json!({"previous_version": "0.1.0", "build_script_added": true, "proc_macro_added": false,
                          "links_changed": false, "new_findings": [], "removed_findings": 0, "new_dependencies": ["cc"]});

        let rows = package_rows(Some(&diff), "0.1.0").unwrap();
        assert_eq!(rows.first().unwrap().1, "added");
        assert_eq!(rows.last().unwrap().1, "cc");
        assert!(
            package_rows(Some(&diff), "0.0.9")
                .unwrap_err()
                .contains("with 0.1.0")
        );
        assert!(package_rows(None, "0.1.0").is_err());
    }

    #[test]
    fn the_source_diff_link_encodes_versions() {
        assert_eq!(
            source_url("evil", "0.1.0", "0.2.0+meta"),
            "https://diff.rs/evil/0.1.0/0.2.0%2Bmeta/"
        );
    }
}
