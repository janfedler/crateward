//! Scoring: every point of a verdict comes with its evidence (ADR 0021).
//!
//! The score is a sum of points from independent signals, capped per group
//! so that one noisy source cannot dominate, and capped at 100 in total.
//! The point values are a starting calibration, documented in the ADR and
//! meant to be tuned on live traffic (M7); they are ordered by how strongly
//! each signal indicates intent:
//!
//! * a honeytoken that left the VM is theft, and alone makes a verdict
//!   critical;
//! * a honeytoken copied inside the VM, a process that became root, an
//!   attempt to tamper with tracing, or a guest that stopped itself are high;
//! * reading credentials, writing to persistence locations, contacting the
//!   network, or running shells and downloaders during a build are
//!   suspicious on their own and common in legitimate `-sys` crates, so they
//!   add up rather than decide;
//! * static findings count by severity, more when the code runs at build
//!   time, and new findings against the previous version count again.
//!
//! Dynamic evidence names the package responsible when the process tree
//! leads to a build script (`/work/target/debug/build/<package>-<hash>/`) or
//! to `rustc` compiling a crate (whose proc macros run inside it).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crateward_core::job::BuildOutcome;
use crateward_core::verdict::{Coverage, Evidence, EvidenceSource, RiskLevel, Verdict};
use crateward_orchestrator::trace::{Process, Role, TraceSummary};
use crateward_orchestrator::worker::RunReport;
use crateward_static_analysis::analyze::StaticReport;
use crateward_static_analysis::diff::VersionDiff;
use crateward_static_analysis::findings::{Finding, FindingKind, Severity};

/// Bumped whenever scoring changes, so old verdicts can be recomputed.
pub const ANALYZER_VERSION: u32 = 2;

/// Everything scoring reads about one version.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    /// The crate's name.
    pub name: &'a str,
    /// What the analysis covered.
    pub coverage: Coverage,
    /// Static analysis of the crate's own file, if it was analyzed.
    pub report: Option<&'a StaticReport>,
    /// Changes against the previous version, if there is one.
    pub diff: Option<&'a VersionDiff>,
    /// VM runs: `cargo check`, and the full build after an escalation.
    pub runs: &'a [RunReport],
    /// The previous analyzed version's behavior profile.
    pub previous_profile: Option<&'a [String]>,
}

/// Points per group, and each group's cap.
struct Groups {
    items: Vec<(Group, Evidence)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Group {
    Theft,
    Integrity,
    Credentials,
    Persistence,
    Network,
    Execution,
    Static,
    Change,
}

impl Group {
    const fn cap(self) -> u32 {
        match self {
            Self::Theft | Self::Integrity => 100,
            Self::Credentials | Self::Persistence => 60,
            Self::Network => 40,
            Self::Static => 30,
            Self::Execution | Self::Change => 20,
        }
    }
}

impl Groups {
    // One call per signal reads best with the fields spelled out.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        group: Group,
        signal: &str,
        points: u32,
        source: EvidenceSource,
        summary: String,
        package: Option<String>,
        location: Option<String>,
    ) {
        // The same signal at the same place counts once, whichever run saw it.
        if self
            .items
            .iter()
            .any(|(_, e)| e.signal == signal && e.location == location && e.package == package)
        {
            return;
        }
        self.items.push((
            group,
            Evidence {
                signal: signal.to_owned(),
                points,
                source,
                summary,
                package,
                location,
            },
        ));
    }

    /// Applies the caps: within a group, the strongest items count first.
    fn finish(mut self) -> (u32, Vec<Evidence>) {
        self.items
            .sort_by(|a, b| a.0.cmp(&b.0).then(b.1.points.cmp(&a.1.points)));
        let mut used: HashMap<Group, u32> = HashMap::new();
        let mut out = Vec::new();
        for (group, mut evidence) in self.items {
            let spent = used.entry(group).or_default();
            let room = group.cap().saturating_sub(*spent);
            evidence.points = evidence.points.min(room);
            *spent += evidence.points;
            out.push(evidence);
        }
        out.sort_by(|a, b| b.points.cmp(&a.points).then(a.signal.cmp(&b.signal)));
        let total = out.iter().map(|e| e.points).sum::<u32>().min(100);
        (total, out)
    }
}

/// The package whose code a process ran, following the process tree up to
/// a build script or to `rustc` compiling a crate.
fn package_of(pid: u32, processes: &HashMap<u32, &Process>) -> Option<String> {
    let mut current = processes.get(&pid).copied();
    for _ in 0..64 {
        let p = current?;
        if p.role == Role::BuildScript
            && let Some(package) = build_script_package(&p.exe)
        {
            return Some(package);
        }
        if p.role == Role::Rustc
            && let Some(i) = p.argv.iter().position(|a| a == "--crate-name")
            && let Some(name) = p.argv.get(i + 1)
            && name != "build_script_build"
        {
            return Some(name.replace('_', "-"));
        }
        current = p.ppid.and_then(|pp| processes.get(&pp).copied());
    }
    None
}

/// `<package>` from a path inside a build script's directory,
/// `…/debug/build/<package>-<hash>/…`, where its outputs land.
fn build_dir_package(path: &str) -> Option<String> {
    let rest = path.split("/debug/build/").nth(1)?;
    let dir = rest.split('/').next()?;
    let (package, hash) = dir.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then(|| package.to_owned())
}

/// `<package>` from `/work/target/debug/build/<package>-<hash>/build-script-build`.
fn build_script_package(exe: &str) -> Option<String> {
    let dir = exe.rsplit('/').nth(1)?;
    let (package, hash) = dir.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then(|| package.to_owned())
}

/// A short class for a sensitive path, used in profiles.
fn sensitive_class(path: &str) -> &'static str {
    if path.contains("/.cargo/credentials") {
        "cargo-credentials"
    } else if path.contains("/.ssh/") {
        "ssh"
    } else if path.contains("/.aws/") {
        "aws"
    } else if path.contains("/.git-credentials") || path.contains("/.config/gh/") {
        "git-credentials"
    } else if path.starts_with("/proc/") {
        "other-process"
    } else {
        "secrets"
    }
}

/// Persistence locations: writing there outlives the build on a developer's
/// machine.
fn persistence(path: &str) -> bool {
    [
        "/.config/autostart/",
        "/.bashrc",
        "/.profile",
        "/.zshrc",
        "/.bash_profile",
        "/.config/systemd/",
        "/.ssh/authorized_keys",
        "/.cargo/config",
        "/.gitconfig",
        "/etc/",
        "/.local/bin/",
    ]
    .iter()
    .any(|p| path.contains(p))
}

/// Programs worth noting when a build script runs them.
fn notable_program(exe: &str) -> Option<(&'static str, u32)> {
    let name = exe.rsplit('/').next().unwrap_or(exe);
    Some(match name {
        "curl" | "wget" => ("downloader", 5),
        "nc" | "ncat" | "netcat" | "socat" | "ssh" | "scp" => ("network-tool", 15),
        "sh" | "bash" | "dash" | "zsh" => ("shell", 3),
        "python3" | "python" | "perl" => ("interpreter", 3),
        "base64" | "xxd" | "openssl" | "gpg" => ("encoder", 8),
        "sudo" | "su" | "chmod" | "chown" | "setcap" => ("privilege", 15),
        _ => return None,
    })
}

/// Points of one finding. Library code runs only when something calls it,
/// and libraries that spawn processes or talk to the network are common, so
/// only code that runs at build time weighs much.
fn static_points(f: &Finding) -> u32 {
    let build = f.context.runs_at_build_time();
    match (f.severity, build) {
        (Severity::High, true) => 30,
        (Severity::High, false) | (Severity::Medium, true) => 10,
        (Severity::Medium, false) => 2,
        (Severity::Low, true) => 1,
        (Severity::Low, false) | (Severity::Info, _) => 0,
    }
}

fn finding_name(kind: &FindingKind) -> String {
    match kind {
        FindingKind::YaraMatch { rule } => format!("yara:{rule}"),
        FindingKind::UnsafeCode { .. } => "unsafe_code".to_owned(),
        other => serde_json::to_value(other)
            .ok()
            .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_owned))
            .unwrap_or_else(|| format!("{other:?}")),
    }
}

/// Each kind of finding counts once, by its strongest instance: a large
/// crate with many ordinary findings must not add up to a high score.
fn score_static(inputs: &Inputs<'_>, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    let Some(report) = inputs.report else { return };
    let mut strongest: BTreeMap<String, (u32, &Finding, u32)> = BTreeMap::new();
    for f in &report.findings {
        let name = finding_name(&f.kind);
        if f.severity >= Severity::Medium {
            profile.insert(format!("static:{name}"));
        }
        let points = static_points(f);
        let entry = strongest.entry(name).or_insert((points, f, 0));
        entry.2 += 1;
        if points > entry.0 {
            entry.0 = points;
            entry.1 = f;
        }
    }
    for (name, (points, f, count)) in strongest {
        if points == 0 {
            continue;
        }
        let more = if count > 1 {
            format!(" ({} places)", count)
        } else {
            String::new()
        };
        groups.add(
            Group::Static,
            &format!("static:{name}"),
            points,
            EvidenceSource::Static,
            format!(
                "{:?} severity {name} in {:?} code{more}: {}",
                f.severity, f.context, f.evidence
            ),
            Some(inputs.name.to_owned()),
            Some(match f.line {
                Some(line) => format!("{}:{line}", f.file),
                None => f.file.clone(),
            }),
        );
    }
}

fn score_diff(inputs: &Inputs<'_>, groups: &mut Groups) {
    let Some(diff) = inputs.diff else { return };
    let own = Some(inputs.name.to_owned());
    let since = &diff.previous_version;
    if diff.build_script_added {
        groups.add(
            Group::Change,
            "build_script_added",
            10,
            EvidenceSource::Diff,
            format!("A build script was added since {since}."),
            own.clone(),
            None,
        );
    }
    if diff.proc_macro_added {
        groups.add(
            Group::Change,
            "proc_macro_added",
            5,
            EvidenceSource::Diff,
            format!("The crate became a proc macro since {since}."),
            own.clone(),
            None,
        );
    }
    for f in diff
        .new_findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
    {
        groups.add(
            Group::Change,
            "new_high_finding",
            10,
            EvidenceSource::Diff,
            format!("New since {since}: {}", finding_name(&f.kind)),
            own.clone(),
            Some(match f.line {
                Some(line) => format!("{}:{line}", f.file),
                None => f.file.clone(),
            }),
        );
    }
}

fn score_run(run: &RunReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    let t: &TraceSummary = &run.trace;
    let processes: HashMap<u32, &Process> = t.processes.iter().map(|p| (p.pid, p)).collect();
    let pkg = |pid: u32| package_of(pid, &processes);

    for leak in &run.leaked {
        profile.insert(format!("leak:{}", leak.kind));
        groups.add(
            Group::Theft,
            "honeytoken_left_vm",
            100,
            EvidenceSource::Network,
            format!("The planted {} left the VM.", leak.kind),
            None,
            Some(leak.via.clone()),
        );
    }
    for leak in run.tokens_in_trace.iter().chain(&run.tokens_on_disk) {
        profile.insert(format!("copy:{}", leak.kind));
        groups.add(
            Group::Theft,
            "honeytoken_copied",
            60,
            EvidenceSource::Disk,
            format!("The planted {} was copied inside the VM.", leak.kind),
            build_dir_package(&leak.via),
            Some(leak.via.clone()),
        );
    }
    for p in t.processes.iter().filter(|p| p.became_root) {
        profile.insert("root".into());
        groups.add(
            Group::Integrity,
            "became_root",
            80,
            EvidenceSource::Trace,
            format!(
                "{} ran as root although the build runs unprivileged.",
                p.exe
            ),
            pkg(p.pid),
            Some(format!("pid {}", p.pid)),
        );
    }
    for x in &t.tamper {
        profile.insert(format!(
            "tamper:{}",
            x.what.split(' ').next().unwrap_or("?")
        ));
        groups.add(
            Group::Integrity,
            "tamper_attempt",
            60,
            EvidenceSource::Trace,
            format!("Tamper attempt: {}.", x.what),
            pkg(x.pid),
            Some(format!("pid {}", x.pid)),
        );
    }
    if run.outcome == BuildOutcome::GuestStopped {
        profile.insert("guest-stopped".into());
        groups.add(
            Group::Integrity,
            "guest_stopped",
            50,
            EvidenceSource::Run,
            "The guest stopped during the build before reporting an end.".into(),
            None,
            None,
        );
    }
    for f in &t.sensitive_opens {
        let exe = f.exe.rsplit('/').next().unwrap_or(&f.exe);
        if exe == "cargo" {
            continue;
        }
        let class = sensitive_class(&f.path);
        profile.insert(format!("read:{class}"));
        let points = if class == "other-process" { 30 } else { 50 };
        groups.add(
            Group::Credentials,
            &format!("read_{}", class.replace('-', "_")),
            points,
            EvidenceSource::Trace,
            format!("{} opened {}.", f.exe, f.path),
            pkg(f.pid),
            Some(f.path.clone()),
        );
    }
    for f in &t.writes_outside_work {
        let persistent = persistence(&f.path);
        profile.insert(
            if persistent {
                "write:persistence"
            } else {
                "write:outside"
            }
            .into(),
        );
        groups.add(
            Group::Persistence,
            if persistent {
                "write_persistence"
            } else {
                "write_outside_build"
            },
            if persistent { 40 } else { 15 },
            EvidenceSource::Trace,
            format!("{} wrote {}.", f.exe, f.path),
            pkg(f.pid),
            Some(f.path.clone()),
        );
    }
    if let Some(s) = &run.scratch {
        for e in &s.outside_build {
            let persistent = persistence(&e.path);
            profile.insert(
                if persistent {
                    "disk:persistence"
                } else {
                    "disk:outside"
                }
                .into(),
            );
            groups.add(
                Group::Persistence,
                if persistent {
                    "disk_persistence"
                } else {
                    "disk_outside_build"
                },
                if persistent { 40 } else { 10 },
                EvidenceSource::Disk,
                format!("The build left {} ({}).", e.path, e.kind),
                None,
                Some(e.path.clone()),
            );
        }
        for e in &s.executables_outside_target {
            profile.insert("disk:executable".into());
            groups.add(
                Group::Persistence,
                "disk_executable",
                20,
                EvidenceSource::Disk,
                format!("The build left an executable at {}.", e.path),
                None,
                Some(e.path.clone()),
            );
        }
        for e in &s.setid {
            profile.insert("disk:setid".into());
            groups.add(
                Group::Integrity,
                "disk_setid",
                40,
                EvidenceSource::Disk,
                format!("The build left a set ID file at {}.", e.path),
                None,
                Some(e.path.clone()),
            );
        }
    }
    // The network, from the host's side: names the build looked up and
    // what it sent. Loopback and the guest's own name service socket are
    // no evidence.
    let senders: BTreeSet<String> = t
        .sockets
        .iter()
        .filter(|s| !s.address.starts_with("unix:"))
        .filter_map(|s| pkg(s.pid))
        .collect();
    let sender = (senders.len() == 1)
        .then(|| senders.iter().next().cloned())
        .flatten();
    for name in &run.network.dns {
        profile.insert(format!("net:{name}"));
        groups.add(
            Group::Network,
            "network_lookup",
            10,
            EvidenceSource::Network,
            format!("The build looked up {name}."),
            sender.clone(),
            Some(name.clone()),
        );
    }
    if run.network.dns.is_empty() && !run.network.connections.is_empty() {
        profile.insert("net:direct".into());
        groups.add(
            Group::Network,
            "network_direct",
            20,
            EvidenceSource::Network,
            "The build connected to an address without a name lookup.".into(),
            sender.clone(),
            None,
        );
    }
    for packet in &run.network.packets {
        profile.insert("net:raw".into());
        groups.add(
            Group::Network,
            "network_raw",
            30,
            EvidenceSource::Network,
            format!("The guest sent a frame no proxy handles: {packet}."),
            None,
            Some(packet.clone()),
        );
    }
    // Programs that build scripts ran, directly or through children.
    let mut seen: BTreeMap<(String, &'static str), u32> = BTreeMap::new();
    for p in &t.processes {
        let Some((kind, points)) = notable_program(&p.exe) else {
            continue;
        };
        let Some(package) = pkg(p.pid) else { continue };
        if seen.insert((package.clone(), kind), points).is_none() {
            profile.insert(format!("exec:{kind}"));
            groups.add(
                Group::Execution,
                &format!("exec_{kind}"),
                points,
                EvidenceSource::Trace,
                format!("The build ran {}.", p.exe),
                Some(package),
                Some(p.exe.clone()),
            );
        }
    }
}

/// Whether a check run leads to one confirmation run with a full build
/// (DISCLOSURE.md, step 3): the verdict needs review, and the dynamic
/// evidence did not already include a honeytoken leaving the VM, which
/// needs no confirmation.
#[must_use]
pub fn should_escalate(verdict: &Verdict) -> bool {
    verdict.coverage == Coverage::DynamicLinux
        && verdict.level.needs_review()
        && !verdict
            .evidence
            .iter()
            .any(|e| e.signal == "honeytoken_left_vm")
}

/// Scores one version.
#[must_use]
pub fn score(inputs: &Inputs<'_>) -> Verdict {
    let mut groups = Groups { items: Vec::new() };
    let mut profile = BTreeSet::new();
    score_static(inputs, &mut groups, &mut profile);
    score_diff(inputs, &mut groups);
    for run in inputs.runs {
        score_run(run, &mut groups, &mut profile);
    }
    let new_behavior: Vec<String> = match inputs.previous_profile {
        Some(previous) => {
            let previous: BTreeSet<&String> = previous.iter().collect();
            profile
                .iter()
                .filter(|p| !previous.contains(p))
                .cloned()
                .collect()
        }
        None => Vec::new(),
    };
    // New dynamic behavior against the previous version counts once more.
    for behavior in new_behavior.iter().filter(|b| !b.starts_with("static:")) {
        groups.add(
            Group::Change,
            "new_behavior",
            5,
            EvidenceSource::Diff,
            format!("New since the previous version: {behavior}."),
            Some(inputs.name.to_owned()),
            Some(behavior.clone()),
        );
    }
    let (score, evidence) = groups.finish();
    Verdict {
        score,
        level: RiskLevel::from_score(score),
        coverage: inputs.coverage,
        evidence,
        profile: profile.into_iter().collect(),
        new_behavior,
        analyzer_version: ANALYZER_VERSION,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SCRIPT: &str = "/work/target/debug/build/evil-0123456789abcdef/build-script-build";

    /// A run report as the orchestrator stores it, with overrides.
    fn run(overrides: serde_json::Value) -> RunReport {
        let mut base = json!({
            "outcome": "succeeded", "end": "Finished", "exit": null,
            "restore_ms": 60, "run_ms": 1000, "stdout_tail": "", "stderr_tail": "",
            "truncated": false, "payload_files": 1, "payload_bytes": 1,
            "missing_packages": [],
            "network": {"dns": [], "connections": [], "udp_datagrams": 0, "refused": 0,
                        "truncated": false},
            "leaked": [],
            "trace": {"processes": [
                          {"pid": 1, "ppid": null, "exe": "/usr/local/bin/cargo", "argv": ["cargo"],
                           "role": "cargo", "started_ms": 0, "became_root": false},
                          {"pid": 2, "ppid": 1, "exe": SCRIPT, "argv": [SCRIPT],
                           "role": "build_script", "started_ms": 1, "became_root": false},
                          {"pid": 3, "ppid": 2, "exe": "/usr/bin/curl", "argv": ["curl"],
                           "role": "other", "started_ms": 2, "became_root": false}
                      ]}
        });
        // The trace's other fields from the summary's defaults.
        let mut trace = serde_json::to_value(TraceSummary::default()).unwrap();
        trace["complete"] = json!(true);
        trace["processes"] = base["trace"]["processes"].take();
        base["trace"] = trace;
        if let (Some(b), Some(o)) = (base.as_object_mut(), overrides.as_object()) {
            for (k, v) in o {
                b.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(base).unwrap()
    }

    fn inputs<'a>(runs: &'a [RunReport]) -> Inputs<'a> {
        Inputs {
            name: "evil",
            coverage: Coverage::DynamicLinux,
            report: None,
            diff: None,
            runs,
            previous_profile: None,
        }
    }

    #[test]
    fn theft_is_critical_and_attributed() {
        let mut r = run(json!({
            "leaked": [{"kind": "cargo_registry_token", "via": "http://exfil.example"}],
        }));
        r.trace.sensitive_opens.push(
            serde_json::from_value(json!({
                "pid": 2, "exe": SCRIPT, "path": "/work/home/.cargo/credentials.toml",
                "flags": 0, "ms": 3
            }))
            .unwrap(),
        );
        let runs = [r];
        let v = score(&inputs(&runs));
        assert_eq!(v.level, RiskLevel::Critical);
        assert_eq!(v.score, 100);
        assert_eq!(v.evidence[0].signal, "honeytoken_left_vm");
        let read = v
            .evidence
            .iter()
            .find(|e| e.signal == "read_cargo_credentials")
            .unwrap();
        assert_eq!(read.package.as_deref(), Some("evil"));
        assert!(v.profile.contains(&"read:cargo-credentials".to_owned()));
        assert!(!should_escalate(&v));
    }

    #[test]
    fn a_quiet_build_scores_nothing() {
        let mut r = run(json!({}));
        r.trace.processes.truncate(1);
        let runs = [r];
        let v = score(&inputs(&runs));
        assert_eq!((v.score, v.level), (0, RiskLevel::None));
        assert!(v.evidence.is_empty());
        assert!(!should_escalate(&v));
    }

    #[test]
    fn a_downloading_sys_crate_stays_low() {
        let runs = [run(json!({
            "network": {"dns": ["github.com"], "connections": [], "udp_datagrams": 0,
                        "refused": 0, "truncated": false}
        }))];
        let v = score(&inputs(&runs));
        // A lookup (10) and curl run by the build script (5): common in
        // `-sys` crates, so no review and no confirmation run.
        assert_eq!(v.score, 15);
        assert_eq!(v.level, RiskLevel::Low);
        let exec = v
            .evidence
            .iter()
            .find(|e| e.signal == "exec_downloader")
            .unwrap();
        assert_eq!(exec.package.as_deref(), Some("evil"));
        assert!(!should_escalate(&v));
    }

    #[test]
    fn groups_are_capped() {
        let names: Vec<String> = (0..10).map(|i| format!("host{i}.example")).collect();
        let runs = [run(json!({
            "network": {"dns": names, "connections": [], "udp_datagrams": 0,
                        "refused": 0, "truncated": false}
        }))];
        let v = score(&inputs(&runs));
        let network: u32 = v
            .evidence
            .iter()
            .filter(|e| e.signal == "network_lookup")
            .map(|e| e.points)
            .sum();
        assert_eq!(network, 40);
        // Every lookup stays listed, even without points.
        assert_eq!(
            v.evidence
                .iter()
                .filter(|e| e.signal == "network_lookup")
                .count(),
            10
        );
    }

    #[test]
    fn new_behavior_against_the_previous_version_counts() {
        let runs = [run(json!({}))];
        let previous = vec!["exec:shell".to_owned()];
        let mut i = inputs(&runs);
        i.previous_profile = Some(&previous);
        let v = score(&i);
        assert_eq!(v.new_behavior, ["exec:downloader"]);
        assert!(v.evidence.iter().any(|e| e.signal == "new_behavior"));
    }

    #[test]
    fn packages_come_from_build_script_paths_and_rustc() {
        assert_eq!(build_script_package(SCRIPT).as_deref(), Some("evil"));
        assert_eq!(
            build_script_package(
                "/work/target/debug/build/serde-json-0123456789abcdef/build-script-build"
            )
            .as_deref(),
            Some("serde-json")
        );
        assert_eq!(build_script_package("/usr/bin/curl"), None);
        assert_eq!(
            build_dir_package(
                "/work/.warm/upper/debug/build/rustpython-vm-56bb5ec5157fcd26/out/env_vars.rs"
            )
            .as_deref(),
            Some("rustpython-vm")
        );
        let rustc: Process = serde_json::from_value(json!({
            "pid": 9, "ppid": null, "exe": "/usr/local/bin/rustc",
            "argv": ["rustc", "--crate-name", "my_macro"], "role": "rustc",
            "started_ms": 0, "became_root": false
        }))
        .unwrap();
        let map: HashMap<u32, &Process> = [(9, &rustc)].into();
        assert_eq!(package_of(9, &map).as_deref(), Some("my-macro"));
    }
}
