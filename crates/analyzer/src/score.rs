//! Scoring: every point of a verdict comes with its evidence (ADR 0009).
//!
//! The score is a sum of points from independent signals, capped per group
//! so that one noisy source cannot dominate, and capped at 100 in total.
//! The point values are a starting calibration, documented in the ADR and
//! meant to be tuned on live traffic; they are ordered by how strongly
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
use crateward_orchestrator::trace::{Process, Role};
use crateward_orchestrator::worker::RunReport;
use crateward_static_analysis::analyze::StaticReport;
use crateward_static_analysis::diff::VersionDiff;
use crateward_static_analysis::findings::{Finding, FindingKind, Severity};

/// Bumped whenever scoring changes, so old verdicts can be recomputed.
pub const ANALYZER_VERSION: u32 = 3;

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

/// The processes of a run by pid.
type Processes<'a> = HashMap<u32, &'a Process>;

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
    fn add(&mut self, group: Group, evidence: Evidence) {
        // The same signal at the same place counts once, whichever run saw
        // it. Cargo puts a unit's outputs in a directory named with a hash
        // of its settings, which differs between `cargo check` and `cargo
        // build`; the place is compared without it.
        let place = evidence.location.as_deref().map(without_unit_hash);
        if self.items.iter().any(|(_, e)| {
            e.signal == evidence.signal
                && e.package == evidence.package
                && e.location.as_deref().map(without_unit_hash) == place
        }) {
            return;
        }
        self.items.push((group, evidence));
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
fn package_of(pid: u32, processes: &Processes<'_>) -> Option<String> {
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

/// A path with every `-<16 hex digits>` directory suffix removed.
fn without_unit_hash(path: &str) -> String {
    path.split('/')
        .map(|part| match part.rsplit_once('-') {
            Some((stem, hash))
                if hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                stem
            }
            _ => part,
        })
        .collect::<Vec<_>>()
        .join("/")
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
        other => other.name().to_owned(),
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
            Evidence {
                signal: format!("static:{name}"),
                points,
                source: EvidenceSource::Static,
                summary: format!(
                    "{} severity {name} in {} code{more}: {}",
                    f.severity.name(),
                    f.context.name(),
                    f.evidence
                ),
                package: Some(inputs.name.to_owned()),
                location: Some(match f.line {
                    Some(line) => format!("{}:{line}", f.file),
                    None => f.file.clone(),
                }),
            },
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
            Evidence {
                signal: "build_script_added".into(),
                points: 10,
                source: EvidenceSource::Diff,
                summary: format!("A build script was added since {since}."),
                package: own.clone(),
                location: None,
            },
        );
    }
    if diff.proc_macro_added {
        groups.add(
            Group::Change,
            Evidence {
                signal: "proc_macro_added".into(),
                points: 5,
                source: EvidenceSource::Diff,
                summary: format!("The crate became a proc macro since {since}."),
                package: own.clone(),
                location: None,
            },
        );
    }
    for f in diff
        .new_findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
    {
        groups.add(
            Group::Change,
            Evidence {
                signal: "new_high_finding".into(),
                points: 10,
                source: EvidenceSource::Diff,
                summary: format!("New since {since}: {}", finding_name(&f.kind)),
                package: own.clone(),
                location: Some(match f.line {
                    Some(line) => format!("{}:{line}", f.file),
                    None => f.file.clone(),
                }),
            },
        );
    }
}

fn score_run(run: &RunReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    let processes: Processes<'_> = run.trace.processes.iter().map(|p| (p.pid, p)).collect();
    score_theft(run, groups, profile);
    score_integrity(run, &processes, groups, profile);
    score_files(run, &processes, groups, profile);
    score_disk(run, groups, profile);
    score_network(run, &processes, groups, profile);
    score_execution(run, &processes, groups, profile);
}

/// Honeytokens that left the VM, and honeytokens copied inside it.
fn score_theft(run: &RunReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    for leak in &run.leaked {
        profile.insert(format!("leak:{}", leak.kind));
        groups.add(
            Group::Theft,
            Evidence {
                signal: "honeytoken_left_vm".into(),
                points: 100,
                source: EvidenceSource::Network,
                summary: format!("The planted {} left the VM.", leak.kind),
                package: None,
                location: Some(leak.via.clone()),
            },
        );
    }
    for leak in run.tokens_in_trace.iter().chain(&run.tokens_on_disk) {
        profile.insert(format!("copy:{}", leak.kind));
        groups.add(
            Group::Theft,
            Evidence {
                signal: "honeytoken_copied".into(),
                points: 60,
                source: EvidenceSource::Disk,
                summary: format!("The planted {} was copied inside the VM.", leak.kind),
                package: build_dir_package(&leak.via),
                location: Some(leak.via.clone()),
            },
        );
    }
}

/// A process that became root, tampering with the tracing, and a guest that
/// stopped itself.
fn score_integrity(
    run: &RunReport,
    processes: &Processes<'_>,
    groups: &mut Groups,
    profile: &mut BTreeSet<String>,
) {
    for p in run.trace.processes.iter().filter(|p| p.became_root) {
        profile.insert("root".into());
        groups.add(
            Group::Integrity,
            Evidence {
                signal: "became_root".into(),
                points: 80,
                source: EvidenceSource::Trace,
                summary: format!(
                    "{} ran as root although the build runs unprivileged.",
                    p.exe
                ),
                package: package_of(p.pid, processes),
                location: Some(format!("pid {}", p.pid)),
            },
        );
    }
    for x in &run.trace.tamper {
        profile.insert(format!(
            "tamper:{}",
            x.what.split(' ').next().unwrap_or("?")
        ));
        groups.add(
            Group::Integrity,
            Evidence {
                signal: "tamper_attempt".into(),
                points: 60,
                source: EvidenceSource::Trace,
                summary: format!("Tamper attempt: {}.", x.what),
                package: package_of(x.pid, processes),
                location: Some(format!("pid {}", x.pid)),
            },
        );
    }
    if run.outcome == BuildOutcome::GuestStopped {
        profile.insert("guest-stopped".into());
        groups.add(
            Group::Integrity,
            Evidence {
                signal: "guest_stopped".into(),
                points: 50,
                source: EvidenceSource::Run,
                summary: "The guest stopped during the build before reporting an end.".into(),
                package: None,
                location: None,
            },
        );
    }
}

/// Credentials the build opened, and files it wrote outside its work
/// directory.
fn score_files(
    run: &RunReport,
    processes: &Processes<'_>,
    groups: &mut Groups,
    profile: &mut BTreeSet<String>,
) {
    for f in &run.trace.sensitive_opens {
        let exe = f.exe.rsplit('/').next().unwrap_or(&f.exe);
        if exe == "cargo" {
            continue;
        }
        let class = sensitive_class(&f.path);
        profile.insert(format!("read:{class}"));
        let points = if class == "other-process" { 30 } else { 50 };
        groups.add(
            Group::Credentials,
            Evidence {
                signal: format!("read_{}", class.replace('-', "_")),
                points,
                source: EvidenceSource::Trace,
                summary: format!("{} opened {}.", f.exe, f.path),
                package: package_of(f.pid, processes),
                location: Some(f.path.clone()),
            },
        );
    }
    for f in &run.trace.writes_outside_work {
        let (behavior, signal, points) = if persistence(&f.path) {
            ("write:persistence", "write_persistence", 40)
        } else {
            ("write:outside", "write_outside_build", 15)
        };
        profile.insert(behavior.into());
        groups.add(
            Group::Persistence,
            Evidence {
                signal: signal.into(),
                points,
                source: EvidenceSource::Trace,
                summary: format!("{} wrote {}.", f.exe, f.path),
                package: package_of(f.pid, processes),
                location: Some(f.path.clone()),
            },
        );
    }
}

/// What the build left on its scratch disk.
fn score_disk(run: &RunReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    let Some(scratch) = &run.scratch else { return };
    for e in &scratch.outside_build {
        let (behavior, signal, points) = if persistence(&e.path) {
            ("disk:persistence", "disk_persistence", 40)
        } else {
            ("disk:outside", "disk_outside_build", 10)
        };
        profile.insert(behavior.into());
        groups.add(
            Group::Persistence,
            Evidence {
                signal: signal.into(),
                points,
                source: EvidenceSource::Disk,
                summary: format!("The build left {} ({}).", e.path, e.kind),
                package: None,
                location: Some(e.path.clone()),
            },
        );
    }
    for e in &scratch.executables_outside_target {
        profile.insert("disk:executable".into());
        groups.add(
            Group::Persistence,
            Evidence {
                signal: "disk_executable".into(),
                points: 20,
                source: EvidenceSource::Disk,
                summary: format!("The build left an executable at {}.", e.path),
                package: None,
                location: Some(e.path.clone()),
            },
        );
    }
    for e in &scratch.setid {
        profile.insert("disk:setid".into());
        groups.add(
            Group::Integrity,
            Evidence {
                signal: "disk_setid".into(),
                points: 40,
                source: EvidenceSource::Disk,
                summary: format!("The build left a set ID file at {}.", e.path),
                package: None,
                location: Some(e.path.clone()),
            },
        );
    }
}

/// The network, from the host's side: names the build looked up and what
/// it sent. Loopback and the guest's own name service socket are no
/// evidence.
fn score_network(
    run: &RunReport,
    processes: &Processes<'_>,
    groups: &mut Groups,
    profile: &mut BTreeSet<String>,
) {
    let senders: BTreeSet<String> = run
        .trace
        .sockets
        .iter()
        .filter(|s| !s.address.starts_with("unix:"))
        .filter_map(|s| package_of(s.pid, processes))
        .collect();
    let sender = if senders.len() == 1 {
        senders.into_iter().next()
    } else {
        None
    };
    for name in &run.network.dns {
        profile.insert(format!("net:{name}"));
        groups.add(
            Group::Network,
            Evidence {
                signal: "network_lookup".into(),
                points: 10,
                source: EvidenceSource::Network,
                summary: format!("The build looked up {name}."),
                package: sender.clone(),
                location: Some(name.clone()),
            },
        );
    }
    if run.network.dns.is_empty() && !run.network.connections.is_empty() {
        profile.insert("net:direct".into());
        groups.add(
            Group::Network,
            Evidence {
                signal: "network_direct".into(),
                points: 20,
                source: EvidenceSource::Network,
                summary: "The build connected to an address without a name lookup.".into(),
                package: sender,
                location: None,
            },
        );
    }
    for packet in &run.network.packets {
        profile.insert("net:raw".into());
        groups.add(
            Group::Network,
            Evidence {
                signal: "network_raw".into(),
                points: 30,
                source: EvidenceSource::Network,
                summary: format!("The guest sent a frame no proxy handles: {packet}."),
                package: None,
                location: Some(packet.clone()),
            },
        );
    }
}

/// Programs that build scripts ran, directly or through children.
fn score_execution(
    run: &RunReport,
    processes: &Processes<'_>,
    groups: &mut Groups,
    profile: &mut BTreeSet<String>,
) {
    let mut seen = BTreeSet::new();
    for p in &run.trace.processes {
        let Some((kind, points)) = notable_program(&p.exe) else {
            continue;
        };
        let Some(package) = package_of(p.pid, processes) else {
            continue;
        };
        if seen.insert((package.clone(), kind)) {
            profile.insert(format!("exec:{kind}"));
            groups.add(
                Group::Execution,
                Evidence {
                    signal: format!("exec_{kind}"),
                    points,
                    source: EvidenceSource::Trace,
                    summary: format!("The build ran {}.", p.exe),
                    package: Some(package),
                    location: Some(p.exe.clone()),
                },
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
            Evidence {
                signal: "new_behavior".into(),
                points: 5,
                source: EvidenceSource::Diff,
                summary: format!("New since the previous version: {behavior}."),
                package: Some(inputs.name.to_owned()),
                location: Some(behavior.clone()),
            },
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
    use crateward_orchestrator::trace::TraceSummary;
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
    fn one_behavior_in_two_runs_counts_once() {
        let copy = |dir: &str| {
            run(json!({"tokens_on_disk": [{"kind": "github_token_env",
                "via": format!("/work/target/debug/build/dep-{dir}/out/env.rs")}]}))
        };
        let runs = [copy("0123456789abcdef"), copy("fedcba9876543210")];
        let v = score(&inputs(&runs));
        let copies: Vec<_> = v
            .evidence
            .iter()
            .filter(|e| e.signal == "honeytoken_copied")
            .collect();
        assert_eq!(copies.len(), 1);
        assert_eq!(copies[0].package.as_deref(), Some("dep"));
        assert_eq!(v.level, RiskLevel::High);
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

    /// Something for every group in one run, and a second run that adds one
    /// signal and repeats another.
    #[test]
    fn a_run_is_scored_group_by_group() {
        let entry =
            |path: &str| json!({"path": path, "kind": "file", "size": 1, "mode": 420, "uid": 1000});
        let file = |pid: u32, exe: &str, path: &str| json!({"pid": pid, "exe": exe, "path": path, "flags": 0, "ms": 3});
        let other = "/work/target/debug/build/other-0123456789abcdef/build-script-build";
        let mut first = run(json!({
            "outcome": "guest_stopped",
            "leaked": [{"kind": "cargo_registry_token", "via": "http://exfil.example"}],
            "tokens_in_trace": [{"kind": "aws_key",
                "via": "/work/target/debug/build/dep-0123456789abcdef/out/k"}],
            "network": {"dns": ["a.example"], "connections": [], "udp_datagrams": 0,
                        "refused": 0, "truncated": false, "packets": ["icmp echo"]},
            "scratch": {"files": 0, "directories": 0, "bytes": 0, "incomplete": false,
                "outside_build": [entry("/home/u/.config/autostart/a.desktop"),
                                  entry("/tmp/left")],
                "executables_outside_target": [entry("/work/src/tool")],
                "setid": [entry("/work/su")], "special": [], "links_outside": [],
                "planted_changed": [], "tokens_found": [], "omitted": 0},
        }));
        let t = &mut first.trace;
        for (pid, ppid, exe, role, root) in [
            (4, 2, "/usr/bin/sudo", "other", true),
            (5, 1, other, "build_script", false),
        ] {
            t.processes.push(
                serde_json::from_value(json!({
                    "pid": pid, "ppid": ppid, "exe": exe, "argv": [exe], "role": role,
                    "started_ms": 3, "became_root": root
                }))
                .unwrap(),
            );
        }
        t.tamper.push(
            serde_json::from_value(json!({"pid": 2, "what": "ptrace attach", "ms": 5})).unwrap(),
        );
        for (pid, exe, path) in [
            (
                1,
                "/usr/local/bin/cargo",
                "/work/home/.cargo/credentials.toml",
            ),
            (2, SCRIPT, "/work/home/.ssh/id_ed25519"),
            (3, "/usr/bin/curl", "/proc/1/environ"),
        ] {
            t.sensitive_opens
                .push(serde_json::from_value(file(pid, exe, path)).unwrap());
        }
        for (pid, exe, path) in [
            (2, SCRIPT, "/work/home/.bashrc"),
            (3, "/usr/bin/curl", "/tmp/x"),
        ] {
            t.writes_outside_work
                .push(serde_json::from_value(file(pid, exe, path)).unwrap());
        }
        // The name service socket is no evidence, even from another package.
        for (pid, exe, address) in [
            (3, "/usr/bin/curl", "1.2.3.4:443"),
            (5, other, "unix:/run/nscd/socket"),
        ] {
            t.sockets.push(
                serde_json::from_value(json!({
                    "pid": pid, "exe": exe, "how": "connect", "address": address,
                    "sock_type": 1, "ms": 3
                }))
                .unwrap(),
            );
        }
        let second = run(json!({
            "network": {"dns": [], "connections": [{"dst": "1.2.3.4:443",
                "protocol": "unknown", "bytes": 10}], "udp_datagrams": 0, "refused": 0,
                "truncated": false},
        }));
        let mut groups = Groups { items: Vec::new() };
        let mut profile = BTreeSet::new();
        for r in [&first, &second] {
            score_run(r, &mut groups, &mut profile);
        }
        let items: Vec<_> = groups
            .items
            .iter()
            .map(|(group, e)| {
                (
                    *group,
                    e.signal.as_str(),
                    e.points,
                    e.package.as_deref(),
                    e.location.as_deref(),
                )
            })
            .collect();
        let dep_key = "/work/target/debug/build/dep-0123456789abcdef/out/k";
        assert_eq!(
            items,
            [
                (
                    Group::Theft,
                    "honeytoken_left_vm",
                    100,
                    None,
                    Some("http://exfil.example")
                ),
                (
                    Group::Theft,
                    "honeytoken_copied",
                    60,
                    Some("dep"),
                    Some(dep_key)
                ),
                (
                    Group::Integrity,
                    "became_root",
                    80,
                    Some("evil"),
                    Some("pid 4")
                ),
                (
                    Group::Integrity,
                    "tamper_attempt",
                    60,
                    Some("evil"),
                    Some("pid 2")
                ),
                (Group::Integrity, "guest_stopped", 50, None, None),
                (
                    Group::Credentials,
                    "read_ssh",
                    50,
                    Some("evil"),
                    Some("/work/home/.ssh/id_ed25519")
                ),
                (
                    Group::Credentials,
                    "read_other_process",
                    30,
                    Some("evil"),
                    Some("/proc/1/environ")
                ),
                (
                    Group::Persistence,
                    "write_persistence",
                    40,
                    Some("evil"),
                    Some("/work/home/.bashrc")
                ),
                (
                    Group::Persistence,
                    "write_outside_build",
                    15,
                    Some("evil"),
                    Some("/tmp/x")
                ),
                (
                    Group::Persistence,
                    "disk_persistence",
                    40,
                    None,
                    Some("/home/u/.config/autostart/a.desktop")
                ),
                (
                    Group::Persistence,
                    "disk_outside_build",
                    10,
                    None,
                    Some("/tmp/left")
                ),
                (
                    Group::Persistence,
                    "disk_executable",
                    20,
                    None,
                    Some("/work/src/tool")
                ),
                (Group::Integrity, "disk_setid", 40, None, Some("/work/su")),
                (
                    Group::Network,
                    "network_lookup",
                    10,
                    Some("evil"),
                    Some("a.example")
                ),
                (Group::Network, "network_raw", 30, None, Some("icmp echo")),
                (
                    Group::Execution,
                    "exec_downloader",
                    5,
                    Some("evil"),
                    Some("/usr/bin/curl")
                ),
                (
                    Group::Execution,
                    "exec_privilege",
                    15,
                    Some("evil"),
                    Some("/usr/bin/sudo")
                ),
                (Group::Network, "network_direct", 20, None, None),
            ]
        );
        assert_eq!(
            profile.into_iter().collect::<Vec<_>>(),
            [
                "copy:aws_key",
                "disk:executable",
                "disk:outside",
                "disk:persistence",
                "disk:setid",
                "exec:downloader",
                "exec:privilege",
                "guest-stopped",
                "leak:cargo_registry_token",
                "net:a.example",
                "net:direct",
                "net:raw",
                "read:other-process",
                "read:ssh",
                "root",
                "tamper:ptrace",
                "write:outside",
                "write:persistence",
            ]
        );
    }
}
