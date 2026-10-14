//! Scoring: every point of a verdict comes with its evidence (ADR 0009).
//!
//! The score is a sum of points from independent signals, capped per group
//! so that one noisy source cannot dominate, and capped at 100 in total.
//! The point values are a starting calibration, documented in the ADR and
//! meant to be tuned on live traffic. They are ordered by how strongly
//! each signal indicates intent:
//!
//! * A honeytoken that left the VM is theft, and alone makes a verdict
//!   critical.
//! * A honeytoken copied inside the VM, a process that became root, an
//!   attempt to tamper with tracing, a build that runs a program it wrote,
//!   or a guest that stopped itself are high.
//! * A build script that prints the whole environment copies the planted
//!   token along with everything else. Common tools do this, so such a dump
//!   counts as reading credentials, not as theft, and only when the crate's
//!   own build script did it.
//! * Reading credentials, writing to persistence locations, contacting the
//!   network, or running shells and downloaders during a build are
//!   suspicious on their own and common in legitimate `-sys` crates, so they
//!   add up rather than decide.
//! * Static findings count by severity, more when the code runs at build
//!   time, and new findings against the previous version count again. A
//!   downloader shape counts less when the run saw the download.
//!
//! Dynamic evidence names the package responsible when the process tree
//! leads to a build script (`/work/target/debug/build/<package>-<hash>/`) or
//! to `rustc` compiling a crate (whose proc macros run inside it).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crateward_core::job::BuildOutcome;
use crateward_core::paths::guest;
use crateward_core::report::findings::{Finding, FindingKind, Severity};
use crateward_core::report::network::{GUEST_ADDRESS, Leak};
use crateward_core::report::run::RunReport;
use crateward_core::report::scratch::{Entry, ScratchReport};
use crateward_core::report::static_report::{StaticReport, VersionDiff};
use crateward_core::report::trace::{Process, Role};
use crateward_core::verdict::{Coverage, Evidence, EvidenceSource, RiskLevel, Verdict};

pub use crateward_core::verdict::ANALYZER_VERSION;

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
    /// Evidence of earlier versions that a reviewer marked as a false
    /// positive, with their versions, newest first.
    pub dismissed: &'a [(String, Vec<Evidence>)],
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
    Dropper,
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
            Self::Theft | Self::Integrity | Self::Dropper => 100,
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
        // build`. The place is compared without it.
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

    /// Whether a run saw `package` look up a name or run a downloader.
    fn downloaded(&self, package: &str) -> bool {
        self.items.iter().any(|(_, e)| {
            matches!(e.signal.as_str(), "network_lookup" | "exec_downloader")
                && e.package.as_deref() == Some(package)
        })
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

/// What makes two pieces of evidence the same finding across versions: the
/// signal, the package, and the place without unit hashes and line numbers,
/// which change with every build and edit.
fn fingerprint(e: &Evidence) -> (&str, Option<&str>, Option<String>) {
    let place = e.location.as_deref().map(|l| {
        let l = without_unit_hash(l);
        match l.rsplit_once(':') {
            Some((file, line)) if !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()) => {
                file.to_owned()
            }
            _ => l,
        }
    });

    (e.signal.as_str(), e.package.as_deref(), place)
}

/// Evidence that a reviewer already marked as a false positive in an
/// earlier version keeps its row but no points, so the same behavior does
/// not raise the same alert with every release. New evidence still counts.
fn dismiss(groups: &mut Groups, dismissed: &[(String, Vec<Evidence>)]) {
    for (_, evidence) in &mut groups.items {
        let print = fingerprint(evidence);
        let Some((version, _)) = dismissed
            .iter()
            .find(|(_, earlier)| earlier.iter().any(|d| fingerprint(d) == print))
        else {
            continue;
        };

        evidence.points = 0;
        evidence.summary = format!(
            "{} A reviewer marked this a false positive in {version}.",
            evidence.summary
        );
    }
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

/// The directory a path left outside the build lies in: the first one below
/// the home directory or `/work`, or the first one of the path elsewhere.
fn top_directory(path: &str) -> String {
    let (base, rest) = [guest::HOME, guest::WORK, ""]
        .into_iter()
        .find_map(|base| Some((base, path.strip_prefix(base)?.strip_prefix('/')?)))
        .unwrap_or(("", path));

    let first = rest.split('/').next().unwrap_or(rest);

    format!("{base}/{first}")
}

/// Whether a program lies where the build can write: anything it runs from
/// there, it put there itself. Build scripts and what cargo builds live in
/// the target directory, and installed tools in `CARGO_HOME/bin`.
fn writable_location(exe: &str) -> bool {
    let work = exe.starts_with(&format!("{}/", guest::WORK))
        && !exe.starts_with(&format!("{}/", guest::TARGET))
        && !exe.starts_with(&format!("{}/bin/", guest::CARGO_HOME));

    work || ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/"]
        .iter()
        .any(|dir| exe.starts_with(dir))
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
    let downloaded = groups.downloaded(inputs.name);
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

        // A payload is no static finding like the others: it does not share
        // their cap. A download the run saw is scored by what the build did
        // with it, so its shape adds little.
        let (group, points) = match f.kind {
            FindingKind::DropperPattern => (Group::Dropper, 40),
            FindingKind::DownloaderPattern if downloaded => (Group::Static, 10),
            _ => (Group::Static, points),
        };

        let more = if count > 1 {
            format!(" ({} places)", count)
        } else {
            String::new()
        };

        groups.add(
            group,
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

    // Like static findings, each kind counts once.
    let mut kinds = BTreeSet::new();
    for f in diff
        .new_findings
        .iter()
        .filter(|f| f.severity >= Severity::High && kinds.insert(finding_name(&f.kind)))
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

fn score_run(name: &str, run: &RunReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    let processes: Processes<'_> = run.trace.processes.iter().map(|p| (p.pid, p)).collect();
    score_leaks(run, groups, profile);
    score_copies(name, run, groups, profile);
    score_integrity(run, &processes, groups, profile);
    score_files(run, &processes, groups, profile);
    score_disk(run, groups, profile);
    score_network(run, &processes, groups, profile);
    score_execution(run, &processes, groups, profile);
}

/// Honeytokens that left the VM, and traffic the search for them missed.
fn score_leaks(run: &RunReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
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

    let unsearched = run.network.unsearched();
    if !unsearched.is_empty() {
        profile.insert("net:unsearched".into());
        groups.add(
            Group::Theft,
            Evidence {
                signal: "network_unsearched".into(),
                points: 50,
                source: EvidenceSource::Network,
                summary: format!(
                    "The guest sent more than the honeytoken search could see: {}.",
                    unsearched.join(", ")
                ),
                package: None,
                location: None,
            },
        );
    }
}

/// Honeytokens copied inside the VM, and build scripts that wrote the whole
/// environment with them. Dumps by dependencies, such as `libz-sys` through
/// `cc`, are shown without points: they say nothing about the crate `name`.
fn score_copies(name: &str, run: &RunReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    for leak in run.tokens_on_disk.iter().filter(|l| dumped(run, l)) {
        let package = build_dir_package(&leak.via);
        let own = package.as_deref() == Some(name);
        if own {
            profile.insert("dump:environment".into());
        }

        groups.add(
            Group::Credentials,
            Evidence {
                signal: "environment_dumped".into(),
                points: if own { 15 } else { 0 },
                source: EvidenceSource::Disk,
                summary: format!(
                    "A build script wrote the whole environment, with the planted {}, \
                     into its build directory.",
                    leak.kind
                ),
                package,
                location: Some(leak.via.clone()),
            },
        );
    }

    let copies = run.tokens_on_disk.iter().filter(|l| !dumped(run, l));
    for leak in run.tokens_in_trace.iter().chain(copies) {
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

/// Whether a honeytoken on disk came with the rest of the environment, in a
/// build script's own directory. Reports of scanners that did not look for
/// the environment count every copy there as a dump.
fn dumped(run: &RunReport, leak: &Leak) -> bool {
    build_dir_package(&leak.via).is_some()
        && run
            .scratch
            .as_ref()
            .and_then(|s| s.environment_dumps.as_ref())
            .is_none_or(|dumps| dumps.contains(&leak.via))
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

    for x in run.trace.tamper.iter().filter(|x| !x.is_read_check()) {
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

    score_left_behind(scratch, groups, profile);
    score_special_files(scratch, groups, profile);
}

/// Entries outside the build areas: persistence locations each, the rest
/// once per top directory.
fn score_left_behind(scratch: &ScratchReport, groups: &mut Groups, profile: &mut BTreeSet<String>) {
    let (lasting, other): (Vec<_>, Vec<_>) = scratch
        .outside_build
        .iter()
        .partition(|e| persistence(&e.path));

    for e in lasting {
        profile.insert("disk:persistence".into());
        groups.add(
            Group::Persistence,
            Evidence {
                signal: "disk_persistence".into(),
                points: 40,
                source: EvidenceSource::Disk,
                summary: format!("The build left {} ({}).", e.path, e.kind),
                package: None,
                location: Some(e.path.clone()),
            },
        );
    }

    // A cache directory with its contents counts once.
    let mut trees: BTreeMap<String, (&Entry, usize)> = BTreeMap::new();
    for e in other {
        let tree = trees.entry(top_directory(&e.path)).or_insert((e, 0));
        tree.1 += 1;

        if e.path.len() < tree.0.path.len() {
            tree.0 = e;
        }
    }

    for (e, count) in trees.into_values() {
        let below = match count {
            1 => String::new(),
            n => format!(" and {} entries below it", n - 1),
        };

        profile.insert("disk:outside".into());
        groups.add(
            Group::Persistence,
            Evidence {
                signal: "disk_outside_build".into(),
                points: 10,
                source: EvidenceSource::Disk,
                summary: format!("The build left {} ({}){below}.", e.path, e.kind),
                package: None,
                location: Some(e.path.clone()),
            },
        );
    }
}

/// Executables outside the target directory and set ID files.
fn score_special_files(
    scratch: &ScratchReport,
    groups: &mut Groups,
    profile: &mut BTreeSet<String>,
) {
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
    let sender = sender(run, processes);

    for name in looked_up(&run.network.dns) {
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

/// The one package that used network sockets, if only one did.
fn sender(run: &RunReport, processes: &Processes<'_>) -> Option<String> {
    let senders: BTreeSet<String> = run
        .trace
        .sockets
        .iter()
        .filter(|s| !s.address.starts_with("unix:"))
        .filter_map(|s| package_of(s.pid, processes))
        .collect();

    if senders.len() == 1 {
        senders.into_iter().next()
    } else {
        None
    }
}

/// The names looked up. Guests without a host name looked up every name a
/// second time with the domain of their address appended, and those
/// repeats are left out.
fn looked_up(dns: &[String]) -> impl Iterator<Item = &String> {
    let (_, domain) = GUEST_ADDRESS.split_once('.').unwrap_or_default();

    dns.iter().filter(move |name| {
        !name
            .strip_suffix(domain)
            .and_then(|n| n.strip_suffix('.'))
            .is_some_and(|bare| dns.iter().any(|d| d == bare))
    })
}

/// Programs that the build wrote and ran, and programs that build scripts
/// ran, directly or through children.
fn score_execution(
    run: &RunReport,
    processes: &Processes<'_>,
    groups: &mut Groups,
    profile: &mut BTreeSet<String>,
) {
    let mut seen = BTreeSet::new();

    for p in run
        .trace
        .processes
        .iter()
        .filter(|p| writable_location(&p.exe))
    {
        profile.insert("exec:dropped".into());
        groups.add(
            Group::Dropper,
            Evidence {
                signal: "exec_dropped".into(),
                points: 60,
                source: EvidenceSource::Trace,
                summary: format!(
                    "The build ran {}, a program in a writable location, which the build put there.",
                    p.exe
                ),
                package: package_of(p.pid, processes),
                location: Some(p.exe.clone()),
            },
        );
    }

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

    for run in inputs.runs {
        score_run(inputs.name, run, &mut groups, &mut profile);
    }

    score_static(inputs, &mut groups, &mut profile);
    score_diff(inputs, &mut groups);

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

    dismiss(&mut groups, inputs.dismissed);
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
mod tests;
