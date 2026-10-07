//! A VM run report as the job page shows it: facts, alerts, the process
//! tree, network, file and disk activity, and the output tails.
//!
//! The report is read as JSON, tolerating missing or odd fields: it may
//! come from an older orchestrator, or be trimmed by retention. Every
//! string in it was escaped by the host when it was recorded, and askama
//! escapes it again for HTML.

use std::collections::{BTreeMap, BTreeSet};

use crateward_core::attack::{self, Technique};
use serde_json::Value;

/// Deepest indentation of the process tree.
const MAX_DEPTH: usize = 8;

/// C compilers, linkers and their helpers, as in the orchestrator's trace,
/// which classified fewer of them in older reports.
const TOOLCHAIN: [&str; 25] = [
    "cc",
    "gcc",
    "g++",
    "c++",
    "clang",
    "clang++",
    "cpp",
    "cc1",
    "cc1plus",
    "collect2",
    "lto-wrapper",
    "lto1",
    "as",
    "ld",
    "ld.bfd",
    "ld.gold",
    "ld.lld",
    "lld",
    "rust-lld",
    "ld.mold",
    "mold",
    "ar",
    "ranlib",
    "strip",
    "objcopy",
];

/// One process in tree order.
#[derive(Debug, Clone)]
pub struct ProcessRow {
    /// Indentation, capped at eight levels.
    pub depth: usize,
    /// Guest process ID.
    pub pid: u64,
    /// `cargo`, `rustc`, `build_script`, `toolchain`, `other` or `unknown`.
    pub role: String,
    /// The program.
    pub exe: String,
    /// Arguments after the program.
    pub args: String,
    /// Start after the job started.
    pub start: String,
    /// Run time, or empty when its end was not traced.
    pub duration: String,
    /// Exit code, or empty.
    pub exit: String,
    /// It ran as root.
    pub root: bool,
}

impl ProcessRow {
    /// `rustc` and the C toolchain, hidden by default: a build runs many.
    /// Only programs of the guest image count, under `/usr`, which the
    /// build cannot write: a build script that names its own program
    /// `rustc` stays visible.
    #[must_use]
    pub fn compiler(&self) -> bool {
        self.exe.starts_with("/usr/") && self.compiler_name()
    }

    /// A compiler by name that runs from outside the guest image.
    #[must_use]
    pub fn disguised(&self) -> bool {
        self.compiler_name() && !self.compiler()
    }

    /// The ATT&CK technique a disguised compiler is consistent with.
    #[must_use]
    pub fn masquerading(&self) -> Option<Technique> {
        self.disguised().then_some(attack::MASQUERADING)
    }

    fn compiler_name(&self) -> bool {
        self.role == "rustc" || self.role == "toolchain"
    }
}

/// A file opened by a process.
#[derive(Debug, Clone)]
pub struct AccessRow {
    /// When.
    pub at: String,
    /// The program.
    pub exe: String,
    /// The path.
    pub path: String,
    /// Open mode, for example `write, create`.
    pub mode: String,
}

/// A TCP connection to the fake internet.
#[derive(Debug, Clone)]
pub struct ConnectionRow {
    /// Destination.
    pub dst: String,
    /// `http`, `tls` or `unknown`.
    pub protocol: String,
    /// What was recognized: request line, host, SNI, user agent.
    pub detail: String,
    /// Bytes sent.
    pub bytes: String,
}

/// An entry the host found on the scratch disk.
#[derive(Debug, Clone)]
pub struct EntryRow {
    /// Why it is listed.
    pub why: &'static str,
    /// Path.
    pub path: String,
    /// `file`, `dir`, `symlink` and so on, with the target of a link.
    pub kind: String,
    /// Size.
    pub size: String,
    /// Permission bits in octal.
    pub mode: String,
}

/// A whole run.
#[derive(Debug, Clone, Default)]
pub struct RunView {
    /// `check` or `full`.
    pub kind: String,
    /// Where the report of a check run downloads that the full run
    /// replaces on the page, or empty.
    pub superseded: String,
    /// Where the report downloads.
    pub download: String,
    /// How the build ended.
    pub outcome: String,
    /// `ok`, `warn` or `bad`.
    pub outcome_class: &'static str,
    /// Label and value.
    pub facts: Vec<(String, String)>,
    /// What a reviewer must see first: honeytokens, tampering, root.
    pub alerts: Vec<String>,
    /// Processes in tree order.
    pub processes: Vec<ProcessRow>,
    /// How many of them are compilers.
    pub compilers: usize,
    /// Notes on the trace: missing processes, dropped events.
    pub trace_notes: Vec<String>,
    /// Names looked up.
    pub dns: Vec<String>,
    /// TCP connections.
    pub connections: Vec<ConnectionRow>,
    /// Other traffic and limits.
    pub network_notes: Vec<String>,
    /// Destinations by process: when, program, how, address, type.
    pub sockets: Vec<(String, String, String, String, String)>,
    /// Opens of credentials and other secrets.
    pub sensitive: Vec<AccessRow>,
    /// Opens for writing outside the build directories.
    pub writes: Vec<AccessRow>,
    /// Tamper attempts: when, process, what.
    pub tamper: Vec<(String, String, String)>,
    /// Scratch disk totals, or empty when it was not scanned.
    pub scratch: Vec<(String, String)>,
    /// Scratch disk entries worth a look.
    pub entries: Vec<EntryRow>,
    /// The end of the build's standard output.
    pub stdout: String,
    /// The end of the build's standard error.
    pub stderr: String,
}

fn str_of(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn u64_of(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Milliseconds as `350 ms`, `4.2 s` or `3 min 5 s`.
#[must_use]
pub fn duration(ms: u64) -> String {
    match ms {
        0..1_000 => format!("{ms} ms"),
        1_000..60_000 => format!("{}.{} s", ms / 1_000, ms % 1_000 / 100),
        _ => format!("{} min {} s", ms / 60_000, ms % 60_000 / 1_000),
    }
}

/// Bytes as `512 B`, `3.4 KiB`, `12.0 MiB`.
#[must_use]
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];

    if n < 1024 {
        return format!("{n} B");
    }

    let mut value = n as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or("TiB"))
}

/// The access mode and notable flags of `open`.
fn open_mode(flags: u64) -> String {
    let mut parts = vec![match flags & 3 {
        0 => "read",
        1 => "write",
        _ => "read and write",
    }];

    for (bit, name) in [(0o100, "create"), (0o1000, "truncate"), (0o2000, "append")] {
        if flags & bit != 0 {
            parts.push(name);
        }
    }

    parts.join(", ")
}

fn exit_text(exit: Option<&Value>) -> String {
    match exit {
        Some(Value::Object(map)) => map
            .iter()
            .map(|(how, n)| match how.as_str() {
                "Code" => format!("exit code {n}"),
                "Signal" => format!("killed by signal {n}"),
                other => format!("{other} {n}"),
            })
            .collect::<Vec<_>>()
            .join(", "),
        Some(Value::String(s)) if s == "TimedOut" => "killed after the timeout".to_owned(),
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn outcome_class(outcome: &str) -> &'static str {
    match outcome {
        "succeeded" => "ok",
        "failed" | "timed_out" | "resource_limit" => "warn",
        _ => "bad",
    }
}

/// The processes in tree order: each after its parent, siblings by start.
/// A process whose parent was not traced starts a tree of its own, and so
/// does one a parent loop cuts off.
fn process_rows(trace: &Value) -> Vec<ProcessRow> {
    let processes = list(trace, "processes");
    let pids: BTreeSet<u64> = processes.iter().filter_map(|p| u64_of(p, "pid")).collect();
    let mut children: BTreeMap<Option<u64>, Vec<&Value>> = BTreeMap::new();
    for p in processes {
        let parent =
            u64_of(p, "ppid").filter(|pp| pids.contains(pp) && Some(*pp) != u64_of(p, "pid"));

        children.entry(parent).or_default().push(p);
    }

    let mut rows = Vec::with_capacity(processes.len());
    let mut seen = BTreeSet::new();

    // Roots first, then anything a parent loop made unreachable.
    let starts = children
        .get(&None)
        .into_iter()
        .flatten()
        .copied()
        .chain(processes);
    for start in starts {
        let mut stack = vec![(start, 0)];
        while let Some((p, depth)) = stack.pop() {
            let pid = u64_of(p, "pid").unwrap_or(0);
            if !seen.insert(pid) {
                continue;
            }

            rows.push(process_row(p, depth));

            if let Some(kids) = children.get(&Some(pid)) {
                stack.extend(kids.iter().rev().map(|k| (*k, depth + 1)));
            }
        }
    }

    rows
}

fn process_row(p: &Value, depth: usize) -> ProcessRow {
    let argv: Vec<String> = list(p, "argv")
        .iter()
        .skip(1)
        .map(|a| a.as_str().unwrap_or_default().to_owned())
        .collect();

    let started = u64_of(p, "started_ms").unwrap_or(0);
    let exe = str_of(p, "exe");
    let name = exe.rsplit('/').next().unwrap_or_default();
    let role = if TOOLCHAIN.contains(&name) {
        "toolchain".to_owned()
    } else {
        str_of(p, "role")
    };

    ProcessRow {
        depth: depth.min(MAX_DEPTH),
        pid: u64_of(p, "pid").unwrap_or(0),
        role,
        exe,
        args: argv.join(" "),
        start: duration(started),
        duration: u64_of(p, "ended_ms")
            .map(|end| duration(end.saturating_sub(started)))
            .unwrap_or_default(),
        exit: u64_of(p, "exit").map(|e| e.to_string()).unwrap_or_default(),
        root: p
            .get("became_root")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn access_rows(trace: &Value, key: &str) -> Vec<AccessRow> {
    list(trace, key)
        .iter()
        .map(|a| AccessRow {
            at: duration(u64_of(a, "ms").unwrap_or(0)),
            exe: str_of(a, "exe"),
            path: str_of(a, "path"),
            mode: open_mode(u64_of(a, "flags").unwrap_or(0)),
        })
        .collect()
}

/// What the fake internet recognized in a connection.
/// How a run ended, from the host's view, in words. Reports store the
/// end's name with an optional reason (`guest_stopped: panic`). Older ones
/// stored Rust's debug form, cut at 64 characters, of which only the
/// variant's name is kept.
fn end_text(raw: &str) -> String {
    let name: String = raw
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .filter(|c| *c != '_')
        .collect::<String>()
        .to_ascii_lowercase();

    let label = match name.as_str() {
        "finished" => "agent reported the end",
        "hosttimeout" => "host time limit",
        "resourcelimit" => "resource limit",
        "gueststopped" => "guest stopped",
        "vmmcrashed" => "VMM crashed",
        "decoytouched" => "decoy touched",
        "kvmerror" => "KVM error",
        "unexpectedexit" => "unexpected exit",
        _ => return raw.to_owned(),
    };

    match raw.split_once(": ") {
        Some((_, reason)) if !raw.contains('(') => format!("{label}: {reason}"),
        _ => label.to_owned(),
    }
}

/// The fake internet's address in every slot (the orchestrator's
/// `HOST_ADDRESS`). Every name the guest looks up resolves to it.
const FAKE_INTERNET: &str = "10.0.2.1";

/// An address as a reader should see it: the fake internet's by its port
/// alone (`:443`), since its address says nothing about where the build
/// wanted to go.
#[must_use]
pub fn address(text: &str) -> String {
    match text.strip_prefix(FAKE_INTERNET) {
        Some("") => "fake internet".to_owned(),
        Some(rest) => rest
            .strip_prefix(':')
            .map_or_else(|| text.to_owned(), |port| format!(":{port}")),
        None => text.to_owned(),
    }
}

fn sniffed(c: &Value) -> String {
    let field = |key: &str, label: &str| {
        let value = str_of(c, key);
        (!value.is_empty()).then(|| format!("{label}{value}"))
    };

    match str_of(c, "protocol").as_str() {
        "http" => [
            Some(format!("{} {}", str_of(c, "method"), str_of(c, "target"))),
            field("host", "host "),
            field("user_agent", "agent "),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", "),
        "tls" => field("sni", "SNI ").unwrap_or_else(|| "no SNI".to_owned()),
        _ => String::new(),
    }
}

fn connection_row(c: &Value) -> ConnectionRow {
    let mut detail = sniffed(c);
    if let Some(inner) = c.get("inner") {
        let inside = sniffed(inner);
        if !inside.is_empty() {
            detail = format!("{detail}, inside TLS: {inside}");
        }
    }

    ConnectionRow {
        dst: address(&str_of(c, "dst")),
        protocol: str_of(c, "protocol"),
        detail,
        bytes: bytes(u64_of(c, "bytes").unwrap_or(0)),
    }
}

fn leak_alerts(report: &Value, alerts: &mut Vec<String>) {
    for (key, what) in [
        ("leaked", "left the VM through"),
        ("tokens_in_trace", "was seen inside the VM in"),
        ("tokens_on_disk", "was copied into"),
    ] {
        for leak in list(report, key) {
            alerts.push(format!(
                "Honeytoken {} {what} {}",
                str_of(leak, "kind"),
                address(&str_of(leak, "via"))
            ));
        }
    }
}

fn network(view: &mut RunView, net: &Value) {
    view.dns = list(net, "dns")
        .iter()
        .map(|d| d.as_str().unwrap_or_default().to_owned())
        .collect();
    view.connections = list(net, "connections")
        .iter()
        .map(connection_row)
        .collect();

    if let Some(n) = u64_of(net, "udp_datagrams").filter(|n| *n > 0) {
        view.network_notes
            .push(format!("{n} UDP datagrams other than DNS"));
    }

    if let Some(n) = u64_of(net, "refused").filter(|n| *n > 0) {
        view.network_notes
            .push(format!("{n} connections refused over the limit"));
    }

    for packet in list(net, "packets") {
        view.network_notes.push(format!(
            "Other frame: {}",
            packet.as_str().unwrap_or_default()
        ));
    }

    if net.get("truncated").and_then(Value::as_bool) == Some(true)
        || net.get("packets_truncated").and_then(Value::as_bool) == Some(true)
    {
        view.network_notes
            .push("The network log hit its limit, so later traffic is missing".to_owned());
    }
}

fn trace(view: &mut RunView, trace: &Value) {
    view.processes = process_rows(trace);
    view.compilers = view.processes.iter().filter(|p| p.compiler()).count();

    for p in view.processes.iter().filter(|p| p.root) {
        view.alerts
            .push(format!("Process {} ({}) ran as root", p.pid, p.exe));
    }

    if trace.get("complete").and_then(Value::as_bool) == Some(false) {
        view.trace_notes
            .push("The agent did not close the trace, so it may be incomplete".to_owned());
    }

    if let Some(n) = u64_of(trace, "processes_omitted").filter(|n| *n > 0) {
        view.trace_notes
            .push(format!("{n} more processes not listed"));
    }

    if let Some(n) = u64_of(trace, "omitted").filter(|n| *n > 0) {
        view.trace_notes
            .push(format!("{n} file or socket entries not listed"));
    }

    if let Some(totals) = trace.get("totals") {
        let dropped = u64_of(totals, "dropped_in_kernel").unwrap_or(0)
            + u64_of(totals, "dropped_by_agent").unwrap_or(0);
        if dropped > 0 {
            view.trace_notes.push(format!("{dropped} events dropped"));
        }
    }

    view.sockets = list(trace, "sockets")
        .iter()
        .map(|s| {
            let kind = match u64_of(s, "sock_type") {
                Some(1) => "stream",
                Some(2) => "datagram",
                Some(3) => "raw",
                _ => "other",
            };

            (
                duration(u64_of(s, "ms").unwrap_or(0)),
                str_of(s, "exe"),
                str_of(s, "how"),
                address(&str_of(s, "address")),
                kind.to_owned(),
            )
        })
        .collect();
    view.sensitive = access_rows(trace, "sensitive_opens");
    view.writes = access_rows(trace, "writes_outside_work");
    view.tamper = list(trace, "tamper")
        .iter()
        .map(|t| {
            (
                duration(u64_of(t, "ms").unwrap_or(0)),
                u64_of(t, "pid").unwrap_or(0).to_string(),
                str_of(t, "what"),
            )
        })
        .collect();

    for t in &view.tamper {
        view.alerts
            .push(format!("Process {} tried to tamper: {}", t.1, t.2));
    }
}

fn scratch(view: &mut RunView, disk: &Value) {
    view.scratch = vec![
        (
            "Files".to_owned(),
            u64_of(disk, "files").unwrap_or(0).to_string(),
        ),
        (
            "Directories".to_owned(),
            u64_of(disk, "directories").unwrap_or(0).to_string(),
        ),
        ("Size".to_owned(), bytes(u64_of(disk, "bytes").unwrap_or(0))),
        (
            "Compiled units".to_owned(),
            list(disk, "units").len().to_string(),
        ),
    ];

    if disk.get("incomplete").and_then(Value::as_bool) == Some(true) {
        view.scratch
            .push(("Scan".to_owned(), "stopped at a limit".to_owned()));
    }

    for (key, why) in [
        ("executables_outside_target", "executable outside target"),
        ("setid", "set user or group ID"),
        ("links_outside", "link leaving the disk"),
        ("special", "device, FIFO or socket"),
        ("outside_build", "outside the build areas"),
    ] {
        for e in list(disk, key) {
            let target = str_of(e, "target");
            view.entries.push(EntryRow {
                why,
                path: str_of(e, "path"),
                kind: if target.is_empty() {
                    str_of(e, "kind")
                } else {
                    format!("{} to {target}", str_of(e, "kind"))
                },
                size: bytes(u64_of(e, "size").unwrap_or(0)),
                mode: format!("{:o}", u64_of(e, "mode").unwrap_or(0)),
            });
        }
    }

    for path in list(disk, "planted_changed") {
        view.alerts.push(format!(
            "Planted file {} changed or disappeared",
            path.as_str().unwrap_or_default()
        ));
    }
}

/// The runs a job page shows: the full run when there is one, since it
/// repeats what the check run did, with a link to the check run's report.
#[must_use]
pub fn run_views(job: i64, runs: &[(String, Value)]) -> Vec<RunView> {
    let full = runs.iter().any(|(kind, _)| kind == "full");
    let check = runs.iter().any(|(kind, _)| kind == "check");

    runs.iter()
        .filter(|(kind, _)| !(full && kind == "check"))
        .map(|(kind, report)| {
            let mut view = run_view(job, kind, report);
            if kind == "full" && check {
                view.superseded = format!("/jobs/{job}/runs/check.json");
            }

            view
        })
        .collect()
}

/// The view of one stored run report.
#[must_use]
pub fn run_view(job: i64, kind: &str, report: &Value) -> RunView {
    let outcome = str_of(report, "outcome");
    let mut view = RunView {
        kind: kind.to_owned(),
        download: format!("/jobs/{job}/runs/{kind}.json"),
        outcome_class: outcome_class(&outcome),
        outcome: outcome.replace('_', " "),
        stdout: str_of(report, "stdout_tail"),
        stderr: str_of(report, "stderr_tail"),
        ..RunView::default()
    };

    let mut facts = vec![("Ended".to_owned(), end_text(&str_of(report, "end")))];
    let exit = exit_text(report.get("exit"));
    if !exit.is_empty() {
        facts.push(("Guest".to_owned(), exit));
    }

    if let Some(ms) = u64_of(report, "run_ms") {
        facts.push(("Run time".to_owned(), duration(ms)));
    }

    if let Some(ms) = u64_of(report, "restore_ms") {
        facts.push(("VM restore".to_owned(), duration(ms)));
    }

    if let Some(files) = u64_of(report, "payload_files") {
        let size = bytes(u64_of(report, "payload_bytes").unwrap_or(0));
        facts.push(("Payload".to_owned(), format!("{files} files, {size}")));
    }

    let missing = list(report, "missing_packages");
    if !missing.is_empty() {
        let names: Vec<&str> = missing.iter().filter_map(Value::as_str).collect();
        facts.push(("Missing packages".to_owned(), names.join(", ")));
    }

    view.facts = facts;
    leak_alerts(report, &mut view.alerts);

    if let Some(t) = report.get("trace") {
        trace(&mut view, t);

        if let Some(opens) = u64_of(t, "opens") {
            view.facts
                .push(("Files opened".to_owned(), opens.to_string()));
        }
    }

    if let Some(net) = report.get("network") {
        network(&mut view, net);
    }

    if let Some(disk) = report.get("scratch").filter(|d| d.is_object()) {
        scratch(&mut view, disk);
    }

    if report.get("truncated").and_then(Value::as_bool) == Some(true) {
        view.facts
            .push(("Output".to_owned(), "cut at the limit".to_owned()));
    }

    view
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn units_read_naturally() {
        assert_eq!(duration(350), "350 ms");
        assert_eq!(duration(4_250), "4.2 s");
        assert_eq!(duration(185_000), "3 min 5 s");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(3_500), "3.4 KiB");
        assert_eq!(bytes(12 * 1024 * 1024), "12.0 MiB");
        assert_eq!(open_mode(0), "read");
        assert_eq!(open_mode(0o1101), "write, create, truncate");
    }

    #[test]
    fn processes_follow_their_parents_and_survive_cycles() {
        let trace = json!({"processes": [
            {"pid": 1, "ppid": null, "exe": "/usr/bin/cargo", "argv": ["cargo", "check"], "role": "cargo", "started_ms": 0},
            {"pid": 3, "ppid": 1, "exe": "/w/build-script-build", "argv": ["b"], "role": "build_script", "started_ms": 20, "ended_ms": 1520},
            {"pid": 2, "ppid": 1, "exe": "/usr/bin/rustc", "argv": [], "role": "rustc", "started_ms": 10},
            {"pid": 4, "ppid": 3, "exe": "/usr/bin/curl", "argv": ["curl", "-o", "x"], "role": "other", "started_ms": 30, "exit": 6, "became_root": true},
            {"pid": 7, "ppid": 8, "exe": "a", "role": "unknown"},
            {"pid": 8, "ppid": 7, "exe": "b", "role": "unknown"},
            {"pid": 9, "ppid": 99, "exe": "orphan", "role": "unknown"}
        ]});

        let rows = process_rows(&trace);
        let order: Vec<(u64, usize)> = rows.iter().map(|r| (r.pid, r.depth)).collect();

        // 7 and 8 are each other's parents: listed after the real roots.
        assert_eq!(
            order,
            [(1, 0), (3, 1), (4, 2), (2, 1), (9, 0), (7, 0), (8, 1)]
        );

        let curl = &rows[2];
        assert_eq!(
            (curl.args.as_str(), curl.exit.as_str(), curl.root),
            ("-o x", "6", true)
        );
        assert_eq!(rows[1].duration, "1.5 s");
        assert!(rows[3].compiler());
    }

    #[test]
    fn only_system_compilers_hide() {
        let trace = json!({"processes": [
            {"pid": 1, "exe": "/usr/local/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld", "role": "other"},
            {"pid": 2, "exe": "/tmp/x/rust-lld", "role": "other"},
            {"pid": 3, "exe": "/work/target/rustc", "role": "rustc"},
            {"pid": 4, "exe": "/usr/local/bin/rustc", "role": "rustc"}
        ]});

        let rows = process_rows(&trace);
        let hidden: Vec<(u64, &str, bool)> = rows
            .iter()
            .map(|r| (r.pid, r.role.as_str(), r.compiler()))
            .collect();

        assert_eq!(
            hidden,
            [
                (1, "toolchain", true),
                (2, "toolchain", false),
                (3, "rustc", false),
                (4, "rustc", true)
            ]
        );
    }

    #[test]
    fn a_report_becomes_facts_alerts_and_tables() {
        let report = json!({
            "outcome": "timed_out", "end": "Finished", "exit": {"Signal": 9},
            "run_ms": 61000, "restore_ms": 120, "payload_files": 10, "payload_bytes": 2048,
            "stdout_tail": "out", "stderr_tail": "err", "truncated": false, "missing_packages": [],
            "network": {"dns": ["evil.example"], "connections": [
                {"dst": "10.0.2.1:443", "protocol": "tls", "sni": "evil.example", "bytes": 517,
                 "inner": {"protocol": "http", "method": "POST", "target": "/up", "host": "evil.example", "user_agent": null}},
                {"dst": "203.0.113.9:80", "protocol": "unknown", "bytes": 3}
            ], "udp_datagrams": 2, "refused": 0, "truncated": false},
            "leaked": [{"kind": "aws_key", "via": "https://evil.example/up"}, {"kind": "ssh_key", "via": "10.0.2.1:4444"}],
            "trace": {"complete": false, "opens": 900, "processes": [], "processes_omitted": 0,
                      "sensitive_opens": [{"pid": 4, "exe": "/bin/cat", "path": "/home/b/.cargo/credentials.toml", "flags": 0, "ms": 40}],
                      "writes_outside_work": [], "sockets": [{"pid": 4, "exe": "curl", "how": "connect", "address": "10.0.2.1:443", "sock_type": 1, "ms": 50}],
                      "tamper": [{"pid": 4, "what": "bpf cmd 5", "ms": 60}], "omitted": 0},
            "scratch": {"files": 5, "directories": 2, "bytes": 100, "incomplete": false,
                        "outside_build": [{"path": "/home/b/.bashrc", "kind": "file", "size": 10, "mode": 420, "uid": 1000}],
                        "executables_outside_target": [], "setid": [], "special": [], "links_outside": [],
                        "planted_changed": ["/home/b/.aws/credentials"], "tokens_found": [], "units": ["a"], "omitted": 0}
        });

        let view = run_view(7, "check", &report);
        assert_eq!(view.download, "/jobs/7/runs/check.json");
        assert_eq!(
            (view.outcome.as_str(), view.outcome_class),
            ("timed out", "warn")
        );
        assert!(
            view.facts
                .contains(&("Guest".into(), "killed by signal 9".into()))
        );
        assert!(
            view.facts
                .contains(&("Run time".into(), "1 min 1 s".into()))
        );
        assert_eq!(
            view.alerts,
            [
                "Honeytoken aws_key left the VM through https://evil.example/up",
                "Honeytoken ssh_key left the VM through :4444",
                "Process 4 tried to tamper: bpf cmd 5",
                "Planted file /home/b/.aws/credentials changed or disappeared",
            ]
        );
        assert_eq!(
            view.connections[0].detail,
            "SNI evil.example, inside TLS: POST /up, host evil.example"
        );
        assert_eq!(view.connections[0].dst, ":443");
        assert_eq!(view.connections[1].detail, "");
        assert_eq!(view.connections[1].dst, "203.0.113.9:80");
        assert_eq!(view.sockets[0].3, ":443");
        assert_eq!(view.network_notes, ["2 UDP datagrams other than DNS"]);
        assert_eq!(view.sensitive[0].mode, "read");
        assert_eq!(view.sockets[0].4, "stream");
        assert_eq!(
            view.trace_notes,
            ["The agent did not close the trace, so it may be incomplete"]
        );
        assert_eq!(view.entries[0].mode, "644");
    }

    #[test]
    fn the_end_is_put_in_words() {
        assert_eq!(end_text("finished"), "agent reported the end");
        assert_eq!(
            end_text("guest_stopped: kernel panic"),
            "guest stopped: kernel panic"
        );

        // The debug form of older reports, cut inside the output bytes.
        assert_eq!(
            end_text("Finished(RunOutcome { exit: Code(0), stdout: [], stderr: [32, 32"),
            "agent reported the end"
        );
        assert_eq!(end_text("HostTimeout"), "host time limit");
        assert_eq!(end_text("something new"), "something new");
        assert_eq!(end_text(""), "");
    }

    #[test]
    fn the_fake_internet_is_named() {
        assert_eq!(address("10.0.2.1:53"), ":53");
        assert_eq!(address("10.0.2.1"), "fake internet");

        for other in ["10.0.2.10:80", "10.0.2.2:1", "/home/b/x", "tls://a.example"] {
            assert_eq!(address(other), other);
        }
    }

    #[test]
    fn the_full_run_replaces_the_check_run() {
        let runs = |kinds: &[&str]| -> Vec<(String, Value)> {
            kinds.iter().map(|k| ((*k).to_owned(), json!({}))).collect()
        };

        let both = run_views(3, &runs(&["check", "full"]));
        assert_eq!(both.len(), 1);
        assert_eq!(
            (both[0].kind.as_str(), both[0].superseded.as_str()),
            ("full", "/jobs/3/runs/check.json")
        );

        let check = run_views(3, &runs(&["check"]));
        assert_eq!(
            (check[0].kind.as_str(), check[0].superseded.as_str()),
            ("check", "")
        );
    }

    #[test]
    fn an_empty_or_odd_report_still_renders() {
        let view = run_view(
            1,
            "full",
            &json!({"network": "x", "trace": 3, "scratch": null}),
        );

        assert!(view.processes.is_empty() && view.alerts.is_empty() && view.scratch.is_empty());
        assert_eq!(view.outcome_class, "bad");
    }
}
