//! A VM run report as the job page shows it: facts, alerts, the process
//! tree, network, file and disk activity, and the output tails.
//!
//! The report is read as JSON, tolerating missing or odd fields: it may
//! come from an older orchestrator, or be trimmed by retention. Every
//! string in it was escaped by the host when it was recorded, and askama
//! escapes it again for HTML.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use crateward_core::report::network::HOST_ADDRESS;
use crateward_core::report::trace::TOOLCHAIN;
use serde_json::Value;

/// Deepest indentation of the process tree.
const MAX_DEPTH: usize = 8;

/// One process in tree order.
#[derive(Debug, Clone)]
pub struct ProcessRow {
    /// Indentation, capped at eight levels.
    pub depth: usize,
    /// Depth in the tree, not capped.
    pub nesting: usize,
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
    /// How many sibling processes this row stands for: siblings that ran
    /// the same program with the same exit and the same tree below.
    pub count: usize,
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

    /// A program from outside the guest image that is neither cargo's nor a
    /// build script, such as one the build wrote to `/tmp`.
    #[must_use]
    pub fn foreign(&self) -> bool {
        let image = ["/usr/", "/bin/", "/sbin/", "/lib/"]
            .iter()
            .any(|dir| self.exe.starts_with(dir));

        !image && !self.exe.is_empty() && self.role != "build_script" && self.role != "cargo"
    }

    /// The program as listed: a build script by its package, since cargo
    /// names it `target/debug/build/<package>-<hash>/build-script-build`.
    #[must_use]
    pub fn label(&self) -> &str {
        match self.role.as_str() {
            "build_script" => build_package(&self.exe).unwrap_or(&self.exe),
            _ => &self.exe,
        }
    }

    /// What makes siblings the same for [`fold`], arguments aside.
    fn shape(&self) -> (&str, &str, bool, &str) {
        (&self.role, &self.exe, self.root, &self.exit)
    }

    fn compiler_name(&self) -> bool {
        self.role == "rustc" || self.role == "toolchain"
    }
}

/// The package of a program under cargo's `build/<package>-<hash>/`
/// directory, if it is one.
#[must_use]
pub fn build_package(exe: &str) -> Option<&str> {
    let (_, rest) = exe.rsplit_once("/build/")?;
    let (dir, _) = rest.split_once('/')?;
    let (name, hash) = dir.rsplit_once('-')?;

    hash.chars().all(|c| c.is_ascii_hexdigit()).then_some(name)
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
    /// Processes in tree order, repeated subtrees folded into one row.
    pub processes: Vec<ProcessRow>,
    /// How many processes were traced.
    pub process_total: usize,
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
    /// Retention removed the process list and the output tails.
    pub trimmed: bool,
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

/// Folds sibling subtrees of the same shape into the first of them, which
/// then counts them all. A C build runs `sh` and `cmake` hundreds of times
/// with only the arguments changing. Depths are capped afterwards, since
/// subtrees follow the real depth.
fn fold(rows: Vec<ProcessRow>) -> Vec<ProcessRow> {
    let n = rows.len();
    let depth = |i: usize| rows.get(i).map_or(0, |r| r.depth);

    // One past the last row of each row's subtree.
    let mut end = vec![n; n];
    let mut open: Vec<usize> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        while let Some(top) = open.pop_if(|top| depth(*top) >= row.depth) {
            if let Some(e) = end.get_mut(top) {
                *e = i;
            }
        }

        open.push(i);
    }

    let end_of = |i: usize| end.get(i).copied().unwrap_or(n);

    // A hash of each subtree's shape, children before parents.
    let mut shape = vec![0_u64; n];
    for (i, row) in rows.iter().enumerate().rev() {
        let mut hasher = DefaultHasher::new();
        row.shape().hash(&mut hasher);
        let mut child = i + 1;
        while child < end_of(i) {
            shape.get(child).hash(&mut hasher);
            child = end_of(child);
        }

        if let Some(s) = shape.get_mut(i) {
            *s = hasher.finish();
        }
    }

    enum Step {
        Siblings(usize, usize),
        Row(usize, usize),
    }

    let mut out = Vec::new();
    let mut steps = vec![Step::Siblings(0, n)];
    while let Some(step) = steps.pop() {
        match step {
            Step::Siblings(mut i, stop) => {
                // Groups in the order of their first member.
                let mut groups: Vec<(usize, usize)> = Vec::new();
                let mut index: BTreeMap<u64, usize> = BTreeMap::new();
                while i < stop {
                    let key = shape.get(i).copied().unwrap_or_default();
                    match index.get(&key).and_then(|g| groups.get_mut(*g)) {
                        Some(group) => group.1 += 1,
                        None => {
                            index.insert(key, groups.len());
                            groups.push((i, 1));
                        }
                    }

                    i = end_of(i);
                }

                steps.extend(groups.iter().rev().map(|&(i, count)| Step::Row(i, count)));
            }
            Step::Row(i, count) => {
                if let Some(row) = rows.get(i) {
                    out.push(ProcessRow {
                        count,
                        nesting: row.depth,
                        depth: row.depth.min(MAX_DEPTH),
                        ..row.clone()
                    });
                }

                steps.push(Step::Siblings(i + 1, end_of(i)));
            }
        }
    }

    out
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

    // Older reports classified fewer toolchain programs.
    let role = if TOOLCHAIN.contains(&name) {
        "toolchain".to_owned()
    } else {
        str_of(p, "role")
    };

    ProcessRow {
        depth,
        nesting: depth,
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
        count: 1,
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

/// An address as a reader should see it: the fake internet's by its port
/// alone (`:443`), since its address says nothing about where the build
/// wanted to go.
#[must_use]
pub fn address(text: &str) -> String {
    match text.strip_prefix(HOST_ADDRESS) {
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
    let rows = process_rows(trace);
    view.process_total = rows.len();
    view.compilers = rows.iter().filter(|p| p.compiler()).count();

    for p in rows.iter().filter(|p| p.root) {
        view.alerts
            .push(format!("Process {} ({}) ran as root", p.pid, p.exe));
    }

    view.processes = fold(rows);

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
        trimmed: report.get("trimmed").and_then(Value::as_bool) == Some(true),
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
mod tests;
