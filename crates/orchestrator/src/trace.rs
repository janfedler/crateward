//! Summarizes the guest's eBPF trace (ADR 0007).
//!
//! The agent streams events while the job runs. Everything in them is
//! hostile input: a crate that controls the guest can send any event it
//! likes, or none. The summary is therefore bounded in every dimension,
//! renders every byte string with escapes, and is read as the guest's
//! account next to the host's own ground truth (network log, scratch disk),
//! never instead of it.

use std::collections::{BTreeMap, HashSet};

use crateward_core::protocol::{SocketAddress, TraceEvent, TraceKind, TraceTotals};
use serde::{Deserialize, Serialize};

use crate::honeytokens::HOME;

/// Processes kept in the summary.
const MAX_PROCESSES: usize = 2000;
/// Entries kept per list of file accesses, connections or tamper attempts.
const MAX_LISTED: usize = 500;
/// Arguments kept per process, and bytes kept per argument or path.
const MAX_ARGS: usize = 32;
const MAX_STRING: usize = 512;

const O_ACCMODE: u32 = 0o3;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;

/// What a process is, judged by the program it executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// `cargo`.
    Cargo,
    /// `rustc`, including proc macros, which run inside it.
    Rustc,
    /// A build script compiled from a crate.
    BuildScript,
    /// A C compiler, linker or archiver.
    Toolchain,
    /// Anything else, for example a shell or `curl`.
    Other,
    /// Seen only through other events; its exec was not traced.
    Unknown,
}

fn role(exe: &str) -> Role {
    let name = exe.rsplit('/').next().unwrap_or(exe);
    if name == "cargo" {
        Role::Cargo
    } else if name == "rustc" {
        Role::Rustc
    } else if exe.contains("/build/") && name.starts_with("build-script-") {
        Role::BuildScript
    } else if matches!(
        name,
        "cc" | "gcc"
            | "g++"
            | "c++"
            | "clang"
            | "ld"
            | "ld.bfd"
            | "ld.gold"
            | "ar"
            | "as"
            | "collect2"
            | "cc1"
            | "cc1plus"
            | "ranlib"
            | "strip"
    ) {
        Role::Toolchain
    } else {
        Role::Other
    }
}

/// One traced process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    /// Guest process ID.
    pub pid: u32,
    /// Parent, if its fork was traced.
    pub ppid: Option<u32>,
    /// The last program it executed.
    pub exe: String,
    /// That program's arguments, possibly cut short.
    pub argv: Vec<String>,
    /// What it is.
    pub role: Role,
    /// Milliseconds after the job started.
    pub started_ms: u32,
    /// Kernel exit code, if its end was traced.
    pub exit: Option<u32>,
    /// Milliseconds after the job started when it ended, if traced.
    #[serde(default)]
    pub ended_ms: Option<u32>,
    /// It ran as root at some point although the job runs as the builder.
    pub became_root: bool,
}

/// A file access worth listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileAccess {
    /// The process.
    pub pid: u32,
    /// Its program.
    pub exe: String,
    /// The path the kernel resolved.
    pub path: String,
    /// `O_*` flags.
    pub flags: u32,
    /// Milliseconds after the job started.
    pub ms: u32,
}

/// A socket destination a process used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketUse {
    /// The process.
    pub pid: u32,
    /// Its program.
    pub exe: String,
    /// `connect` or `send`.
    pub how: String,
    /// The destination, rendered.
    pub address: String,
    /// `SOCK_*` type.
    pub sock_type: u32,
    /// Milliseconds after the job started.
    pub ms: u32,
}

/// An attempt to tamper with the tracing or the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tamper {
    /// The process.
    pub pid: u32,
    /// What it tried, for example `bpf cmd 5`.
    pub what: String,
    /// Milliseconds after the job started.
    pub ms: u32,
}

/// The guest's account of a job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSummary {
    /// The agent closed the trace with its totals.
    pub complete: bool,
    /// The agent's totals, if it sent them.
    pub totals: Option<TraceTotals>,
    /// Events the host received.
    pub received: u64,
    /// Files opened, in total.
    pub opens: u64,
    /// Processes, by start.
    pub processes: Vec<Process>,
    /// Processes beyond the limit.
    pub processes_omitted: u64,
    /// Opens of credentials, keys and other secrets.
    pub sensitive_opens: Vec<FileAccess>,
    /// Opens for writing outside the build directories.
    pub writes_outside_work: Vec<FileAccess>,
    /// Destinations, without repeats per process.
    pub sockets: Vec<SocketUse>,
    /// Tamper attempts.
    pub tamper: Vec<Tamper>,
    /// Entries dropped from the lists above.
    pub omitted: u64,
}

/// Renders guest bytes: printable UTF-8 is kept, everything else escaped.
#[must_use]
pub fn render(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes.get(..MAX_STRING).unwrap_or(bytes));
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    if bytes.len() > MAX_STRING {
        out.push('\u{2026}');
    }
    out
}

fn render_address(address: &SocketAddress) -> String {
    match address {
        SocketAddress::Ip(a) => a.to_string(),
        SocketAddress::Unix(path) => format!("unix:{}", render(path)),
        SocketAddress::Other(family) => format!("family {family}"),
    }
}

/// Whether a path holds secrets a stealer would read. `pid` is the process
/// that opened it: every Rust program reads its own `/proc/<pid>/maps`.
fn is_sensitive(path: &str, pid: u32) -> bool {
    let home = |rest: &str| path.strip_prefix(HOME).is_some_and(|p| p.starts_with(rest));
    home("/.cargo/credentials")
        || home("/.ssh/")
        || home("/.aws/")
        || home("/.git-credentials")
        || home("/.gnupg/")
        || home("/.config/gh/")
        || home("/.docker/config")
        || home("/.npmrc")
        || home("/.pypirc")
        || home("/.netrc")
        || path == "/etc/shadow"
        || path == "/etc/gshadow"
        || path.starts_with("/etc/sudoers")
        || path.starts_with("/root/")
        || path
            .strip_prefix("/proc/")
            .and_then(|rest| rest.split_once('/'))
            .is_some_and(|(owner, file)| {
                matches!(file, "environ" | "mem" | "maps") && owner != pid.to_string()
            })
}

/// Whether a write to this path is part of a normal build.
fn is_build_write(path: &str) -> bool {
    path.starts_with("/work/")
        || path.starts_with("/tmp/")
        || matches!(path, "/dev/null" | "/dev/tty" | "/dev/zero" | "/dev/full")
        || path.starts_with("/dev/pts/")
        || path.starts_with("/proc/self/")
        || path.starts_with("pipe:")
        || path.starts_with("anon_inode:")
}

/// Builds a [`TraceSummary`] from events as they arrive.
#[derive(Debug, Default)]
pub struct TraceBuilder {
    summary: TraceSummary,
    /// Index into `summary.processes` by process ID.
    index: BTreeMap<u32, usize>,
    /// Parents of forks seen before the child did anything.
    parents: BTreeMap<u32, (u32, u32)>,
    sockets_seen: HashSet<(u32, String)>,
}

impl TraceBuilder {
    fn process(&mut self, pid: u32, ms: u32) -> Option<&mut Process> {
        if let Some(&i) = self.index.get(&pid) {
            return self.summary.processes.get_mut(i);
        }
        if self.summary.processes.len() >= MAX_PROCESSES {
            self.summary.processes_omitted += 1;
            return None;
        }
        let (ppid, started_ms) = self
            .parents
            .remove(&pid)
            .map_or((None, ms), |(p, at)| (Some(p), at));
        self.index.insert(pid, self.summary.processes.len());
        self.summary.processes.push(Process {
            pid,
            ppid,
            exe: String::new(),
            argv: Vec::new(),
            role: Role::Unknown,
            started_ms,
            exit: None,
            ended_ms: None,
            became_root: false,
        });
        self.summary.processes.last_mut()
    }

    fn exe(&self, pid: u32) -> String {
        self.index
            .get(&pid)
            .and_then(|&i| self.summary.processes.get(i))
            .map(|p| p.exe.clone())
            .unwrap_or_default()
    }

    fn push<T>(list: &mut Vec<T>, omitted: &mut u64, item: T) {
        if list.len() < MAX_LISTED {
            list.push(item);
        } else {
            *omitted += 1;
        }
    }

    /// Adds one event.
    pub fn add(&mut self, event: &TraceEvent) {
        self.summary.received += 1;
        let (pid, ms) = (event.pid, event.ms);
        if event.uid == 0
            && let Some(p) = self.process(pid, ms)
        {
            p.became_root = true;
        }
        match &event.kind {
            TraceKind::Fork { child } => self.fork(pid, ms, *child),
            TraceKind::Exec { filename, argv } => self.exec(pid, ms, filename, argv),
            TraceKind::Exit { code } => self.exit(pid, ms, *code),
            TraceKind::Open { path, flags } => self.open(pid, ms, path, *flags),
            TraceKind::Connect { sock_type, address } => {
                self.socket(pid, ms, "connect", *sock_type, address);
            }
            TraceKind::Send { sock_type, address } => {
                self.socket(pid, ms, "send", *sock_type, address);
            }
            TraceKind::Bpf { cmd } => self.tamper(pid, format!("bpf cmd {cmd}"), ms),
            TraceKind::Ptrace { target, mode } => {
                self.tamper(pid, format!("ptrace {target} mode {mode:#x}"), ms);
            }
            TraceKind::Mount { fstype } => {
                self.tamper(pid, format!("mount {}", render(fstype)), ms);
            }
        }
    }

    fn fork(&mut self, pid: u32, ms: u32, child: u32) {
        if self.index.len() + self.parents.len() < MAX_PROCESSES * 2 {
            self.parents.insert(child, (pid, ms));
        }
        let _ = self.process(pid, ms);
    }

    fn exec(&mut self, pid: u32, ms: u32, filename: &[u8], argv: &[Vec<u8>]) {
        if let Some(p) = self.process(pid, ms) {
            p.exe = render(filename);
            p.argv = argv.iter().take(MAX_ARGS).map(|a| render(a)).collect();
            p.role = role(&p.exe);
        }
    }

    fn exit(&mut self, pid: u32, ms: u32, code: u32) {
        if let Some(p) = self.process(pid, ms) {
            p.exit = Some(code);
            p.ended_ms = Some(ms);
        }
    }

    fn open(&mut self, pid: u32, ms: u32, path: &[u8], flags: u32) {
        self.summary.opens += 1;
        let path = render(path);
        let writes = flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC) != 0;
        let sensitive = is_sensitive(&path, pid);
        if !sensitive && !(writes && !is_build_write(&path)) {
            return;
        }
        let _ = self.process(pid, ms);
        let access = FileAccess {
            pid,
            exe: self.exe(pid),
            path,
            flags,
            ms,
        };
        let s = &mut self.summary;
        if sensitive {
            Self::push(&mut s.sensitive_opens, &mut s.omitted, access);
        } else {
            Self::push(&mut s.writes_outside_work, &mut s.omitted, access);
        }
    }

    fn socket(&mut self, pid: u32, ms: u32, how: &str, sock_type: u32, address: &SocketAddress) {
        let address = render_address(address);
        let _ = self.process(pid, ms);
        if self.sockets_seen.len() >= MAX_LISTED * 4
            || !self.sockets_seen.insert((pid, address.clone()))
        {
            return;
        }
        let used = SocketUse {
            pid,
            exe: self.exe(pid),
            how: how.into(),
            address,
            sock_type,
            ms,
        };
        let s = &mut self.summary;
        Self::push(&mut s.sockets, &mut s.omitted, used);
    }

    fn tamper(&mut self, pid: u32, what: String, ms: u32) {
        let s = &mut self.summary;
        Self::push(&mut s.tamper, &mut s.omitted, Tamper { pid, what, ms });
    }

    /// Records the agent's closing totals.
    pub fn end(&mut self, totals: TraceTotals) {
        self.summary.complete = true;
        self.summary.totals = Some(totals);
    }

    /// The summary so far.
    #[must_use]
    pub fn finish(self) -> TraceSummary {
        self.summary
    }
}

impl TraceSummary {
    /// Where the given values appear in the trace: in an argument vector or
    /// a path. Returns `(value index, place)` pairs.
    #[must_use]
    pub fn find(&self, values: &[&str]) -> Vec<(usize, String)> {
        let mut found = Vec::new();
        for (i, value) in values.iter().enumerate() {
            if value.is_empty() {
                continue;
            }
            for p in &self.processes {
                if p.argv.iter().any(|a| a.contains(value)) {
                    found.push((i, format!("argv of {} ({})", p.pid, p.exe)));
                }
            }
            for f in self.sensitive_opens.iter().chain(&self.writes_outside_work) {
                if f.path.contains(value) {
                    found.push((i, format!("path {}", f.path)));
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The builder's user ID in the guest.
    const BUILDER_UID: u32 = 1000;

    fn event(pid: u32, uid: u32, ms: u32, kind: TraceKind) -> TraceEvent {
        TraceEvent {
            ms,
            pid,
            tid: pid,
            uid,
            kind,
        }
    }

    fn exec(pid: u32, exe: &str, argv: &[&str]) -> TraceEvent {
        event(
            pid,
            BUILDER_UID,
            1,
            TraceKind::Exec {
                filename: exe.into(),
                argv: argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
            },
        )
    }

    #[test]
    fn builds_a_process_tree_with_roles_and_findings() {
        let mut b = TraceBuilder::default();
        b.add(&exec(10, "/usr/local/bin/cargo", &["cargo", "check"]));
        b.add(&event(10, BUILDER_UID, 2, TraceKind::Fork { child: 11 }));
        b.add(&exec(
            11,
            "/work/target/debug/build/evil-0123/build-script-build",
            &["build-script-build"],
        ));
        b.add(&event(
            11,
            BUILDER_UID,
            3,
            TraceKind::Open {
                path: format!("{HOME}/.cargo/credentials.toml").into_bytes(),
                flags: 0,
            },
        ));
        b.add(&event(
            11,
            BUILDER_UID,
            4,
            TraceKind::Open {
                path: b"/work/target/debug/out.rs".to_vec(),
                flags: O_CREAT | 1,
            },
        ));
        b.add(&event(
            11,
            BUILDER_UID,
            4,
            TraceKind::Open {
                path: b"/etc/cron.d/x".to_vec(),
                flags: O_CREAT | 1,
            },
        ));
        for _ in 0..3 {
            b.add(&event(
                11,
                BUILDER_UID,
                5,
                TraceKind::Connect {
                    sock_type: 1,
                    address: SocketAddress::Ip("93.184.216.34:443".parse().unwrap()),
                },
            ));
        }
        b.add(&event(11, 0, 6, TraceKind::Bpf { cmd: 5 }));
        b.add(&event(11, BUILDER_UID, 7, TraceKind::Exit { code: 0 }));
        b.end(TraceTotals::default());
        let s = b.finish();
        assert!(s.complete);
        let script = s.processes.iter().find(|p| p.pid == 11).unwrap();
        assert_eq!(script.role, Role::BuildScript);
        assert_eq!(script.ppid, Some(10));
        assert_eq!(script.started_ms, 2);
        assert!(script.became_root);
        assert_eq!(script.exit, Some(0));
        assert_eq!(script.ended_ms, Some(7));
        assert_eq!(s.sensitive_opens.len(), 1);
        assert_eq!(s.writes_outside_work.len(), 1);
        assert_eq!(s.writes_outside_work[0].path, "/etc/cron.d/x");
        assert_eq!(s.sockets.len(), 1);
        assert_eq!(s.tamper[0].what, "bpf cmd 5");
        assert_eq!(s.opens, 3);
    }

    fn process_entry(pid: u32, ppid: Option<u32>, exe: &str, argv: &[&str], role: Role) -> Process {
        Process {
            pid,
            ppid,
            exe: exe.into(),
            argv: argv.iter().map(|a| (*a).into()).collect(),
            role,
            started_ms: 0,
            exit: None,
            ended_ms: None,
            became_root: false,
        }
    }

    fn access(path: &str, flags: u32, ms: u32) -> FileAccess {
        FileAccess {
            pid: 2,
            exe: "/usr/bin/curl".into(),
            path: path.into(),
            flags,
            ms,
        }
    }

    fn socket_use(how: &str, address: &str, sock_type: u32, ms: u32) -> SocketUse {
        SocketUse {
            pid: 2,
            exe: "/usr/bin/curl".into(),
            how: how.into(),
            address: address.into(),
            sock_type,
            ms,
        }
    }

    fn tamper_entry(what: &str) -> Tamper {
        Tamper {
            pid: 2,
            what: what.into(),
            ms: 6,
        }
    }

    #[test]
    fn every_event_kind_lands_in_the_summary() {
        let mut b = TraceBuilder::default();
        let open = |ms: u32, path: &str, flags: u32| {
            event(
                2,
                BUILDER_UID,
                ms,
                TraceKind::Open {
                    path: path.as_bytes().to_vec(),
                    flags,
                },
            )
        };
        let connect = |ms: u32, sock_type: u32, address: SocketAddress| {
            event(
                2,
                BUILDER_UID,
                ms,
                TraceKind::Connect { sock_type, address },
            )
        };
        let send = |ms: u32, sock_type: u32, address: SocketAddress| {
            event(2, BUILDER_UID, ms, TraceKind::Send { sock_type, address })
        };
        let ip = |text: &str| SocketAddress::Ip(text.parse().unwrap());
        let aws = format!("{HOME}/.aws/credentials");
        let events = [
            event(1, 0, 0, TraceKind::Fork { child: 2 }),
            exec(2, "/usr/bin/curl", &["curl", "-d", "x"]),
            open(2, &aws, 0),
            open(3, "/etc/passwd", O_CREAT | 1),
            open(3, "/work/target/x", O_CREAT | 1),
            open(3, "/usr/lib/libc.so", 0),
            connect(4, 1, ip("192.0.2.1:80")),
            connect(4, 1, ip("192.0.2.1:80")),
            send(5, 2, ip("192.0.2.1:80")),
            send(5, 2, ip("192.0.2.1:53")),
            send(5, 2, SocketAddress::Unix(b"/run/x.sock".to_vec())),
            connect(6, 1, SocketAddress::Other(10)),
            event(2, BUILDER_UID, 6, TraceKind::Bpf { cmd: 5 }),
            event(
                2,
                BUILDER_UID,
                6,
                TraceKind::Ptrace {
                    target: 7,
                    mode: 0x10,
                },
            ),
            event(
                2,
                BUILDER_UID,
                6,
                TraceKind::Mount {
                    fstype: b"tmpfs".to_vec(),
                },
            ),
            event(2, BUILDER_UID, 9, TraceKind::Exit { code: 3 }),
            event(99, BUILDER_UID, 10, TraceKind::Exit { code: 0 }),
        ];
        for event in &events {
            b.add(event);
        }
        let totals = TraceTotals {
            events: 17,
            ..TraceTotals::default()
        };
        b.end(totals);

        let mut root = process_entry(1, None, "", &[], Role::Unknown);
        root.became_root = true;
        let mut curl = process_entry(
            2,
            Some(1),
            "/usr/bin/curl",
            &["curl", "-d", "x"],
            Role::Other,
        );
        curl.exit = Some(3);
        curl.ended_ms = Some(9);
        let mut unknown = process_entry(99, None, "", &[], Role::Unknown);
        unknown.started_ms = 10;
        unknown.exit = Some(0);
        unknown.ended_ms = Some(10);
        let expected = TraceSummary {
            complete: true,
            totals: Some(totals),
            received: 17,
            opens: 4,
            processes: vec![root, curl, unknown],
            processes_omitted: 0,
            sensitive_opens: vec![access(&aws, 0, 2)],
            writes_outside_work: vec![access("/etc/passwd", O_CREAT | 1, 3)],
            sockets: vec![
                socket_use("connect", "192.0.2.1:80", 1, 4),
                socket_use("send", "192.0.2.1:53", 2, 5),
                socket_use("send", "unix:/run/x.sock", 2, 5),
                socket_use("connect", "family 10", 1, 6),
            ],
            tamper: vec![
                tamper_entry("bpf cmd 5"),
                tamper_entry("ptrace 7 mode 0x10"),
                tamper_entry("mount tmpfs"),
            ],
            omitted: 0,
        };
        assert_eq!(b.finish(), expected);
    }

    #[test]
    fn every_list_is_bounded_and_counts_what_it_drops() {
        let mut b = TraceBuilder::default();
        let mut add = |kind: TraceKind| b.add(&event(7, BUILDER_UID, 0, kind));
        for i in 0..MAX_LISTED + 2 {
            let path = format!("{HOME}/.ssh/key{i}").into_bytes();
            add(TraceKind::Open { path, flags: 0 });
        }
        for i in 0..MAX_LISTED + 3 {
            let path = format!("/etc/w{i}").into_bytes();
            add(TraceKind::Open {
                path,
                flags: O_CREAT,
            });
        }
        for _ in 0..MAX_LISTED + 4 {
            add(TraceKind::Bpf { cmd: 1 });
        }
        for i in 0..MAX_LISTED * 4 + 100 {
            let address = SocketAddress::Unix(format!("s{i}").into_bytes());
            add(TraceKind::Connect {
                sock_type: 1,
                address,
            });
        }
        let s = b.finish();
        assert_eq!(s.sensitive_opens.len(), MAX_LISTED);
        assert_eq!(s.writes_outside_work.len(), MAX_LISTED);
        assert_eq!(s.tamper.len(), MAX_LISTED);
        assert_eq!(s.sockets.len(), MAX_LISTED);
        assert_eq!(s.opens, (MAX_LISTED * 2 + 5) as u64);
        // Sockets are remembered up to four times the listed count.
        assert_eq!(s.omitted, 2 + 3 + 4 + (MAX_LISTED * 3) as u64);
        assert_eq!(s.processes.len(), 1);
    }

    #[test]
    fn arguments_and_remembered_parents_are_bounded() {
        let mut b = TraceBuilder::default();
        let many = vec!["a"; MAX_ARGS + 5];
        b.add(&exec(3, "/bin/sh", &many));
        assert_eq!(b.summary.processes[0].argv.len(), MAX_ARGS);
        for child in 0..MAX_PROCESSES as u32 * 2 + 10 {
            b.add(&event(
                1,
                BUILDER_UID,
                0,
                TraceKind::Fork {
                    child: 1000 + child,
                },
            ));
        }
        assert_eq!(b.index.len() + b.parents.len(), MAX_PROCESSES * 2);
    }

    #[test]
    fn stays_bounded_and_escapes_guest_bytes() {
        let mut b = TraceBuilder::default();
        for pid in 0..(MAX_PROCESSES as u32 + 50) {
            b.add(&exec(pid, "/bin/sh", &["sh"]));
        }
        let s = b.finish();
        assert_eq!(s.processes.len(), MAX_PROCESSES);
        assert_eq!(s.processes_omitted, 50);
        assert_eq!(render(b"a\x1b[31m\xe2\x80\xaeb"), "a\\u{1b}[31m\\u{202e}b");
        assert!(render(&[b'x'; 2000]).ends_with('\u{2026}'));
    }

    #[test]
    fn own_proc_files_are_not_sensitive() {
        assert!(!is_sensitive("/proc/42/maps", 42));
        assert!(is_sensitive("/proc/1/environ", 42));
        assert!(is_sensitive("/proc/43/mem", 42));
        assert!(!is_sensitive("/proc/42/status", 1));
        assert!(is_sensitive(&format!("{HOME}/.ssh/id_ed25519"), 1));
        assert!(!is_sensitive("/work/target/debug/.fingerprint", 1));
    }

    #[test]
    fn finds_values_in_arguments() {
        let mut b = TraceBuilder::default();
        b.add(&exec(5, "/usr/bin/curl", &["curl", "-d", "key=AKIATEST"]));
        let found = b.finish().find(&["AKIATEST", "absent"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 0);
    }
}
