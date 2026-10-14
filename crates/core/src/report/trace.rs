//! The guest's eBPF trace of a job, as the orchestrator summarized it
//! (ADR 0007). The guest controls every event, so the summary is its
//! account, read next to the host's own ground truth.

use serde::{Deserialize, Serialize};

use crate::protocol::TraceTotals;

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
    /// Seen only through other events. Its exec was not traced.
    Unknown,
}

/// C compilers, linkers (including the `rust-lld` that rustc ships) and
/// their helpers. The dashboard uses the list too.
pub const TOOLCHAIN: [&str; 25] = [
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

/// `PTRACE_MODE_ATTACH` from `linux/ptrace.h`: attaching to a process, or
/// reading or writing its memory.
pub const PTRACE_MODE_ATTACH: u32 = 0x02;

impl Role {
    /// Judges a process by the program it executed.
    #[must_use]
    pub fn of(exe: &str) -> Self {
        let name = exe.rsplit('/').next().unwrap_or(exe);

        if name == "cargo" {
            Self::Cargo
        } else if name == "rustc" {
            Self::Rustc
        } else if exe.contains("/build/") && name.starts_with("build-script-") {
            Self::BuildScript
        } else if TOOLCHAIN.contains(&name) {
            Self::Toolchain
        } else {
            Self::Other
        }
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

impl Tamper {
    /// Whether this is a ptrace check for read access only, which reports
    /// from before such checks were left out still list.
    #[must_use]
    pub fn is_read_check(&self) -> bool {
        self.what
            .strip_prefix("ptrace ")
            .and_then(|rest| rest.split_once(" mode 0x"))
            .and_then(|(_, mode)| u32::from_str_radix(mode, 16).ok())
            .is_some_and(|mode| mode & PTRACE_MODE_ATTACH == 0)
    }
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

    #[test]
    fn linkers_belong_to_the_toolchain() {
        assert_eq!(
            Role::of("/usr/local/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"),
            Role::Toolchain
        );
        assert_eq!(Role::of("/usr/bin/cc"), Role::Toolchain);
        assert_eq!(Role::of("/usr/bin/curl"), Role::Other);
        assert_eq!(
            Role::of("/work/target/debug/build/x-1/build-script-build"),
            Role::BuildScript
        );
    }
}
