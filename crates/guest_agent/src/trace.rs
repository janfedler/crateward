//! Loads the eBPF programs and turns their records into trace events.
//!
//! The programs live in `crateward_guest_ebpf` (ADR 0006, ADR 0017). The
//! agent loads them once at boot, before the base snapshot, so every
//! restored VM traces from its first instruction. Loading needs the kernel
//! structure offsets the programs read ([`OFFSETS`]); they come from the
//! running kernel's BTF ([`crate::btf`]).
//!
//! Records are decoded byte by byte against the layouts documented in the
//! eBPF package. The decoder never trusts a length field beyond the record
//! it came with; a record that does not fit is counted as malformed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aya::maps::{Map, MapData, MapError, PerCpuArray, RingBuf};
use aya::programs::{BtfTracePoint, Lsm, Program, ProgramError};
use aya::{Btf as AyaBtf, BtfError as AyaBtfError, Ebpf, EbpfError, EbpfLoader};
use crateward_core::protocol::{SocketAddress, TraceEvent, TraceKind, TraceTotals};

use crate::btf::{Btf, BtfError};

/// Where the root filesystem keeps the compiled programs.
pub const OBJECT_PATH: &str = "/usr/lib/crateward/guest-ebpf.o";

/// Global name, struct and member of every kernel offset the programs use.
pub const OFFSETS: [(&str, &str, &str); 15] = [
    ("OFF_TASK_PID", "task_struct", "pid"),
    ("OFF_TASK_TGID", "task_struct", "tgid"),
    ("OFF_TASK_MM", "task_struct", "mm"),
    ("OFF_TASK_EXIT_CODE", "task_struct", "exit_code"),
    ("OFF_TASK_REAL_CRED", "task_struct", "real_cred"),
    ("OFF_CRED_EUID", "cred", "euid"),
    ("OFF_MM_ARG_START", "mm_struct", "arg_start"),
    ("OFF_MM_ARG_END", "mm_struct", "arg_end"),
    ("OFF_BINPRM_FILENAME", "linux_binprm", "filename"),
    ("OFF_FILE_PATH", "file", "f_path"),
    ("OFF_FILE_FLAGS", "file", "f_flags"),
    ("OFF_FILE_MODE", "file", "f_mode"),
    ("OFF_SOCKET_TYPE", "socket", "type"),
    ("OFF_MSGHDR_NAME", "msghdr", "msg_name"),
    ("OFF_MSGHDR_NAMELEN", "msghdr", "msg_namelen"),
];

/// BTF tracepoints, by program name (which is also the tracepoint name).
const TRACEPOINTS: [&str; 3] = [
    "sched_process_fork",
    "sched_process_exec",
    "sched_process_exit",
];

/// LSM programs, by program name (which is also the hook name).
const LSM_HOOKS: [&str; 6] = [
    "file_open",
    "socket_connect",
    "socket_sendmsg",
    "bpf",
    "ptrace_access_check",
    "sb_mount",
];

/// A batch is sent once its estimated encoded size passes this, which keeps
/// every frame well below the protocol's frame limit.
const BATCH_BYTES: usize = 32 * 1024;

/// Estimated encoded bytes the agent sends per job before it drops events.
/// The host's connection budget is larger, so output still fits.
const MAX_TRACE_BYTES: usize = 96 * 1024 * 1024;

/// How long the reader sleeps when the ring buffer is empty.
const IDLE: Duration = Duration::from_millis(10);

// Record kinds and layouts; see `crates/guest_ebpf/src/main.rs`.
const HEADER_LEN: usize = 24;
const KIND_FORK: u32 = 1;
const KIND_EXEC: u32 = 2;
const KIND_EXIT: u32 = 3;
const KIND_OPEN: u32 = 4;
const KIND_CONNECT: u32 = 5;
const KIND_SEND: u32 = 6;
const KIND_BPF: u32 = 7;
const KIND_PTRACE: u32 = 8;
const KIND_MOUNT: u32 = 9;
const FILENAME_LEN: usize = 256;
const ARGS_LEN: usize = 1024;
const PATH_LEN: usize = 512;
const ADDR_LEN: usize = 112;
const FSTYPE_LEN: usize = 32;

const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn i32_at(data: &[u8], at: usize) -> Option<i32> {
    data.get(at..at + 4)?
        .try_into()
        .ok()
        .map(i32::from_le_bytes)
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at + 8)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

/// The first `len` bytes of a fixed buffer, without a trailing NUL.
fn string(buffer: &[u8], len: i32) -> Vec<u8> {
    let len = usize::try_from(len).unwrap_or(0).min(buffer.len());
    let bytes = buffer.get(..len).unwrap_or_default();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes.get(..end).unwrap_or_default().to_vec()
}

fn socket_address(addr: &[u8], addr_len: u32) -> SocketAddress {
    let len = usize::try_from(addr_len).unwrap_or(0).min(addr.len());
    let family = u16_at(addr, 0).unwrap_or(0);
    let port = || {
        addr.get(2..4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u16::from_be_bytes)
    };
    match family {
        AF_INET if len >= 8 => {
            let ip: [u8; 4] = addr
                .get(4..8)
                .and_then(|b| b.try_into().ok())
                .unwrap_or_default();
            SocketAddress::Ip((std::net::Ipv4Addr::from(ip), port()).into())
        }
        AF_INET6 if len >= 24 => {
            let ip: [u8; 16] = addr
                .get(8..24)
                .and_then(|b| b.try_into().ok())
                .unwrap_or_default();
            SocketAddress::Ip((std::net::Ipv6Addr::from(ip), port()).into())
        }
        AF_UNIX => {
            let path = addr.get(2..len.max(2)).unwrap_or_default();
            // A path name ends at its NUL; an abstract name keeps its bytes.
            let path = if path.first() == Some(&0) {
                path
            } else {
                let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
                path.get(..end).unwrap_or_default()
            };
            SocketAddress::Unix(path.to_vec())
        }
        other => SocketAddress::Other(other),
    }
}

/// An error with its sources, which name the failing system call's errno.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(inner) = source {
        text.push_str(": ");
        text.push_str(&inner.to_string());
        source = inner.source();
    }
    text
}

/// Decodes one ring buffer record. `start_ns` is the job's start on the
/// same clock as the records.
#[must_use]
pub fn decode(record: &[u8], start_ns: u64) -> Option<TraceEvent> {
    let kind = u32_at(record, 0)?;
    let pid = u32_at(record, 4)?;
    let tid = u32_at(record, 8)?;
    let uid = u32_at(record, 12)?;
    let time_ns = u64_at(record, 16)?;
    let ms = u32::try_from(time_ns.saturating_sub(start_ns) / 1_000_000).unwrap_or(u32::MAX);
    let body = record.get(HEADER_LEN..)?;
    let kind = match kind {
        KIND_FORK => TraceKind::Fork {
            child: u32_at(body, 0)?,
        },
        KIND_EXEC => {
            let filename_len = i32_at(body, 0)?;
            let args_len = usize::try_from(u32_at(body, 4)?).ok()?.min(ARGS_LEN);
            let filename = string(body.get(8..8 + FILENAME_LEN)?, filename_len);
            let args = body.get(8 + FILENAME_LEN..8 + FILENAME_LEN + ARGS_LEN)?;
            let args = args.get(..args_len)?;
            let mut argv: Vec<Vec<u8>> = args.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
            // The vector ends with a NUL, which leaves one empty piece.
            if args.last() == Some(&0) {
                argv.pop();
            }
            TraceKind::Exec { filename, argv }
        }
        KIND_EXIT => TraceKind::Exit {
            code: u32_at(body, 0)?,
        },
        KIND_OPEN => {
            let flags = u32_at(body, 0)?;
            let path_len = i32_at(body, 4)?;
            let buffer = body.get(8..8 + PATH_LEN)?;
            let path = if path_len > 0 {
                string(buffer, path_len)
            } else {
                format!("<unresolved: error {path_len}>").into_bytes()
            };
            TraceKind::Open { path, flags }
        }
        KIND_CONNECT | KIND_SEND => {
            let sock_type = u32_at(body, 0)?;
            let addr_len = u32_at(body, 4)?;
            let address = socket_address(body.get(8..8 + ADDR_LEN)?, addr_len);
            if kind == KIND_CONNECT {
                TraceKind::Connect { sock_type, address }
            } else {
                TraceKind::Send { sock_type, address }
            }
        }
        KIND_BPF => TraceKind::Bpf {
            cmd: u32_at(body, 0)?,
        },
        KIND_PTRACE => TraceKind::Ptrace {
            target: u32_at(body, 0)?,
            mode: u32_at(body, 4)?,
        },
        KIND_MOUNT => {
            let len = i32_at(body, 0)?;
            TraceKind::Mount {
                fstype: string(body.get(8..8 + FSTYPE_LEN)?, len),
            }
        }
        _ => return None,
    };
    Some(TraceEvent {
        ms,
        pid,
        tid,
        uid,
        kind,
    })
}

/// Estimated encoded size of an event, never below the real one.
fn estimate(event: &TraceEvent) -> usize {
    let strings = match &event.kind {
        TraceKind::Exec { filename, argv } => {
            filename.len() + argv.iter().map(|a| a.len() + 3).sum::<usize>()
        }
        TraceKind::Open { path, .. } => path.len(),
        TraceKind::Connect {
            address: SocketAddress::Unix(p),
            ..
        }
        | TraceKind::Send {
            address: SocketAddress::Unix(p),
            ..
        } => p.len(),
        TraceKind::Mount { fstype } => fstype.len(),
        _ => 0,
    };
    strings + 64
}

/// What the reader sends to the job runner.
#[derive(Debug)]
pub enum Batch {
    /// Decoded events.
    Events(Vec<TraceEvent>),
    /// The trace is complete.
    Done(TraceTotals),
}

/// The loaded and attached programs.
pub struct Tracer {
    // Dropping `Ebpf` detaches the programs, so it lives as long as this.
    _ebpf: Ebpf,
    ring: RingBuf<MapData>,
    dropped: PerCpuArray<MapData, u64>,
}

/// Why the programs could not be loaded and attached.
#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    /// The compiled programs cannot be read.
    #[error("{}: {}", OBJECT_PATH, .0)]
    Object(std::io::Error),
    /// The kernel structure offsets are unavailable.
    #[error(transparent)]
    Btf(#[from] BtfError),
    /// The loader refused the programs.
    #[error("load: {}", chain(.0))]
    Load(#[from] EbpfError),
    /// The loader cannot read the kernel's BTF.
    #[error("BTF: {0}")]
    KernelBtf(#[from] AyaBtfError),
    /// The object has no program of this name.
    #[error("no program {0}")]
    NoProgram(&'static str),
    /// The object has no map of this name.
    #[error("no map {0}")]
    NoMap(&'static str),
    /// A program could not be prepared, loaded or attached.
    #[error("{name}: {}", chain(.source))]
    Program {
        /// The program.
        name: &'static str,
        /// The underlying error.
        source: ProgramError,
    },
    /// A map cannot be used.
    #[error("{name}: {source}")]
    Map {
        /// The map.
        name: &'static str,
        /// The underlying error.
        source: MapError,
    },
}

impl TraceError {
    /// For `map_err`: a [`TraceError::Program`] of `name`.
    fn program(name: &'static str) -> impl FnOnce(ProgramError) -> Self {
        move |source| Self::Program { name, source }
    }
}

/// Loads the object with the kernel offsets and the ids of the agent and
/// the builder filled in.
fn load(object: &[u8], builder_uid: u32) -> Result<Ebpf, TraceError> {
    let btf = Btf::from_kernel()?;
    let mut values = Vec::with_capacity(OFFSETS.len());
    for (global, name, member) in OFFSETS {
        values.push((global, btf.offset(name, member)?));
    }
    let agent = rustix::process::getpid()
        .as_raw_nonzero()
        .get()
        .cast_unsigned();
    let mut loader = EbpfLoader::new();
    loader
        .override_global("BUILDER_UID", &builder_uid, true)
        .override_global("AGENT_TGID", &agent, true);
    for (global, value) in &values {
        loader.override_global(global, value, true);
    }
    Ok(loader.load(object)?)
}

/// The program `name` of a loaded object, as the type its kind needs.
fn program<'a, P>(ebpf: &'a mut Ebpf, name: &'static str) -> Result<P, TraceError>
where
    P: TryFrom<&'a mut Program, Error = ProgramError>,
{
    let program = ebpf.program_mut(name).ok_or(TraceError::NoProgram(name))?;
    program.try_into().map_err(TraceError::program(name))
}

/// The map `name` of a loaded object, as the type it is used as.
fn map<M: TryFrom<Map, Error = MapError>>(
    ebpf: &mut Ebpf,
    name: &'static str,
) -> Result<M, TraceError> {
    let map = ebpf.take_map(name).ok_or(TraceError::NoMap(name))?;
    M::try_from(map).map_err(|source| TraceError::Map { name, source })
}

impl std::fmt::Debug for Tracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tracer")
    }
}

impl Tracer {
    /// Loads the programs from [`OBJECT_PATH`] and attaches them. Events of
    /// `builder_uid` and their descendants are traced.
    ///
    /// # Errors
    ///
    /// Describes the step that failed.
    pub fn start(builder_uid: u32) -> Result<Self, TraceError> {
        let object = std::fs::read(OBJECT_PATH).map_err(TraceError::Object)?;
        let mut ebpf = load(&object, builder_uid)?;
        let kernel_btf = AyaBtf::from_sys_fs()?;
        for name in TRACEPOINTS {
            let program: &mut BtfTracePoint = program(&mut ebpf, name)?;
            program
                .load(name, &kernel_btf)
                .map_err(TraceError::program(name))?;
            program.attach().map_err(TraceError::program(name))?;
        }
        for name in LSM_HOOKS {
            let program: &mut Lsm = program(&mut ebpf, name)?;
            program
                .load(name, &kernel_btf)
                .map_err(TraceError::program(name))?;
            program.attach().map_err(TraceError::program(name))?;
        }
        let ring = map(&mut ebpf, "EVENTS")?;
        let dropped = map(&mut ebpf, "DROPPED")?;
        Ok(Self {
            _ebpf: ebpf,
            ring,
            dropped,
        })
    }

    fn dropped_in_kernel(&self) -> u64 {
        self.dropped
            .get(&0, 0)
            .map(|values| values.iter().sum())
            .unwrap_or(0)
    }

    /// Discards records that are already in the ring buffer, so a job's
    /// trace starts empty.
    pub fn clear(&mut self) {
        while self.ring.next().is_some() {}
    }

    /// Reads records until `stop` is set and the ring buffer is empty, and
    /// passes them to `send` in batches, ending with [`Batch::Done`].
    /// `start_ns` is the job's start on `CLOCK_MONOTONIC`. Stops early when
    /// `send` returns false.
    pub fn stream(
        &mut self,
        start_ns: u64,
        stop: &AtomicBool,
        mut send: impl FnMut(Batch) -> bool,
    ) {
        let dropped_before = self.dropped_in_kernel();
        let mut totals = TraceTotals::default();
        let mut sent_bytes = 0_usize;
        let mut batch = Vec::new();
        let mut batch_bytes = 0;
        loop {
            // Read the flag first: records written before it was set are
            // then drained below.
            let stopping = stop.load(Ordering::Acquire);
            let mut read_any = false;
            while let Some(record) = self.ring.next() {
                read_any = true;
                let Some(event) = decode(&record, start_ns) else {
                    totals.malformed += 1;
                    continue;
                };
                let size = estimate(&event);
                if sent_bytes + size > MAX_TRACE_BYTES {
                    totals.dropped_by_agent += 1;
                    continue;
                }
                sent_bytes += size;
                batch_bytes += size;
                totals.events += 1;
                batch.push(event);
                if batch_bytes >= BATCH_BYTES {
                    if !send(Batch::Events(std::mem::take(&mut batch))) {
                        return;
                    }
                    batch_bytes = 0;
                }
            }
            if !batch.is_empty() {
                if !send(Batch::Events(std::mem::take(&mut batch))) {
                    return;
                }
                batch_bytes = 0;
            }
            if stopping && !read_any {
                break;
            }
            if !read_any {
                std::thread::sleep(IDLE);
            }
        }
        totals.dropped_in_kernel = self.dropped_in_kernel().saturating_sub(dropped_before);
        let _ = send(Batch::Done(totals));
    }
}

/// `CLOCK_MONOTONIC` in nanoseconds, the clock of `bpf_ktime_get_ns`.
#[must_use]
pub fn monotonic_ns() -> u64 {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u32, time_ns: u64) -> Vec<u8> {
        let mut r = Vec::new();
        for v in [kind, 100, 101, 1000] {
            r.extend_from_slice(&v.to_le_bytes());
        }
        r.extend_from_slice(&time_ns.to_le_bytes());
        r
    }

    fn exec(filename: &[u8], args: &[u8]) -> Vec<u8> {
        let mut r = header(KIND_EXEC, 5_000_000);
        r.extend_from_slice(&i32::try_from(filename.len()).unwrap().to_le_bytes());
        r.extend_from_slice(&u32::try_from(args.len()).unwrap().to_le_bytes());
        let mut f = filename.to_vec();
        f.resize(FILENAME_LEN, 0);
        r.extend_from_slice(&f);
        let mut a = args.to_vec();
        a.resize(ARGS_LEN, 0);
        r.extend_from_slice(&a);
        r
    }

    #[test]
    fn decodes_exec_with_its_arguments() {
        let record = exec(
            b"/usr/bin/curl",
            b"curl\0-d\0@/work/home/.aws/credentials\0",
        );
        let event = decode(&record, 2_000_000).unwrap();
        assert_eq!(
            (event.ms, event.pid, event.tid, event.uid),
            (3, 100, 101, 1000)
        );
        let TraceKind::Exec { filename, argv } = event.kind else {
            panic!("not an exec");
        };
        assert_eq!(filename, b"/usr/bin/curl");
        assert_eq!(argv, [&b"curl"[..], b"-d", b"@/work/home/.aws/credentials"]);
    }

    #[test]
    fn decodes_sockets_of_each_family() {
        let sock = |addr: &[u8]| {
            let mut r = header(KIND_CONNECT, 0);
            r.extend_from_slice(&1_u32.to_le_bytes());
            r.extend_from_slice(&u32::try_from(addr.len()).unwrap().to_le_bytes());
            let mut a = addr.to_vec();
            a.resize(ADDR_LEN, 0);
            r.extend_from_slice(&a);
            decode(&r, 0).unwrap().kind
        };
        let v4 = [2, 0, 0x01, 0xbb, 10, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            sock(&v4),
            TraceKind::Connect {
                sock_type: 1,
                address: SocketAddress::Ip("10.0.2.1:443".parse().unwrap())
            }
        );
        let mut v6 = vec![10, 0, 0, 53, 0, 0, 0, 0];
        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0; 4]);
        assert!(matches!(
            sock(&v6),
            TraceKind::Connect { address: SocketAddress::Ip(a), .. } if a.to_string() == "[::1]:53"
        ));
        let unix = b"\x01\x00/run/dbus/system_bus_socket\0";
        assert_eq!(
            sock(unix),
            TraceKind::Connect {
                sock_type: 1,
                address: SocketAddress::Unix(b"/run/dbus/system_bus_socket".to_vec())
            }
        );
        let abstract_name = b"\x01\x00\0hidden";
        assert!(matches!(
            sock(abstract_name),
            TraceKind::Connect { address: SocketAddress::Unix(p), .. } if p == b"\0hidden"
        ));
        assert!(matches!(
            sock(&[16, 0, 1, 2]),
            TraceKind::Connect {
                address: SocketAddress::Other(16),
                ..
            }
        ));
    }

    #[test]
    fn decodes_opens_and_rejects_short_or_unknown_records() {
        let mut r = header(KIND_OPEN, 0);
        r.extend_from_slice(&0o101_u32.to_le_bytes());
        let path = b"/work/home/.cargo/credentials.toml\0";
        r.extend_from_slice(&i32::try_from(path.len()).unwrap().to_le_bytes());
        let mut p = path.to_vec();
        p.resize(PATH_LEN, 0);
        r.extend_from_slice(&p);
        assert_eq!(
            decode(&r, 0).unwrap().kind,
            TraceKind::Open {
                path: b"/work/home/.cargo/credentials.toml".to_vec(),
                flags: 0o101
            }
        );
        // Every truncation is refused, never read past.
        for cut in 0..r.len() {
            assert!(decode(&r[..cut], 0).is_none());
        }
        assert!(decode(&header(99, 0), 0).is_none());
        // A length field larger than its buffer is clamped.
        let record = exec(b"/bin/sh", b"sh\0");
        let mut long = record.clone();
        long[24..28].copy_from_slice(&i32::MAX.to_le_bytes());
        long[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&long, 0).is_some());
    }
}
