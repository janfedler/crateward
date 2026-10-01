//! eBPF programs that trace a build inside the guest (ADR 0007).
//!
//! The guest agent loads these programs once at boot, before the base
//! snapshot is taken, so every restored VM starts with them attached. They
//! only observe: every LSM program returns 0 and never changes a decision.
//!
//! # What is traced
//!
//! A process is tracked when it runs as the builder user, or when a tracked
//! process forked it. The second rule keeps a process tracked after it
//! changes its user, for example through a setuid binary or an exploit.
//!
//! * `sched_process_fork`, `sched_process_exec` and `sched_process_exit`
//!   (BTF tracepoints): the process tree, each program's path, and its
//!   argument vector read from the new image's memory after the kernel
//!   copied it there, so another thread cannot change it after the fact.
//! * `file_open` (LSM): every file a tracked process opens, with the path
//!   the kernel resolved and the open flags.
//! * `socket_connect` and `socket_sendmsg` (LSM): destinations, from the
//!   kernel's own copy of the address.
//! * `bpf`, `ptrace_access_check` and `sb_mount` (LSM): attempts to tamper
//!   with the tracing or the guest. `bpf` is recorded for every process
//!   except the agent.
//!
//! # Wire format
//!
//! Every record in the `EVENTS` ring buffer starts with [`Header`]; `kind`
//! selects the layout that follows. All fields are little endian, as the
//! BPF target is. The guest agent decodes these layouts byte by byte
//! (`crateward_guest_agent::trace`), so a change here must change the
//! decoder and the kind numbers together.
//!
//! # Kernel structures
//!
//! The programs read a few fields of kernel structures. Their offsets are
//! not compiled in: the agent looks them up in the running kernel's BTF and
//! sets the `OFF_*` globals before loading, so the programs follow the
//! guest kernel without a rebuild.

#![no_std]
#![no_main]

use core::ptr::{addr_of_mut, read_volatile};

use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel,
    bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf, generated::bpf_d_path,
};
use aya_ebpf::macros::{btf_tracepoint, lsm, map};
use aya_ebpf::maps::{LruHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{BtfTracePointContext, LsmContext};

/// Record kinds.
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
/// Power of two, so a mask bounds the read length for the verifier.
const ARGS_LEN: usize = 1024;
const PATH_LEN: usize = 512;
const ADDR_LEN: usize = 112;
const FSTYPE_LEN: usize = 32;

/// Files the kernel opens for its own use (`include/linux/fs.h`, 6.18):
/// `FMODE_BACKING` for overlayfs's files on the underlying filesystem, and
/// `FMODE_NOACCOUNT` for those and for its copy up temporary files. The
/// open the process made on the overlay is traced; these would only repeat
/// it with internal paths. No open from user space carries either flag.
const FMODE_KERNEL_INTERNAL: u32 = (1 << 24) | (1 << 29);

/// Starts every record. 24 bytes.
#[repr(C)]
struct Header {
    kind: u32,
    /// Process ID (thread group ID) of the current task.
    tgid: u32,
    /// Thread ID of the current task.
    tid: u32,
    /// Effective user ID of the current task, from its objective
    /// credentials.
    uid: u32,
    /// `CLOCK_MONOTONIC` time in nanoseconds.
    time_ns: u64,
}

/// A new process (not a thread). 32 bytes.
#[repr(C)]
struct Fork {
    header: Header,
    child: u32,
    _pad: u32,
}

/// A successful exec. 1312 bytes.
#[repr(C)]
struct Exec {
    header: Header,
    /// Bytes of `filename` used, without the NUL, or a negative error.
    filename_len: i32,
    /// Bytes of `args` used.
    args_len: u32,
    filename: [u8; FILENAME_LEN],
    /// The argument vector, NUL separated, as the new image sees it.
    args: [u8; ARGS_LEN],
}

/// A process ended. 32 bytes.
#[repr(C)]
struct Exit {
    header: Header,
    /// The kernel's exit code: status in bits 8 to 15, signal in 0 to 6.
    exit_code: u32,
    _pad: u32,
}

/// A file was opened. 544 bytes.
#[repr(C)]
struct Open {
    header: Header,
    /// `O_*` flags of the open file.
    flags: u32,
    /// Bytes of `path` used, including the NUL, or a negative error.
    path_len: i32,
    path: [u8; PATH_LEN],
}

/// A connect or a send with an explicit destination. 144 bytes.
#[repr(C)]
struct Sock {
    header: Header,
    /// `SOCK_*` type of the socket.
    sock_type: u32,
    /// Length of the address the caller passed.
    addr_len: u32,
    /// The raw `sockaddr`, family first.
    addr: [u8; ADDR_LEN],
}

/// A `bpf` system call, or a ptrace attempt. 32 bytes.
#[repr(C)]
struct Pair {
    header: Header,
    /// `bpf`: the command. `ptrace`: the target's process ID.
    first: u32,
    /// `ptrace`: the access mode.
    second: u32,
}

/// A mount attempt. 64 bytes.
#[repr(C)]
struct Mount {
    header: Header,
    fstype_len: i32,
    _pad: u32,
    fstype: [u8; FSTYPE_LEN],
}

/// Set by the agent before loading. `#[no_mangle]` keeps the names that
/// the loader looks up; being immutable, they land in `.rodata`, which the
/// verifier treats as constant.
#[unsafe(no_mangle)]
static BUILDER_UID: u32 = u32::MAX;
#[unsafe(no_mangle)]
static AGENT_TGID: u32 = 0;
#[unsafe(no_mangle)]
static OFF_TASK_PID: u32 = 0;
#[unsafe(no_mangle)]
static OFF_TASK_TGID: u32 = 0;
#[unsafe(no_mangle)]
static OFF_TASK_MM: u32 = 0;
#[unsafe(no_mangle)]
static OFF_TASK_EXIT_CODE: u32 = 0;
#[unsafe(no_mangle)]
static OFF_TASK_REAL_CRED: u32 = 0;
#[unsafe(no_mangle)]
static OFF_CRED_EUID: u32 = 0;
#[unsafe(no_mangle)]
static OFF_MM_ARG_START: u32 = 0;
#[unsafe(no_mangle)]
static OFF_MM_ARG_END: u32 = 0;
#[unsafe(no_mangle)]
static OFF_BINPRM_FILENAME: u32 = 0;
#[unsafe(no_mangle)]
static OFF_FILE_PATH: u32 = 0;
#[unsafe(no_mangle)]
static OFF_FILE_FLAGS: u32 = 0;
#[unsafe(no_mangle)]
static OFF_FILE_MODE: u32 = 0;
#[unsafe(no_mangle)]
static OFF_SOCKET_TYPE: u32 = 0;
#[unsafe(no_mangle)]
static OFF_MSGHDR_NAME: u32 = 0;
#[unsafe(no_mangle)]
static OFF_MSGHDR_NAMELEN: u32 = 0;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 << 20, 0);

/// Tracked process IDs.
#[map]
static TRACKED: LruHashMap<u32, u8> = LruHashMap::with_max_entries(65536, 0);

/// Records lost because the ring buffer was full.
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn config(value: &u32) -> u32 {
    // SAFETY: a plain read of an immutable global.
    unsafe { read_volatile(value) }
}

#[inline(always)]
fn config_usize(value: &u32) -> usize {
    config(value) as usize
}

/// The current task's process and thread IDs and effective user ID.
///
/// The user comes from the task's objective credentials (`real_cred`), not
/// from `bpf_get_current_uid_gid`, which reads the subjective ones: the
/// kernel overrides those temporarily, for example overlayfs with its
/// mounter's (root) credentials during a copy up. A real change of user
/// (a set user ID program, or an exploit that commits new credentials)
/// shows in both.
#[inline(always)]
fn current() -> (u32, u32, u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    // SAFETY: the helper returns the current task, valid while the program
    // runs; the reads go through `bpf_probe_read_kernel`.
    let uid = unsafe {
        let task = bpf_get_current_task() as *const u8;
        let cred = field_u64(task, &OFF_TASK_REAL_CRED) as *const u8;
        if cred.is_null() {
            u32::MAX
        } else {
            field_u32(cred, &OFF_CRED_EUID)
        }
    };
    ((pid_tgid >> 32) as u32, pid_tgid as u32, uid)
}

#[inline(always)]
fn is_tracked(tgid: u32, uid: u32) -> bool {
    uid == config(&BUILDER_UID) || unsafe { TRACKED.get(tgid) }.is_some()
}

#[inline(always)]
fn track(tgid: u32) {
    let _ = TRACKED.insert(tgid, 1, 0);
}

#[inline(always)]
fn dropped() {
    if let Some(counter) = DROPPED.get_ptr_mut(0) {
        // SAFETY: a per CPU slot; no other program writes it concurrently.
        unsafe { *counter += 1 };
    }
}

#[inline(always)]
fn header(kind: u32, tgid: u32, tid: u32, uid: u32) -> Header {
    Header {
        kind,
        tgid,
        tid,
        uid,
        // SAFETY: the helper has no preconditions.
        time_ns: unsafe { bpf_ktime_get_ns() },
    }
}

/// Reads a `u32` field of a kernel object.
#[inline(always)]
unsafe fn field_u32(base: *const u8, offset: &u32) -> u32 {
    unsafe { bpf_probe_read_kernel(base.add(config_usize(offset)).cast::<u32>()) }.unwrap_or(0)
}

/// Reads a pointer sized field of a kernel object.
#[inline(always)]
unsafe fn field_u64(base: *const u8, offset: &u32) -> u64 {
    unsafe { bpf_probe_read_kernel(base.add(config_usize(offset)).cast::<u64>()) }.unwrap_or(0)
}

#[btf_tracepoint(function = "sched_process_fork")]
pub fn sched_process_fork(ctx: BtfTracePointContext) -> i32 {
    let (tgid, tid, uid) = current();
    if !is_tracked(tgid, uid) {
        return 0;
    }
    let child: *const u8 = ctx.arg(1);
    // SAFETY: `child` is the new task, valid for the tracepoint's duration.
    let (child_pid, child_tgid) = unsafe {
        (
            field_u32(child, &OFF_TASK_PID),
            field_u32(child, &OFF_TASK_TGID),
        )
    };
    // A new thread belongs to a tracked process already.
    if child_pid != child_tgid {
        return 0;
    }
    track(child_pid);
    match EVENTS.reserve::<Fork>(0) {
        Some(mut entry) => {
            entry.write(Fork {
                header: header(KIND_FORK, tgid, tid, uid),
                child: child_pid,
                _pad: 0,
            });
            entry.submit(0);
        }
        None => dropped(),
    }
    0
}

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> i32 {
    let (tgid, tid, uid) = current();
    if !is_tracked(tgid, uid) {
        return 0;
    }
    track(tgid);
    let task: *const u8 = ctx.arg(0);
    let bprm: *const u8 = ctx.arg(2);
    let Some(mut entry) = EVENTS.reserve::<Exec>(0) else {
        dropped();
        return 0;
    };
    let record = entry.as_mut_ptr();
    // SAFETY: `record` points to a reserved entry of the right size; the
    // kernel pointers are the tracepoint's arguments.
    unsafe {
        addr_of_mut!((*record).header).write(header(KIND_EXEC, tgid, tid, uid));
        let filename = field_u64(bprm, &OFF_BINPRM_FILENAME) as *const u8;
        let buffer = &mut *addr_of_mut!((*record).filename);
        let filename_len = match bpf_probe_read_kernel_str_bytes(filename, buffer) {
            Ok(bytes) => bytes.len() as i32,
            Err(error) => error,
        };
        addr_of_mut!((*record).filename_len).write(filename_len);

        let mm = field_u64(task, &OFF_TASK_MM) as *const u8;
        let start = field_u64(mm, &OFF_MM_ARG_START);
        let end = field_u64(mm, &OFF_MM_ARG_END);
        let mut len = end.saturating_sub(start) as usize;
        if len > ARGS_LEN - 1 {
            len = ARGS_LEN - 1;
        }
        let len = len & (ARGS_LEN - 1);
        let args = &mut *addr_of_mut!((*record).args);
        let read = match args.get_mut(..len) {
            Some(target) if len > 0 => bpf_probe_read_user_buf(start as *const u8, target).is_ok(),
            _ => false,
        };
        addr_of_mut!((*record).args_len).write(if read { len as u32 } else { 0 });
    }
    entry.submit(0);
    0
}

#[btf_tracepoint(function = "sched_process_exit")]
pub fn sched_process_exit(ctx: BtfTracePointContext) -> i32 {
    let (tgid, tid, uid) = current();
    // Only the end of a whole process, not of each thread.
    let group_dead: u64 = ctx.arg(1);
    if group_dead & 0xff == 0 || !is_tracked(tgid, uid) {
        return 0;
    }
    let task: *const u8 = ctx.arg(0);
    // SAFETY: `task` is the exiting task.
    let exit_code = unsafe { field_u32(task, &OFF_TASK_EXIT_CODE) };
    match EVENTS.reserve::<Exit>(0) {
        Some(mut entry) => {
            entry.write(Exit {
                header: header(KIND_EXIT, tgid, tid, uid),
                exit_code,
                _pad: 0,
            });
            entry.submit(0);
        }
        None => dropped(),
    }
    0
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    let (tgid, tid, uid) = current();
    if !is_tracked(tgid, uid) {
        return 0;
    }
    let file: *const u8 = ctx.arg(0);
    // SAFETY: `file` is the hook's argument.
    if unsafe { field_u32(file, &OFF_FILE_MODE) } & FMODE_KERNEL_INTERNAL != 0 {
        return 0;
    }
    let Some(mut entry) = EVENTS.reserve::<Open>(0) else {
        dropped();
        return 0;
    };
    let record = entry.as_mut_ptr();
    // SAFETY: `record` is a reserved entry; `file` is the hook's argument,
    // and `file + OFF_FILE_PATH` is its `f_path` member, which the verifier
    // checks against the kernel's BTF before `bpf_d_path` may use it.
    unsafe {
        addr_of_mut!((*record).header).write(header(KIND_OPEN, tgid, tid, uid));
        addr_of_mut!((*record).flags).write(field_u32(file, &OFF_FILE_FLAGS));
        let path = file.add(config_usize(&OFF_FILE_PATH));
        let buffer = addr_of_mut!((*record).path).cast::<i8>();
        let len = bpf_d_path(path as *mut _, buffer, PATH_LEN as u32);
        addr_of_mut!((*record).path_len).write(len as i32);
    }
    entry.submit(0);
    0
}

/// Records a socket destination from a kernel copy of a `sockaddr`.
#[inline(always)]
fn socket_event(kind: u32, socket: *const u8, address: *const u8, addr_len: u32) {
    let (tgid, tid, uid) = current();
    let Some(mut entry) = EVENTS.reserve::<Sock>(0) else {
        dropped();
        return;
    };
    let record = entry.as_mut_ptr();
    // SAFETY: `record` is a reserved entry; the kernel pointers come from
    // the hook's arguments.
    unsafe {
        addr_of_mut!((*record).header).write(header(kind, tgid, tid, uid));
        let sock_type =
            bpf_probe_read_kernel(socket.add(config_usize(&OFF_SOCKET_TYPE)).cast::<u16>())
                .unwrap_or(0);
        addr_of_mut!((*record).sock_type).write(u32::from(sock_type));
        addr_of_mut!((*record).addr_len).write(addr_len);
        let addr = &mut *addr_of_mut!((*record).addr);
        addr.fill(0);
        let mut len = addr_len as usize;
        if len > ADDR_LEN {
            len = ADDR_LEN;
        }
        if let Some(target) = addr.get_mut(..len)
            && len > 0
        {
            let _ = aya_ebpf::helpers::bpf_probe_read_kernel_buf(address, target);
        }
    }
    entry.submit(0);
}

#[lsm(hook = "socket_connect")]
pub fn socket_connect(ctx: LsmContext) -> i32 {
    let (tgid, _, uid) = current();
    if !is_tracked(tgid, uid) {
        return 0;
    }
    let socket: *const u8 = ctx.arg(0);
    let address: *const u8 = ctx.arg(1);
    let addr_len: u64 = ctx.arg(2);
    socket_event(KIND_CONNECT, socket, address, addr_len as u32);
    0
}

#[lsm(hook = "socket_sendmsg")]
pub fn socket_sendmsg(ctx: LsmContext) -> i32 {
    let (tgid, _, uid) = current();
    if !is_tracked(tgid, uid) {
        return 0;
    }
    let socket: *const u8 = ctx.arg(0);
    let message: *const u8 = ctx.arg(1);
    // SAFETY: `message` is the hook's `struct msghdr`, a kernel copy.
    let (name, name_len) = unsafe {
        (
            field_u64(message, &OFF_MSGHDR_NAME),
            field_u32(message, &OFF_MSGHDR_NAMELEN),
        )
    };
    // Sends on a connected socket carry no address; the connect was
    // recorded already.
    if name != 0 && name_len != 0 {
        socket_event(KIND_SEND, socket, name as *const u8, name_len);
    }
    0
}

#[inline(always)]
fn pair_event(kind: u32, first: u32, second: u32) {
    let (tgid, tid, uid) = current();
    match EVENTS.reserve::<Pair>(0) {
        Some(mut entry) => {
            entry.write(Pair {
                header: header(kind, tgid, tid, uid),
                first,
                second,
            });
            entry.submit(0);
        }
        None => dropped(),
    }
}

#[lsm(hook = "bpf")]
pub fn bpf(ctx: LsmContext) -> i32 {
    let (tgid, _, _) = current();
    let kernel: u64 = ctx.arg(3);
    // Everyone but the agent, whether tracked or not: after boot, nothing
    // else in the guest has a reason to use BPF.
    if tgid != config(&AGENT_TGID) && kernel & 0xff == 0 {
        let cmd: u64 = ctx.arg(0);
        pair_event(KIND_BPF, cmd as u32, 0);
    }
    0
}

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    let (tgid, _, uid) = current();
    if is_tracked(tgid, uid) {
        let child: *const u8 = ctx.arg(0);
        let mode: u64 = ctx.arg(1);
        // SAFETY: `child` is the hook's target task.
        let target = unsafe { field_u32(child, &OFF_TASK_TGID) };
        pair_event(KIND_PTRACE, target, mode as u32);
    }
    0
}

#[lsm(hook = "sb_mount")]
pub fn sb_mount(ctx: LsmContext) -> i32 {
    let (tgid, tid, uid) = current();
    if !is_tracked(tgid, uid) {
        return 0;
    }
    let fstype: *const u8 = ctx.arg(2);
    let Some(mut entry) = EVENTS.reserve::<Mount>(0) else {
        dropped();
        return 0;
    };
    let record = entry.as_mut_ptr();
    // SAFETY: `record` is a reserved entry; `fstype` is a kernel string or
    // null, which the helper reports as an error.
    unsafe {
        addr_of_mut!((*record).header).write(header(KIND_MOUNT, tgid, tid, uid));
        addr_of_mut!((*record)._pad).write(0);
        let buffer = &mut *addr_of_mut!((*record).fstype);
        let len = match bpf_probe_read_kernel_str_bytes(fstype, buffer) {
            Ok(bytes) => bytes.len() as i32,
            Err(error) => error,
        };
        addr_of_mut!((*record).fstype_len).write(len);
    }
    entry.submit(0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

/// The kernel reads the license from this section. See the package's
/// `license` field for why it is GPL.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

// Size checks for the wire format above.
const _: () = assert!(size_of::<Header>() == 24);
const _: () = assert!(size_of::<Fork>() == 32);
const _: () = assert!(size_of::<Exec>() == 32 + FILENAME_LEN + ARGS_LEN);
const _: () = assert!(size_of::<Exit>() == 32);
const _: () = assert!(size_of::<Open>() == 32 + PATH_LEN);
const _: () = assert!(size_of::<Sock>() == 32 + ADDR_LEN);
const _: () = assert!(size_of::<Pair>() == 32);
const _: () = assert!(size_of::<Mount>() == 32 + FSTYPE_LEN);
