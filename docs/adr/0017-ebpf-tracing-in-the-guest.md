# 0017: eBPF tracing in the guest

* Status: Accepted
* Date: 2026-09-25

## Context

ADR 0006 chose eBPF, loaded by the guest agent with aya, to observe a build
from inside the guest. This ADR records how that is built, what is traced
and what the host does with it. The maintainer decided that only the eBPF
programs carry a license (GPL, which the kernel requires); the rest of the
project stays unlicensed for now.

Facts verified on 2026-09-25:

* `bpf-linker` must use the same LLVM as the compiler. Release v0.11.1 was
  built against LLVM 23.1.1, the LLVM of `nightly-2026-09-07`; the release
  notes and its `MODULE.bazel` name that nightly.
* In the pinned 6.18 kernel, `bpf_d_path` is allowed in an LSM program when
  its hook is in the sleepable hook set (`bpf_d_path_allowed` in
  `kernel/trace/bpf_trace.c`); `file_open`, `socket_connect`,
  `socket_sendmsg`, `bpf` and `sb_mount` all are.
* LSM programs attach through BPF trampolines. With
  `CONFIG_FUNCTION_TRACER` off, attaching failed with `EBUSY`; with the
  function tracer, dynamic ftrace and direct calls on, all programs attach.
* aya's BTF type does not expose struct members, so it cannot provide
  field offsets.
* In the canary run, `cargo check` of a small crate produced 485 events,
  none dropped, and the trace showed the build script reading the cargo
  credentials, connecting out and starting `curl`, which read the AWS file.

## Decision

1. **A separate package.** `crates/guest_ebpf` is its own workspace with
   its own lockfile and toolchain file (`nightly-2026-09-07`, `rust-src`).
   It is excluded from the main workspace. `cargo xtask guest-ebpf`
   downloads `bpf-linker` (SHA-256 pinned in `guest/bpf-linker.toml`),
   runs format, clippy and the build, checks that the object's `license`
   section reads `GPL`, and places it at `target/guest/out/guest-ebpf.o`.
   The root filesystem build installs it at
   `/usr/lib/crateward/guest-ebpf.o`. Its license is GPL-2.0-only.
2. **What is traced.**
   * BTF tracepoints `sched_process_fork`, `sched_process_exec` and
     `sched_process_exit`: the process tree (threads are skipped), each
     executed path and the new image's argument vector, read from its own
     memory after the kernel copied it there, and exit codes.
   * LSM hooks `file_open` (path from `bpf_d_path`, open flags),
     `socket_connect` and `socket_sendmsg` (the kernel's copy of the
     destination), and `bpf`, `ptrace_access_check` and `sb_mount` as
     tamper attempts. Every LSM program returns 0: tracing never changes a
     decision.
3. **Which processes.** A process is tracked when it runs as the builder
   user or when a tracked process forked it, so changing the user does not
   end tracking. `bpf` is recorded for every process except the agent.
4. **Kernel offsets from BTF.** The programs read a few fields of kernel
   structures. The agent looks the offsets up in `/sys/kernel/btf/vmlinux`
   with its own small BTF reader (which follows anonymous members) and sets
   them as read only globals before loading, so the verifier sees them as
   constants and the programs follow the guest kernel without a rebuild.
5. **Loaded before the snapshot.** The agent loads and attaches the
   programs at boot. The agent reports the tracing status in `Hello`. The
   orchestrator refuses to take a base snapshot when tracing is
   unavailable, so no dynamic run goes without a trace.
6. **Wire format.** Records in a 16 MiB ring buffer have a fixed layout per
   kind behind a 24 byte header (kind, process, thread, user, time),
   documented in the package. The agent decodes them byte by byte, never
   trusting a length beyond its record, and streams them to the host as
   protocol version 3 `Trace` batches of about 32 KiB, closed by
   `TraceEnd` with counts of sent, dropped and malformed events. The agent
   stops at about 96 MiB per job; the host's connection budget is larger.
7. **Host summary.** The orchestrator builds a bounded summary: up to 2000
   processes with parent, role (cargo, rustc, build script, toolchain,
   other), program and arguments; opens of credentials and other secrets
   (including another process's `/proc/<pid>/environ`, `mem` or `maps`);
   writes outside `/work`, `/tmp` and a few device files; socket
   destinations per process; tamper attempts; processes that ran as root.
   Every byte string is rendered with control and bidirectional characters
   escaped. Honeytoken values found in arguments or paths are listed as
   `tokens_in_trace`. The summary is stored in the run report.

## Consequences

* Building the eBPF programs needs the pinned nightly and `bpf-linker`; CI
  has a separate job for it. The main workspace still builds with the
  stable toolchain alone.
* The guest kernel config gains the function tracer. Its patchable entries
  cost a few bytes per function and nothing measurable at run time.
* The trace is the guest's account. A crate that reaches guest root can
  blind or feed it. It is therefore read next to the host's ground truth
  (the fake internet's log, and the scratch disk once it is examined),
  never instead of it, and a trace without `TraceEnd` is marked incomplete.
* A run that the host kills at its own wall clock has no trace; the
  agent's own timeout is shorter and still sends one.
* Scoring (M6) decides what the summary means. For example, cargo itself
  reading the credentials file is different from a build script doing it,
  which is why each access names its process.

## Revision (2026-09-25, with ADR 0008)

* The user in every record is the effective user of the task's objective
  credentials (`task->real_cred->euid`), not of the subjective ones that
  `bpf_get_current_uid_gid` reads: overlayfs replaces those with its
  mounter's root credentials during a copy up, which made build processes
  look like root. A real change of user shows in both.
* `file_open` skips files the kernel opens for its own use
  (`FMODE_BACKING` and `FMODE_NOACCOUNT` in `f_mode`): overlayfs's backing
  files and copy up temporary files, which would repeat the job's own
  opens under internal paths.

## Sources

* aya `README.md` and aya template, `https://github.com/aya-rs/aya`,
  `https://github.com/aya-rs/aya-template`
* `bpf-linker` v0.11.1 `README.md`, `BUILDING.md`, `MODULE.bazel` and release
  notes, `https://github.com/aya-rs/bpf-linker`
* Linux 6.18: `include/linux/lsm_hook_defs.h`, `include/trace/events/sched.h`,
  `kernel/bpf/bpf_lsm.c`, `kernel/trace/bpf_trace.c`, `kernel/bpf/verifier.c`,
  `Documentation/bpf/btf.rst`, `Documentation/bpf/bpf_licensing.rst`,
  `Documentation/bpf/prog_lsm.rst`
