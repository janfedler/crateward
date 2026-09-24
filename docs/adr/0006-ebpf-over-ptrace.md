# 0006: eBPF with aya for guest tracing, not ptrace

* Status: Accepted (maintainer decision, 2026-09-24)
* Date: 2026-09-24

## Context

The guest agent must record process starts, file access, network attempts
and selected system calls of a build, including every process a build script
spawns, detaches or daemonizes. `rustc` makes many system calls, so overhead
matters on a server with three vCPUs for VMs.

## Options

1. **eBPF** programs attached to tracepoints and LSM hooks, loaded by the
   agent with the `aya` library.
2. **ptrace**, optionally combined with seccomp user notification to stop
   only on selected system calls.

## Decision

Option 1. The eBPF programs live in a separate package,
`crateward_guest_ebpf`, added in M4.

## Rationale

* **Coverage.** eBPF observes the whole guest. ptrace follows only the
  descendants of the traced process.
* **Visibility to the tracee.** A traced process can see its tracer (for
  example through `TracerPid` in `/proc/self/status`) and behave harmlessly.
  eBPF programs are not visible to an unprivileged process; crate code runs
  unprivileged.
* **Correct arguments.** System call arguments read at a tracepoint can be
  changed by another thread after the read (a time of check to time of use
  race). LSM hooks see the objects the kernel actually resolved.
* **Overhead.** ptrace stops the tracee on every traced event; eBPF runs in
  the kernel without a context switch.
* **Rust only.** aya is written in Rust and, per its README, "does not rely
  on libbpf nor bcc"; with BTF and musl linking it produces a self contained
  binary. That keeps the guest agent a static musl binary.

## Consequences

* Building the eBPF programs needs a pinned nightly toolchain with `rust-src`
  and `bpf-linker`, as the aya template documents. The package is excluded
  from default workspace builds and built by xtask.
* The guest kernel needs BPF, BTF and `CONFIG_BPF_LSM` (which depends on
  `BPF_EVENTS`, `BPF_SYSCALL`, `SECURITY` and `BPF_JIT`), with `bpf` in the
  active LSM list (`CONFIG_LSM` or the `lsm=` boot parameter).
* **Licensing.** The kernel documentation on BPF licensing states that LSM
  BPF programs implicitly call "GPL only" functions and must be GPL
  compatible. `crateward_guest_ebpf` therefore needs a GPL compatible
  license, independent of the license the maintainer chooses for the rest
  of the project.
* A crate that reaches guest root could unload or blind the programs. Host
  ground truth (tap capture, disk diff) covers that case
  ([ADR 0003](0003-guest-agent-now-introspection-later.md)).

## Sources

* aya `README.md`, `https://github.com/aya-rs/aya`; aya template
  `README.md` (prerequisites), `https://github.com/aya-rs/aya-template`
* Linux `Documentation/bpf/bpf_licensing.rst`, `Documentation/bpf/prog_lsm.rst`,
  `kernel/bpf/Kconfig` (`BPF_LSM`), `security/Kconfig` (`LSM`)
