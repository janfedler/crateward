# 0007: An agent in the guest that traces with eBPF

* Status: Accepted
* Date: 2026-09-24, updated 2026-09-25

## Context

Dynamic analysis must see which processes a build starts, which files they
open and where they connect, including processes that detach or
daemonize. `rustc` makes many system calls, and only three vCPUs run VMs,
so overhead matters.

## Decision

1. **An agent in the guest**, a static musl binary that runs the job as an
   unprivileged user and streams events over vsock. The trace source is a
   trait, so host side introspection can be added later.
2. **eBPF programs, loaded with aya**, in their own package
   (`crateward_guest_ebpf`) with a pinned nightly and `bpf-linker`:
   * tracepoints for fork, exec (path and argument vector) and exit;
   * LSM hooks `file_open`, `socket_connect` and `socket_sendmsg`, plus
     `bpf`, `ptrace_access_check` and `sb_mount` as tamper attempts. Every
     hook returns 0: tracing never changes a decision.
3. **Who is traced:** the builder user and everything it forks, so a change
   of user does not end tracking. The user comes from the task's objective
   credentials, which overlayfs does not swap during a copy up.
4. **Kernel offsets from BTF.** The agent reads the few structure offsets
   the programs need from `/sys/kernel/btf/vmlinux` with its own small BTF
   reader and sets them as constants before loading.
5. **Loaded before the snapshot.** The orchestrator refuses to take a base
   snapshot without working tracing, so no dynamic run goes untraced.
6. **Hostile bytes.** The agent decodes ring buffer records byte by byte,
   never trusting a length beyond its record; the host treats the whole
   stream as hostile and keeps a bounded summary: processes with their
   roles, sensitive opens, writes outside the build, sockets, tamper
   attempts and honeytokens seen in arguments or paths.

## Alternatives

* **Agentless introspection** from the hypervisor: Firecracker has no API
  for guest memory or vCPU state; it would mean patching the VMM.
* **ptrace:** follows only descendants, is visible to the tracee
  (`TracerPid`), races with threads that change arguments after the read,
  and stops the tracee on every event.

## Consequences

* The trace is the guest's account. A crate that reaches guest root can
  blind it, so it is always read next to the host's ground truth (ADR
  0006), and a trace without its end marker is marked incomplete.
* LSM programs call helpers the kernel reserves for GPL compatible code, so
  `crateward_guest_ebpf` is `GPL-2.0-only` (ADR 0010).
* The guest kernel needs BTF, `CONFIG_BPF_LSM` and the function tracer
  (LSM programs attach through trampolines).
* In the canary run, `cargo check` of a small crate produced 485 events,
  none dropped, and showed the build script reading the cargo
  credentials, connecting out and starting `curl`.

## Sources

* aya `README.md` and template, `https://github.com/aya-rs/aya`
* `bpf-linker` v0.11.1 release notes, `https://github.com/aya-rs/bpf-linker`
* Linux 6.18 `include/linux/lsm_hook_defs.h`, `kernel/trace/bpf_trace.c`,
  `Documentation/bpf/btf.rst`, `bpf_licensing.rst`, `prog_lsm.rst`
* Firecracker `src/firecracker/swagger/firecracker.yaml`
