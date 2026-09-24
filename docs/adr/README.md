# Architecture decision records

Each record captures one decision with real alternatives: the context, the
options, the choice and its consequences. Records are numbered and never
rewritten; a changed decision gets a new record that supersedes the old one.
[0000](0000-template.md) is the template.

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-firecracker-over-cloud-hypervisor-and-cratera.md) | Firecracker directly, not Cloud Hypervisor or cratera | Accepted |
| [0003](0003-guest-agent-now-introspection-later.md) | In guest agent now, agentless introspection later | Accepted |
| [0004](0004-postgres-as-queue.md) | Postgres as the job queue | Accepted |
| [0005](0005-htmx-over-spa.md) | Server rendered HTML with htmx, not a single page app | Accepted |
| [0006](0006-ebpf-over-ptrace.md) | eBPF with aya for guest tracing, not ptrace | Accepted |
| [0007](0007-ansible-on-debian.md) | Ansible on Debian 13, not NixOS or Arch | Accepted |
| [0008](0008-prewarmed-snapshot-and-shared-sccache.md) | Prewarmed base snapshot and read only sccache | Proposed |
| [0009](0009-single-server-with-external-services.md) | One server; GitHub Pages, healthchecks.io and ntfy.sh instead of a VPS | Accepted |
| [0010](0010-smt-off-and-ram-hot-path.md) | SMT disabled and the hot path in RAM | Accepted |
| [0011](0011-guest-kernel-source.md) | Guest kernel from a pinned Amazon Linux 6.18 branch commit | Accepted |
