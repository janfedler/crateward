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
| [0008](0008-prewarmed-snapshot-and-shared-sccache.md) | A warm build cache from replayed dependency builds | Accepted |
| [0009](0009-single-server-with-external-services.md) | One server; GitHub Pages, healthchecks.io and ntfy.sh instead of a VPS | Accepted |
| [0010](0010-smt-off-and-ram-hot-path.md) | SMT disabled and the hot path in RAM | Accepted |
| [0011](0011-guest-kernel-source.md) | Guest kernel from a pinned Amazon Linux 6.18 branch commit | Accepted |
| [0012](0012-rootless-jail.md) | A rootless jail instead of Firecracker's jailer | Accepted |
| [0013](0013-ext4-on-md-raid-without-encryption.md) | ext4 on md RAID1, without disk encryption | Accepted |
| [0014](0014-resolve-fetch-validate.md) | Resolve with Cargo, fetch and validate ourselves, never extract | Accepted |
| [0015](0015-static-analysis-and-triage.md) | Static analysis in a sandboxed child, reports per crate file, rule based triage | Accepted |
| [0016](0016-dynamic-runs-payload-fake-internet-honeytokens.md) | Dynamic runs with payload images, a fake internet per slot and honeytokens | Accepted |
| [0017](0017-ebpf-tracing-in-the-guest.md) | eBPF tracing in the guest | Accepted |
| [0018](0018-frames-the-proxies-do-not-see.md) | Logging frames the proxies do not see | Accepted |
| [0019](0019-scratch-disk-scan.md) | Reading the scratch disk after a run | Accepted |
| [0020](0020-autonomy-breakers-quarantine-canaries-alerts.md) | Autonomy: breakers, quarantine, canaries and alerts | Accepted |
| [0021](0021-explainable-scoring.md) | Explainable scoring, behavior profiles and the review inbox | Accepted |
| [0022](0022-dashboard-and-public-export.md) | The dashboard and the public export | Accepted |
| [0023](0023-host-escape-detection-and-retention.md) | Host escape detection and retention | Accepted |
