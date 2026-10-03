# Architecture decision records

Each record explains one area of the design: the context, what was decided,
the alternatives that lost and the consequences. A reviewer can read them
in order, or start with the four that shape the security of the system:
0002 (the sandbox), 0006 (dynamic runs), 0007 (tracing) and 0008 (autonomy
and escape detection).

Records describe the decision as it stands. When it changes, the record is
updated and says so in its date line. Git keeps the earlier text. Small
changes go in the commit message, not in a record. New records use
[the template](0000-template.md).

| ADR | Decision |
|-----|----------|
| [0001](0001-one-server-postgres-queue.md) | One server, Postgres as the queue, few external services |
| [0002](0002-firecracker-rootless-jail.md) | Firecracker microVMs in a rootless jail |
| [0003](0003-debian-ansible-ssh.md) | Debian 13 with Ansible, SSH only, no disk encryption |
| [0004](0004-resolve-fetch-validate.md) | Resolve with Cargo, fetch and validate ourselves, never extract |
| [0005](0005-static-analysis-and-triage.md) | Static analysis in a sandboxed child, rule based triage |
| [0006](0006-dynamic-runs.md) | Dynamic runs with a fake internet, honeytokens and host side ground truth |
| [0007](0007-guest-agent-ebpf.md) | An agent in the guest that traces with eBPF |
| [0008](0008-autonomy-and-escape-detection.md) | Autonomy and escape detection |
| [0009](0009-scoring-and-dashboard.md) | Explainable scoring and a server rendered dashboard |
| [0010](0010-license.md) | MIT OR Apache-2.0, with GPL-2.0-only for the eBPF programs |
