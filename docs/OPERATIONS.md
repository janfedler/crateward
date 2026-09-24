# Operations

How the server is set up and run. Values marked "target" become measured
numbers during milestone M7.

## Host

| Item | Value |
|------|-------|
| Provider | Hetzner dedicated server |
| CPU | Intel Core i7-7700, SMT disabled (4 cores in use) |
| Memory | 64 GiB, no ECC |
| Disks | 2 × 2 TB enterprise HDD |
| OS | Debian 13, stock 6.12 kernel, unattended upgrades |
| Configuration | Ansible, from this repository (M1 and M8) |
| Admin access | WireGuard on one UDP port, SSH with keys only over WireGuard |

Kernel command line additions: `nosmt`, `mds=full,nosmt` and
`l1tf=full,force` (see [ADR 0010](adr/0010-smt-off-and-ram-hot-path.md)).
KSM disabled, no swap.

## Storage layout

| Mount | Medium | Contents |
|-------|--------|----------|
| `/boot` | md RAID1 | kernel and initramfs |
| `/` | LUKS2 on each disk, btrfs raid1, `compress=zstd:1`, `noatime` | system, Postgres, content addressed store, evidence, logs, image archive |
| `/run/crateward/images` | tmpfs, 14 GiB | promoted images |
| `/run/crateward/scratch` | tmpfs, capped | per job scratch disks |

PostgreSQL clusters are created with data checksums enabled.

## Memory budget

| Consumer | Target |
|----------|--------|
| Host services and Postgres | about 12 GiB |
| Image tmpfs | 14 GiB |
| MicroVMs | 3 × 4 GiB |
| Scratch tmpfs | 3 × 4 GiB cap |
| Headroom and page cache | the rest |

`sandbox.host_memory_budget_mib` enforces the sandbox part at startup.

## Storage budget

Target 100 to 200 GB in steady state. Measured values replace the targets in
M7.

| Item | Target |
|------|--------|
| Content addressed store (zstd) | to be measured |
| Behavior profiles and diffs | to be measured |
| Raw logs (flagged runs, plus 7 days of the rest) | to be measured |
| Image archive (last two promoted versions) | to be measured |
| Postgres | to be measured |
| Database dump (latest only, streamed) | to be measured |

## Capacity

Three VM slots of one vCPU each. Static analysis runs on every version;
dynamic analysis runs by priority, and jobs that wait longer than
`triage.dynamic_deadline_hours` are scored as static only. The dashboard
publishes the share of versions with dynamic results.

## Schedules

| Task | When |
|------|------|
| RSS poll | every 2 minutes |
| Database dump | daily |
| Canaries | hourly |
| Image refresh (Debian packages, toolchain, warm set) | weekly, at night; dynamic stage paused while the warmer runs |
| Guest kernel rebuild | only when its version or configuration changes |
| Retention | daily |
| Heartbeat | every minute |

## Services and users

Each component runs as its own system user under systemd with
`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, and a minimal
capability bounding set. Unit files arrive with the milestones that build
the components.

## External services

| Service | Purpose | Secret |
|---------|---------|--------|
| GitHub Pages (`janfedler/crateward-site`) | public site at crateward.com | deploy key for that repository only |
| healthchecks.io | dead man's switch | ping URL |
| ntfy.sh | alerts | topic name |

## Backups

Encrypted offsite backups with tested restores are required. The offsite
target is not chosen yet; it is decided with the maintainer before M7.
