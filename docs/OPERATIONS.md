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
| `/` | ext4 on md RAID1 (`md2`), unencrypted; monthly `mdcheck` scrub | system, Postgres, content addressed store, evidence, logs, image archive |
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
| Image refresh (Debian packages, toolchain) | weekly, at night |
| Warm build cache | at every orchestrator start (about 13 minutes for 60 replayed jobs; jobs wait meanwhile); stop and start the orchestrator to refresh it |
| Guest kernel rebuild | only when its version or configuration changes |
| Retention | daily |
| Heartbeat | every minute |

## Host setup done by hand (Ansible in M8)

These steps were applied to the production server on 2026-09-24 and are the
specification for the Ansible role.

* Kernel command line: `nosmt mds=full,nosmt l1tf=full,force` in
  `GRUB_CMDLINE_LINUX_DEFAULT`. Verified: SMT `forceoff`, L1TF "VMX: cache
  flushes, SMT disabled", `kvm_intel.vmentry_l1d_flush=always`.
* Swap disabled and removed from `/etc/fstab`; KSM off.
* Packages: `build-essential bc bison flex libelf-dev libssl-dev dwarves nftables erofs-utils mmdebstrap uidmap`.
  Still to install: `musl-tools`, the proper C compiler for the fake
  internet's static build (ring compiles a little C); until then the build
  falls back to the host `gcc`.
* Development user `claude`: groups `kvm` and `systemd-journal`, lingering
  enabled, subordinate IDs `100000:65536`, and
  `/etc/systemd/system/user@1000.service.d/delegate.conf` with
  `Delegate=cpu cpuset io memory pids`.

For production the orchestrator gets its own user (see below) instead of
the development account.

## Services and users

Each component runs as its own system user under systemd with
`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, and a minimal
capability bounding set. Unit files arrive with the milestones that build
the components.

The orchestrator user has requirements of its own (ADR 0012):

* its only supplementary group is `kvm`, because every jailed Firecracker
  keeps the orchestrator's supplementary groups;
* a subordinate UID and GID range in `/etc/subuid` and `/etc/subgid` that
  covers `sandbox.slot_uid_base` plus the number of slots, and that no
  other user shares;
* its unit runs with `Delegate=yes`, so it owns a cgroup subtree for the
  slot limits;
* every other Crateward unit sets `RestrictNamespaces=yes`, since only the
  orchestrator needs unprivileged user namespaces.

## External services

| Service | Purpose | Secret |
|---------|---------|--------|
| GitHub Pages (`janfedler/crateward-site`) | public site at crateward.com | deploy key for that repository only |
| healthchecks.io | dead man's switch | ping URL |
| ntfy.sh | alerts | topic name |

## Backups

Encrypted offsite backups with tested restores are required. The offsite
target is not chosen yet; it is decided with the maintainer before M7.
