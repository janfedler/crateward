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
| `/run/crateward` | tmpfs, capped at the images, the scratch disks and the snapshot together (31 GiB) | the base snapshot, the warm image, per job payload and scratch images, the slot jails, the fetcher's and the export's work directories |

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

Target 100 to 200 GB in steady state. Measured on 2026-09-25 over the first
live day: 2266 versions fetched, 734 dynamic runs, feed database of 190 MB.
The rates below are per 1000 versions, from the two busiest hours (1466
versions).

| Item | Measured | Per 1000 versions |
|------|----------|-------------------|
| Content addressed store (zstd), crate files and their dependencies | 1.7 GB | about 540 MB; falls as dependencies repeat |
| Original `.crate` files | 616 MB | about 300 MB |
| Postgres, all tables | 190 MB | about 85 MB |
| of which fetch records (lockfile and resolution) | 70 MB | 31 MB |
| of which run reports, before trimming | 24 MB | 48 kB per run, up to 255 kB |
| of which static reports | 14 MB | 6 MB |
| Behavior profiles and diffs | inside the run reports and verdicts | |
| Guest image versions (current and previous) | about 800 MB each | |
| Database dump (latest only, streamed) | about the database size, compressed | |

Retention trims the raw part of unflagged run reports (the process list
and the output tails, 87 percent of the stored reports) after
`storage.raw_log_retention_days`. The blob store and the originals have no
retention yet: at the first day's rate they grow by about 0.85 GB per 1000
versions, which reaches the target within months. Deduplication will lower
the rate; how far is measured again after a week. Pruning originals that
the blob store already holds is a decision for the maintainer.

## Capacity

Three VM slots of one vCPU each. Static analysis runs on every version;
dynamic analysis runs by priority, and jobs that wait longer than
`triage.dynamic_deadline_hours` are scored as static only. The dashboard
publishes the share of versions with dynamic results.

## Schedules

| Task | When |
|------|------|
| RSS poll | every 2 minutes |
| Database dump (`crateward-db-dump.timer`, to `/var/backups/crateward`) | daily |
| Egress allowlist refresh (`crateward-egress.timer`) | every 2 minutes |
| Canaries | hourly |
| Image refresh: `cargo xtask bump-debian-snapshot`, rootfs build, canary, release, deploy ([ADR 0024](adr/0024-guest-image-versions-and-rollback.md)) | weekly, by the maintainer |
| Warm build cache | at every orchestrator start (about 13 minutes for 60 replayed jobs; jobs wait meanwhile); stop and start the orchestrator to refresh it |
| Guest kernel rebuild | only when its version or configuration changes |
| Retention: trim up to 500 run reports older than `storage.raw_log_retention_days` | every supervisor round |
| Integrity manifest check | every `supervisor.integrity_interval_minutes` (60) |
| Heartbeat | every minute |

## Host setup

These steps were applied to the production server by hand on 2026-09-24.
`deploy/ansible/site.yml` now encodes them, with everything else a fresh
server needs; see [deploy/README.md](../deploy/README.md).

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

## Opening the dashboard

The dashboard listens on `127.0.0.1:8080` only (ADR 0022). With WireGuard
up, open a tunnel and browse to `http://localhost:8080`:

```sh
ssh -N -L 8080:127.0.0.1:8080 <server>
```

`crateward status` shows the same pipeline state on the command line.

## Services and users

Each component runs as its own system user (`crateward-feed`,
`crateward-fetcher` and so on, all in the group `crateward`) under systemd
with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, no
capabilities and `UMask=0027`. The units are in `deploy/systemd`; all
score "OK" in `systemd-analyze security`. All users reach PostgreSQL over
the socket as the one role `crateward`, through a peer map.

The orchestrator user has requirements of its own (ADR 0012):

* its only supplementary group is `kvm`, because every jailed Firecracker
  keeps the orchestrator's supplementary groups;
* a subordinate UID and GID range in `/etc/subuid` and `/etc/subgid` that
  covers `sandbox.slot_uid_base` plus the number of slots, and that no
  other user shares;
* its unit runs with `Delegate=yes`, so it owns a cgroup subtree for the
  slot limits;
* it keeps `NoNewPrivileges` off, because `newuidmap` and `newgidmap` are
  setuid programs.

The fetcher and the static analysis create user and network namespaces for
their sandboxed children, so their units allow exactly those two; every
other unit sets `RestrictNamespaces=yes`.

## External services

| Service | Purpose | Secret |
|---------|---------|--------|
| GitHub Pages (`janfedler/crateward-site`) | public site at crateward.com | deploy key for that repository only |
| healthchecks.io | dead man's switch | ping URL |
| ntfy.sh | alerts | topic name |

## Deploying a new build

1. `cargo xtask release` builds the release bundle.
2. `ansible-playbook -i inventory.yml deploy/ansible/site.yml -e @vars.yml`
   installs it, records the integrity manifest and restarts the services
   whose binaries or configuration changed.

By hand, the same steps are: install the binaries next to each other,
restart the services, and record the manifest with
`crateward integrity --config /etc/crateward/crateward.toml record`.
Without the manifest the supervisor quarantines the pipeline within
`supervisor.integrity_interval_minutes`, since the binaries changed. The
orchestrator finishes its running jobs after SIGTERM; `systemctl restart`
waits for it, and a second orchestrator refuses to start while the first
holds `orchestrator.lock` in `sandbox.slots_dir`.

The decoys in `supervisor.decoys` look like credentials. Backups, indexers
and anything else that reads the home directories must exclude them, or
they raise a sandbox escape indicator.

## Backups

Encrypted offsite backups with tested restores are required. The offsite
target is not chosen yet; it waits for the maintainer's decision. Backups
must exclude the decoys listed in `supervisor.decoys`.
