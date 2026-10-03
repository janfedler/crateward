# Operations

How the server is set up and run. Values marked "target" become measured
numbers during milestone M7.

## Host

| Item | Value |
|------|-------|
| CPU | SMT disabled |
| Memory | no ECC |
| OS | Debian 13, stock 6.12 kernel, unattended upgrades |
| Configuration | Ansible, from this repository (M1 and M8) |
| Admin access | SSH with keys only ([ADR 0003](adr/0003-debian-ansible-ssh.md)) |

Kernel command line additions: `nosmt`, `mds=full,nosmt` and
`l1tf=full,force` (see [ADR 0002](adr/0002-firecracker-rootless-jail.md)).
KSM disabled, no swap.

## Storage layout

| Mount | Medium | Contents |
|-------|--------|----------|
| `/boot` | md RAID1 | kernel and initramfs |
| `/` | ext4 on md RAID1, unencrypted. Monthly `mdcheck` scrub | system, Postgres, content addressed store, evidence, logs, image archive |
| `/run/crateward` | tmpfs, capped at the images, the scratch disks and the snapshot together | the base snapshot, the warm image, per job payload and scratch images, the slot jails, the fetcher's and the export's work directories |

PostgreSQL clusters are created with data checksums enabled.

## Memory budget

| Consumer | Target |
|----------|--------|
| Host services and Postgres | about 12 GiB |
| Image tmpfs | 14 GiB |
| MicroVMs | 3 × 4 GiB |
| Scratch tmpfs | 3 × 4 GiB cap |
| Headroom and page cache | the rest |

## Capacity

One VM slot of one vCPU per core, with one core left for the host
(`sandbox.slots`, `sandbox.vcpus_per_slot`). Static analysis runs on every
version.
Dynamic analysis runs by priority, and jobs that wait longer than
`triage.dynamic_deadline_hours` are scored as static only. The dashboard
publishes the share of versions with dynamic results.

## Schedules

| Task | When |
|------|------|
| RSS poll | every 2 minutes |
| Database dump (`crateward-db-dump.timer`, to `/var/backups/crateward`) | daily |
| Egress allowlist refresh (`crateward-egress.timer`) | every 2 minutes |
| Canaries | hourly |
| Image refresh: `cargo xtask bump-debian-snapshot`, rootfs build, canary, release, deploy ([ADR 0002](adr/0002-firecracker-rootless-jail.md)) | weekly, by the maintainer |
| Warm build cache | at every orchestrator start. Stop and start the orchestrator to refresh it |
| Guest kernel rebuild | only when its version or configuration changes |
| Retention: trim up to 500 run reports older than `storage.raw_log_retention_days` | every `supervisor.interval_secs` (30) |
| Integrity manifest check | every `supervisor.integrity_interval_minutes` (60) |

## Host setup

`deploy/ansible/site.yml` encodes these steps, with everything else a fresh
server needs. See [deploy/README.md](../deploy/README.md).

* Kernel command line: `nosmt mds=full,nosmt l1tf=full,force` in
  `GRUB_CMDLINE_LINUX_DEFAULT`. Verified: SMT `forceoff`, L1TF "VMX: cache
  flushes, SMT disabled", `kvm_intel.vmentry_l1d_flush=always`.
* Swap disabled and removed from `/etc/fstab`. KSM off.
* Packages: `build-essential bc bison flex libelf-dev libssl-dev dwarves nftables erofs-utils mmdebstrap uidmap musl-tools`.

## Opening the dashboard

The dashboard listens on `127.0.0.1:8080` only (ADR 0009). Open a tunnel
and browse to `http://localhost:8080`:

```sh
ssh -N -L 8080:127.0.0.1:8080 <server>
```

`crateward status` shows the same pipeline state on the command line.

## Services and users

Each component runs as its own system user (`crateward-feed`,
`crateward-fetcher` and so on, all in the group `crateward`) under systemd
with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, no
capabilities and `UMask=0027`. The units are in `deploy/systemd`. All
score "OK" in `systemd-analyze security`. All users reach PostgreSQL over
the socket as the one role `crateward`, through a peer map.

The orchestrator user has requirements of its own (ADR 0002):

* Its only supplementary group is `kvm`, because every jailed Firecracker
  keeps the orchestrator's supplementary groups.
* A subordinate UID and GID range in `/etc/subuid` and `/etc/subgid` that
  covers `sandbox.slot_uid_base` plus the number of slots, and that no
  other user shares.
* Its unit runs with `Delegate=yes`, so it owns a cgroup subtree for the
  slot limits.
* It keeps `NoNewPrivileges` off, because `newuidmap` and `newgidmap` are
  setuid programs.

The fetcher and the static analysis create user and network namespaces for
their sandboxed children, so their units allow exactly those two. Every
other unit sets `RestrictNamespaces=yes`.

## External services

| Service | Purpose | Secret |
|---------|---------|--------|
| GitHub Pages (`janfedler/crateward-site`) | public site at crateward.com | deploy key for that repository only |
| ntfy.sh | alerts | topic name |

## Deploying a new build

1. `cargo xtask release` builds the release bundle and its tarball. Sign
   `SHA256SUMS` and run `cargo xtask pack` ([deploy/README.md](../deploy/README.md)).
2. `./install.sh` in the unpacked bundle verifies it, runs
   `deploy/ansible/site.yml` on the server, records the integrity manifest
   and restarts the services whose binaries or configuration changed.
   `./install.sh uninstall` removes the software again and keeps the state.

By hand, the same steps are: install the binaries next to each other,
restart the services, and record the manifest with
`crateward integrity --config /etc/crateward/crateward.toml record`.
Without the manifest the supervisor quarantines the pipeline within
`supervisor.integrity_interval_minutes`, since the binaries changed. The
orchestrator finishes its running jobs after SIGTERM. `systemctl restart`
waits for it, and a second orchestrator refuses to start while the first
holds `orchestrator.lock` in `sandbox.slots_dir`.

The decoys in `supervisor.decoys` look like credentials. Backups, indexers
and anything else that reads the home directories must exclude them, or
they raise a sandbox escape indicator.

## Backups

Encrypted offsite backups with tested restores are required. Backups must
exclude the decoys listed in `supervisor.decoys`.
