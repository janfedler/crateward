# Operations

How the server is set up and run.

## Host

| Item | Value |
|------|-------|
| CPU | SMT disabled |
| Memory | no ECC |
| OS | Debian 13, stock 6.12 kernel, unattended upgrades |
| Configuration | Ansible, from this repository |
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
| MicroVMs | `sandbox.memory_mib_per_slot` (4 GiB) per slot |
| Scratch tmpfs | at most `sandbox.scratch_mib_per_slot` (4 GiB) per slot |
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

* Kernel command line in `GRUB_CMDLINE_LINUX_DEFAULT`:
  `nosmt mds=full,nosmt l1tf=full,force kvm_intel.nested=0 kvm_amd.nested=0`.
  Verified: SMT `forceoff`, L1TF "VMX: cache flushes, SMT disabled",
  `kvm_intel.vmentry_l1d_flush=always`.
* Swap disabled and removed from `/etc/fstab`. KSM off.
* Packages: `build-essential bc bison flex libelf-dev libssl-dev dwarves nftables erofs-utils mmdebstrap uidmap musl-tools`.

## Opening the dashboard

The dashboard listens on `127.0.0.1:8080` only (ADR 0009). Open a tunnel
and browse to `http://localhost:8080`:

```sh
ssh -N -L 8080:127.0.0.1:8080 <server>
```

`crateward status` shows the same pipeline state on the command line.

## Archiving job pages

`crateward archive --out <dir>` writes chosen job pages as static files
that need no server: an `index.html` with the aggregate numbers, a page
per job under `jobs/`, and the stylesheet and fonts. A terminal screen
chooses the jobs by level, review, coverage, minimum score, crate name
prefix and a cap per level, and single jobs can be added or left out by
hand. The choice is saved as `selection.json` in the archive.
`--selection <file>` writes from a saved choice without the screen.
Writing into an earlier archive replaces it. A job whose previous version
is archived too gets its comparison with it ([ADR 0011](adr/0011-version-diff-view.md)).

The archive holds only what may be published: verdicts waiting for review
and confirmed findings before their publication are refused
([DISCLOSURE.md](DISCLOSURE.md)). Honeytokens are redacted.

`crateward archive --publish`, as root, puts the chosen reports on the
public site under `reports/` instead, replacing the ones there, and saves
the choice in `/etc/crateward/report-selection.json`. With
`export.reports = true` (asked by `install.sh` on the first install) every
export refreshes them from that choice, so new jobs that match it appear
and reports that may no longer be published disappear. Every export
replaces the site repository's history with a single commit
([ADR 0013](adr/0013-job-reports-on-the-public-site.md)). Before editing
the site repository by hand, fetch and reset to its branch, since a pull
cannot merge a replaced history.

## SBOMs and findings documents

Every finished job gets a CycloneDX SBOM of the crate and its locked
dependencies, and a findings document that points into it
([ADR 0012](adr/0012-cyclonedx-sbom-and-vex.md)). The job page links both,
the archive holds them next to each page, and `crateward sbom <job> --out
<dir>` writes them. The analyzer logs what an SBOM still lacks for
TR-03183-2 as `wrote the SBOM` with `gaps`. Missing SHA-512 hashes and
licences fill in while the fetcher and static analysis are idle, and the
analyzer then replaces the SBOM with its next version.

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
| GitHub Pages (`janfedler/crateward-site`) | public site at crateward.com | deploy key for that repository only, allowed to force push |
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

## Decoys

The decoys in `supervisor.decoys` look like credentials. Backups, indexers
and anything else that reads the home directories must exclude them, or
they raise a sandbox escape indicator.

## Backups

Encrypted offsite backups with tested restores are required. They must
exclude the [decoys](#decoys).
