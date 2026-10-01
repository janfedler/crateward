# 0003: Debian 13 with Ansible, SSH only, no disk encryption

* Status: Accepted
* Date: 2026-09-24, updated 2026-10-01

## Context

The host must be reproducible, minimal, updated without a human and set up
as code. It runs at Hetzner, whose installimage created two md RAID1 arrays
with ext4 over the two HDDs. Firecracker 1.17 validates the host kernels
5.10, 6.1 and 6.18; others "might work".

## Decision

1. **Debian 13 with its stock 6.12 kernel**, configured by the Ansible
   playbooks in `deploy/` and installed from a release bundle with
   `install.sh`. Unattended upgrades install security fixes.
2. **SSH with keys only is the only inbound service.** Passwords and
   keyboard interactive logins are off; the dashboard is reached through an
   SSH tunnel.
3. **ext4 on md RAID1, unencrypted.** Integrity is checked end to end
   instead: blobs are named by their BLAKE3 digest and verified on every
   read, crate files against the index's SHA-256, images against BLAKE3
   manifests, and Postgres runs with data checksums.

## Alternatives

* **NixOS:** not an installation image Hetzner supports.
* **Arch Linux with `linux-lts`:** moves to each new LTS series within
  weeks, faster than Firecracker validates them, and upgrades Postgres
  across major versions.
* **Debian with a self built 6.18:** in the validated matrix, but kernel
  security fixes would no longer come from the distribution.
* **WireGuard in front of SSH:** hides SSH from scanners, but costs a second
  key pair, a client on every admin machine and a setup step that can lock
  the maintainer out. Removed on 2026-10-01.
* **LUKS2 with btrfs raid1:** checksums that repair a bad copy and
  encryption at rest, at the cost of a reinstall.

## Consequences

* 6.12 is outside Firecracker's validated host kernels. The soak test, the
  hourly canaries and a test that guest CPU mitigations are not weaker than
  the host's (`guest_cpu_mitigations_are_not_weaker_than_the_host`)
  compensate. Revisit at every Debian point release.
* SSH faces the whole internet, so OpenSSH security updates matter.
* Replaced or returned disks carry readable data. Secrets stay few, scoped
  and rotatable, and the RUNBOOK wipes both disks before the server is
  cancelled. The threat model lists this as an accepted risk.

## Sources

* Firecracker `docs/kernel-policy.md` and `CHANGELOG.md` (1.17.0)
* Debian kernel list, "Re: Trixie-backports : 6.18 LTS kernel",
  `https://lists.debian.org/debian-kernel/2025/12/msg00176.html`
* Hetzner standard images,
  `https://docs.hetzner.com/robot/dedicated-server/operating-systems/standard-images/`
* `pg_checksums(1)`, PostgreSQL 17
