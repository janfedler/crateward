# 0013: ext4 on md RAID1, without disk encryption

* Status: Accepted (maintainer decision, 2026-09-24)
* Date: 2026-09-24
* Replaces decision D12 of the M0 plan (LUKS2 with btrfs raid1).

## Context

The server was installed by Hetzner's installimage with three md RAID1
arrays over the two HDDs: `md0` (formerly swap, now unused), `md1`
(`/boot`) and `md2` (`/`, ext4). The M0 plan proposed LUKS2 on each disk
with btrfs raid1 and zstd compression instead, for two reasons: btrfs
checksums let raid1 repair a bad copy from the good one, which matters on a
host without ECC memory, and full disk encryption protects data on disks
that leave the data center.

## Options

1. **Keep ext4 on md RAID1, unencrypted.** No reinstall.
2. **Reinstall with LUKS2 and btrfs raid1** before real data arrives.

## Decision

Option 1, by the maintainer.

## Consequences

* **Integrity.** md RAID1 keeps two copies, and the scheduled `mdcheck`
  timers compare them monthly, but md cannot tell which copy is right when
  they differ, and ext4 checksums only its metadata. Crateward therefore
  checks data end to end itself:
  * the content addressed store names every blob by its BLAKE3 digest and
    verifies the digest on every read;
  * crate files are verified against the SHA-256 from the crates.io index;
  * images carry BLAKE3 manifests verified before use;
  * PostgreSQL data checksums must be enabled (`pg_checksums --enable` on
    the stopped cluster); the Debian cluster was created without them.
* **Confidentiality at rest.** Disks that are replaced or returned when the
  server is cancelled carry readable data: Crateward's own secrets (the
  GitHub deploy key and read token, the ntfy topic, the heartbeat URL),
  crate files, evidence, and undisclosed findings. Mitigations:
  * secrets stay few, scoped (one repository, read only where possible)
    and rotatable, and the RUNBOOK lists how to rotate each one;
  * the RUNBOOK's decommissioning procedure wipes both disks from the
    rescue system before the server is cancelled;
  * undisclosed findings are the most sensitive data at rest; the
    disclosure workflow keeps them short lived.
* **No compression.** Storage use is measured against the 100 to 200 GB
  budget without filesystem compression; blobs are zstd compressed by
  Crateward itself.
* **Remote unlock** is no longer needed, which removes a boot time inbound
  service (and the question in ADR 0009).
* The threat model's requirement of full disk encryption is not met; it is
  listed there as an accepted risk.

## Sources

* `/proc/mdstat`, `findmnt` and `systemctl list-timers` on the server,
  2026-09-24
* `pg_checksums(1)`, PostgreSQL 17 documentation
