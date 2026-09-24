# 0007: Ansible on Debian 13, not NixOS or Arch

* Status: Accepted (maintainer decision, 2026-09-24)
* Date: 2026-09-24

## Context

The host must be reproducible, minimal, updated unattended, and set up as
code. It runs at Hetzner. Firecracker 1.17 validates three host kernels:
5.10, 6.1 and 6.18. Other kernels "might work" but are not validated.

## Options

1. **NixOS.** Declarative, atomic rollback, trivial to pin kernel 6.18.
   Rejected by the maintainer: Hetzner does not officially support it as an
   installation image.
2. **Arch Linux with `linux-lts`.** A Hetzner standard image; `linux-lts` has
   carried 6.18 since late 2025. Rejected: `linux-lts` moves to each new LTS
   series within weeks, while Firecracker added 6.18 host support months
   after its release, and rolling upgrades include PostgreSQL major versions
   that need `pg_upgrade`.
3. **Debian 13 with a self built 6.18 kernel.** In the validated matrix, but
   kernel security updates would no longer arrive through the distribution.
   Debian does not package 6.18 as a separate long term series for trixie;
   the kernel team stated that trixie backports follow testing.
4. **Debian 12 with its stock 6.1 kernel.** Validated, but Debian 12 is
   already in its LTS phase and Firecracker may deprecate 6.1 on the host.
5. **Debian 13 with its stock 6.12 kernel.**

## Decision

Option 5, configured with Ansible. The maintainer accepted that 6.12 is
outside Firecracker's validated host kernel matrix.

## Consequences

* Kernel security fixes arrive through Debian and unattended upgrades. The
  supervisor drains VM slots before a reboot.
* Crateward must validate Firecracker on the running kernel itself: the M1
  soak test, the hourly canaries, and a check that guest visible CPU
  mitigations match the host. The last one exists because Firecracker 1.17
  fixed a host kernel specific bug that hid eIBRS from guests on 6.18
  hosts; functional tests would not have noticed it.
* Revisit this decision at every Debian point release and every change of
  Firecracker's kernel support policy.

## Sources

* Firecracker `docs/kernel-policy.md` and `CHANGELOG.md` (1.17.0, pull request
  6120)
* Debian kernel mailing list, "Re: Trixie-backports : 6.18 LTS kernel",
  `https://lists.debian.org/debian-kernel/2025/12/msg00176.html`
* Hetzner documentation, standard images and installimage,
  `https://docs.hetzner.com/robot/dedicated-server/operating-systems/standard-images/`
