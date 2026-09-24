# 0011: Guest kernel from a pinned Amazon Linux 6.18 branch commit

* Status: Accepted
* Date: 2026-09-24

## Context

The guest kernel runs inside the untrusted zone, but it still matters: it
decides how easily a crate reaches guest root and blinds the eBPF tracing,
and it must work with Firecracker's devices and snapshots. Firecracker
validates its guest configurations against Amazon Linux microVM kernels and
states that "these configurations should be used to build exclusively the
aforementioned Amazon Linux kernels"; it does not guarantee them for
upstream kernels.

Amazon Linux publishes microVM kernel sources under tags of the form
`microvm-kernel-*`. On 2026-09-24 the newest 6.18 tag was
`microvm-kernel-6.18.25-57.115.amzn2023`, 28 stable releases behind upstream
6.18.53. The Firecracker 6.18 configuration itself was generated from an
Amazon Linux 6.18.39 build that has no public tag. The branch
`amazon-6.18.y/mainline` in the same repository was at 6.18.51.

## Options

1. **The newest public microVM tag (6.18.25).** The documented form, but
   old: a guest root exploit fixed upstream since then is easier to reach.
2. **Upstream stable 6.18.53** with Firecracker's configuration. Newest, but
   outside what Firecracker validates.
3. **A pinned commit of `amazon-6.18.y/mainline` (6.18.51).** The Amazon
   Linux line Firecracker's configuration comes from, with current stable
   updates and Amazon's backports.

## Decision

Option 3. `guest/kernel/kernel.toml` pins repository, branch, commit and
expected version; `cargo xtask guest-kernel` fetches exactly that commit and
fails if the version differs. The Firecracker configuration is vendored
unchanged from the v1.17.0 tag, and Crateward's changes live in a separate
fragment whose every line is checked after `make olddefconfig`.

## Consequences

* A branch commit is not a release. Crateward's own boot, snapshot and
  canary tests are the validation, and a failing weekly refresh rolls back.
* Updating the kernel means updating the commit and version in one file;
  the image digest changes and the canaries gate promotion.
* The image is a `bzImage`, which Firecracker 1.17 boots directly. BTF type
  information is part of the image for eBPF (ADR 0006).
* First boot on the production server: 425 ms from process start to a
  ready guest agent; snapshot restore to a ready agent: 13 to 26 ms. The
  `vmgenid` platform device is bound in the guest, so restores reseed the
  random number generator.

## Sources

* Firecracker `docs/kernel-policy.md` and
  `resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config` (v1.17.0)
* Firecracker `CHANGELOG.md` 1.17.0, pull request 6037 (`bzImage` support)
* Tags and branches of `https://github.com/amazonlinux/linux`, listed with
  `git ls-remote` on 2026-09-24
