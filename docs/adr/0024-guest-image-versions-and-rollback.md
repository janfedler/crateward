# 0024: Guest image versions, refresh and rollback

* Status: Accepted
* Date: 2026-09-26

## Context

The threat model planned image promotion and rollback "with the weekly
refresh", and OPERATIONS listed a weekly image refresh at night and an
archive of the last two promoted versions. Three facts shape how that can
work:

* The guest image is built from pins: a Debian snapshot time, the Rust
  release with its digests, the kernel commit (`guest/`). A refresh is a
  change of those pins, which is a reviewed commit, not something a timer
  on the server should decide.
* The fake internet's authority belongs to the image that trusts it; the
  kernel, the root filesystem and the authority change together.
* A running orchestrator must keep the root filesystem its base snapshot
  was made from. Swapping the file under it gives restored VMs a
  different disk than their memory expects.
* Installing files in `/usr/local` and restarting services needs root,
  which the services do not have.

ADR 0008 also left a persistent, signed warm image for this milestone.

## Decision

1. **Versions.** The playbook installs the guest files of a release into
   `/usr/local/lib/crateward/guest/<first 16 hex digits of the root
   filesystem's SHA-256>/` and points the link `current` at it. The
   version that was current becomes `previous`; older versions are
   removed. The configuration names the files through `current`.
2. **Resolved once.** The orchestrator resolves the three paths when it
   starts, so moving the link never changes the files of a running
   instance. The playbook restarts the orchestrator when the link moved;
   the restart waits until it drained its jobs.
3. **Promotion.** A new version is used only after the canaries pass: at
   every start the orchestrator runs them in slot 0, and the other slots
   wait until that round is over before they take a job. A failure pauses
   the sandbox, analysis and finalize stages (ADR 0020). Promotion is
   therefore "the canaries passed on the new version"; no job runs on a
   version before its first canaries did. (Until this ADR, slots 1 and 2
   started taking jobs while slot 0 ran the canaries.)
4. **Rollback.** `deploy/ansible/rollback.yml` swaps `current` and
   `previous`, restarts the orchestrator and records the integrity
   manifest. Running it again switches forward.
5. **Refresh.** `cargo xtask bump-debian-snapshot` moves the Debian pin to
   today; the maintainer's routine is then `cargo xtask rootfs`,
   `cargo xtask canary`, a commit, `cargo xtask release` and the playbook.
   The Rust and kernel pins move in the same way, by hand, since each
   needs its signature or tag checked.
6. **Warm image.** The warm image stays per process: it is built at every
   orchestrator start (about 13 minutes) and dropped at exit. Restarts
   happen only at deploys and rollbacks, so a persistent image would save
   little and would need a signing key the orchestrator holds, which a
   compromise of that user would also hold. ADR 0008's persistent signed
   image is not built.

## Consequences

* The refresh is weekly by routine, not by timer. A missed week leaves the
  guest a little older, which costs realism, not safety: the guest is
  hostile anyway, and the kernel and Firecracker are pinned separately.
* A rollback is one command, but it needs the maintainer, since it
  changes files outside the services' reach. The canaries keep the
  pipeline paused until then.
* Two guest versions take about 1.6 GB on the system disk.

## Sources

* `deploy/ansible/tasks/guest.yml`, `deploy/ansible/rollback.yml`,
  tested against a temporary directory with three bundles on 2026-09-26.
* ADR 0008, ADR 0020.
