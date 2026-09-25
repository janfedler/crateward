# 0023: Host escape detection and retention

* Status: Accepted
* Date: 2026-09-25

## Context

The threat model plans that "host honeytokens and integrity monitoring
detect a successful escape" (M7). The jail (ADR 0012) and Firecracker's
seccomp filter make an escape hard; ADR 0020 already treats a crashed VMM
as a sign of one. What was missing is a tripwire for an escape that
succeeds quietly: code running outside the VM, as the slot's UID inside
the jail, or later with more rights on the host.

M7 also has to keep storage bounded. The run reports of the live run on
2026-09-25 (240 runs) take 49 kB each in Postgres on average (up to
255 kB), almost all of it the trace's process list with every argument.

Facts verified on 2026-09-25:

* Linux `relatime` (the default of ext4 and tmpfs) updates a file's access
  time on a read when the old access time is earlier than its modification
  or change time (`mount(8)`, "relatime"). Checked on this host for ext4
  (`/`) and tmpfs (`/dev/shm`). `stat` alone does not update it.
* inotify reports `IN_OPEN` and `IN_ACCESS` for any process that opens or
  reads a watched file, whatever its user (`inotify(7)`). rustix 1.1 wraps
  it (`rustix::fs::inotify`).
* `/proc/<pid>/status` is readable by every user and holds `Name`, `PPid`
  and the four UIDs (`proc_pid_status(5)`).
* On this host a slot runs exactly two processes as its UID: `firecracker`,
  child of the orchestrator, and `fake-internet`, child of that Firecracker
  (the launcher starts the fake internet, then executes Firecracker).

## Decision

1. **A decoy in every jail root.** The orchestrator puts a file that looks
   like a credential (`host-credentials`, readable by the slot) into each
   jail root, with its access time set to the epoch. Firecracker never
   opens it. After the run the orchestrator checks the access time; a read
   (or a missing file) ends the job as `DecoyTouched`, a suspected
   compromise: quarantine and a sandbox escape alert. At startup the
   orchestrator plants a probe, reads it, and refuses to run if the access
   time did not change (a `noatime` mount would switch the check off).
2. **Stray processes.** Every supervisor round reads `/proc`. A process
   with a slot UID is expected only as that slot's single `firecracker`
   (parent outside the slot range) or its single `fake-internet` (parent
   that Firecracker), with all four UIDs equal. Anything else found in two
   rounds in a row is a finding; one round alone is not, because the
   launcher briefly runs as the slot before it executes Firecracker.
3. **Host decoys.** `supervisor.decoys` lists files on the host that look
   like credentials. The supervisor plants each missing one and watches it
   with inotify; any open, read, change or removal is a finding. Backups
   and indexers must exclude them.
4. **Integrity manifest.** `crateward integrity record` writes the BLAKE3
   digests of the files the sandbox trusts (every `crateward*` executable
   next to the tool, Firecracker, the launcher, the fake internet, the
   guest kernel and root filesystem, the toolchain's `cargo`) to
   `integrity.b3` in `instance.data_dir`, in `b3sum` format. The supervisor
   checks them every `supervisor.integrity_interval_minutes`. A missing
   manifest is logged once; a difference is a finding. Every deploy ends
   with `crateward integrity record`.
5. **Response.** Findings of points 2 to 4 set the quarantine pause with the
   findings as its detail and raise `SandboxEscapeIndicator` without a job.
   Only a human lifts it (RUNBOOK.md).
6. **Retention.** Each round the supervisor trims up to 500 run reports
   older than `storage.raw_log_retention_days` whose job is done with a
   verdict of none or low and no review: the process list and the output
   tails are emptied, the count of omitted processes keeps the size, and
   the report is marked `trimmed`. Evidence (sensitive opens, writes,
   sockets, tamper attempts, network, honeytokens, scratch scan), the
   verdict and its profile stay. A trimmed job keeps its verdict when the
   analyzer version changes, since scoring it again would lose the
   attribution the process list gave. Flagged runs (medium and above, or
   anything a human reviewed) keep everything.

## Consequences

* Each check is a tripwire, not a wall. An attacker with the service
  user's rights can rewrite the manifest or read the decoy's access time
  back. The checks target the step before that: a process that escaped
  the VM and looks around, or a change made without that care.
* The decoy check in the jail costs one `stat` per run; the process scan
  reads a few hundred small files per round.
* A deploy that forgets `crateward integrity record` quarantines the
  pipeline within the interval. That is intended: a changed binary must
  be explained.
* A trimmed report can no longer show every command a build ran. The
  dashboard shows it as trimmed.

## Sources

* `mount(8)` ("relatime", "strictatime"), `inotify(7)`,
  `proc_pid_status(5)`, Linux man pages 6.9
* rustix 1.1.5, `src/fs/inotify.rs`
* The live run of 2026-09-25 in the dev database (`job_runs` sizes).
