# 0008: Autonomy and escape detection

* Status: Accepted
* Date: 2026-09-25, updated 2026-10-01

## Context

The pipeline must run for weeks without a human, interrupt one only for a
closed list of reasons (`crateward_core::escalation`), and never let a
hostile crate stop it for everyone. The jail and Firecracker's seccomp
filter make an escape hard. What is needed besides is a tripwire for an
escape that succeeds quietly. Storage must stay bounded: a run report takes
about 49 kB, almost all of it the trace's process list.

## Decision

1. **State in the database:** stage breakers, pipeline pauses (quarantine,
   canary, disk), an alert outbox and canary runs. Claiming skips paused
   stages and open breakers. Workers need nothing else.
2. **Quarantine in the same transaction** as the transition that suspects a
   compromise. Only a human lifts it (`crateward quarantine lift`).
3. **How a VM ended** comes from Firecracker's exit code when the agent's
   connection breaks: a guest that stopped is a build result, never
   retried. A forbidden system call or fatal signal in Firecracker (148,
   149, 150, 157, 2) is a suspected compromise. 151 and 154 are resource
   limits. A faulty KVM exit opens the sandbox breaker at once.
4. **Circuit breakers** per stage over a 15 minute window: at least 5
   infrastructure failures making up at least half of the results open it.
   After a cooldown (5 minutes, doubling up to 2 hours) it turns half open.
5. **Canaries.** An inert known bad fixture (steals, copies, persists,
   phones home over HTTP, HTTPS and IPv6) must be caught in every channel,
   and a known good one must come out clean, at every start and every
   hour. A wrong result pauses the stages that produce verdicts.
6. **Tripwires** for a quiet escape:
   * A decoy credential in every jail root, its access time set to the
     epoch. A read ends the job as a suspected compromise.
   * A `/proc` scan for processes with a slot UID other than that slot's
     Firecracker and fake internet.
   * Host decoys watched with inotify.
   * An integrity manifest (BLAKE3 of every binary and image the sandbox
     trusts), checked every hour. Every deploy records it again.
   Any finding sets the quarantine.
7. **Alerts** from the outbox, deduplicated within
   `supervisor.alert_repeat_hours`, with a category, a short title and a
   runbook pointer only.
8. **Retention.** Reports older than `storage.raw_log_retention_days` of
   jobs with a none or low verdict and no review lose their process list
   and output tails. Evidence, verdict and profile stay.

## Alternatives

* **Every unexpected VM end is an infrastructure failure**, the original
  behavior: a crate that crashed its own guest could pause dynamic analysis
  for every other crate.
* **Alert on every failure:** the maintainer would learn to ignore alerts.
* **An external heartbeat** (healthchecks.io): removed on 2026-10-01 (ADR
  0001). Every alert now comes from the server itself.

## Consequences

* A hostile crate cannot pause the sandbox stage by crashing its VM. What
  it did becomes evidence for scoring.
* Each tripwire can be defeated by an attacker who already holds the
  service user's rights. They target the step before, a process that
  escaped and looks around.
* A deploy that forgets `crateward integrity record` quarantines the
  pipeline within the hour, by design: a changed binary must be explained.
* If the server or the supervisor is down, no alert arrives.

## Sources

* Firecracker v1.17.0 `src/vmm/src/lib.rs` (exit codes),
  `signal_handler.rs`, `vstate/vcpu.rs`
* `mount(8)` ("relatime"), `inotify(7)`, `proc_pid_status(5)`
* Michael Nygard, *Release It!*, second edition, chapter 5
