# 0020: Autonomy: breakers, quarantine, canaries and alerts

* Status: Accepted
* Date: 2026-09-25

## Context

Workers retry with backoff, and the job state machine already assigns
every failure a class (`crateward_core::failure`) and a side effect: retry,
report to the stage circuit breaker, or enter quarantine. Until M5 nothing
acted on the last two. The pipeline must run for weeks without a human,
page one only for the closed list of escalations
(`crateward_core::escalation`), and never let a hostile crate stop the
pipeline for everyone.

Facts verified on 2026-09-25:

* Firecracker v1.17 handles fatal signals itself and exits with fixed
  codes (`FcExitCode` in `src/vmm/src/lib.rs`, `signal_handler.rs`): 0 when
  the guest stopped or reset, 1 on errors including faulty KVM exits
  (`vstate/vcpu.rs`, logged as `FaultyKvmExit`), 148 after a system call
  its seccomp filter forbids, 149, 150 and 157 after `SIGBUS`, `SIGSEGV`
  and `SIGILL`, 151 and 154 after `SIGXFSZ` and `SIGXCPU`, 2 when a signal
  handler saw something impossible.
* Until now every VM that ended without the agent's report was an
  infrastructure failure: retried up to 50 times and counted against the
  sandbox stage. A crate that crashed its own guest could therefore pause
  dynamic analysis for every other crate.
* ntfy takes a message body with `Title` and `Priority` (1 to 5, 5 being
  `urgent`) headers (`docs/publish.md`); healthchecks.io accepts `HEAD`,
  `GET` or `POST` on the ping URL and answers `200 OK`
  (`templates/docs/http_api.md`).

## Decision

1. **State in the database.** Migration 6 adds `stage_breakers`,
   `pipeline_pauses` (reasons `quarantine`, `canary`, `disk`, each with the
   stages it stops), an `alerts` outbox and `canary_runs`. Claiming skips
   stages that are paused or whose breaker is open; workers need no other
   change.
2. **Quarantine in the same transaction.** When a transition yields the
   quarantine effect, `Store::complete` also inserts the quarantine pause
   (all stages) and a `SandboxEscapeIndicator` alert. Only a human lifts it
   (`crateward quarantine lift`).
3. **How a VM ended.** The orchestrator waits two seconds for Firecracker's
   exit status when the agent's connection breaks:
   * exit 0, or Firecracker still running: the guest stopped or its agent
     vanished. Only code in the guest can do that, so it is a build result
     (`BuildOutcome::GuestStopped`), recorded and never retried;
   * 148, 149, 150, 157 or 2: Firecracker, which parses guest input, died
     on a forbidden system call or a fatal signal: suspected compromise,
     quarantine;
   * 151 or 154: a resource limit;
   * 1 with a faulty KVM exit in the log: an infrastructure failure, a
     `KvmError` alert, and the sandbox breaker opened at once;
   * anything else: an infrastructure failure, as before.
4. **Circuit breakers.** The supervisor counts, per stage, infrastructure
   failures and completed steps in the job events over a sliding window
   (15 minutes). At least 5 failures that make up at least half of the
   results open the breaker and raise `StageFailingAfterRetries`. After a
   cooldown (5 minutes, doubling after each failed probe up to 2 hours) it
   turns half open: jobs flow, the first completion closes it, the first
   failure opens it again. The decision is a pure function
   (`crateward_core::breaker`).
5. **Canaries.** Two inert fixture crates run in slot 0 at startup, after
   the warm build, and then every `sandbox.canary_interval_minutes`: the
   known bad one (steals, copies, persists, phones home over HTTP, HTTPS and
   IPv6) must be caught in every channel; the known good one must come out
   clean. A wrong result pauses the stages that produce and publish
   verdicts (sandbox, analysis, finalize) and raises `CanaryFailure`; the
   pause lifts when all canaries pass again. A canary whose run fails for
   infrastructure reasons records nothing.
6. **Deadlines and disks.** Jobs that waited longer than
   `triage.dynamic_deadline_hours` for a VM are scored as static only. Above
   `storage.disk_alert_percent`, the supervisor raises
   `DiskUsageAboveThreshold`; if it is the scratch filesystem, the sandbox
   stage pauses until usage drops.
7. **Alerts.** The supervisor delivers the outbox in order. An alert whose
   deduplication key went out within `supervisor.alert_repeat_hours` is
   marked suppressed, not sent. Messages carry a category, a short title and
   a pointer to the runbook; never a crate name or a job number. The `log`
   notifier only logs, for development.
8. **Heartbeat.** A task pings healthchecks.io every
   `heartbeat.interval_secs` as long as a supervisor round succeeded within
   three intervals; a dead server, supervisor or database therefore all end
   in the heartbeat alert. The example's all zero check ID is never pinged.

## Consequences

* A hostile crate can no longer pause the sandbox stage by crashing its own
  VM; what it did is a result that scoring (M6) sees.
* Paging stays limited to the closed list; everything else is in the logs
  and, from M6, on the dashboard.
* Breaker thresholds are guesses until M7 measures them on live traffic.
* The supervisor's round is sequential and cheap (a handful of queries);
  its interval is 30 seconds.

## Sources

* Firecracker v1.17.0 `src/vmm/src/lib.rs`, `src/vmm/src/signal_handler.rs`,
  `src/vmm/src/vstate/vcpu.rs`
* ntfy `docs/publish.md`, `https://github.com/binwiederhier/ntfy`
* healthchecks `templates/docs/http_api.md`,
  `https://github.com/healthchecks/healthchecks`
* Michael Nygard, *Release It!*, second edition, chapter 5 (circuit breaker)
