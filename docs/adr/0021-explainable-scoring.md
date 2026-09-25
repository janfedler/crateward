# 0021: Explainable scoring, behavior profiles and the review inbox

* Status: Accepted
* Date: 2026-09-25

## Context

Earlier stages store what they observed: the static report of every crate
file (ADR 0015), the diff against the previous version, and each VM run's
report with the eBPF trace, the fake internet's log and the scratch disk
scan (ADRs 0016 to 0019). M6 turns that into a verdict a human can check:
a score, and for every point of it the evidence and who caused it.

The inbox has a hard constraint: crates.io publishes about 7,400 versions a
day (ADR 0008). If even one percent of them landed in front of a human, the
inbox would be unusable within a day, and real findings would drown.

Facts from the first live scoring run on 2026-09-25 (672 versions of the dev
database):

* Counting every static finding instance let large crates reach a medium
  score through volume alone (108 medium, 5 high), most of them library
  code that spawns processes or talks to the network, which is ordinary.
* `rustpython-vm`'s build script writes the whole build environment into
  generated source; the planted `GITHUB_TOKEN` ended up in its build output.
  That is a real finding about the dependency, not about the crate that
  pulled it in.

## Decision

1. **A sum of evidence, capped per group.** The analyzer (`score.rs`) adds
   points per signal and caps each group, so one noisy source cannot
   dominate; the total is capped at 100. Levels: none (0), low (1 to 19),
   medium (20 to 49), high (50 to 79), critical (80 and up).

   | Group | Cap | Signals and points |
   |-------|-----|--------------------|
   | Theft | 100 | honeytoken left the VM 100; copied inside the VM 60 |
   | Integrity | 100 | became root 80; tamper attempt 60; guest stopped 50; set ID file 40 |
   | Credentials | 60 | a non cargo process read credentials 50, another process's memory or environment 30 |
   | Persistence | 60 | write to a persistence location 40, elsewhere outside the build 15; left on disk: persistence 40, executable 20, other 10 |
   | Network | 40 | name looked up 10; connection without lookup 20; raw frame 30 |
   | Static | 30 | per finding kind, its strongest instance: high at build time 30, high elsewhere or medium at build time 10, medium elsewhere 2, low at build time 1 |
   | Execution | 20 | a build script ran a network tool or privilege tool 15, an encoder 8, a downloader 5, a shell or interpreter 3 |
   | Change | 20 | build script added 10, new high finding 10, proc macro added 5, each new dynamic behavior 5 |

2. **Attribution.** Dynamic evidence names the package whose code acted:
   the process tree leads to a build script (`…/build/<package>-<hash>/`) or
   to `rustc` compiling a crate (whose proc macros run inside it); disk
   evidence names the build directory it sits in. A malicious dependency is
   named as such.
3. **Behavior profiles.** Each verdict stores a small set of normalized
   behaviors (`exec:downloader`, `read:cargo-credentials`,
   `net:github.com`, `static:downloader_pattern`, …). Behavior the previous
   version (by semantic version order) did not have is listed and counts in
   the change group: a `-sys` crate that always downloaded its library stays
   medium, a new version that starts to is pushed higher.
4. **Inbox.** High and critical verdicts go to review: finalize sets the
   review to pending and raises `HighRiskVerdict`, whose alert carries no
   details. A human marks it confirmed or a false positive.
5. **Confirmation run.** A high or critical verdict from a `cargo check`
   run gets one `cargo build` run in a fresh VM with fresh honeytokens
   (DISCLOSURE.md, step 3), unless a honeytoken already left the VM. The
   verdict after it combines the evidence of both runs. Tests would need
   the crate's dev dependencies, which the consumer probe does not resolve.
6. **Recomputation.** Verdicts carry the analyzer version. When idle, the
   analyzer recomputes finished jobs' verdicts from an older version; one
   that newly needs review enters the inbox, one that no longer does leaves
   it unless a human already decided.

## Consequences

* After the recalibration and the confirmation runs, the 672 dev versions
  scored none 496, low 165, medium 10, high 1. The one high verdict is a
  crate whose dependency (`rustpython-vm`) writes the build environment,
  including the planted `GITHUB_TOKEN`, into generated source; the
  evidence names that dependency. Evidence is deduplicated with cargo's
  unit hashes removed from paths, so a behavior seen in both runs counts
  once. The point values are a first calibration;
  M7 measures precision on live traffic and the canaries pin the extremes
  (the known bad canary is critical, the known good one scores nothing).
* The analyzer links the orchestrator and static analysis packages for
  their report types only. That adds build time, not runtime coupling: the
  zone boundaries are processes.
* Library code weighs little by design. Malicious code that runs only when
  a library is called is out of reach of build time analysis anyway, and
  static analysis still lists it.

## Sources

* The stored reports described in ADRs 0015 to 0019, and the live run of
  2026-09-25 in the dev database.
* DISCLOSURE.md, steps 1 to 3.
