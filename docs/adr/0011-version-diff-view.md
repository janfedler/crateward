# 0011: A diff view against the previous version

* Status: Accepted
* Date: 2026-10-13

## Context

Most malicious releases are updates of crates that existed before. The
monica_rand_core case (0.10.1 to 0.10.3) is one: what matters is what
changed. Crateward already computes parts of that change, but scatters it:

* The static analysis stores a `VersionDiff` in `job_static.diff`: a build
  script or proc macro that appeared, a changed `links` value, new findings
  (compared by kind, file and evidence, not by line), the number of removed
  findings, and new locked dependencies
  (`crates/static_analysis/src/diff.rs`).
* The analyzer compares behavior profiles with the newest scored version
  before this one (`Store::previous_profile`) and stores the result as
  `new_behavior` in the verdict.
* The job page shows `new_behavior` as chips and nothing else of the diff.
  The VM runs, the network log and the scratch scan are not compared at all.

The previous version's raw run data may be gone: retention trims the
process list and output tails of none and low verdicts after
`storage.raw_log_retention_days` (`store/retention.rs`). Its evidence,
network summary, verdict and profile stay.

## Decision

1. **A diff page per job**, `/jobs/{id}/diff`, linked from the job page's
   head ("Compare with 0.10.1"). It compares the job with the newest
   scored version before it in semantic version order, the same rule as
   `previous_profile` (`Store::analyzed_versions`, `diff::counterpart`).
   A `?against={job}` parameter picks another version of the same crate
   from the list of its scored versions. The page links both job pages
   and the two versions' source diff on diff.rs.
2. **Built from stored data only.** No stage changes, no new analysis, no
   migration. Its sections, each with new, gone and unchanged counts:
   * **Verdict**: score and level of both, and evidence by signal and
     package: new, gone, and points changed.
   * **Package**: the stored `VersionDiff` (build script, proc macro,
     `links`, new dependencies), when it was computed against the
     version compared with. Otherwise the section says why it is missing.
   * **Static findings**: compared by severity, kind, rule, context, file
     and evidence, not by line, so code that only moved is the same. New
     and gone findings are grouped like on the job page.
   * **Processes**: the folded trees of a run kind both versions have, the
     full run first. A process is compared by its place in the tree: the
     programs of its ancestors, its own program, exit and whether it
     became root. Build scripts count by package, since their directory
     name has a hash. New and gone processes show with their ancestors as
     grey context. A run that retention trimmed on either side is named
     instead of compared.
   * **Network**: lookups, and connections by destination, protocol and
     what was sent, as new and gone sets.
   * **Files**: secrets read, writes outside the build directories and
     scratch entries, by program and path, as new and gone sets.
   * **Behavior profile**: the set difference both ways.
3. **The comparison is pure.** `diff::compare(now, before)` takes two
   loaded `diff::Side`s, so tests need no database and the archive renders
   it too.
4. **Show change, hide sameness.** Unchanged items are counted, not
   listed. New items use the warning tone, gone ones the muted tone. The
   page reuses the job page's parts: the report head with both scores, the
   sticky table of contents, the finding groups, the folded tree and the
   scroll panels.
5. **The archive includes comparisons** of archived jobs whose previous
   version is archived too, as `jobs/{id}-diff.html`, linked from the
   newer job's page. A comparison never names a version the archive does
   not hold.

## Alternatives

* **Store a full diff at scoring time.** It would be frozen at the analyzer
  version that made it and would need a migration and reprocessing. The
  inputs are stored already, and a comparison on read is cheap: two job
  loads and set differences.
* **A textual diff of the run reports' JSON.** Process IDs, timings and
  ordering change on every run, so everything would differ. Comparing by
  shape is what makes the folded tree readable already.
* **Diffing the source files of the two `.crate` archives.** That is
  diff.rs' job, and the page links to it. Crateward's value is the
  behavior diff, which no other tool shows.

## Consequences

* A reviewer sees in one screen why 0.10.2 differs from 0.10.1: the new
  build script, the new outbound connection, the new file it read.
* Scoring does not change. If the diff view shows signals worth points,
  they go into the analyzer separately, with their own tests.
* Retention limits the process comparison for old benign versions. The
  page states it. Evidence, network summaries and files are still compared.
* Watch: the size of the page for crates whose trees change completely
  between versions (code generators). The fold keeps it bounded like the
  job page, and each process list stops at 400 lines with a count of the
  rest.

## Sources

* `crates/static_analysis/src/diff.rs`, `crates/core/src/store/verdicts.rs`
  (`previous_profile`), `crates/core/src/store/retention.rs`,
  `crates/api/src/run_view.rs`, `crates/api/src/diff.rs`
* [diff.rs](https://diff.rs)
