# 0011: A diff view against the previous version

* Status: Proposed
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
   head ("Compare with 0.10.1") and from a new "Changes" entry in the
   table of contents. It compares the job with the newest analyzed version
   before it in semantic version order, the same rule as
   `previous_profile`. A `?against={job}` parameter picks another version
   of the same crate, from a list of the crate's analyzed versions.
2. **One model, `views::DiffView`, built from stored data only.** No stage
   changes, no new analysis, no migration. Its sections, each with added,
   removed and unchanged counts:
   * **Verdict**: score and level of both, and evidence by signal: added,
     removed, and points changed.
   * **Package**: the stored `VersionDiff` (build script, proc macro,
     `links`, new dependencies). For older jobs without one, the section
     says so.
   * **Static findings**: grouped like the job page (severity, kind,
     context), each group marked added, removed or unchanged by the
     diff's key (kind, file, evidence).
   * **Processes**: the folded process trees of the matching runs (full
     against full, check against check), compared by the fold's shape
     (`run_view::shape`): role, label, exit and children. Only added and
     removed subtrees show by default, with their ancestors as context.
     A trimmed run on either side shows "process list removed by
     retention" instead of a false "everything is new".
   * **Network**: lookups, destinations by port and protocol, HTTP hosts
     and TLS SNI, as added and removed sets.
   * **Files**: secrets opened, writes outside the build directories, and
     scratch entries, as added and removed sets of path and program.
   * **Behavior profile**: the full set difference, which the verdict
     holds only one way today.
3. **The comparison is pure.** `diff_view(current, previous)` takes two
   loaded `JobPage`-like inputs and returns the view, so tests need no
   database and the archive can render it too.
4. **Show change, hide sameness.** Unchanged items are counted, not
   listed, behind a "show N unchanged" fold. Added items use the warning
   tone, removed ones the muted tone. The page reuses the job page's
   components: the report head (both scores side by side), the sticky table
   of contents, the group lists, the folded tree and the scroll panels.
5. **The archive includes diffs** of archived jobs whose previous version
   is archived too, as `jobs/{id}-diff.html`, and links them from both
   pages. The diff never names a version the archive does not hold.

## Alternatives

* **Store a full diff at scoring time.** It would be frozen at the analyzer
  version that made it and would need a migration and reprocessing. The
  inputs are stored already, and a comparison on read is cheap: two job
  loads and set differences.
* **A textual diff of the run reports' JSON.** Process IDs, timings and
  ordering change on every run, so everything would differ. Comparing by
  shape is what makes the folded tree readable already.
* **Diffing the source files of the two `.crate` archives.** That is
  diffs.rs' job, and the dashboard can link to it. Crateward's value is the
  behavior diff, which no other tool shows. A link to diffs.rs is added
  next to "Compare", so the reviewer has both.

## Consequences

* A reviewer sees in one screen why 0.10.2 differs from 0.10.1: the new
  build script, the new outbound connection, the new file it read.
* Scoring does not change. If the diff view shows signals worth points,
  they go into the analyzer separately, with their own tests.
* Retention limits the process comparison for old benign versions. The
  page states it. Evidence, network summaries and files are still compared.
* Watch: the size of the page for crates whose trees change completely
  between versions (code generators). The fold and the "unchanged" counts
  keep it bounded like the job page.

### Steps

1. `run_view`: expose the fold's shape key per row and a function that
   matches two folded trees by it.
2. `views::DiffView` and `diff_view()`, with unit tests from the job page's
   fixtures (one added subtree, one removed connection, a trimmed side).
3. The store query for the crate's analyzed versions in semantic version
   order.
4. Route, template and styles. Job page links. Tests in `job_page.rs`.
5. Archive: render the diff pages and link them.

## Sources

* `crates/static_analysis/src/diff.rs`, `crates/core/src/store/verdicts.rs`
  (`previous_profile`), `crates/core/src/store/retention.rs`,
  `crates/api/src/run_view.rs`
* [diffs.rs](https://diffs.rs)
