# Disclosure workflow

Crateward finds two kinds of problems, and each has its own documented
reporting path.

* **Malicious crates** (intentionally harmful code). crates.io asks that
  "crates violating these policies" be reported to `help@crates.io`.
  RustSec's contribution guide agrees: "Suspected malicious crates should
  instead be reported to crates.io."
* **Vulnerabilities** (unintended flaws). crates.io asks reporters to "seek
  guidance from the individual crate's owners and their specific policies",
  often a `SECURITY.md`. RustSec accepts an advisory once "the maintainers
  confirm the vulnerability exists", and states that it does not handle
  embargoed vulnerabilities.

This refines the specification, which asked to report to "the crates.io
security team and RustSec before publishing anything": RustSec's own process
asks not to be the first recipient.

## Steps

1. **Detection.** The analyzer produces a high risk verdict and puts the
   job into the "needs you" inbox. The alert text carries no crate name.
2. **Review.** The maintainer checks the evidence on the dashboard. Common
   false positives: `-sys` crates that download prebuilt libraries, build
   scripts that probe the network for feature detection, code generators
   that write outside `OUT_DIR`.
3. **Confirmation.** A high or critical verdict from `cargo check` has
   already been confirmed automatically by a full build in a fresh VM
   (ADR 0009), unless the finding came from a sandbox escape indicator;
   such crates are never executed again without a deliberate decision.
   After the review, mark the verdict confirmed on the dashboard, then
   write the evidence pack: `crateward evidence <job> --out <dir>`. It
   holds the job and its events, the verdict with its evidence, the static
   report, every VM run (trace, network log, scratch disk scan), the
   resolution, the original `.crate` file, and `SHA256SUMS`; honeytokens
   are redacted. `verdict.json` also names the MITRE ATT&CK techniques
   the evidence is consistent with, and T1195.001 for the crate once the
   verdict is confirmed.
4. **Report.**
   * Malicious: email `help@crates.io` with the crate name, affected
     versions, the behavior observed with its ATT&CK technique IDs, and
     the evidence pack.
   * Vulnerability: contact the owners through their security policy; after
     they confirm, file a RustSec advisory by pull request to
     `RustSec/advisory-db`.

   Then record it:
   `crateward disclosure report <job> --kind malicious --to help@crates.io`
   (or `--kind vulnerability --to <owners>`), with `--reference` once the
   recipient gives one. Only a confirmed verdict can be recorded.
5. **Wait.** Default embargo proposals, to be confirmed by the maintainer
   before M8:
   * malicious crates: publish after crates.io has acted, or 14 days after an
     acknowledged report;
   * vulnerabilities: follow the owners' timeline, at most 90 days.

   When the recipient acted, or the embargo passed, record it:
   `crateward disclosure resolved <job>`.
6. **Publish.** Write the finding page from
   [the template](findings/TEMPLATE.md) into the site repository as
   `findings/<slug>/index.html`, then run
   `crateward disclosure publish <job> --slug <slug>`. The database refuses
   to publish a finding that was not reported and resolved. The next export
   lists it on crateward.com with its dates and a link to the page.
7. **Record.** `crateward disclosure show <job>` and the job page on the
   dashboard show the timeline: reported, reference, resolved, published.

## Rules

* Never publish before step 4 is complete and the embargo has passed.
* Report facts and evidence, not motives. Name crates and versions, not
  people.
* Never include real credentials. Honeytokens in evidence are fake by
  construction, but are redacted anyway to avoid confusion.
* Mistakes are corrected publicly on the same page.

## Sources

* crates.io security page, `svelte/src/routes/policies/security/+page.svelte`
  in `https://github.com/rust-lang/crates.io`
* RustSec `CONTRIBUTING.md`, `https://github.com/rustsec/advisory-db`
