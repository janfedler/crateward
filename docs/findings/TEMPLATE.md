# Finding: `<crate>` `<versions>`

<!-- Write the finding from this outline as findings/<slug>/index.html in
the site repository; the site is served without Jekyll, so Markdown is not
rendered. Publish only after the disclosure workflow in DISCLOSURE.md is
complete, with `crateward disclosure publish <job> --slug <slug>`. -->

* **Crate:** `<crate>` on crates.io
* **Affected versions:** `<versions>`
* **Classification:** malicious, or vulnerability
* **Coverage:** dynamic on Linux, or static only (reason)
* **Reported to:** crates.io (`help@crates.io`) or the crate owners, on `YYYY-MM-DD`;
  or "not reported: crates.io removed the crate on `YYYY-MM-DD`, before a
  report". Crateward's copy is the `.crate` file it stored when it fetched
  the version, with the checksum crates.io published.
* **Status:** removed from crates.io, yanked, fixed in `<version>`, or open
* **References:** RustSec identifier, crates.io notice, owner advisory

## Summary

Two or three sentences: what the crate does when it is built or used, and
who is affected.

## Timeline

| Date | Event |
|------|-------|
| `YYYY-MM-DD` | Version published |
| `YYYY-MM-DD` | Crateward verdict |
| `YYYY-MM-DD` | Reported |
| `YYYY-MM-DD` | Acknowledged |
| `YYYY-MM-DD` | Action taken |
| `YYYY-MM-DD` | Published here |

## Behavior

What was observed, in order, each point linked to evidence: static findings
with file and line, process and file events, network attempts caught by the
fake internet, honeytoken access.

## Indicators

Domains, IP addresses, file paths and hashes a defender can search for.

## How Crateward found it

Which detectors and signals contributed to the score, and what the score was.

## Remediation

What users of the affected versions should do.
