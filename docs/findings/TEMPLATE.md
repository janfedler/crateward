# Finding: `<crate>` `<versions>`

<!-- Copy this file to findings/<year>-<crate>.md. Publish only after the
disclosure workflow in DISCLOSURE.md is complete. -->

* **Crate:** `<crate>` on crates.io
* **Affected versions:** `<versions>`
* **Classification:** malicious, or vulnerability
* **Coverage:** dynamic on Linux, or static only (reason)
* **Reported to:** crates.io (`help@crates.io`) or the crate owners, on `YYYY-MM-DD`
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
