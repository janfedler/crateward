# 0005: Static analysis in a sandboxed child, rule based triage

* Status: Accepted
* Date: 2026-09-25

## Context

Every new version gets static analysis. It must find behavior that matters
on any platform, point at the code that caused each finding, and decide
whether a microVM run can add evidence. The input is hostile: sources,
manifests and arbitrary binary files. Measured on the server: `syn` parses
about 10 MB of Rust per second; the largest crate seen (`windows` 0.59.0,
111 MB unpacked) takes 13 s, of which YARA-X needs 0.16 s.

## Decision

1. **Parse every Rust file in the archive**, not the module tree. `syn`
   ignores `cfg`, so Windows and macOS branches are parsed like Linux ones,
   and files hidden behind `#[path]` or `cfg_attr` are parsed anyway. Each
   finding records file, line, the innermost `cfg` and its platform.
2. **Context decides severity.** Build scripts and proc macros (by Cargo's
   rules) run at build time, so their findings are raised one level.
3. **YARA-X for bytes, `syn` for code.** The built in rules cover Trojan
   Source characters, shipped or base64 encoded executables, reverse
   shells, persistence paths, wallet and browser data and sandbox checks.
4. **A sandboxed child parses.** `sandbox-analyze` enters its own user and
   network namespace, sets resource limits and drops all filesystem access
   with Landlock before it reads a byte. Tars arrive on stdin, one JSON
   report per tar comes back.
5. **Reports belong to crate file content**: keyed by the `.crate` SHA-256
   and stamped with the analyzer version, so shared dependencies are
   analyzed once and a detector change recomputes them on demand.
6. **Triage rules, in order.** An archive that failed validation or
   unresolved dependencies: static only, with that reason. A library gated
   to Windows or Apple with no build time code: not applicable on Linux.
   Its own build script or proc macro, a `links` key, a high severity
   finding, or an unfamiliar dependency with build time code (not popular,
   not locked by an earlier version, without its own job): dynamic.
   Otherwise static only.
7. **A diff** against the newest earlier version compares findings by kind,
   file and evidence, and lists new dependencies.
8. **Evidence is escaped**: control, bidi and invisible characters are
   written as `\u{..}`, so the dashboard never renders a Trojan Source
   string as code.

## Alternatives

* **Follow the module tree** like the compiler: misses files that a `cfg`
  or `#[path]` hides, which is where platform specific payloads live.
* **Parse in the service process:** a parser bug on hostile input would run
  inside a process with database access.
* **Analyze per job:** popular dependencies would be parsed thousands of
  times.

## Consequences

* Every finding explains itself with a file, usually a line, the context,
  the `cfg` and a truncated evidence string. YARA-X matches in text files
  get the line of their first match. The job page links each finding to
  that line in the crates.io code viewer, so a reviewer reads the code
  without unpacking the crate.
* A report from an older analyzer is written again when a job needs it, and
  in idle time for scored jobs, verdicts waiting for review first.
* About half of the sampled jobs are dynamic, more than three VM slots can
  take at busy times; the dynamic deadline turns the rest into static only
  verdicts, labeled with the reason.
* Detectors are heuristics. A false positive costs a VM run and a report
  line, not a verdict: the analyzer weighs findings together (ADR 0009).

## Sources

* `syn` 2 and `proc-macro2` documentation, `https://docs.rs/syn/2/syn/`
* YARA-X 1.20.0 crate source and `https://virustotal.github.io/yara-x/docs/`
* Cargo reference, build scripts, targets and platform specific
  dependencies
* Trojan Source, CVE-2021-42574, `https://trojansource.codes/`
* Landlock, `https://docs.kernel.org/userspace-api/landlock.html`
