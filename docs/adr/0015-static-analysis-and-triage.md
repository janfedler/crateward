# 0015: Static analysis in a sandboxed child, reports per crate file, rule based triage

* Status: Accepted
* Date: 2026-09-25

## Context

Every new version gets static analysis. The stage must find behavior that
matters on any platform, point at the code that caused each finding, and
decide whether a microVM run can add evidence. The input is hostile: source
files, manifests and arbitrary binary files from the archive.

Facts measured on the server on 2026-09-25, with the 76 live jobs that M2
fetched (1,572 distinct crate files including dependencies):

* `syn` parses about 10 MB of Rust per second. The largest crate seen,
  `windows` 0.59.0 (111 MB unpacked, 722 Rust files), takes 13 s in total;
  YARA-X needs 0.16 s of that.
* With reports cached, triage of a job takes 66 ms at the median and
  455 ms at most. The first pass over all 1,572 crate files took 190 s.
* The first detector version flagged URLs in doc comments and error
  messages, bidi characters in images and archives, and `toast.txt` as an
  exfiltration host. Those false positives are fixed and covered by tests.

## Decision

1. **Parse every Rust file in the archive, not the module tree.** `syn`
   ignores `cfg`, so Windows and macOS branches are parsed like Linux ones,
   and a file hidden behind `#[path]` or `cfg_attr` is parsed anyway. Each
   finding records the file, the line, the innermost `cfg` predicate and the
   platform it selects. Dead files make the analysis more conservative,
   never less.
2. **Context decides severity.** A file is build script, proc macro,
   library, binary or test code by its path and the manifest (Cargo's rules:
   `build.rs` unless `build = false`, `proc-macro` in `[lib]`). Findings in
   code that runs at build time are raised one severity level.
3. **YARA-X for bytes, `syn` for code.** The built in rules
   (`crates/static_analysis/rules/crateward.yar`) cover Trojan Source
   characters (CVE-2021-42574) in source files only, shipped executables,
   base64 encoded executables, reverse shells, persistence paths, wallet and
   browser data, and sandbox checks. Each rule carries `severity` and
   `description` metadata.
4. **A sandboxed child does the parsing.** The service starts itself again
   as `sandbox-analyze`, which enters a private user and network namespace,
   sets rlimits (CPU, no file writes, 32 descriptors) and drops all
   filesystem access with Landlock before it reads a byte. Crate tars arrive
   on stdin; one JSON line per tar comes back. The address space limit is
   16 GiB because YARA-X runs its rules on a WebAssembly runtime that
   reserves large virtual regions; resident memory stays far below.
5. **Reports belong to crate file content.** `static_reports` is keyed by
   the SHA-256 of the `.crate` file and stamped with `ANALYZER_VERSION`.
   Shared dependencies are analyzed once; a detector change bumps the
   version and reports are recomputed on demand. The job's decision, its
   reasons and the version diff go into `job_static`.
6. **Triage rules, in order.** An archive that failed validation, or a
   version whose dependencies do not resolve, cannot be built and is static
   only with that reason. A library gated to Windows or Apple with no
   build time code is not applicable on Linux. The crate's own build script
   or proc macro, a `links` key, or any high severity finding makes the job
   dynamic. So does a locked dependency with build time code that is
   unfamiliar: not popular (reverse dependencies or downloads over the
   configured thresholds), not locked by an earlier version of the same
   crate, and without its own job. Otherwise the job is static only. A
   dependency version that has its own job gets its own dynamic run, so the
   dependent does not repeat it; the analyzer (M6) carries that verdict to
   dependents.
7. **The diff compares findings by kind, file and evidence**, not by line,
   against the newest earlier version with a report, and lists new locked
   dependencies.
8. **Evidence is escaped.** Control, bidi and invisible characters are
   written as `\u{..}`: Postgres `jsonb` rejects NUL, and the dashboard must
   never render a Trojan Source string as if it were code.

## Consequences

* A report explains itself: every finding has a file, usually a line, the
  code context, the `cfg` and a truncated evidence string.
* The pipeline never waits for an unfamiliar dependency to be analyzed
  first; the dependent job runs it instead.
* About 55 percent of the 76 sampled jobs are dynamic. At busy times that
  exceeds the three VM slots, which the dynamic deadline absorbs (static
  only, with the reason on the label). M5 measures this on live traffic.
* Detectors are heuristics. False positives cost a VM run and a line in a
  report, not a verdict: the analyzer (M6) weighs findings together.
* Generated crates with more than 96 MiB of Rust or single files over
  2 MiB are analyzed partly; the report lists the skipped files.

## Sources

* `syn` 2 documentation: `parse_file`, `visit::Visit`, spans with the
  `span-locations` feature of `proc-macro2`:
  <https://docs.rs/syn/2/syn/>, <https://docs.rs/proc-macro2/1/proc_macro2/>
* YARA-X 1.20.0 API (`compile`, `Scanner::scan`, `Rule::metadata`), read
  from the published crate source, and the rule language:
  <https://virustotal.github.io/yara-x/docs/>
* Cargo reference, build scripts (`build` key and default), `links`,
  `proc-macro` targets and platform specific dependencies:
  <https://doc.rust-lang.org/cargo/reference/build-scripts.html>,
  <https://doc.rust-lang.org/cargo/reference/cargo-targets.html>,
  <https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html>
* Trojan Source, CVE-2021-42574: <https://trojansource.codes/>
* Landlock: <https://docs.kernel.org/userspace-api/landlock.html>
* PostgreSQL `jsonb` rejects `\u0000`:
  <https://www.postgresql.org/docs/17/datatype-json.html>
