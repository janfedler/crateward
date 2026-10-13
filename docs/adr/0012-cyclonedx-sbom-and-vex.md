# 0012: A CycloneDX SBOM and a separate findings document per job

* Status: Proposed
* Date: 2026-10-13

## Context

Users of a crate increasingly need an SBOM, and in the EU the Cyber
Resilience Act makes it an obligation. BSI TR-03183-2 v2.1.0 says what a
compliant SBOM holds:

* Format: CycloneDX 1.6 or newer, or SPDX 3.0.1 or newer.
* For the SBOM: its creator as an email address or URL, and a timestamp.
* For each component: creator, name, version, filename, dependencies with
  a completeness indicator, distribution licences as SPDX identifiers or
  expressions, the SHA-512 of the deployable file, and whether it is
  executable, an archive and structured. BSI's CycloneDX property taxonomy
  names the last ones `bsi:component:filename`, `bsi:component:executable`,
  `bsi:component:archive` and `bsi:component:structured`.
* When known: source code URI, URI of the deployable form, and other
  identifiers such as a purl.
* No vulnerability data inside the SBOM. It goes into a separate document
  (VEX, VDR or CSAF).

Most SBOM generators only list what a build contains. Crateward knows what
each component did when it was built and run in the sandbox. Keeping that
evidence in its own document that points into the SBOM satisfies the BSI
rule, and an SBOM consumer such as `Dependency-Track` can read both.

What Crateward already stores, and what is missing:

* **Dependencies.** `job_fetches.lockfile` is the lockfile of the consumer
  probe (ADR 0004): every package a crate pulls in with its default
  features, for every target, with the edges between them. Dev
  dependencies are not in it, which is right, since they are not
  deployed. A job whose resolution failed has no lockfile.
* **Hashes.** `crate_files` has the SHA-256 the index publishes. SHA-512 is
  not computed, and the `.crate` files of dependencies are not kept
  (`supervisor.keep_originals` keeps only the analyzed crate's file), so
  older rows cannot be hashed again without downloading them again.
* **Licences, repository, authors.** Every locked package gets a static
  report (`static_reports`), but `ManifestFacts` does not read `license`,
  `license-file`, `repository` or `authors` yet.
* **Findings.** A verdict's evidence names a signal, a summary, a source
  and the responsible package by name only (`Evidence.package`). The
  review state is `none`, `pending`, `confirmed` or `false_positive`, and
  a published finding has a page under `crateward.com/findings/<slug>/`.
  There is no packet capture. Network evidence comes from the fake
  internet's log, and each job has at most one check run and one full run.

The Rust library `cyclonedx-bom` supports spec 1.3 to 1.5 in its current
release. Support for 1.6 is an open pull request.

## Decision

1. **Two documents per job.** `{name}-{version}.cdx.json` is the SBOM and
   `{name}-{version}.vex.cdx.json` holds Crateward's findings. The
   dashboard serves them at `/jobs/{id}/sbom.cdx.json` and
   `/jobs/{id}/vex.cdx.json` and links them from the job page. The
   archive writes them next to each job page, so they outlive the server.
   `crateward sbom <job> --out <dir>` writes both for one job.
2. **The SBOM** is CycloneDX 1.6 JSON:
   * `metadata`: timestamp, the tool `crateward` with its version, and
     Crateward as the manufacturer with the site URL, since BSI wants an
     email address or URL, not a bare name. The analyzed crate is
     `metadata.component`.
   * One component per locked package. Its `bom-ref` and `purl` are
     `pkg:cargo/{name}@{version}`. It carries the SHA-512 and SHA-256 of
     the `.crate` file, the declared licence as an SPDX expression with
     `acknowledgement: declared`, the `distribution` URL on
     static.crates.io, a `vcs` reference from `repository` when the
     manifest has one, and the four `bsi:component:*` properties. A
     `.crate` file is a compressed tar of sources, so it is
     `non-executable`, `archive` and `structured`.
   * `dependencies` gives each package's edges from the lockfile.
   * `compositions` declares the graph `complete` for the analyzed crate.
     A property `crateward:resolution` says what complete means here:
     default features, all targets, no dev dependencies. A job without a
     lockfile lists only the crate itself, with the aggregate `unknown`.
3. **The SBOM is stored once and does not change.** Finalize generates it
   and stores it in a new table, keyed by the crate's SHA-256 and the
   SHA-256 of the lockfile. A rescan with the same lockfile reuses the
   stored SBOM, its `serialNumber` and its `version`. The findings of
   every rescan then point into the same document. Jobs finalized before
   this change get theirs from a backfill command.
4. **The findings document** is a CycloneDX 1.6 BOM with only
   `vulnerabilities`, built on read from the verdict and the review, since
   a review can change after the scan.
   * Its `serialNumber` is a UUIDv5 of the job id. `version` counts the
     job's review changes.
   * One entry per evidence signal. The `id` is `CW-{job}-{signal}`, and
     `source` names Crateward with the job page, or the finding page
     once the finding is published.
   * `affects` points at the components with BOM links of the form
     `urn:cdx:{serial}/{version}#pkg:cargo/{name}@{version}`. Evidence
     without a package affects the analyzed crate. A name that the
     lockfile holds in two versions affects both.
   * `ratings` has the severity from the verdict level with the method
     `other`. `cwes` comes from a fixed table per signal, for example
     CWE-506 for a confirmed malicious crate. `description` is the
     evidence summary. `properties` in the `crateward:` namespace hold
     the signal, its source, the points, the run kind and the location.
     Honeytokens are redacted as on the pages.
   * `analysis.state` follows the review: `in_triage` for no review or a
     pending one, `exploitable` for confirmed, `false_positive` for false
     positive.
5. **A crate without evidence gets no `not_affected` claim.** VEX
   `not_affected` needs a justification from a fixed list, such as
   `code_not_present`, and dynamic analysis cannot prove an absence.
   Instead the findings document records the scan itself in `metadata`
   properties: coverage, the analyzer version, the runs and the verdict.
   An empty `vulnerabilities` list next to them says that the crate was
   checked and nothing was found, without claiming more.
6. **Data to add first:**
   * The fetcher computes SHA-512 while it downloads, next to SHA-256,
     into a new column `crate_files.sha512`.
   * `ManifestFacts` reads `license`, `license-file`, `repository` and
     `authors`. Old `/` separators become `OR` as crates.io does, and the
     result is checked with the `spdx` crate. A crate with only a licence
     file gets `LicenseRef-crateward-license-file`. Static reports from
     before are recomputed on demand through the analyzer version, like
     any other report change.
   * The backfill command downloads the `.crate` files of rows without
     SHA-512 from static.crates.io, checks them against the stored SHA-256
     and records the SHA-512. It runs only when the operator starts it.
7. **Own serde types instead of `cyclonedx-bom`.** The documents use a few
   dozen fields. Types for exactly those, with `deny_unknown_fields` off
   and tests against the official JSON schemas, are less work than
   waiting for or patching the library. Switching later stays possible,
   since the documents are the contract, not the types.
8. **Validation.** A test validates generated documents against the
   CycloneDX 1.6 JSON schema, vendored into the repository, so `cargo
   xtask ci` checks them offline. The GitHub workflow additionally runs
   `cyclonedx validate` from a pinned `cyclonedx-cli` release and a BSI
   TR-03183-2 check with sbomqs on a sample job's documents.

## Alternatives

* **Findings inside the SBOM.** One file is simpler to hand around, but
  BSI forbids vulnerability data in the SBOM, and every rescan would
  change it.
* **SPDX 3.0.1.** Also allowed by BSI, but its security profile is newer
  and less supported by tools than CycloneDX VEX, and the BSI taxonomy
  for CycloneDX already exists.
* **`cyclonedx-bom` or `cargo-cyclonedx`.** No 1.6 release yet, and
  `cargo-cyclonedx` runs `cargo metadata` on a workspace, which Crateward
  never does with an untrusted crate (ADR 0004).
* **Generating the SBOM on every request.** Pure and with no storage, but
  a later change to the generator would change a document that others
  may already reference by serial and version.
* **`not_affected` for clean crates.** It states more than a sandbox run
  can know (see 5).
* **CSAF instead of VEX.** TR-03183-3 asks vendors for CSAF advisories.
  Crateward is not the vendor of the crates it scans, and CycloneDX VEX
  links to the SBOM's components directly.

## Consequences

* A user can feed both files into `Dependency-Track` or another CycloneDX
  tool and see Crateward's behavior evidence next to each component.
* The SBOM is only as complete as the stored data. Until the backfill
  runs, older jobs have components without SHA-512 or licence, and the
  generator lists them in its log. Such a document is still valid
  CycloneDX but not TR-03183-2 compliant.
* Component creators are often unknown: `authors` is optional in
  `Cargo.toml` and frequently empty. The SBOM then falls back to the
  repository URL, or leaves the field out.
* Open question: the BSI taxonomy lists `bsi:component:effectiveLicence`.
  For a dual licence such as `MIT OR Apache-2.0` the effective licence is
  the user's choice, which Crateward cannot make. Until that is decided,
  it is left out.
* The CWE table is a judgment per signal and needs review like the
  scoring weights.
* One new table, one new column, one migration, and the `spdx` crate and
  a JSON schema validator as dependencies, each with a cargo vet
  exemption.

## Sources

* [BSI TR-03183-2 v2.1.0](https://www.bsi.bund.de/dok/TR-03183-en)
* [BSI CycloneDX property taxonomy](https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy)
* [CycloneDX 1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)
* [CycloneDX BOM link](https://cyclonedx.org/capabilities/bomlink/)
* [`cyclonedx-rust-cargo` pull request for 1.6](https://github.com/CycloneDX/cyclonedx-rust-cargo/pull/872)
* `crates/fetcher/src/resolve.rs`, `crates/fetcher/src/worker.rs`,
  `crates/static_analysis/src/manifest.rs`, `crates/core/src/verdict.rs`,
  `crates/core/src/store/verdicts.rs`, `crates/core/migrations/0002_fetch.sql`
