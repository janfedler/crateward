# 0012: A CycloneDX SBOM and a separate findings document per job

* Status: Accepted
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
  `bsi:component:archive` and `bsi:component:structured`. A component
  without dependencies still needs an empty entry in the graph.
* The component creator is the email address of whoever created and
  maintains it. Without one it MUST be a URL, "e.g. the creator's home
  page or the project's web page" (table 3). A maintainer who took over a
  project counts as its creator (section 8.1.8). In CycloneDX it is the
  component's `manufacturer`, with either `url` or `contact.email`.
* Licences come in three kinds. The distribution licence is required and
  maps to `acknowledgement: concluded`. The original licence, as the
  creator assigned it, is required when known and maps to `declared`. The
  effective licence, the one the SBOM's creator chose, is optional.
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
* **Licences, authors, links.** Every locked package gets a static
  report (`static_reports`), but `ManifestFacts` does not read `license`,
  `license-file`, `authors`, `homepage` or `repository` yet. `authors` is
  optional and empty in many crates.
* **Findings.** A verdict's evidence names a signal, a summary, a source
  and the responsible package by name only (`Evidence.package`). The
  review state is `none`, `pending`, `confirmed` or `false_positive`, and
  a published finding has a page under `crateward.com/findings/<slug>/`.
  There is no packet capture. Network evidence comes from the fake
  internet's log, and each job has at most one check run and one full run.

The Rust library `cyclonedx-bom` supports spec 1.3 to 1.5 in its current
release. Support for 1.6 is an open pull request.

## Decision

1. **Two documents per job.** The SBOM, `{name}-{version}.cdx.json`, and
   Crateward's findings, `{name}-{version}.vex.cdx.json`. The dashboard
   serves them at `/jobs/{id}/sbom.cdx.json` and `/jobs/{id}/vex.cdx.json`
   and links them from the job page. The archive writes them as
   `jobs/{id}.cdx.json` and `jobs/{id}.vex.cdx.json` next to each job
   page, so they outlive the server. `crateward sbom <job> --out <dir>`
   writes both for one job. The builders are pure functions in
   `crateward_core::cyclonedx`.
2. **The SBOM** is CycloneDX 1.6 JSON:
   * `metadata`: timestamp, the tool `crateward` with its version, and
     Crateward as the `manufacturer` with the site URL, since BSI wants an
     email address or URL, not a bare name. The analyzed crate is
     `metadata.component`.
   * One component per locked package. Its `bom-ref` and `purl` are
     `pkg:cargo/{name}@{version}`. The SHA-512 and SHA-256 of the `.crate`
     file are on the component and, as the TR's mapping wants them, on
     its `distribution` reference to static.crates.io. A `.crate` file is
     also the crate's source code, so the same URL and hashes are its
     `source-distribution`. A `vcs` reference comes from `repository` and
     a `website` from `homepage`. The four `bsi:component:*` properties
     say `non-executable`, `archive` and `structured`, with the file name.
   * The licence comes from `Cargo.toml`, normalized and checked with the
     `spdx` crate, so `MIT/Apache-2.0` becomes `MIT OR Apache-2.0`. A
     crate's users get it under the licence its author assigned, so the
     distribution licence (`concluded`) and the original licence
     (`declared`) are the same. CycloneDX 1.6 holds only one expression
     per component, so a compound expression is written once, as
     `concluded`, the required one. A single identifier is written as
     both. A crate with only a licence file gets
     `LicenseRef-crateward-license-file`. The effective licence is
     optional and left out: for `MIT OR Apache-2.0` it is a choice that
     only the crate's user makes.
   * The component creator is the first of these that exists: an email
     address from `authors`, `homepage`, `repository`, and the crate's page
     on crates.io. The last always exists, names the crate's owners and is
     the project's web page in the registry, so no component is without a
     creator. The property `crateward:creator` says which one was used.
   * `dependencies` gives each package's edges from the lockfile, with an
     empty `dependsOn` for packages without dependencies.
   * `compositions` declares the graph `complete` for every package. The
     property `crateward:resolution` says what complete means here:
     default features, all targets, no dev dependencies. A job without a
     lockfile lists only the crate itself, with the aggregate `unknown`.
3. **The SBOM is stored and changes only to become complete.** Finalize
   writes it into the table `sboms`, keyed by the crate's SHA-256 and the
   SHA-256 of the lockfile, so a rescan with the same lockfile shares it.
   Its `serialNumber` is a UUID derived from that key. The builder lists
   what the data lacks for TR-03183-2 as gaps. A complete document never
   changes. One with gaps is built again when the analyzer is idle, at
   most daily, and replaced with the next `version` only when it lacks
   less. The same sweep writes the SBOMs of jobs finished before this
   change.
4. **The findings document** is a CycloneDX 1.6 BOM with only
   `vulnerabilities`, built on read from the verdict and the review, since
   a review can change after the scan.
   * Its `serialNumber` is a UUID derived from the job id. `version` is
     `verdicts.revision`, which counts changes of the verdict and its
     review, plus one once the finding is published.
   * One entry per evidence signal with points. The `id` is
     `CW-{job}-{signal}`, and `source` names Crateward with the site, or
     the finding page once the finding is published.
   * `affects` points at the components with BOM links of the form
     `urn:cdx:{serial}/{version}#pkg:cargo/{name}@{version}`. Evidence
     without a package affects the analyzed crate. A name that the
     lockfile holds in two versions affects both.
   * `ratings` has the severity of the signal's own points, on the
     verdict's scale, with the method `other`. `cwes` comes from a table
     per signal: CWE-200 for honeytokens, CWE-526 for a dumped
     environment, CWE-269 for root and set ID files, and CWE-506 on every
     entry of a confirmed finding. `description` holds the evidence
     summaries. `properties` in the `crateward:` namespace hold the
     signal, the points, the sources and the locations. Honeytokens are
     redacted as on the pages.
   * `analysis.state` follows the review: `in_triage` for no review or a
     pending one, `exploitable` for confirmed, `false_positive` for false
     positive.
5. **A crate without evidence gets no `not_affected` claim.** VEX
   `not_affected` needs a justification from a fixed list, such as
   `code_not_present`, and dynamic analysis cannot prove an absence.
   Instead the findings document records the scan in `metadata`
   properties: the SBOM it belongs to, score, level, coverage, runs,
   review and analyzer version. An empty `vulnerabilities` list next to
   them says that the crate was checked and nothing was found, without
   claiming more.
6. **The data behind it:**
   * The fetcher computes SHA-512 while it downloads, next to SHA-256,
     into `crate_files.sha512`. When it has no job, it downloads files
     fetched before that again, one at a time at the configured rate,
     checks them against the stored SHA-256 and records their SHA-512.
   * `ManifestFacts` reads `license`, `license-file`, `authors`,
     `homepage` and `repository`. The static analyzer version is 8, so
     older reports are analyzed again. The idle refresh now includes the
     files of dependencies, after the scored jobs' own files.
7. **Own types instead of `cyclonedx-bom`.** The documents use a few dozen
   fields, built as `serde_json` values. Switching later stays possible,
   since the documents are the contract, not the types.
8. **Validation in the GitHub workflow.** A test writes a sample SBOM and
   findings document from Crateward's own lockfile. The `cyclonedx` job
   validates both with a pinned `cyclonedx-cli` against the 1.6 schema,
   and checks the SBOM against TR-03183-2 v2.1.0 with a pinned sbomqs.
   The sample scores 9.8 of 10 there. The licence fields are left out of
   the gate: compound expressions lack the `declared` copy (see 2), and
   sbomqs rejects `WITH` exceptions, which the TR allows.

## Alternatives

* **Findings inside the SBOM.** One file is simpler to hand around, but
  BSI forbids vulnerability data in the SBOM, and every rescan would
  change it.
* **SPDX 3.0.1.** Also allowed by BSI, but its security profile is newer
  and less supported by tools than CycloneDX VEX, and the BSI taxonomy
  for CycloneDX already exists.
* **CycloneDX 1.7.** It allows several licence expressions, so a
  compound licence could be both `concluded` and `declared`. The TR's
  mapping tables use 1.6, and fewer tools read 1.7 yet. Moving is a
  change of `SPEC_VERSION` and the licence builder.
* **`cyclonedx-bom` or `cargo-cyclonedx`.** No 1.6 release yet, and
  `cargo-cyclonedx` runs `cargo metadata` on a workspace, which Crateward
  never does with an untrusted crate (ADR 0004).
* **A JSON schema validator as a dev dependency.** It would check the
  schema in `cargo xtask ci` offline, but `jsonschema` brings about 25
  crates the workspace does not have. The workflow's `cyclonedx-cli`
  checks the same schema.
* **A backfill command for SHA-512.** It would need the crates.io
  downloads and egress the fetcher already has. The fetcher's idle time
  does the same without an operator.
* **Generating the SBOM on every request.** Pure and with no storage, but
  a later change to the generator would change a document that others
  may already reference by serial and version.
* **The owners' GitHub profiles as creators.** The crates.io owners API
  returns each owner's GitHub login, and `https://github.com/{login}` is
  the creator's home page in the TR's sense. It costs one API request per
  crate name at the one request per second crates.io allows, and owners
  change over time, so the SBOM would depend on when it was made. The
  crate's page on crates.io lists the same owners without a request.
* **`not_affected` for clean crates.** It states more than a sandbox run
  can know (see 5).
* **CSAF instead of VEX.** TR-03183-3 asks vendors for CSAF advisories.
  Crateward is not the vendor of the crates it scans, and CycloneDX VEX
  links to the SBOM's components directly.

## Consequences

* A user can feed both files into `Dependency-Track` or another CycloneDX
  tool and see Crateward's behavior evidence next to each component.
* After the deploy, the static refresh analyzes every stored report
  again, dependencies included, and the verdicts built on them are
  scored again. Burst mode speeds that up. Until it is done, and until
  the fetcher has hashed older files, older SBOMs have gaps. They are
  valid CycloneDX but not TR-03183-2 compliant, and the sweep replaces
  them as the data arrives.
* Every component has a creator, but for crates without `authors`,
  `homepage` and `repository` it is only the crates.io page. That meets
  the TR's wording, though a reader learns less from it than from an
  address.
* The CWE table is a judgment per signal and needs review like the
  scoring weights.
* Migration 13 adds the table `sboms` and the columns
  `crate_files.sha512`, `job_fetches.lockfile_key` and
  `verdicts.revision`. The `spdx` crate is a new dependency.

## Sources

* [BSI TR-03183-2 v2.1.0](https://www.bsi.bund.de/dok/TR-03183-en)
* [BSI CycloneDX property taxonomy](https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy)
* [CycloneDX 1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)
* [CycloneDX BOM link](https://cyclonedx.org/capabilities/bomlink/)
* [`cyclonedx-rust-cargo` pull request for 1.6](https://github.com/CycloneDX/cyclonedx-rust-cargo/pull/872)
* [CycloneDX 1.7 licence choice](https://cyclonedx.org/docs/1.7/json/)
* [`cyclonedx-cli`](https://github.com/CycloneDX/cyclonedx-cli) and
  [sbomqs](https://github.com/interlynk-io/sbomqs)
* `crates/core/src/cyclonedx.rs`, `crates/core/src/store/sbom.rs`,
  `crates/fetcher/src/worker.rs`, `crates/static_analysis/src/manifest.rs`,
  `crates/core/migrations/0013_cyclonedx.sql`
