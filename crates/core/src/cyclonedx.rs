//! CycloneDX 1.6 documents (ADR 0012): an SBOM per crate version and
//! lockfile, which follows BSI TR-03183-2, and a findings document per job
//! whose entries point into that SBOM with BOM links.
//!
//! Both are pure functions of stored data, so tests need no database. The
//! types are `serde_json` values rather than a library's structs, since the
//! documents use only a few dozen fields.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::digest::Sha256Digest;
use crate::package::PackageMeta;
use crate::paths::site::DOMAIN;
use crate::store::Review;
use crate::text::{Utc, redact};
use crate::verdict::{Evidence, RiskLevel, Verdict};

/// The CycloneDX version the documents follow.
pub const SPEC_VERSION: &str = "1.6";

/// What a complete dependency graph means here: the consumer probe's
/// lockfile (ADR 0004).
pub const RESOLUTION: &str = "default features, all targets, no dev dependencies";

/// The source of the crates.io registry in a lockfile.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// A package of a lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locked {
    /// Package name.
    pub name: String,
    /// Version.
    pub version: String,
    /// SHA-256 of the `.crate` file. `None` for the probe, which has no
    /// source.
    pub checksum: Option<Sha256Digest>,
    /// Direct dependencies as the lockfile writes them: `name`,
    /// `name version` or `name version (source)`.
    pub dependencies: Vec<String>,
}

#[derive(Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockEntry>,
}

#[derive(Deserialize)]
struct LockEntry {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

/// The packages of a lockfile. `None` if it does not parse, or names a
/// source other than crates.io or a registry package without a checksum,
/// which the fetcher would have refused.
#[must_use]
pub fn locked(lockfile: &str) -> Option<Vec<Locked>> {
    let parsed: Lockfile = toml::from_str(lockfile).ok()?;

    parsed
        .package
        .into_iter()
        .map(|p| {
            let checksum = match p.source.as_deref() {
                None => None,
                Some(CRATES_IO) => Some(p.checksum?.parse().ok()?),
                Some(_) => return None,
            };

            Some(Locked {
                name: p.name,
                version: p.version,
                checksum,
                dependencies: p.dependencies,
            })
        })
        .collect()
}

/// What the store knows about a `.crate` file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileFacts {
    /// SHA-512 of the file, hex. `None` for files fetched before it was
    /// computed.
    pub sha512: Option<String>,
    /// The manifest's licence, authors and links. `None` while the file's
    /// static report is from an analyzer that did not read them.
    pub meta: Option<PackageMeta>,
}

/// Everything an SBOM is made from.
#[derive(Debug, Clone)]
pub struct SbomInput<'a> {
    /// The analyzed crate's name.
    pub name: &'a str,
    /// Its version.
    pub version: &'a str,
    /// SHA-256 of its `.crate` file.
    pub sha256: Sha256Digest,
    /// The probe's lockfile, `None` when resolution failed.
    pub lockfile: Option<&'a str>,
    /// Facts per `.crate` file, for the crate and its dependencies.
    pub files: &'a BTreeMap<Sha256Digest, FileFacts>,
    /// Seconds since the epoch.
    pub timestamp: i64,
    /// Crateward's version.
    pub tool_version: &'a str,
}

/// A generated SBOM.
#[derive(Debug, Clone, PartialEq)]
pub struct Sbom {
    /// `urn:uuid:...`, the same for every version of the document.
    pub serial: String,
    /// The document.
    pub document: Value,
    /// What TR-03183-2 asks for and the stored data lacks, one line each.
    /// Empty for a compliant document.
    pub gaps: Vec<String>,
}

/// The key an SBOM is stored under: the SHA-256 of the lockfile, or of
/// nothing when there is none. With the crate's own SHA-256 it names the
/// exact set of files the SBOM lists.
#[must_use]
pub fn lockfile_key(lockfile: Option<&str>) -> [u8; 32] {
    Sha256::digest(lockfile.unwrap_or_default().as_bytes()).into()
}

/// A UUID of version 8 (RFC 9562) from the SHA-256 of `parts`, so the
/// same inputs give the same serial number without storing it.
fn uuid(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }

    let hash: [u8; 32] = hasher.finalize().into();
    let mut bytes: Vec<u8> = hash.iter().take(16).copied().collect();
    if let Some(b) = bytes.get_mut(6) {
        *b = (*b & 0x0f) | 0x80;
    }

    if let Some(b) = bytes.get_mut(8) {
        *b = (*b & 0x3f) | 0x80;
    }

    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let part = |range: std::ops::Range<usize>| hex.get(range).unwrap_or_default().to_owned();

    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        part(0..8),
        part(8..12),
        part(12..16),
        part(16..20),
        part(20..32)
    )
}

/// The serial number of the SBOM of a crate file and lockfile.
#[must_use]
pub fn sbom_serial(sha256: &Sha256Digest, lockfile: Option<&str>) -> String {
    uuid(&[
        b"crateward sbom",
        sha256.as_bytes(),
        &lockfile_key(lockfile),
    ])
}

/// Percent encodes the characters of a version that a purl or URL path
/// does not take literally. Crate names are ASCII letters, digits, `-` and
/// `_`, which need nothing.
fn encode(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c.to_string()
            } else {
                let mut buf = [0_u8; 4];
                c.encode_utf8(&mut buf)
                    .bytes()
                    .map(|b| format!("%{b:02X}"))
                    .collect()
            }
        })
        .collect()
}

/// The purl of a crate version, which is also its `bom-ref`.
#[must_use]
pub fn purl(name: &str, version: &str) -> String {
    format!("pkg:cargo/{}@{}", encode(name), encode(version))
}

/// An absolute http or https URL from a manifest, or `None`.
fn web_url(text: Option<&str>) -> Option<String> {
    let url = url::Url::parse(text?.trim()).ok()?;

    matches!(url.scheme(), "http" | "https")
        .then(|| url.host_str().is_some())
        .filter(|host| *host)
        .map(|_| url.to_string())
}

/// The component creator as TR-03183-2 table 3 asks for it: an email
/// address, or else the project's web page. The crate's page on crates.io
/// always exists and names its owners. Returns the CycloneDX
/// `manufacturer` and where it came from.
fn creator(name: &str, meta: Option<&PackageMeta>) -> (Value, &'static str) {
    if let Some((author, email)) = meta.and_then(PackageMeta::author_email) {
        let contact = if author.is_empty() {
            json!({ "email": email })
        } else {
            json!({ "name": author, "email": email })
        };

        return (json!({ "contact": [contact] }), "authors");
    }

    let homepage = meta.and_then(|m| web_url(m.homepage.as_deref()));
    let repository = meta.and_then(|m| web_url(m.repository.as_deref()));
    let (url, source) = match (homepage, repository) {
        (Some(url), _) => (url, "homepage"),
        (None, Some(url)) => (url, "repository"),
        (None, None) => (format!("https://crates.io/crates/{name}"), "crates.io"),
    };

    (json!({ "url": [url] }), source)
}

/// The licence of a package as CycloneDX `licenses`, or why there is none.
///
/// The distribution licence is required and is `concluded` in CycloneDX.
/// The original licence is `declared`. For a crate both are the manifest's
/// expression. CycloneDX 1.6 allows one expression only, so both are
/// written only when the licence is a single identifier.
fn licences(meta: &PackageMeta) -> Result<Value, String> {
    let Some(raw) = meta.license.as_deref() else {
        return match &meta.license_file {
            Some(_) => Ok(json!([{
                "expression": "LicenseRef-crateward-license-file",
                "acknowledgement": "concluded",
            }])),
            None => Err("no licence".to_owned()),
        };
    };

    let canonical = spdx::Expression::canonicalize(raw)
        .map_err(|_| format!("licence `{raw}` is not an SPDX expression"))?
        .unwrap_or_else(|| raw.to_owned());

    let mode = spdx::ParseMode {
        allow_deprecated: true,
        ..spdx::ParseMode::STRICT
    };

    spdx::Expression::parse_mode(&canonical, mode)
        .map_err(|_| format!("licence `{raw}` is not an SPDX expression"))?;

    Ok(match spdx::license_id(&canonical) {
        Some(id) if id.name == canonical => json!([
            { "license": { "id": id.name, "acknowledgement": "concluded" } },
            { "license": { "id": id.name, "acknowledgement": "declared" } },
        ]),
        _ => json!([{ "expression": canonical, "acknowledgement": "concluded" }]),
    })
}

/// One component: the analyzed crate or a locked package.
fn component(
    name: &str,
    version: &str,
    sha256: Option<&Sha256Digest>,
    facts: Option<&FileFacts>,
    gaps: &mut Vec<String>,
) -> Value {
    let reference = purl(name, version);
    let mut gap = |what: &str| gaps.push(format!("{name} {version}: {what}"));
    let meta = facts.and_then(|f| f.meta.as_ref());

    let mut hashes = Vec::new();
    match facts.and_then(|f| f.sha512.as_deref()) {
        Some(sha512) => hashes.push(json!({ "alg": "SHA-512", "content": sha512 })),
        None => gap("no SHA-512"),
    }

    if let Some(sha256) = sha256 {
        hashes.push(json!({ "alg": "SHA-256", "content": sha256.to_string() }));
    }

    let (manufacturer, creator_source) = creator(name, meta);
    let filename = format!("{name}-{version}.crate");

    // TR-03183-2 puts the deployable file's hash on its distribution
    // reference. A `.crate` file is also the crate's source code, so the
    // same file is its source distribution.
    let url = format!(
        "https://static.crates.io/crates/{name}/{name}-{}.crate",
        encode(version)
    );

    let mut references = vec![
        json!({ "type": "distribution", "url": url, "hashes": hashes }),
        json!({ "type": "source-distribution", "url": url, "hashes": hashes }),
    ];

    if let Some(url) = meta.and_then(|m| web_url(m.repository.as_deref())) {
        references.push(json!({ "type": "vcs", "url": url }));
    }

    if let Some(url) = meta.and_then(|m| web_url(m.homepage.as_deref())) {
        references.push(json!({ "type": "website", "url": url }));
    }

    let mut properties = vec![
        json!({ "name": "bsi:component:filename", "value": filename }),
        json!({ "name": "bsi:component:executable", "value": "non-executable" }),
        json!({ "name": "bsi:component:archive", "value": "archive" }),
        json!({ "name": "bsi:component:structured", "value": "structured" }),
        json!({ "name": "crateward:creator", "value": creator_source }),
    ];

    let mut component = Map::new();
    component.insert("type".into(), json!("library"));
    component.insert("bom-ref".into(), json!(reference));
    component.insert("manufacturer".into(), manufacturer);
    component.insert("name".into(), json!(name));
    component.insert("version".into(), json!(version));
    component.insert("purl".into(), json!(reference));

    match meta {
        None => gap("no licence and authors yet, the static report predates them"),
        Some(meta) => {
            if let Some(file) = &meta.license_file {
                properties.push(json!({ "name": "crateward:license-file", "value": file }));
            }

            match licences(meta) {
                Ok(licences) => {
                    component.insert("licenses".into(), licences);
                }
                Err(why) => gap(&why),
            }
        }
    }

    component.insert("hashes".into(), Value::Array(hashes));
    component.insert("externalReferences".into(), Value::Array(references));
    component.insert("properties".into(), Value::Array(properties));
    Value::Object(component)
}

/// The `bom-ref` a lockfile dependency entry names, given the packages by
/// name.
fn resolve(entry: &str, by_name: &BTreeMap<&str, Vec<&str>>) -> Option<String> {
    let mut words = entry.split_whitespace();
    let name = words.next()?;
    let version = match words.next() {
        Some(version) => version,
        None => match by_name.get(name)?.as_slice() {
            [only] => only,
            _ => return None,
        },
    };

    Some(purl(name, version))
}

/// The SBOM of a crate version.
#[must_use]
pub fn sbom(input: &SbomInput<'_>) -> Sbom {
    let mut gaps = Vec::new();
    let root_ref = purl(input.name, input.version);
    let root = component(
        input.name,
        input.version,
        Some(&input.sha256),
        input.files.get(&input.sha256),
        &mut gaps,
    );

    let packages = input.lockfile.map(|text| locked(text).ok_or(()));
    let (components, dependencies, aggregate) = match packages {
        Some(Ok(packages)) => {
            let registry: Vec<&Locked> = packages.iter().filter(|p| p.checksum.is_some()).collect();
            let mut by_name: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for p in &registry {
                by_name.entry(&p.name).or_default().push(&p.version);
            }

            let components: Vec<Value> = registry
                .iter()
                .filter(|p| purl(&p.name, &p.version) != root_ref)
                .map(|p| {
                    let sha = p.checksum.as_ref();
                    let facts = sha.and_then(|s| input.files.get(s));
                    component(&p.name, &p.version, sha, facts, &mut gaps)
                })
                .collect();

            let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            graph.entry(root_ref.clone()).or_default();

            for p in &registry {
                let targets = p.dependencies.iter().filter_map(|d| resolve(d, &by_name));
                graph
                    .entry(purl(&p.name, &p.version))
                    .or_default()
                    .extend(targets);
            }

            (components, graph, "complete")
        }
        Some(Err(())) => {
            gaps.push("the lockfile does not parse".to_owned());
            (Vec::new(), single(&root_ref), "unknown")
        }
        None => {
            gaps.push("cargo could not resolve the dependencies".to_owned());
            (Vec::new(), single(&root_ref), "unknown")
        }
    };

    let all: Vec<&String> = dependencies.keys().collect();
    let serial = sbom_serial(&input.sha256, input.lockfile);
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": Utc::from_epoch(input.timestamp).rfc3339(),
            "tools": { "components": [tool(input.tool_version)] },
            "manufacturer": { "name": "Crateward", "url": [format!("https://{DOMAIN}")] },
            "component": root,
            "properties": [{ "name": "crateward:resolution", "value": RESOLUTION }],
        },
        "components": components,
        "dependencies": dependencies
            .iter()
            .map(|(r, on)| json!({ "ref": r, "dependsOn": on }))
            .collect::<Vec<_>>(),
        "compositions": [{ "aggregate": aggregate, "dependencies": all }],
    });

    Sbom {
        serial,
        document,
        gaps,
    }
}

/// A graph of only the analyzed crate, with unknown dependencies.
fn single(root: &str) -> BTreeMap<String, BTreeSet<String>> {
    BTreeMap::from([(root.to_owned(), BTreeSet::new())])
}

/// Crateward as the tool that wrote a document.
fn tool(version: &str) -> Value {
    json!({
        "type": "application",
        "name": "crateward",
        "version": version,
        "externalReferences": [{ "type": "website", "url": format!("https://{DOMAIN}") }],
    })
}

/// Everything a findings document is made from.
#[derive(Debug, Clone)]
pub struct VexInput<'a> {
    /// The job.
    pub job: i64,
    /// The crate's name.
    pub name: &'a str,
    /// Its version.
    pub version: &'a str,
    /// The SBOM's serial number and version the entries point into.
    pub sbom: (&'a str, i32),
    /// The probe's lockfile, to find a responsible package's version.
    pub lockfile: Option<&'a str>,
    /// The verdict.
    pub verdict: &'a Verdict,
    /// Its review.
    pub review: Review,
    /// How often the verdict or its review changed, from 1.
    pub revision: i32,
    /// The published finding's page, if there is one.
    pub finding_url: Option<&'a str>,
    /// The job's honeytokens, redacted from every text.
    pub honeytokens: &'a [String],
    /// The coverage label.
    pub coverage: &'a str,
    /// The kinds of runs the job had.
    pub runs: &'a [String],
    /// Seconds since the epoch of the last change.
    pub timestamp: i64,
    /// Crateward's version.
    pub tool_version: &'a str,
}

/// The serial number of a job's findings document.
#[must_use]
pub fn vex_serial(job: i64) -> String {
    uuid(&[b"crateward vex", &job.to_be_bytes()])
}

/// The CWEs a signal stands for, where one fits. Signals that are only
/// unusual, such as a network lookup, have none. A confirmed finding is
/// also CWE-506, embedded malicious code.
fn cwes(signal: &str, review: Review) -> Vec<u32> {
    let mut cwes = match signal {
        "honeytoken_left_vm" | "honeytoken_copied" => vec![200],
        "environment_dumped" => vec![526],
        "became_root" | "disk_setid" => vec![269],
        _ => Vec::new(),
    };

    if review == Review::Confirmed {
        cwes.push(506);
    }

    cwes
}

/// The severity of a signal by its own points, as the verdict's levels
/// rate a score.
fn severity(points: u32) -> &'static str {
    match RiskLevel::from_score(points) {
        RiskLevel::None => "info",
        level => level.name(),
    }
}

/// The findings document of a job: one vulnerability per signal that
/// scored points, pointing at the responsible packages in the SBOM. A job
/// without such evidence has an empty list and says in `metadata` what was
/// checked, without claiming `not_affected` (ADR 0012).
#[must_use]
pub fn vex(input: &VexInput<'_>) -> Value {
    let root = purl(input.name, input.version);
    let (serial, sbom_version) = input.sbom;
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in input.lockfile.and_then(locked).unwrap_or_default() {
        if p.checksum.is_some() {
            versions.entry(p.name).or_default().push(p.version);
        }
    }

    let mut by_signal: BTreeMap<&str, Vec<&Evidence>> = BTreeMap::new();
    for e in input.verdict.evidence.iter().filter(|e| e.points > 0) {
        by_signal.entry(&e.signal).or_default().push(e);
    }

    let link = |reference: &str| {
        format!(
            "urn:cdx:{}/{sbom_version}#{reference}",
            serial.trim_start_matches("urn:uuid:")
        )
    };

    let state = match input.review {
        Review::None | Review::Pending => "in_triage",
        Review::Confirmed => "exploitable",
        Review::FalsePositive => "false_positive",
    };

    let source_url = input
        .finding_url
        .map_or_else(|| format!("https://{DOMAIN}"), str::to_owned);

    let vulnerabilities: Vec<Value> = by_signal
        .into_iter()
        .map(|(signal, evidence)| {
            let points: u32 = evidence.iter().map(|e| e.points).sum();
            let affects: BTreeSet<String> = evidence
                .iter()
                .flat_map(|e| match e.package.as_deref() {
                    Some(name) => versions
                        .get(name)
                        .map(|vs| vs.iter().map(|v| purl(name, v)).collect())
                        .unwrap_or_else(|| vec![root.clone()]),
                    None => vec![root.clone()],
                })
                .collect();

            let description = evidence
                .iter()
                .map(|e| redact(&e.summary, input.honeytokens))
                .collect::<Vec<_>>()
                .join("\n");

            let mut properties = vec![
                json!({ "name": "crateward:signal", "value": signal }),
                json!({ "name": "crateward:points", "value": points.to_string() }),
            ];
            for e in &evidence {
                properties.push(json!({ "name": "crateward:source", "value": e.source.name() }));

                if let Some(location) = &e.location {
                    properties.push(json!({
                        "name": "crateward:location",
                        "value": redact(location, input.honeytokens),
                    }));
                }
            }

            let id = format!("CW-{}-{signal}", input.job);
            let mut entry = json!({
                "bom-ref": id,
                "id": id,
                "source": { "name": "Crateward", "url": source_url },
                "ratings": [{
                    "source": { "name": "Crateward" },
                    "severity": severity(points),
                    "method": "other",
                }],
                "description": description,
                "affects": affects.iter().map(|r| json!({ "ref": link(r) })).collect::<Vec<_>>(),
                "analysis": { "state": state },
                "properties": properties,
            });

            let cwes = cwes(signal, input.review);
            if !cwes.is_empty()
                && let Some(entry) = entry.as_object_mut()
            {
                entry.insert("cwes".into(), json!(cwes));
            }

            entry
        })
        .collect();

    let verdict = input.verdict;

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": vex_serial(input.job),
        "version": input.revision.max(1),
        "metadata": {
            "timestamp": Utc::from_epoch(input.timestamp).rfc3339(),
            "tools": { "components": [tool(input.tool_version)] },
            "manufacturer": { "name": "Crateward", "url": [format!("https://{DOMAIN}")] },
            "component": {
                "type": "library",
                "bom-ref": root,
                "name": input.name,
                "version": input.version,
                "purl": root,
            },
            "properties": [
                { "name": "crateward:sbom", "value": link("").trim_end_matches('#') },
                { "name": "crateward:score", "value": verdict.score.to_string() },
                { "name": "crateward:level", "value": verdict.level.name() },
                { "name": "crateward:coverage", "value": input.coverage },
                { "name": "crateward:runs", "value": input.runs.join(", ") },
                { "name": "crateward:review", "value": input.review.name() },
                { "name": "crateward:analyzer-version", "value": verdict.analyzer_version.to_string() },
            ],
        },
        "vulnerabilities": vulnerabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Coverage, EvidenceSource};

    const LOCK: &str = r#"
version = 4

[[package]]
name = "crateward-probe"
version = "0.0.0"
dependencies = ["foo"]

[[package]]
name = "foo"
version = "1.2.3+build"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
dependencies = ["bar 0.1.0", "bar 0.2.0", "baz"]

[[package]]
name = "bar"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"

[[package]]
name = "bar"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3333333333333333333333333333333333333333333333333333333333333333"

[[package]]
name = "baz"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4444444444444444444444444444444444444444444444444444444444444444"
dependencies = ["bar 0.2.0 (registry+https://github.com/rust-lang/crates.io-index)"]
"#;

    fn sha(digit: char) -> Sha256Digest {
        digit.to_string().repeat(64).parse().unwrap()
    }

    fn facts(license: Option<&str>, authors: &[&str], repository: Option<&str>) -> FileFacts {
        FileFacts {
            sha512: Some("ab".repeat(64)),
            meta: Some(PackageMeta {
                license: license.map(str::to_owned),
                authors: authors.iter().map(|a| (*a).to_owned()).collect(),
                repository: repository.map(str::to_owned),
                ..PackageMeta::default()
            }),
        }
    }

    fn files() -> BTreeMap<Sha256Digest, FileFacts> {
        BTreeMap::from([
            (
                sha('1'),
                facts(Some("MIT/Apache-2.0"), &["Ann <ann@example.com>"], None),
            ),
            (
                sha('2'),
                facts(Some("MIT"), &[], Some("https://github.com/x/bar")),
            ),
            (sha('3'), FileFacts::default()),
            (
                sha('4'),
                facts(Some("not a licence"), &["Bob"], Some("javascript:alert(1)")),
            ),
        ])
    }

    fn input<'a>(
        lockfile: Option<&'a str>,
        files: &'a BTreeMap<Sha256Digest, FileFacts>,
    ) -> SbomInput<'a> {
        SbomInput {
            name: "foo",
            version: "1.2.3+build",
            sha256: sha('1'),
            lockfile,
            files,
            timestamp: 1_790_000_000,
            tool_version: "0.1.0",
        }
    }

    fn component<'a>(doc: &'a Value, purl: &str) -> &'a Value {
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["purl"] == purl)
            .unwrap()
    }

    fn property<'a>(c: &'a Value, name: &str) -> &'a str {
        c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .and_then(|p| p["value"].as_str())
            .unwrap()
    }

    #[test]
    fn the_sbom_lists_every_locked_package_with_the_graph() {
        let files = files();
        let sbom = sbom(&input(Some(LOCK), &files));
        let doc = &sbom.document;

        assert_eq!(doc["specVersion"], "1.6");
        assert_eq!(doc["serialNumber"], sbom.serial);
        assert_eq!(doc["metadata"]["timestamp"], "2026-09-21T14:13:20Z");
        assert_eq!(
            doc["metadata"]["manufacturer"]["url"][0],
            "https://crateward.com"
        );

        let root = &doc["metadata"]["component"];
        assert_eq!(root["purl"], "pkg:cargo/foo@1.2.3%2Bbuild");
        assert_eq!(
            root["licenses"],
            json!([{ "expression": "MIT OR Apache-2.0", "acknowledgement": "concluded" }])
        );
        assert_eq!(
            root["manufacturer"]["contact"][0]["email"],
            "ann@example.com"
        );
        assert_eq!(
            property(root, "bsi:component:filename"),
            "foo-1.2.3+build.crate"
        );
        assert_eq!(property(root, "crateward:creator"), "authors");
        assert_eq!(
            root["externalReferences"][0]["url"],
            "https://static.crates.io/crates/foo/foo-1.2.3%2Bbuild.crate"
        );
        let sha512 = json!({ "alg": "SHA-512", "content": "ab".repeat(64) });
        assert_eq!(root["externalReferences"][0]["type"], "distribution");
        assert_eq!(root["externalReferences"][0]["hashes"][0], sha512);
        assert_eq!(root["externalReferences"][1]["type"], "source-distribution");
        assert_eq!(root["hashes"][0], sha512);

        let purls: Vec<&str> = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["purl"].as_str().unwrap())
            .collect();
        assert_eq!(
            purls,
            [
                "pkg:cargo/bar@0.1.0",
                "pkg:cargo/bar@0.2.0",
                "pkg:cargo/baz@1.0.0"
            ]
        );

        let graph: BTreeMap<&str, &Value> = doc["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| (d["ref"].as_str().unwrap(), &d["dependsOn"]))
            .collect();
        assert_eq!(
            graph["pkg:cargo/foo@1.2.3%2Bbuild"],
            &json!([
                "pkg:cargo/bar@0.1.0",
                "pkg:cargo/bar@0.2.0",
                "pkg:cargo/baz@1.0.0"
            ])
        );
        assert_eq!(
            graph["pkg:cargo/baz@1.0.0"],
            &json!(["pkg:cargo/bar@0.2.0"])
        );
        assert_eq!(graph["pkg:cargo/bar@0.1.0"], &json!([]));
        assert_eq!(doc["compositions"][0]["aggregate"], "complete");
        assert_eq!(
            doc["compositions"][0]["dependencies"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn a_single_licence_is_both_distribution_and_original_licence() {
        let files = files();
        let doc = sbom(&input(Some(LOCK), &files)).document;
        let bar = component(&doc, "pkg:cargo/bar@0.1.0");

        assert_eq!(
            bar["licenses"],
            json!([
                { "license": { "id": "MIT", "acknowledgement": "concluded" } },
                { "license": { "id": "MIT", "acknowledgement": "declared" } },
            ])
        );
        assert_eq!(
            bar["manufacturer"],
            json!({ "url": ["https://github.com/x/bar"] })
        );
        assert_eq!(
            bar["externalReferences"][2],
            json!({ "type": "vcs", "url": "https://github.com/x/bar" })
        );
    }

    #[test]
    fn missing_facts_are_gaps_and_creators_fall_back_to_crates_io() {
        let files = files();
        let sbom = sbom(&input(Some(LOCK), &files));

        let old = component(&sbom.document, "pkg:cargo/bar@0.2.0");
        assert_eq!(
            old["manufacturer"],
            json!({ "url": ["https://crates.io/crates/bar"] })
        );
        assert!(old.get("licenses").is_none());
        assert_eq!(old["hashes"].as_array().unwrap().len(), 1);

        let odd = component(&sbom.document, "pkg:cargo/baz@1.0.0");
        assert_eq!(property(odd, "crateward:creator"), "crates.io");
        assert!(odd.get("licenses").is_none());
        assert_eq!(odd["externalReferences"].as_array().unwrap().len(), 2);

        assert_eq!(
            sbom.gaps,
            [
                "bar 0.2.0: no SHA-512",
                "bar 0.2.0: no licence and authors yet, the static report predates them",
                "baz 1.0.0: licence `not a licence` is not an SPDX expression",
            ]
        );
    }

    #[test]
    fn without_a_lockfile_the_graph_is_unknown() {
        let files = files();
        let sbom = sbom(&input(None, &files));

        assert_eq!(sbom.document["components"], json!([]));
        assert_eq!(sbom.document["compositions"][0]["aggregate"], "unknown");
        assert_eq!(
            sbom.document["dependencies"],
            json!([{ "ref": "pkg:cargo/foo@1.2.3%2Bbuild", "dependsOn": [] }])
        );
        assert_eq!(sbom.gaps, ["cargo could not resolve the dependencies"]);
    }

    #[test]
    fn serials_are_stable_uuids_per_crate_and_lockfile() {
        let a = sbom_serial(&sha('1'), Some(LOCK));

        assert_eq!(a, sbom_serial(&sha('1'), Some(LOCK)));
        assert_ne!(a, sbom_serial(&sha('1'), None));
        assert_ne!(a, sbom_serial(&sha('2'), Some(LOCK)));
        assert_ne!(vex_serial(1), vex_serial(2));

        let uuid = a.strip_prefix("urn:uuid:").unwrap();
        let groups: Vec<usize> = uuid.split('-').map(str::len).collect();
        assert_eq!(groups, [8, 4, 4, 4, 12]);
        assert_eq!(uuid.chars().nth(14), Some('8'));
        assert!(matches!(uuid.chars().nth(19), Some('8' | '9' | 'a' | 'b')));
    }

    fn evidence(signal: &str, points: u32, package: Option<&str>, summary: &str) -> Evidence {
        Evidence {
            signal: signal.to_owned(),
            points,
            source: EvidenceSource::Network,
            summary: summary.to_owned(),
            package: package.map(str::to_owned),
            location: Some("10.0.0.1:443".to_owned()),
        }
    }

    fn verdict(evidence: Vec<Evidence>) -> Verdict {
        let score = evidence.iter().map(|e| e.points).sum::<u32>().min(100);

        Verdict {
            score,
            level: RiskLevel::from_score(score),
            coverage: Coverage::DynamicLinux,
            evidence,
            profile: Vec::new(),
            new_behavior: Vec::new(),
            analyzer_version: 7,
        }
    }

    fn vex_input<'a>(verdict: &'a Verdict, review: Review, tokens: &'a [String]) -> VexInput<'a> {
        VexInput {
            job: 42,
            name: "foo",
            version: "1.2.3+build",
            sbom: ("urn:uuid:0000aaaa-0000-8000-8000-000000000000", 2),
            lockfile: Some(LOCK),
            verdict,
            review,
            revision: 3,
            finding_url: None,
            honeytokens: tokens,
            coverage: "dynamic linux",
            runs: &[],
            timestamp: 0,
            tool_version: "0.1.0",
        }
    }

    #[test]
    fn findings_point_into_the_sbom_per_signal() {
        let verdict = verdict(vec![
            evidence("honeytoken_left_vm", 60, Some("bar"), "bar sent ghp_secret"),
            evidence("honeytoken_left_vm", 10, None, "foo sent it too"),
            evidence(
                "network_lookup",
                5,
                Some("unknown"),
                "looked up example.com",
            ),
            evidence("network_quiet", 0, None, "nothing"),
        ]);

        let tokens = ["ghp_secret".to_owned()];
        let doc = vex(&vex_input(&verdict, Review::Confirmed, &tokens));

        assert_eq!(doc["version"], 3);
        assert_eq!(doc["serialNumber"], vex_serial(42));
        let list = doc["vulnerabilities"].as_array().unwrap();
        assert_eq!(list.len(), 2);

        let token = &list[0];
        assert_eq!(token["id"], "CW-42-honeytoken_left_vm");
        assert_eq!(token["ratings"][0]["severity"], "high");
        assert_eq!(token["cwes"], json!([200, 506]));
        assert_eq!(token["analysis"]["state"], "exploitable");
        assert_eq!(
            token["description"],
            "bar sent [honeytoken]\nfoo sent it too"
        );
        assert_eq!(
            token["affects"],
            json!([
                { "ref": "urn:cdx:0000aaaa-0000-8000-8000-000000000000/2#pkg:cargo/bar@0.1.0" },
                { "ref": "urn:cdx:0000aaaa-0000-8000-8000-000000000000/2#pkg:cargo/bar@0.2.0" },
                { "ref": "urn:cdx:0000aaaa-0000-8000-8000-000000000000/2#pkg:cargo/foo@1.2.3%2Bbuild" },
            ])
        );

        let lookup = &list[1];
        assert_eq!(lookup["ratings"][0]["severity"], "low");
        assert_eq!(lookup["cwes"], json!([506]));
        assert_eq!(
            lookup["affects"][0]["ref"],
            "urn:cdx:0000aaaa-0000-8000-8000-000000000000/2#pkg:cargo/foo@1.2.3%2Bbuild"
        );
        assert!(!doc.to_string().contains("ghp_secret"));
    }

    #[test]
    fn a_clean_crate_has_no_vulnerabilities_but_says_what_was_checked() {
        let verdict = verdict(vec![evidence("network_quiet", 0, None, "nothing")]);
        let doc = vex(&vex_input(&verdict, Review::None, &[]));

        assert_eq!(doc["vulnerabilities"], json!([]));
        let properties = &doc["metadata"]["properties"];
        assert_eq!(
            properties[0],
            json!({ "name": "crateward:sbom", "value": "urn:cdx:0000aaaa-0000-8000-8000-000000000000/2" })
        );
        assert_eq!(
            properties[3],
            json!({ "name": "crateward:coverage", "value": "dynamic linux" })
        );
    }

    #[test]
    fn review_states_map_to_vex_states() {
        let verdict = verdict(vec![evidence("became_root", 50, None, "root")]);
        let state = |review| {
            vex(&vex_input(&verdict, review, &[]))["vulnerabilities"][0]["analysis"]["state"]
                .clone()
        };

        assert_eq!(state(Review::None), "in_triage");
        assert_eq!(state(Review::Pending), "in_triage");
        assert_eq!(state(Review::FalsePositive), "false_positive");
    }
}
