//! What static analysis stores about a crate file: its manifest facts and
//! findings, and the diff against the previous version.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::package::PackageMeta;
use crate::report::findings::{CodeContext, Finding, Platform, Severity};

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
    /// [`STATIC_ANALYZER_VERSION`](crate::verdict::STATIC_ANALYZER_VERSION)
    /// that produced it.
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
    /// Findings dropped beyond the analysis limit.
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

/// What the manifest says about build time code and platforms.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFacts {
    /// Path of the build script, if any.
    pub build_script: Option<String>,
    /// Whether the library is a proc macro.
    pub proc_macro: bool,
    /// The `links` key.
    pub links: Option<String>,
    /// Edition.
    pub edition: Option<String>,
    /// Dependencies per `cfg` or target triple of `[target.*]` tables.
    pub target_dependencies: BTreeMap<String, Vec<String>>,
    /// Targets listed for docs.rs, a hint at the platforms the author cares
    /// about.
    pub docs_rs_targets: Vec<String>,
    /// Licence, authors and links for the SBOM (ADR 0012). `None` in
    /// reports from before they were read.
    pub package: Option<PackageMeta>,
    /// Whether the manifest parsed at all.
    pub parsed: bool,
}

impl ManifestFacts {
    /// The code context of a file, by its path relative to the crate root.
    #[must_use]
    pub fn context_of(&self, path: &str) -> CodeContext {
        let build_dir = self
            .build_script
            .as_deref()
            .and_then(|b| b.rsplit_once('/').map(|(dir, _)| format!("{dir}/")));
        if self.build_script.as_deref() == Some(path)
            || path.starts_with("build/")
            || build_dir.is_some_and(|d| !d.starts_with("src/") && path.starts_with(&d))
        {
            CodeContext::BuildScript
        } else if path.starts_with("tests/") {
            CodeContext::Test
        } else if path.starts_with("examples/")
            || path.starts_with("benches/")
            || path.starts_with("src/bin/")
            || path == "src/main.rs"
        {
            CodeContext::Binary
        } else if self.proc_macro {
            CodeContext::ProcMacro
        } else {
            CodeContext::Library
        }
    }

    /// Whether building the crate runs any of its own code.
    #[must_use]
    pub fn has_build_time_code(&self) -> bool {
        self.build_script.is_some() || self.proc_macro
    }
}

/// Changes against the previous version's report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionDiff {
    /// The version compared against.
    pub previous_version: String,
    /// A build script exists now and did not before.
    pub build_script_added: bool,
    /// The crate became a proc macro.
    pub proc_macro_added: bool,
    /// The `links` value changed.
    pub links_changed: bool,
    /// Findings that the previous version did not have, highest severity
    /// first.
    pub new_findings: Vec<Finding>,
    /// Count of findings that disappeared.
    pub removed_findings: u32,
    /// Locked dependencies (by name) that are new.
    pub new_dependencies: Vec<String>,
}
