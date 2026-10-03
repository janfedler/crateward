//! What changed since the previous version.
//!
//! Most malicious releases are updates of existing crates, and the change is
//! the signal: a build script that appears, a new network call, a new
//! dependency. Findings are compared by kind, file and evidence, not by line,
//! so code that only moved does not show up as new.

use std::collections::{BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::analyze::StaticReport;
use crate::findings::{Finding, FindingKind};

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

fn key(f: &Finding) -> (&FindingKind, &str, &str) {
    (&f.kind, f.file.as_str(), f.evidence.as_str())
}

/// Compares two reports. `dependencies` and `previous_dependencies` are the
/// locked package names of both versions.
#[must_use]
pub fn diff(
    current: &StaticReport,
    previous: &StaticReport,
    previous_version: &str,
    dependencies: &BTreeSet<String>,
    previous_dependencies: &BTreeSet<String>,
) -> VersionDiff {
    let old: HashSet<_> = previous.findings.iter().map(key).collect();
    let new: HashSet<_> = current.findings.iter().map(key).collect();
    VersionDiff {
        previous_version: previous_version.to_owned(),
        build_script_added: current.manifest.build_script.is_some()
            && previous.manifest.build_script.is_none(),
        proc_macro_added: current.manifest.proc_macro && !previous.manifest.proc_macro,
        links_changed: current.manifest.links != previous.manifest.links,
        new_findings: current
            .findings
            .iter()
            .filter(|f| !old.contains(&key(f)))
            .cloned()
            .collect(),
        removed_findings: u32::try_from(old.difference(&new).count()).unwrap_or(u32::MAX),
        new_dependencies: dependencies
            .difference(previous_dependencies)
            .cloned()
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{AnalyzeLimits, analyze};
    use crate::yara::Rules;

    fn report(build: Option<&[u8]>) -> StaticReport {
        let mut files: Vec<(&str, &[u8])> = vec![
            (
                "Cargo.toml",
                b"[package]\nname = \"f\"\nversion = \"0.1.0\"\n",
            ),
            ("src/lib.rs", b"pub fn f() {}"),
        ];

        if let Some(b) = build {
            files.push(("build.rs", b));
        }

        let mut builder = tar::Builder::new(Vec::new());

        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("f-0.1.0/{path}"), data)
                .unwrap();
        }

        analyze(
            &builder.into_inner().unwrap(),
            &Rules::builtin().unwrap(),
            &AnalyzeLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn an_added_build_script_and_its_findings_show_up() {
        let old = report(None);
        let new = report(Some(b"fn main() { std::process::Command::new(\"sh\"); }"));
        let deps: BTreeSet<String> = ["cc".to_owned()].into();
        let d = diff(&new, &old, "0.0.9", &deps, &BTreeSet::new());

        assert!(d.build_script_added);
        assert!(!d.new_findings.is_empty());
        assert_eq!(d.new_dependencies, vec!["cc".to_owned()]);

        let same = diff(&new, &new, "0.1.0", &deps, &deps);
        assert!(same.new_findings.is_empty() && !same.build_script_added);
    }
}
