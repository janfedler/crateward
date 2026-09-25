//! The triage decision: does a version need a microVM run?
//!
//! Dynamic analysis observes what happens while a crate builds, so it only
//! adds evidence when building runs code that nobody vetted. The rules, in
//! order (ADR 0015):
//!
//! 1. A library gated to Windows or Apple platforms, with no build script
//!    and no proc macro, compiles to nothing on Linux: not applicable.
//! 2. The crate's own build script or proc macro: dynamic.
//! 3. A native link (`links`) or any high severity finding: dynamic, so a
//!    run can confirm or dismiss it.
//! 4. A locked dependency with build time code that is unfamiliar, meaning
//!    neither popular, nor locked by an earlier version of the same crate,
//!    nor analyzed by Crateward in its own job: dynamic, because building
//!    the version runs that code and nothing else observes it.
//! 5. Otherwise: static only, because building runs none of its code.

use serde::{Deserialize, Serialize};

use crateward_core::job::Triage;
use crateward_core::verdict::StaticOnlyReason;

use crate::analyze::StaticReport;
use crate::findings::{Platform, Severity};

/// A locked dependency as triage sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// Name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Whether building it runs its code.
    pub build_time_code: bool,
    /// Whether it counts as popular (crate statistics).
    pub popular: bool,
    /// Whether an earlier version of the analyzed crate locked it too.
    pub seen_before: bool,
    /// Whether this exact version has its own job, which runs its build
    /// time code in its own microVM run.
    pub tracked: bool,
}

/// The decision with the reasons that led to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The triage.
    pub triage: Triage,
    /// Human readable reasons, in rule order.
    pub reasons: Vec<String>,
}

/// Decides.
#[must_use]
pub fn decide(report: &StaticReport, dependencies: &[Dependency]) -> Decision {
    let facts = &report.manifest;
    let mut reasons = Vec::new();
    if !facts.has_build_time_code()
        && matches!(report.library_platform, Platform::Windows | Platform::Apple)
    {
        reasons.push(format!(
            "the library is gated to {:?} and nothing runs at build time",
            report.library_platform
        ));
        return Decision {
            triage: Triage::NotApplicableOnLinux,
            reasons,
        };
    }
    if let Some(script) = &facts.build_script {
        reasons.push(format!("build script {script}"));
    }
    if facts.proc_macro {
        reasons.push("proc macro".to_owned());
    }
    if let Some(links) = &facts.links {
        reasons.push(format!("links the native library {links}"));
    }
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    if high > 0 {
        reasons.push(format!("{high} high severity findings"));
    }
    let unfamiliar: Vec<String> = dependencies
        .iter()
        .filter(|d| d.build_time_code && !d.popular && !d.seen_before && !d.tracked)
        .map(|d| format!("{} {}", d.name, d.version))
        .collect();
    if !unfamiliar.is_empty() {
        reasons.push(format!(
            "unfamiliar dependencies with build time code: {}",
            unfamiliar.join(", ")
        ));
    }
    if reasons.is_empty() {
        reasons
            .push("building it runs no code of its own or of unfamiliar dependencies".to_owned());
        Decision {
            triage: Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode),
            reasons,
        }
    } else {
        Decision {
            triage: Triage::Dynamic,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{AnalyzeLimits, analyze};
    use crate::yara::Rules;

    fn report(files: &[(&str, &[u8])]) -> StaticReport {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("f-0.1.0/{path}"), *data)
                .unwrap();
        }
        let tar = builder.into_inner().unwrap();
        analyze(&tar, &Rules::builtin().unwrap(), &AnalyzeLimits::default()).unwrap()
    }

    const MANIFEST: (&str, &[u8]) = (
        "Cargo.toml",
        b"[package]\nname = \"f\"\nversion = \"0.1.0\"\n",
    );

    fn dep(build_time_code: bool, popular: bool, seen_before: bool) -> Dependency {
        Dependency {
            name: "d".into(),
            version: "1.0.0".into(),
            build_time_code,
            popular,
            seen_before,
            tracked: false,
        }
    }

    #[test]
    fn plain_libraries_are_static_only() {
        let r = report(&[MANIFEST, ("src/lib.rs", b"pub fn f() {}")]);
        let tracked = Dependency {
            tracked: true,
            ..dep(true, false, false)
        };
        let d = decide(
            &r,
            &[
                dep(true, true, false),
                dep(true, false, true),
                dep(false, false, false),
                tracked,
            ],
        );
        assert_eq!(
            d.triage,
            Triage::StaticOnly(StaticOnlyReason::NoBuildTimeCode)
        );
    }

    #[test]
    fn build_scripts_and_unfamiliar_dependencies_are_dynamic() {
        let r = report(&[MANIFEST, ("build.rs", b"fn main() {}"), ("src/lib.rs", b"")]);
        assert_eq!(decide(&r, &[]).triage, Triage::Dynamic);
        let plain = report(&[MANIFEST, ("src/lib.rs", b"")]);
        let d = decide(&plain, &[dep(true, false, false)]);
        assert_eq!(d.triage, Triage::Dynamic);
        assert!(d.reasons[0].contains("d 1.0.0"));
    }

    #[test]
    fn windows_only_libraries_are_not_applicable() {
        let r = report(&[MANIFEST, ("src/lib.rs", b"#![cfg(windows)]\npub fn f() {}")]);
        assert_eq!(decide(&r, &[]).triage, Triage::NotApplicableOnLinux);
    }
}
