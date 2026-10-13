//! Writes a sample SBOM and findings document for the CycloneDX and BSI
//! validators in CI (ADR 0012). Without `CRATEWARD_CYCLONEDX_SAMPLES`, the
//! directory to write them to, it only builds them.
//!
//! The SBOM is that of `reqwest` with the packages it pulls in from
//! Crateward's own lockfile, with made up hashes and a mix of licence
//! forms, so every shape of component appears.

#![cfg(feature = "sbom")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crateward_core::cyclonedx::{self, FileFacts, Locked, SbomInput, VexInput};
use crateward_core::package::PackageMeta;
use crateward_core::store::Review;
use crateward_core::verdict::{Coverage, Evidence, EvidenceSource, RiskLevel, Verdict};

const LOCK: &str = include_str!("../../../Cargo.lock");

/// Facts for the `n`th package, cycling through the forms a manifest has.
fn facts(n: usize) -> FileFacts {
    let (license, license_file, authors, homepage, repository) = match n % 5 {
        0 => (Some("MIT"), None, vec!["Ann <ann@example.com>"], None, None),
        1 => (
            Some("MIT/Apache-2.0"),
            None,
            vec!["Bob"],
            None,
            Some("https://github.com/example/b"),
        ),
        2 => (
            Some("Apache-2.0 WITH LLVM-exception"),
            None,
            Vec::new(),
            Some("https://example.com"),
            None,
        ),
        3 => (None, Some("LICENSE"), Vec::new(), None, None),
        _ => (Some("GPL-2.0"), None, Vec::new(), None, None),
    };

    FileFacts {
        sha512: Some(format!("{:0128x}", n + 1)),
        meta: Some(PackageMeta {
            license: license.map(str::to_owned),
            license_file: license_file.map(str::to_owned),
            authors: authors.into_iter().map(str::to_owned).collect(),
            homepage: homepage.map(str::to_owned),
            repository: repository.map(str::to_owned),
        }),
    }
}

/// The lockfile of only `root` and what it depends on, as a consumer
/// probe's lockfile would be.
fn lockfile_of(root: &str) -> String {
    let packages = cyclonedx::locked(LOCK).unwrap();
    let find = |entry: &str| -> Option<&Locked> {
        let mut words = entry.split_whitespace();
        let (name, version) = (words.next()?, words.next());
        packages
            .iter()
            .find(|p| p.name == name && version.is_none_or(|v| v == p.version))
    };

    let mut seen = BTreeSet::new();
    let mut todo = vec![find(root).unwrap()];
    while let Some(p) = todo.pop() {
        if seen.insert((p.name.clone(), p.version.clone())) {
            todo.extend(p.dependencies.iter().filter_map(|d| find(d)));
        }
    }

    let mut text = String::from("version = 4\n");
    for p in packages
        .iter()
        .filter(|p| seen.contains(&(p.name.clone(), p.version.clone())))
    {
        let deps: Vec<String> = p.dependencies.iter().map(|d| format!("{d:?}")).collect();
        write!(
            text,
            "\n[[package]]\nname = {:?}\nversion = {:?}\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\ndependencies = [{}]\n",
            p.name,
            p.version,
            p.checksum.unwrap(),
            deps.join(", ")
        )
        .unwrap();
    }

    text
}

#[test]
fn samples_build_and_are_written_for_the_validators() {
    let lock = lockfile_of("reqwest");
    let packages = cyclonedx::locked(&lock).unwrap();
    let root = packages.iter().find(|p| p.name == "reqwest").unwrap();
    let files: BTreeMap<_, _> = packages
        .iter()
        .filter_map(|p| p.checksum)
        .enumerate()
        .map(|(n, sha)| (sha, facts(n)))
        .collect();

    let sbom = cyclonedx::sbom(&SbomInput {
        name: &root.name,
        version: &root.version,
        sha256: root.checksum.unwrap(),
        lockfile: Some(&lock),
        files: &files,
        timestamp: 1_790_000_000,
        tool_version: env!("CARGO_PKG_VERSION"),
    });
    assert_eq!(sbom.gaps, Vec::<String>::new());

    let evidence = |signal: &str, points, package: &str| Evidence {
        signal: signal.to_owned(),
        points,
        source: EvidenceSource::Network,
        summary: format!("{package} did {signal}"),
        package: Some(package.to_owned()),
        location: Some("203.0.113.7:443".to_owned()),
    };

    let verdict = Verdict {
        score: 70,
        level: RiskLevel::from_score(70),
        coverage: Coverage::DynamicLinux,
        evidence: vec![
            evidence("honeytoken_left_vm", 60, "reqwest"),
            evidence("network_lookup", 10, "hyper"),
        ],
        profile: Vec::new(),
        new_behavior: Vec::new(),
        analyzer_version: 1,
    };

    let vex = cyclonedx::vex(&VexInput {
        job: 1,
        name: &root.name,
        version: &root.version,
        sbom: (&sbom.serial, 1),
        lockfile: Some(&lock),
        verdict: &verdict,
        review: Review::Confirmed,
        revision: 1,
        finding_url: None,
        honeytokens: &[],
        coverage: verdict.coverage.label(),
        runs: &["check".to_owned(), "full".to_owned()],
        timestamp: 1_790_000_000,
        tool_version: env!("CARGO_PKG_VERSION"),
    });

    if let Some(dir) = std::env::var_os("CRATEWARD_CYCLONEDX_SAMPLES") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        let json = |v| serde_json::to_string_pretty(v).unwrap();
        std::fs::write(dir.join("sample.cdx.json"), json(&sbom.document)).unwrap();
        std::fs::write(dir.join("sample.vex.cdx.json"), json(&vex)).unwrap();
    }
}
