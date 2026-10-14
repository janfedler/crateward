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
        vex(&vex_input(&verdict, review, &[]))["vulnerabilities"][0]["analysis"]["state"].clone()
    };

    assert_eq!(state(Review::None), "in_triage");
    assert_eq!(state(Review::Pending), "in_triage");
    assert_eq!(state(Review::FalsePositive), "false_positive");
}
