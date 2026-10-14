use super::*;

fn evidence(signal: &str, points: u32, summary: &str) -> EvidenceView {
    EvidenceView {
        points,
        signal: signal.to_owned(),
        source: "trace".to_owned(),
        package: String::new(),
        location: String::new(),
        summary: summary.to_owned(),
        code_url: String::new(),
    }
}

fn process(pid: u64, ppid: Option<u64>, exe: &str, role: &str) -> Value {
    json!({"pid": pid, "ppid": ppid, "exe": exe, "argv": [exe, format!("arg{pid}")], "role": role, "started_ms": pid})
}

/// A full run with a cargo, a build script under a hashed directory and
/// what the build script started.
fn report(hash: &str, children: &[&str], extra: Value) -> Value {
    let script = format!("/w/target/debug/build/evil-{hash}/build-script-build");
    let mut processes = vec![
        process(1, None, "/usr/bin/cargo", "cargo"),
        process(2, Some(1), &script, "build_script"),
    ];

    for (i, exe) in children.iter().enumerate() {
        processes.push(process(10 + i as u64, Some(2), exe, "other"));
    }

    let mut report = json!({
        "outcome": "succeeded",
        "trace": {"complete": true, "processes": processes,
                  "sensitive_opens": [], "writes_outside_work": [], "sockets": [], "tamper": []},
        "network": {"dns": [], "connections": []},
    });

    if let (Some(r), Some(e)) = (report.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            r.insert(k.clone(), v.clone());
        }
    }

    report
}

fn side(
    id: i64,
    version: &str,
    evidence: Vec<EvidenceView>,
    findings: Value,
    runs: Vec<(String, Value)>,
) -> Side {
    Side {
        id,
        name: "evil".to_owned(),
        version: version.to_owned(),
        score: "0".to_owned(),
        level: "none".to_owned(),
        evidence,
        profile: Vec::new(),
        report: json!({ "findings": findings }),
        runs,
    }
}

#[test]
fn evidence_is_new_gone_or_weighs_differently() {
    let (changes, same) = evidence_changes(
        &[
            evidence("honeytoken_left_vm", 60, "a token went out"),
            evidence("exec_curl", 10, "ran curl"),
            evidence("exec_curl", 5, "ran curl again"),
            evidence("same", 3, "unchanged"),
        ],
        &[
            evidence("exec_curl", 10, "ran curl"),
            evidence("same", 3, "unchanged"),
            evidence("timeout", 3, "ended late"),
        ],
    );

    let shown: Vec<String> = changes
        .iter()
        .map(|c| {
            format!(
                "{} {} {}->{} {}",
                c.change, c.signal, c.before, c.after, c.tone
            )
        })
        .collect();

    assert_eq!(
        shown,
        [
            "added honeytoken_left_vm ->60 bad",
            "changed exec_curl 10->15 low",
            "removed timeout 3-> low",
        ]
    );
    assert_eq!(same, 1);
}

#[test]
fn findings_that_only_moved_are_the_same() {
    let now = json!([
        {"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": 40, "evidence": "curl"},
        {"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": 41, "evidence": "wget"},
        {"severity": "info", "kind": "filler", "file": "src/a.rs", "line": 1, "evidence": "x"},
    ]);

    let before = json!([
        {"severity": "high", "kind": "build_script", "rule": "net_call", "context": "fn main", "file": "build.rs", "line": 12, "evidence": "curl"},
        {"severity": "low", "kind": "unsafe_block", "file": "src/lib.rs", "evidence": "unsafe"},
        {"severity": "info", "kind": "filler", "file": "src/a.rs", "line": 1, "evidence": "x"},
        {"severity": "info", "kind": "filler", "file": "src/a.rs", "line": 2, "evidence": "x"},
    ]);

    let c = compare(
        &side(2, "0.2.0", vec![], now, vec![]),
        &side(1, "0.1.0", vec![], before, vec![]),
    );

    assert_eq!(
        (c.findings_added, c.findings_removed, c.findings_same),
        (1, 2, 2)
    );
    let added = c.added_groups.first().unwrap();
    assert_eq!(added.kind, "build_script net_call");
    assert_eq!(added.items.first().unwrap().evidence, "wget");
    assert!(
        added
            .items
            .first()
            .unwrap()
            .places
            .first()
            .unwrap()
            .1
            .contains("/evil/0.2.0/")
    );
    assert!(c.removed_groups.iter().any(|g| g.kind == "unsafe_block"));
    assert!(
        c.removed_groups
            .first()
            .unwrap()
            .items
            .first()
            .unwrap()
            .places
            .first()
            .unwrap()
            .1
            .contains("/evil/0.1.0/")
    );
}

#[test]
fn new_processes_show_with_their_ancestors_and_build_hashes_do_not_matter() {
    let now = report("aaaa1111", &["/usr/bin/cc", "/tmp/payload"], json!({}));
    let before = report("bbbb2222", &["/usr/bin/cc", "/usr/bin/git"], json!({}));
    let c = compare(
        &side(
            2,
            "0.2.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), now)],
        ),
        &side(
            1,
            "0.1.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), before)],
        ),
    );

    let run = c.runs.first().unwrap();
    let lines = |l: &[TreeLine]| -> Vec<String> {
        l.iter()
            .map(|t| {
                format!(
                    "{}{}{}",
                    if t.context { "~" } else { "+" },
                    "  ".repeat(t.row.nesting),
                    t.row.label()
                )
            })
            .collect()
    };

    assert_eq!(
        lines(&run.new_processes),
        ["~/usr/bin/cargo", "~  evil", "+    /tmp/payload"]
    );
    assert_eq!(
        lines(&run.gone_processes),
        ["~/usr/bin/cargo", "~  evil", "+    /usr/bin/git"]
    );
    assert_eq!((run.added, run.removed, run.same), (1, 1, 3));
    assert!(c.runs_note.is_empty());
}

#[test]
fn a_whole_new_subtree_is_new_and_network_and_files_are_sets() {
    let extra = |dns: &[&str], host: &str, secret: &str| {
        json!({
            "network": {"dns": dns, "connections": [{"dst": "10.0.2.1:443", "protocol": "tls", "sni": host, "bytes_out": 10}]},
            "trace": {"complete": true,
                      "processes": [{"pid": 1, "exe": "/usr/bin/cargo", "role": "cargo"}],
                      "sensitive_opens": [{"exe": "/w/target/debug/build/evil-ab12/build-script-build", "path": secret, "ms": 3, "flags": 0}],
                      "writes_outside_work": [], "sockets": [], "tamper": []},
        })
    };

    let now = report(
        "a1",
        &[],
        extra(
            &["evil.example", "crates.io"],
            "evil.example",
            "/root/.ssh/id_rsa",
        ),
    );

    let before = report(
        "b2",
        &[],
        extra(&["crates.io"], "crates.io", "/root/.ssh/id_rsa"),
    );

    let c = compare(
        &side(
            2,
            "0.2.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), now)],
        ),
        &side(
            1,
            "0.1.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), before)],
        ),
    );

    let run = c.runs.first().unwrap();
    assert_eq!(run.dns_added, ["evil.example"]);
    assert!(run.dns_removed.is_empty());
    assert_eq!(run.connections_added.len(), 1);
    assert_eq!(run.connections_removed.len(), 1);
    assert_eq!(run.network_same, 1);
    assert_eq!(run.file_changes(), 0);
    assert_eq!(run.files_same, 1);
}

#[test]
fn trimmed_runs_and_missing_runs_are_named() {
    let trimmed = report("a1", &["/usr/bin/cc"], json!({"trimmed": true}));
    let full = report("b2", &[], json!({}));
    let c = compare(
        &side(
            2,
            "0.2.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), full.clone())],
        ),
        &side(
            1,
            "0.1.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), trimmed)],
        ),
    );

    let run = c.runs.first().unwrap();
    assert!(run.trimmed.starts_with("Retention removed"));
    assert!(run.new_processes.is_empty() && run.added == 0);

    let c = compare(
        &side(
            2,
            "0.2.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), full)],
        ),
        &side(1, "0.1.0", vec![], json!([]), vec![]),
    );
    assert_eq!(c.runs_note, "0.1.0 was not built in a VM.");

    let any = report("c3", &[], json!({}));
    let c = compare(
        &side(
            2,
            "0.2.0",
            vec![],
            json!([]),
            vec![("full".to_owned(), any.clone())],
        ),
        &side(
            1,
            "0.1.0",
            vec![],
            json!([]),
            vec![("check".to_owned(), any)],
        ),
    );
    assert_eq!(c.runs_note, "The versions have no VM run of the same kind.");
}

#[test]
fn the_counterpart_is_the_version_before_or_the_chosen_one() {
    let v = |id: i64, version: &str| AnalyzedVersion {
        id: JobId(id),
        version: version.to_owned(),
        score: 0,
        level: "none".to_owned(),
    };

    let versions = [v(9, "1.0.0"), v(3, "0.10.0"), v(7, "0.9.1")];

    assert_eq!(counterpart(&versions, 3, None).unwrap().id, JobId(7));
    assert!(counterpart(&versions, 7, None).is_none());
    assert_eq!(counterpart(&versions, 7, Some(9)).unwrap().id, JobId(9));
    assert_eq!(counterpart(&versions, 9, Some(9)).unwrap().id, JobId(3));
    assert!(counterpart(&versions, 9, Some(42)).is_none());
}

#[test]
fn the_package_diff_shows_only_against_its_version() {
    let diff = json!({"previous_version": "0.1.0", "build_script_added": true, "proc_macro_added": false,
                          "links_changed": false, "new_findings": [], "removed_findings": 0, "new_dependencies": ["cc"]});

    let rows = package_rows(Some(&diff), "0.1.0").unwrap();
    assert_eq!(rows.first().unwrap().1, "added");
    assert_eq!(rows.last().unwrap().1, "cc");
    assert!(
        package_rows(Some(&diff), "0.0.9")
            .unwrap_err()
            .contains("with 0.1.0")
    );
    assert!(package_rows(None, "0.1.0").is_err());
}

#[test]
fn the_source_diff_link_encodes_versions() {
    assert_eq!(
        source_url("evil", "0.1.0", "0.2.0+meta"),
        "https://diff.rs/evil/0.1.0/0.2.0%2Bmeta/"
    );
}
