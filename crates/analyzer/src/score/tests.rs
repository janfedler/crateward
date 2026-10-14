use crateward_core::report::trace::TraceSummary;
use serde_json::json;

use super::*;

const SCRIPT: &str = "/work/target/debug/build/evil-0123456789abcdef/build-script-build";

/// A run report as the orchestrator stores it, with overrides.
fn run(overrides: serde_json::Value) -> RunReport {
    let mut base = json!({
        "outcome": "succeeded", "end": "Finished", "exit": null,
        "restore_ms": 60, "run_ms": 1000, "stdout_tail": "", "stderr_tail": "",
        "truncated": false, "payload_files": 1, "payload_bytes": 1,
        "missing_packages": [],
        "network": {"dns": [], "connections": [], "udp_datagrams": 0, "refused": 0,
                    "truncated": false},
        "leaked": [],
        "trace": {"processes": [
                      {"pid": 1, "ppid": null, "exe": "/usr/local/bin/cargo", "argv": ["cargo"],
                       "role": "cargo", "started_ms": 0, "became_root": false},
                      {"pid": 2, "ppid": 1, "exe": SCRIPT, "argv": [SCRIPT],
                       "role": "build_script", "started_ms": 1, "became_root": false},
                      {"pid": 3, "ppid": 2, "exe": "/usr/bin/curl", "argv": ["curl"],
                       "role": "other", "started_ms": 2, "became_root": false}
                  ]}
    });

    // The trace's other fields from the summary's defaults.
    let mut trace = serde_json::to_value(TraceSummary::default()).unwrap();
    trace["complete"] = json!(true);
    trace["processes"] = base["trace"]["processes"].take();
    base["trace"] = trace;

    if let (Some(b), Some(o)) = (base.as_object_mut(), overrides.as_object()) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }

    serde_json::from_value(base).unwrap()
}

fn inputs<'a>(runs: &'a [RunReport]) -> Inputs<'a> {
    Inputs {
        name: "evil",
        coverage: Coverage::DynamicLinux,
        report: None,
        diff: None,
        runs,
        previous_profile: None,
        dismissed: &[],
    }
}

#[test]
fn theft_is_critical_and_attributed() {
    let mut r = run(json!({
        "leaked": [{"kind": "cargo_registry_token", "via": "http://exfil.example"}],
    }));

    r.trace.sensitive_opens.push(
        serde_json::from_value(json!({
            "pid": 2, "exe": SCRIPT, "path": "/work/home/.cargo/credentials.toml",
            "flags": 0, "ms": 3
        }))
        .unwrap(),
    );
    let runs = [r];
    let v = score(&inputs(&runs));

    assert_eq!(v.level, RiskLevel::Critical);
    assert_eq!(v.score, 100);
    assert_eq!(v.evidence[0].signal, "honeytoken_left_vm");

    let read = v
        .evidence
        .iter()
        .find(|e| e.signal == "read_cargo_credentials")
        .unwrap();

    assert_eq!(read.package.as_deref(), Some("evil"));
    assert!(v.profile.contains(&"read:cargo-credentials".to_owned()));
    assert!(!should_escalate(&v));
}

/// The same leak a reviewer dismissed in an earlier version scores
/// nothing, wherever the line moved. A new leak still counts.
#[test]
fn evidence_a_reviewer_dismissed_scores_nothing_again() {
    let leak = |via: &str| json!({"kind": "github_token", "via": via});
    let runs = [run(json!({"leaked": [leak("https://api.github.com")]}))];
    let earlier = score(&inputs(&runs));

    assert_eq!(earlier.level, RiskLevel::Critical);

    let mut moved = earlier.evidence.clone();
    moved[0].location = moved[0].location.as_ref().map(|l| format!("{l}:12"));
    let dismissed = [("2.41.0".to_owned(), moved)];
    let mut again = inputs(&runs);
    again.dismissed = &dismissed;
    let v = score(&again);

    assert_eq!(v.score, 0);
    assert_eq!(v.level, RiskLevel::None);
    assert!(
        v.evidence[0]
            .summary
            .ends_with("A reviewer marked this a false positive in 2.41.0.")
    );

    let runs = [run(json!({"leaked": [
        leak("https://api.github.com"),
        leak("http://exfil.example"),
    ]}))];

    let mut new = inputs(&runs);
    new.dismissed = &dismissed;
    let v = score(&new);

    assert_eq!(v.level, RiskLevel::Critical);
    assert_eq!(
        v.evidence[0].location.as_deref(),
        Some("http://exfil.example")
    );
}

/// A scan of the scratch disk that found the given environment dumps,
/// and the entries outside the build.
fn scratch(dumps: &[&str], outside: &[&str]) -> serde_json::Value {
    let entry = |path: &&str| Entry {
        path: (*path).to_owned(),
        kind: "dir".into(),
        size: 0,
        mode: 0o755,
        uid: 1000,
        target: None,
    };

    serde_json::to_value(ScratchReport {
        environment_dumps: Some(dumps.iter().map(|d| (*d).to_owned()).collect()),
        outside_build: outside.iter().map(entry).collect(),
        ..ScratchReport::default()
    })
    .unwrap()
}

/// A build script's output, as `libz-sys` writes it.
const OUTPUT: &str = "/work/.warm/upper/debug/build/libz-sys-8151eeab73d3e858/output";

/// The crate's own build script's output.
const OWN_OUTPUT: &str = "/work/target/debug/build/evil-0123456789abcdef/output";

#[test]
fn a_dumped_environment_is_no_theft() {
    let with = |via: &str, scratch: serde_json::Value| {
        let mut r = run(json!({
            "tokens_on_disk": [{"kind": "github_token_env", "via": via}],
            "scratch": scratch,
        }));

        r.trace.processes.truncate(2);
        score(&inputs(&[r]))
    };

    let v = with(OWN_OUTPUT, scratch(&[OWN_OUTPUT], &[]));

    assert_eq!((v.score, v.level), (15, RiskLevel::Low));
    assert_eq!(v.evidence[0].signal, "environment_dumped");
    assert_eq!(v.profile, ["dump:environment"]);

    // A dependency's dump is shown, without points.
    let v = with(OUTPUT, scratch(&[OUTPUT], &[]));

    assert_eq!((v.score, v.level), (0, RiskLevel::None));
    assert_eq!(v.evidence[0].signal, "environment_dumped");
    assert_eq!(v.evidence[0].package.as_deref(), Some("libz-sys"));
    assert!(v.profile.is_empty());

    // The same file without the rest of the environment is a copy.
    let v = with(OUTPUT, scratch(&[], &[]));

    assert_eq!((v.score, v.level), (60, RiskLevel::High));
    assert_eq!(v.evidence[0].signal, "honeytoken_copied");

    // A report from before the scanner looked for dumps.
    assert_eq!(
        with(OUTPUT, serde_json::Value::Null).evidence[0].signal,
        "environment_dumped"
    );
}

/// A high finding in the build script.
fn finding(kind: FindingKind, file: &str) -> Finding {
    Finding {
        kind,
        severity: Severity::High,
        file: file.into(),
        line: Some(1),
        context: crateward_core::report::findings::CodeContext::BuildScript,
        cfg: None,
        platform: crateward_core::report::findings::Platform::Any,
        evidence: "e".into(),
    }
}

fn report(findings: Vec<Finding>) -> StaticReport {
    StaticReport {
        analyzer_version: 6,
        manifest: crateward_core::report::static_report::ManifestFacts::default(),
        files: 4,
        rust_files: 1,
        skipped: Vec::new(),
        findings,
        findings_dropped: 0,
        library_platform: crateward_core::report::findings::Platform::Any,
        platforms: BTreeMap::new(),
    }
}

/// `monica_rand_core` 0.10.2: its build script printed the environment,
/// wrote an embedded executable to `/tmp` and started it.
#[test]
fn a_build_that_runs_what_it_dropped_is_critical() {
    let mut r = run(json!({
        "tokens_on_disk": [{"kind": "github_token_env", "via": OWN_OUTPUT}],
        "scratch": scratch(&[OWN_OUTPUT], &[]),
    }));

    r.trace.processes[2].exe = "/tmp/code-helper".into();
    let runs = [r];
    let report = report(vec![
        finding(FindingKind::EnvironmentEnumeration, "build.rs"),
        finding(FindingKind::IncludedBinary, "build.rs"),
        finding(FindingKind::DropperPattern, "build.rs"),
    ]);

    let mut i = inputs(&runs);
    let dynamic = score(&i);

    assert_eq!((dynamic.score, dynamic.level), (75, RiskLevel::High));

    let dropped = dynamic
        .evidence
        .iter()
        .find(|e| e.signal == "exec_dropped")
        .unwrap();

    assert_eq!(dropped.package.as_deref(), Some("evil"));
    assert!(dynamic.profile.contains(&"exec:dropped".to_owned()));

    i.report = Some(&report);
    let v = score(&i);

    assert_eq!(v.level, RiskLevel::Critical);
    assert!(
        v.evidence
            .iter()
            .any(|e| e.signal == "static:dropper_pattern" && e.points == 40)
    );
}

#[test]
fn network_data_the_search_missed_needs_review() {
    let flooded = run(json!({"network": {"dns": [], "connections": [],
            "udp_datagrams": 0, "refused": 0, "truncated": true, "cut": 3}}));

    let v = score(&inputs(&[flooded]));
    let missed: Vec<_> = v
        .evidence
        .iter()
        .filter(|e| e.signal == "network_unsearched")
        .map(|e| (e.points, e.summary.as_str()))
        .collect();

    assert_eq!(
        missed,
        [(
            50,
            "The guest sent more than the honeytoken search could see: more events \
                 than the fake internet logs, connections or frames longer than it keeps."
        )]
    );
    assert!(v.level.needs_review());
    assert!(
        score(&inputs(&[run(json!({}))]))
            .evidence
            .iter()
            .all(|e| e.signal != "network_unsearched")
    );
}

#[test]
fn a_directory_left_outside_the_build_counts_once() {
    let r = run(json!({"scratch": scratch(&[], &[
        "/work/home/.cache",
        "/work/home/.cache/ort.pyke.io",
        "/work/home/.cache/ort.pyke.io/dfbin",
        "/tmp/left",
    ])}));

    let v = score(&inputs(&[r]));
    let left: Vec<_> = v
        .evidence
        .iter()
        .filter(|e| e.signal == "disk_outside_build")
        .map(|e| (e.points, e.summary.as_str()))
        .collect();

    assert_eq!(
        left,
        [
            (10, "The build left /tmp/left (dir)."),
            (
                10,
                "The build left /work/home/.cache (dir) and 2 entries below it."
            ),
        ]
    );
}

#[test]
fn stored_resolver_and_procfs_artifacts_count_nothing() {
    let mut r = run(json!({
        "network": {"dns": ["index.crates.io", "index.crates.io.0.2.2", "x.0.2.2"],
                    "connections": [], "udp_datagrams": 0, "refused": 0, "truncated": false}
    }));

    r.trace.processes.truncate(2);
    r.trace.tamper.push(
        serde_json::from_value(json!({"pid": 2, "what": "ptrace 1 mode 0xd", "ms": 5})).unwrap(),
    );
    let v = score(&inputs(&[r]));
    let signals: Vec<_> = v
        .evidence
        .iter()
        .map(|e| (e.signal.as_str(), e.location.as_deref()))
        .collect();

    assert_eq!(
        signals,
        [
            ("network_lookup", Some("index.crates.io")),
            ("network_lookup", Some("x.0.2.2")),
        ]
    );
}

#[test]
fn programs_in_writable_places_were_dropped() {
    for dropped in [
        "/tmp/code-helper",
        "/dev/shm/x",
        "/work/home/.local/bin/x",
        "/work/x",
    ] {
        assert!(writable_location(dropped), "{dropped}");
    }

    for installed in [
        "/usr/bin/cc",
        "/work/target/debug/build/x-0123456789abcdef/build-script-build",
        "/work/home/.cargo/bin/cargo-x",
        "./conftest",
    ] {
        assert!(!writable_location(installed), "{installed}");
    }

    assert_eq!(top_directory("/work/home/.cache/a/b"), "/work/home/.cache");
    assert_eq!(top_directory("/work/src/tool"), "/work/src");
    assert_eq!(top_directory("/tmp/left"), "/tmp");
}

#[test]
fn one_behavior_in_two_runs_counts_once() {
    let copy = |dir: &str| {
        let via = format!("/work/target/debug/build/dep-{dir}/out/env.rs");
        run(
            json!({"tokens_on_disk": [{"kind": "github_token_env", "via": via}],
                "scratch": scratch(&[], &[])}),
        )
    };

    let runs = [copy("0123456789abcdef"), copy("fedcba9876543210")];
    let v = score(&inputs(&runs));
    let copies: Vec<_> = v
        .evidence
        .iter()
        .filter(|e| e.signal == "honeytoken_copied")
        .collect();

    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].package.as_deref(), Some("dep"));
    assert_eq!(v.level, RiskLevel::High);
}

#[test]
fn a_quiet_build_scores_nothing() {
    let mut r = run(json!({}));
    r.trace.processes.truncate(1);
    let runs = [r];
    let v = score(&inputs(&runs));

    assert_eq!((v.score, v.level), (0, RiskLevel::None));
    assert!(v.evidence.is_empty());
    assert!(!should_escalate(&v));
}

#[test]
fn a_downloading_sys_crate_stays_low() {
    let runs = [run(json!({
        "network": {"dns": ["github.com"], "connections": [], "udp_datagrams": 0,
                    "refused": 0, "truncated": false}
    }))];

    let v = score(&inputs(&runs));

    // A lookup (10) and curl run by the build script (5): common in
    // `-sys` crates, so no review and no confirmation run.
    assert_eq!(v.score, 15);
    assert_eq!(v.level, RiskLevel::Low);

    let exec = v
        .evidence
        .iter()
        .find(|e| e.signal == "exec_downloader")
        .unwrap();

    assert_eq!(exec.package.as_deref(), Some("evil"));
    assert!(!should_escalate(&v));
}

/// `dittolive-ditto-sys`: the build script's download ran in the VM.
#[test]
fn a_download_the_run_saw_weighs_less_than_its_shape() {
    let report = report(vec![finding(FindingKind::DownloaderPattern, "build.rs")]);
    let downloader = |runs: &[RunReport]| {
        let mut i = inputs(runs);
        i.report = Some(&report);
        score(&i)
            .evidence
            .into_iter()
            .find(|e| e.signal == "static:downloader_pattern")
            .unwrap()
            .points
    };

    assert_eq!(downloader(&[run(json!({}))]), 10);

    let mut quiet = run(json!({}));
    quiet.trace.processes.truncate(2);

    assert_eq!(downloader(&[quiet]), 30);
    assert_eq!(downloader(&[]), 30);
}

/// `trusty-mpm` 1.7.12: one rule in two new places.
#[test]
fn a_new_high_finding_counts_once_per_kind() {
    let diff = VersionDiff {
        previous_version: "1.7.9".into(),
        build_script_added: false,
        proc_macro_added: false,
        links_changed: false,
        new_findings: vec![
            finding(FindingKind::ShellCommand, "src/a.rs"),
            finding(FindingKind::ShellCommand, "src/b.rs"),
            finding(FindingKind::ProcessSpawn, "src/c.rs"),
        ],
        removed_findings: 0,
        new_dependencies: Vec::new(),
    };

    let mut i = inputs(&[]);
    i.diff = Some(&diff);
    let new: Vec<_> = score(&i)
        .evidence
        .into_iter()
        .filter(|e| e.signal == "new_high_finding")
        .map(|e| e.summary)
        .collect();

    assert_eq!(
        new,
        [
            "New since 1.7.9: shell_command",
            "New since 1.7.9: process_spawn"
        ]
    );
}

#[test]
fn groups_are_capped() {
    let names: Vec<String> = (0..10).map(|i| format!("host{i}.example")).collect();
    let runs = [run(json!({
        "network": {"dns": names, "connections": [], "udp_datagrams": 0,
                    "refused": 0, "truncated": false}
    }))];

    let v = score(&inputs(&runs));
    let network: u32 = v
        .evidence
        .iter()
        .filter(|e| e.signal == "network_lookup")
        .map(|e| e.points)
        .sum();

    assert_eq!(network, 40);

    // Every lookup stays listed, even without points.
    assert_eq!(
        v.evidence
            .iter()
            .filter(|e| e.signal == "network_lookup")
            .count(),
        10
    );
}

#[test]
fn new_behavior_against_the_previous_version_counts() {
    let runs = [run(json!({}))];
    let previous = vec!["exec:shell".to_owned()];
    let mut i = inputs(&runs);
    i.previous_profile = Some(&previous);
    let v = score(&i);

    assert_eq!(v.new_behavior, ["exec:downloader"]);
    assert!(v.evidence.iter().any(|e| e.signal == "new_behavior"));
}

#[test]
fn packages_come_from_build_script_paths_and_rustc() {
    assert_eq!(build_script_package(SCRIPT).as_deref(), Some("evil"));
    assert_eq!(
        build_script_package(
            "/work/target/debug/build/serde-json-0123456789abcdef/build-script-build"
        )
        .as_deref(),
        Some("serde-json")
    );
    assert_eq!(build_script_package("/usr/bin/curl"), None);
    assert_eq!(
        build_dir_package(
            "/work/.warm/upper/debug/build/rustpython-vm-56bb5ec5157fcd26/out/env_vars.rs"
        )
        .as_deref(),
        Some("rustpython-vm")
    );

    let rustc: Process = serde_json::from_value(json!({
        "pid": 9, "ppid": null, "exe": "/usr/local/bin/rustc",
        "argv": ["rustc", "--crate-name", "my_macro"], "role": "rustc",
        "started_ms": 0, "became_root": false
    }))
    .unwrap();

    let map: HashMap<u32, &Process> = [(9, &rustc)].into();

    assert_eq!(package_of(9, &map).as_deref(), Some("my-macro"));
}

/// A run with something for every group.
fn every_group_run() -> RunReport {
    let entry =
        |path: &str| json!({"path": path, "kind": "file", "size": 1, "mode": 420, "uid": 1000});

    let file = |pid: u32, exe: &str, path: &str| json!({"pid": pid, "exe": exe, "path": path, "flags": 0, "ms": 3});
    let other = "/work/target/debug/build/other-0123456789abcdef/build-script-build";
    let mut first = run(json!({
        "outcome": "guest_stopped",
        "leaked": [{"kind": "cargo_registry_token", "via": "http://exfil.example"}],
        "tokens_in_trace": [{"kind": "aws_key",
            "via": "/work/target/debug/build/dep-0123456789abcdef/out/k"}],
        "network": {"dns": ["a.example"], "connections": [], "udp_datagrams": 0,
                    "refused": 0, "truncated": false, "packets": ["icmp echo"]},
        "scratch": {"files": 0, "directories": 0, "bytes": 0, "incomplete": false,
            "outside_build": [entry("/home/u/.config/autostart/a.desktop"),
                              entry("/tmp/left")],
            "executables_outside_target": [entry("/work/src/tool")],
            "setid": [entry("/work/su")], "special": [], "links_outside": [],
            "planted_changed": [], "tokens_found": [], "omitted": 0},
    }));

    let t = &mut first.trace;

    for (pid, ppid, exe, role, root) in [
        (4, 2, "/usr/bin/sudo", "other", true),
        (5, 1, other, "build_script", false),
    ] {
        t.processes.push(
            serde_json::from_value(json!({
                "pid": pid, "ppid": ppid, "exe": exe, "argv": [exe], "role": role,
                "started_ms": 3, "became_root": root
            }))
            .unwrap(),
        );
    }

    t.tamper
        .push(serde_json::from_value(json!({"pid": 2, "what": "ptrace attach", "ms": 5})).unwrap());

    for (pid, exe, path) in [
        (
            1,
            "/usr/local/bin/cargo",
            "/work/home/.cargo/credentials.toml",
        ),
        (2, SCRIPT, "/work/home/.ssh/id_ed25519"),
        (3, "/usr/bin/curl", "/proc/1/environ"),
    ] {
        t.sensitive_opens
            .push(serde_json::from_value(file(pid, exe, path)).unwrap());
    }

    for (pid, exe, path) in [
        (2, SCRIPT, "/work/home/.bashrc"),
        (3, "/usr/bin/curl", "/tmp/x"),
    ] {
        t.writes_outside_work
            .push(serde_json::from_value(file(pid, exe, path)).unwrap());
    }

    // The name service socket is no evidence, even from another package.
    for (pid, exe, address) in [
        (3, "/usr/bin/curl", "1.2.3.4:443"),
        (5, other, "unix:/run/nscd/socket"),
    ] {
        t.sockets.push(
            serde_json::from_value(json!({
                "pid": pid, "exe": exe, "how": "connect", "address": address,
                "sock_type": 1, "ms": 3
            }))
            .unwrap(),
        );
    }

    first
}

/// What [`every_group_run`] and a second run score, in order: group,
/// signal, points, package and location.
const EVERY_GROUP_ITEMS: [&str; 18] = [
    "Theft honeytoken_left_vm 100 - http://exfil.example",
    "Theft honeytoken_copied 60 dep /work/target/debug/build/dep-0123456789abcdef/out/k",
    "Integrity became_root 80 evil pid 4",
    "Integrity tamper_attempt 60 evil pid 2",
    "Integrity guest_stopped 50 - -",
    "Credentials read_ssh 50 evil /work/home/.ssh/id_ed25519",
    "Credentials read_other_process 30 evil /proc/1/environ",
    "Persistence write_persistence 40 evil /work/home/.bashrc",
    "Persistence write_outside_build 15 evil /tmp/x",
    "Persistence disk_persistence 40 - /home/u/.config/autostart/a.desktop",
    "Persistence disk_outside_build 10 - /tmp/left",
    "Persistence disk_executable 20 - /work/src/tool",
    "Integrity disk_setid 40 - /work/su",
    "Network network_lookup 10 evil a.example",
    "Network network_raw 30 - icmp echo",
    "Execution exec_downloader 5 evil /usr/bin/curl",
    "Execution exec_privilege 15 evil /usr/bin/sudo",
    "Network network_direct 20 - -",
];

/// Something for every group in one run, and a second run that adds one
/// signal and repeats another.
#[test]
fn a_run_is_scored_group_by_group() {
    let first = every_group_run();
    let second = run(json!({
        "network": {"dns": [], "connections": [{"dst": "1.2.3.4:443",
            "protocol": "unknown", "bytes": 10}], "udp_datagrams": 0, "refused": 0,
            "truncated": false},
    }));

    let mut groups = Groups { items: Vec::new() };
    let mut profile = BTreeSet::new();
    for r in [&first, &second] {
        score_run("evil", r, &mut groups, &mut profile);
    }

    let items: Vec<String> = groups
        .items
        .iter()
        .map(|(group, e)| {
            let package = e.package.as_deref().unwrap_or("-");
            let location = e.location.as_deref().unwrap_or("-");

            format!("{group:?} {} {} {package} {location}", e.signal, e.points)
        })
        .collect();

    assert_eq!(items, EVERY_GROUP_ITEMS);
    assert_eq!(
        profile.into_iter().collect::<Vec<_>>(),
        [
            "copy:aws_key",
            "disk:executable",
            "disk:outside",
            "disk:persistence",
            "disk:setid",
            "exec:downloader",
            "exec:privilege",
            "guest-stopped",
            "leak:cargo_registry_token",
            "net:a.example",
            "net:direct",
            "net:raw",
            "read:other-process",
            "read:ssh",
            "root",
            "tamper:ptrace",
            "write:outside",
            "write:persistence",
        ]
    );
}
