use serde_json::json;

use super::*;

#[test]
fn units_read_naturally() {
    assert_eq!(duration(350), "350 ms");
    assert_eq!(duration(4_250), "4.2 s");
    assert_eq!(duration(185_000), "3 min 5 s");
    assert_eq!(bytes(512), "512 B");
    assert_eq!(bytes(3_500), "3.4 KiB");
    assert_eq!(bytes(12 * 1024 * 1024), "12.0 MiB");
    assert_eq!(open_mode(0), "read");
    assert_eq!(open_mode(0o1101), "write, create, truncate");
}

#[test]
fn processes_follow_their_parents_and_survive_cycles() {
    let trace = json!({"processes": [
        {"pid": 1, "ppid": null, "exe": "/usr/bin/cargo", "argv": ["cargo", "check"], "role": "cargo", "started_ms": 0},
        {"pid": 3, "ppid": 1, "exe": "/w/build-script-build", "argv": ["b"], "role": "build_script", "started_ms": 20, "ended_ms": 1520},
        {"pid": 2, "ppid": 1, "exe": "/usr/bin/rustc", "argv": [], "role": "rustc", "started_ms": 10},
        {"pid": 4, "ppid": 3, "exe": "/usr/bin/curl", "argv": ["curl", "-o", "x"], "role": "other", "started_ms": 30, "exit": 6, "became_root": true},
        {"pid": 7, "ppid": 8, "exe": "a", "role": "unknown"},
        {"pid": 8, "ppid": 7, "exe": "b", "role": "unknown"},
        {"pid": 9, "ppid": 99, "exe": "orphan", "role": "unknown"}
    ]});

    let rows = process_rows(&trace);
    let order: Vec<(u64, usize)> = rows.iter().map(|r| (r.pid, r.depth)).collect();

    // 7 and 8 are each other's parents: listed after the real roots.
    assert_eq!(
        order,
        [(1, 0), (3, 1), (4, 2), (2, 1), (9, 0), (7, 0), (8, 1)]
    );

    let curl = &rows[2];
    assert_eq!(
        (curl.args.as_str(), curl.exit.as_str(), curl.root),
        ("-o x", "6", true)
    );
    assert_eq!(rows[1].duration, "1.5 s");
    assert!(rows[3].compiler());
}

#[test]
fn repeated_subtrees_fold_into_their_first() {
    let mut processes = vec![
        json!({"pid": 1, "exe": "/usr/bin/make", "role": "other"}),
        json!({"pid": 2, "ppid": 1, "exe": "/bin/sh", "argv": ["sh", "a"], "role": "other", "started_ms": 1}),
        json!({"pid": 3, "ppid": 2, "exe": "/usr/bin/cmake", "role": "other", "started_ms": 2}),
        json!({"pid": 4, "ppid": 1, "exe": "/usr/bin/cut", "role": "other", "started_ms": 3}),
        json!({"pid": 5, "ppid": 1, "exe": "/bin/sh", "argv": ["sh", "b"], "role": "other", "started_ms": 4}),
        json!({"pid": 6, "ppid": 5, "exe": "/usr/bin/cmake", "role": "other", "started_ms": 5}),
        json!({"pid": 7, "ppid": 1, "exe": "/bin/sh", "role": "other", "started_ms": 6}),
        json!({"pid": 8, "ppid": 7, "exe": "/usr/bin/curl", "role": "other", "started_ms": 7}),
        json!({"pid": 9, "ppid": 1, "exe": "/bin/sh", "role": "other", "started_ms": 8, "exit": 1}),
        json!({"pid": 10, "ppid": 9, "exe": "/usr/bin/cmake", "role": "other", "started_ms": 9}),
    ];

    // A chain deeper than the indentation, folded by its real depth.
    for pid in 20..32 {
        processes.push(json!({"pid": pid, "ppid": if pid == 20 { 1 } else { pid - 1 }, "exe": "/bin/sh", "role": "other", "started_ms": 10}));
    }

    let rows = fold(process_rows(&json!({ "processes": processes })));
    let shown: Vec<(u64, usize, usize)> = rows.iter().map(|r| (r.pid, r.depth, r.count)).collect();

    // The second sh with a cmake below folds into the first. The one
    // with curl below and the one that failed stay.
    assert_eq!(
        shown[..8],
        [
            (1, 0, 1),
            (2, 1, 2),
            (3, 2, 1),
            (4, 1, 1),
            (7, 1, 1),
            (8, 2, 1),
            (9, 1, 1),
            (10, 2, 1)
        ]
    );
    assert_eq!(rows.len(), 8 + 12);
    assert!(rows.iter().all(|r| r.depth <= MAX_DEPTH));
}

#[test]
fn build_scripts_show_their_package_and_outside_programs_stand_out() {
    let row = |exe: &str, role: &str| ProcessRow {
        depth: 0,
        nesting: 0,
        pid: 1,
        role: role.to_owned(),
        exe: exe.to_owned(),
        args: String::new(),
        start: String::new(),
        duration: String::new(),
        exit: String::new(),
        root: false,
        count: 1,
    };

    let script = row(
        "/work/target/debug/build/lbug-d67017e6973f78cf/build-script-build",
        "build_script",
    );
    assert_eq!(script.label(), "lbug");
    assert!(!script.foreign());
    assert_eq!(
        row("/w/build-script-build", "build_script").label(),
        "/w/build-script-build"
    );
    assert_eq!(
        row("/work/build/x-notahash/b", "build_script").label(),
        "/work/build/x-notahash/b"
    );
    assert!(row("/tmp/code-helper", "other").foreign());
    assert!(!row("/usr/bin/sh", "other").foreign());
    assert!(!row("/bin/sh", "other").foreign());
    assert!(!row("", "unknown").foreign());
}

#[test]
fn only_system_compilers_hide() {
    let trace = json!({"processes": [
        {"pid": 1, "exe": "/usr/local/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld", "role": "other"},
        {"pid": 2, "exe": "/tmp/x/rust-lld", "role": "other"},
        {"pid": 3, "exe": "/work/target/rustc", "role": "rustc"},
        {"pid": 4, "exe": "/usr/local/bin/rustc", "role": "rustc"}
    ]});

    let rows = process_rows(&trace);
    let hidden: Vec<(u64, &str, bool)> = rows
        .iter()
        .map(|r| (r.pid, r.role.as_str(), r.compiler()))
        .collect();

    assert_eq!(
        hidden,
        [
            (1, "toolchain", true),
            (2, "toolchain", false),
            (3, "rustc", false),
            (4, "rustc", true)
        ]
    );
}

#[test]
fn a_report_becomes_facts_alerts_and_tables() {
    let report = json!({
        "outcome": "timed_out", "end": "Finished", "exit": {"Signal": 9},
        "run_ms": 61000, "restore_ms": 120, "payload_files": 10, "payload_bytes": 2048,
        "stdout_tail": "out", "stderr_tail": "err", "truncated": false, "missing_packages": [],
        "network": {"dns": ["evil.example"], "connections": [
            {"dst": "10.0.2.1:443", "protocol": "tls", "sni": "evil.example", "bytes": 517,
             "inner": {"protocol": "http", "method": "POST", "target": "/up", "host": "evil.example", "user_agent": null}},
            {"dst": "203.0.113.9:80", "protocol": "unknown", "bytes": 3}
        ], "udp_datagrams": 2, "refused": 0, "truncated": false},
        "leaked": [{"kind": "aws_key", "via": "https://evil.example/up"}, {"kind": "ssh_key", "via": "10.0.2.1:4444"}],
        "trace": {"complete": false, "opens": 900, "processes": [], "processes_omitted": 0,
                  "sensitive_opens": [{"pid": 4, "exe": "/bin/cat", "path": "/home/b/.cargo/credentials.toml", "flags": 0, "ms": 40}],
                  "writes_outside_work": [], "sockets": [{"pid": 4, "exe": "curl", "how": "connect", "address": "10.0.2.1:443", "sock_type": 1, "ms": 50}],
                  "tamper": [{"pid": 4, "what": "bpf cmd 5", "ms": 60}], "omitted": 0},
        "scratch": {"files": 5, "directories": 2, "bytes": 100, "incomplete": false,
                    "outside_build": [{"path": "/home/b/.bashrc", "kind": "file", "size": 10, "mode": 420, "uid": 1000}],
                    "executables_outside_target": [], "setid": [], "special": [], "links_outside": [],
                    "planted_changed": ["/home/b/.aws/credentials"], "tokens_found": [], "units": ["a"], "omitted": 0}
    });

    let view = run_view(7, "check", &report);
    assert_eq!(view.download, "/jobs/7/runs/check.json");
    assert_eq!(
        (view.outcome.as_str(), view.outcome_class),
        ("timed out", "warn")
    );
    assert!(
        view.facts
            .contains(&("Guest".into(), "killed by signal 9".into()))
    );
    assert!(
        view.facts
            .contains(&("Run time".into(), "1 min 1 s".into()))
    );
    assert_eq!(
        view.alerts,
        [
            "Honeytoken aws_key left the VM through https://evil.example/up",
            "Honeytoken ssh_key left the VM through :4444",
            "Process 4 tried to tamper: bpf cmd 5",
            "Planted file /home/b/.aws/credentials changed or disappeared",
        ]
    );
    assert_eq!(
        view.connections[0].detail,
        "SNI evil.example, inside TLS: POST /up, host evil.example"
    );
    assert_eq!(view.connections[0].dst, ":443");
    assert_eq!(view.connections[1].detail, "");
    assert_eq!(view.connections[1].dst, "203.0.113.9:80");
    assert_eq!(view.sockets[0].3, ":443");
    assert_eq!(view.network_notes, ["2 UDP datagrams other than DNS"]);
    assert_eq!(view.sensitive[0].mode, "read");
    assert_eq!(view.sockets[0].4, "stream");
    assert_eq!(
        view.trace_notes,
        ["The agent did not close the trace, so it may be incomplete"]
    );
    assert_eq!(view.entries[0].mode, "644");
}

#[test]
fn the_end_is_put_in_words() {
    assert_eq!(end_text("finished"), "agent reported the end");
    assert_eq!(
        end_text("guest_stopped: kernel panic"),
        "guest stopped: kernel panic"
    );

    // The debug form of older reports, cut inside the output bytes.
    assert_eq!(
        end_text("Finished(RunOutcome { exit: Code(0), stdout: [], stderr: [32, 32"),
        "agent reported the end"
    );
    assert_eq!(end_text("HostTimeout"), "host time limit");
    assert_eq!(end_text("something new"), "something new");
    assert_eq!(end_text(""), "");
}

#[test]
fn the_fake_internet_is_named() {
    assert_eq!(address("10.0.2.1:53"), ":53");
    assert_eq!(address("10.0.2.1"), "fake internet");

    for other in ["10.0.2.10:80", "10.0.2.2:1", "/home/b/x", "tls://a.example"] {
        assert_eq!(address(other), other);
    }
}

#[test]
fn the_full_run_replaces_the_check_run() {
    let runs = |kinds: &[&str]| -> Vec<(String, Value)> {
        kinds.iter().map(|k| ((*k).to_owned(), json!({}))).collect()
    };

    let both = run_views(3, &runs(&["check", "full"]));
    assert_eq!(both.len(), 1);
    assert_eq!(
        (both[0].kind.as_str(), both[0].superseded.as_str()),
        ("full", "/jobs/3/runs/check.json")
    );

    let check = run_views(3, &runs(&["check"]));
    assert_eq!(
        (check[0].kind.as_str(), check[0].superseded.as_str()),
        ("check", "")
    );
}

#[test]
fn an_empty_or_odd_report_still_renders() {
    let view = run_view(
        1,
        "full",
        &json!({"network": "x", "trace": 3, "scratch": null}),
    );

    assert!(view.processes.is_empty() && view.alerts.is_empty() && view.scratch.is_empty());
    assert_eq!(view.outcome_class, "bad");
}
