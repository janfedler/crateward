use super::*;

fn sample(name: &str, deps: &[(&str, &str)]) -> Sample {
    let mut locked = vec![((name.to_owned(), "1.0.0".to_owned()), format!("sum-{name}"))];
    locked.extend(
        deps.iter()
            .map(|(n, v)| (((*n).to_owned(), (*v).to_owned()), format!("sum-{n}-{v}"))),
    );

    Sample {
        name: name.into(),
        version: "1.0.0".into(),
        lockfile: "version = 4\n".into(),
        locked,
    }
}

fn stored(samples: &[Sample]) -> HashMap<String, String> {
    samples
        .iter()
        .flat_map(|s| {
            s.locked
                .iter()
                .map(|(_, c)| (c.clone(), format!("blob-{c}")))
        })
        .collect()
}

#[test]
fn only_fully_qualifying_samples_are_replayed_with_stubs() {
    let serde = ("serde", "1.0.0");
    let rare = ("rare", "0.1.0");
    let samples = vec![
        sample("a", &[serde]),
        sample("b", &[serde, rare]),
        sample("c", &[serde]),
    ];

    let blobs = stored(&samples);
    let all: HashSet<String> = blobs.keys().cloned().collect();
    let plan = plan(&samples, &all, &blobs, 2, 10);

    // `b` locks `rare`, which only one sample locks.
    assert_eq!(plan.stubs, ["a-1.0.0", "c-1.0.0"]);
    assert_eq!(plan.units, 1);

    let text = script(&plan, 900);
    assert!(text.contains(
        "cd /cw/probe && timeout -k 10 900 cargo check --locked --offline --keep-going\n\
             case $? in 124|137) slow=\"$slow a-1.0.0\" ;; esac\n"
    ));

    assert!(text.contains("cd /cw/probes/0 && "));
    assert!(text.ends_with("echo \"crateward-warm: timed out:$slow\" >&2\n"));

    // The gate: nothing eligible, nothing replayed.
    assert!(
        super::plan(&samples, &HashSet::new(), &blobs, 2, 10)
            .probes
            .is_empty()
    );
}

#[test]
fn the_warm_vm_takes_what_the_slots_would_use() {
    let mut config = crateward_core::config::Config::from_toml(include_str!(
        "../../../../config/crateward.example.toml"
    ))
    .unwrap();

    let warm = config.sandbox.warm.take().unwrap();

    // Three slots of 1 vCPU, 4 GiB and a 4 GiB scratch disk: 24 GiB,
    // less the 8 GiB scratch disk of the warm build, halved.
    assert_eq!(machine(&config.sandbox, &warm), Some((3, 8192)));

    config.sandbox.scratch_mib_per_slot = 2048;

    assert_eq!(machine(&config.sandbox, &warm), Some((3, 5120)));

    // Not more than one slot has.
    config.sandbox.scratch_mib_per_slot = 512;

    assert_eq!(machine(&config.sandbox, &warm), None);

    config.sandbox.scratch_mib_per_slot = 4096;
    config.sandbox.slots = 1;

    assert_eq!(machine(&config.sandbox, &warm), None);
}

#[test]
fn a_crate_is_never_both_a_stub_and_a_dependency() {
    let samples = vec![
        sample("a", &[("serde", "1.0.0")]),
        // Depends on `a` 1.0.0, which the first probe stubs.
        sample("x", &[("serde", "1.0.0"), ("a", "1.0.0")]),
        sample("y", &[("serde", "1.0.0"), ("a", "1.0.0")]),
    ];

    let blobs = stored(&samples);
    let mut blobs = blobs;
    blobs.insert("sum-a-1.0.0".into(), "blob".into());
    let all: HashSet<String> = blobs.keys().cloned().collect();
    let plan = plan(&samples, &all, &blobs, 2, 10);

    assert_eq!(plan.stubs, ["a-1.0.0"]);
}

#[test]
fn an_image_that_cannot_be_read_names_its_path() {
    let path = Path::new("/nonexistent/warm.erofs");
    let error = blake3_file(path).map_err(image_io(path)).unwrap_err();

    assert!(matches!(error, WarmError::Image { .. }));
    assert!(error.to_string().starts_with("/nonexistent/warm.erofs: "));
}

#[test]
fn a_missing_blob_skips_the_sample() {
    let samples = vec![
        sample("a", &[("serde", "1.0.0")]),
        sample("b", &[("serde", "1.0.0")]),
    ];

    let blobs: HashMap<String, String> = [("sum-serde-1.0.0".to_owned(), "b".to_owned())].into();

    let all: HashSet<String> = blobs.keys().cloned().collect();

    assert!(plan(&samples, &all, &blobs, 2, 10).probes.is_empty());
}

use crateward_core::report::network::{Connection, Leak, NetworkSummary, Sniffed};
use crateward_core::report::scratch::Entry;
use crateward_core::report::trace::{FileAccess, Process, Role, SocketUse, Tamper};

/// A run the warm build accepts.
fn clean() -> RunReport {
    RunReport {
        outcome: BuildOutcome::Succeeded,
        end: String::new(),
        exit: None,
        restore_ms: 0,
        run_ms: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        truncated: false,
        payload_files: 0,
        payload_bytes: 0,
        missing_packages: Vec::new(),
        network: NetworkSummary::default(),
        leaked: Vec::new(),
        trace: TraceSummary {
            complete: true,
            ..TraceSummary::default()
        },
        tokens_in_trace: Vec::new(),
        scratch: Some(ScratchReport {
            units: vec!["libserde-0123456789abcdef.rmeta".into()],
            ..ScratchReport::default()
        }),
        tokens_on_disk: Vec::new(),
    }
}

fn access(exe: &str, path: &str) -> FileAccess {
    FileAccess {
        pid: 7,
        exe: exe.into(),
        path: path.into(),
        flags: 0,
        ms: 0,
    }
}

fn socket(exe: &str, address: &str) -> SocketUse {
    SocketUse {
        pid: 7,
        exe: exe.into(),
        how: "connect".into(),
        address: address.into(),
        sock_type: 1,
        ms: 0,
    }
}

fn tamper(what: &str) -> Tamper {
    Tamper {
        pid: 7,
        what: what.into(),
        ms: 0,
    }
}

fn root() -> Process {
    Process {
        pid: 7,
        ppid: Some(1),
        exe: "/bin/sh".into(),
        argv: Vec::new(),
        role: Role::Other,
        started_ms: 0,
        exit: None,
        ended_ms: None,
        became_root: true,
    }
}

fn leak() -> Leak {
    Leak {
        kind: "aws_access_key_id".into(),
        via: "udp".into(),
    }
}

fn connection() -> Connection {
    Connection {
        dst: "1.2.3.4:80".into(),
        sniffed: Sniffed::Unknown,
        bytes: 0,
        inner: None,
    }
}

fn entry(path: &str, kind: &str) -> Entry {
    Entry {
        path: path.into(),
        kind: kind.into(),
        size: 0,
        mode: 0o644,
        uid: 0,
        target: None,
    }
}

type Edit<T> = fn(&mut T);

fn rejected(change: Edit<RunReport>) -> Option<String> {
    let mut report = clean();
    change(&mut report);

    rejection(&report)
}

#[test]
fn a_clean_run_is_used() {
    assert_eq!(rejection(&clean()), None);
}

#[test]
fn each_problem_of_the_run_is_named_with_its_example() {
    let cases: [(&str, Edit<RunReport>); 13] = [
        ("the trace is incomplete: ", |r| r.trace.complete = false),
        ("a process used a socket: curl 1.2.3.4:80", |r| {
            r.trace.sockets = vec![socket("curl", "1.2.3.4:80")];
        }),
        ("a process opened a sensitive file: cat /etc/shadow", |r| {
            r.trace.sensitive_opens = vec![access("cat", "/etc/shadow")];
        }),
        ("a process wrote outside the build: tee /etc/motd", |r| {
            r.trace.writes_outside_work = vec![access("tee", "/etc/motd")];
        }),
        ("a process tried to tamper: bpf cmd 5", |r| {
            r.trace.tamper = vec![tamper("bpf cmd 5")];
        }),
        ("a process ran as root: ", |r| {
            r.trace.processes = vec![root()];
        }),
        ("a honeytoken was used: ", |r| {
            r.leaked = vec![leak()];
        }),
        ("a honeytoken was used: ", |r| {
            r.tokens_in_trace = vec![leak()];
        }),
        ("a honeytoken was used: ", |r| {
            r.tokens_on_disk = vec![leak()];
        }),
        ("the fake internet saw traffic: ", |r| {
            r.network.dns = vec!["example.com".into()];
        }),
        ("the fake internet saw traffic: ", |r| {
            r.network.connections = vec![connection()];
        }),
        ("the fake internet saw traffic: ", |r| {
            r.network.packets = vec!["icmp".into()];
        }),
        ("the fake internet saw traffic: ", |r| {
            r.network.udp_datagrams = 1;
        }),
    ];

    for (expected, change) in cases {
        assert_eq!(rejected(change).as_deref(), Some(expected));
    }
}

#[test]
fn problems_are_reported_in_a_fixed_order() {
    let mut report = clean();
    report.trace.complete = false;
    report.trace.sockets = vec![socket("curl", "1.2.3.4:80")];
    report.trace.sensitive_opens = vec![access("cat", "/etc/shadow")];
    report.trace.writes_outside_work = vec![access("tee", "/etc/motd")];
    report.trace.tamper = vec![tamper("bpf cmd 5")];
    report.trace.processes = vec![root()];
    report.leaked = vec![leak()];
    report.network.udp_datagrams = 1;
    report.scratch = None;
    let steps: [(&str, Edit<RunReport>); 9] = [
        ("the trace is incomplete: curl 1.2.3.4:80", |r| {
            r.trace.complete = true;
        }),
        ("a process used a socket: curl 1.2.3.4:80", |r| {
            r.trace.sockets.clear();
        }),
        ("a process opened a sensitive file: cat /etc/shadow", |r| {
            r.trace.sensitive_opens.clear();
        }),
        ("a process wrote outside the build: tee /etc/motd", |r| {
            r.trace.writes_outside_work.clear();
        }),
        ("a process tried to tamper: bpf cmd 5", |r| {
            r.trace.tamper.clear();
        }),
        ("a process ran as root: ", |r| r.trace.processes.clear()),
        ("a honeytoken was used: ", |r| r.leaked.clear()),
        ("the fake internet saw traffic: ", |r| {
            r.network.udp_datagrams = 0;
        }),
        ("the scratch disk was not scanned", |r| {
            r.scratch = Some(ScratchReport::default());
        }),
    ];

    for (expected, fix) in steps {
        assert_eq!(rejection(&report).as_deref(), Some(expected));

        fix(&mut report);
    }

    assert_eq!(
        rejection(&report).as_deref(),
        Some("the replays compiled nothing")
    );
}

#[test]
fn the_scratch_disk_must_hold_compiled_units() {
    assert_eq!(
        rejected(|r| r.scratch = None).as_deref(),
        Some("the scratch disk was not scanned")
    );
    assert_eq!(
        rejected(|r| r.scratch = Some(ScratchReport::default())).as_deref(),
        Some("the replays compiled nothing")
    );
}

#[test]
fn unexpected_scratch_entries_are_reported_in_a_fixed_order() {
    let mut report = clean();
    let scratch = report.scratch.as_mut().unwrap();
    scratch.error = Some("reading the image: bad".into());
    scratch.outside_build = vec![entry("/etc/outside", "file")];
    scratch.executables_outside_target = vec![entry("/work/tool", "file")];
    scratch.setid = vec![entry("/work/su", "file")];
    scratch.special = vec![entry("/work/pipe", "fifo")];
    scratch.links_outside = vec![entry("/work/link", "symlink")];
    scratch.planted_changed = vec!["/work/home/.aws/credentials".into()];
    let steps: [(&str, Edit<ScratchReport>); 7] = [
        ("reading the image: bad", |s| s.error = None),
        ("/etc/outside", |s| s.outside_build.clear()),
        ("/work/tool", |s| s.executables_outside_target.clear()),
        ("/work/su", |s| s.setid.clear()),
        ("/work/pipe (fifo)", |s| s.special.clear()),
        ("/work/link", |s| s.links_outside.clear()),
        ("/work/home/.aws/credentials", |s| s.planted_changed.clear()),
    ];

    for (expected, fix) in steps {
        assert_eq!(
            rejection(&report),
            Some(format!(
                "the scratch disk holds unexpected entries: {expected}"
            ))
        );

        fix(report.scratch.as_mut().unwrap());
    }

    assert_eq!(rejection(&report), None);
}
