use super::*;
use crate::firecracker::agent::RunOutcome;
use crateward_core::bytes::hex;
use crateward_core::failure::FailureClass;

fn finished(exit: ExitStatus) -> JobEnd {
    JobEnd::Finished(RunOutcome {
        exit,
        stdout: b"out".to_vec(),
        stderr: b"err".to_vec(),
        truncated: true,
        trace: Box::default(),
    })
}

fn setup(work_dir: PathBuf) -> WorkerSetup {
    WorkerSetup {
        exe: PathBuf::from("/nonexistent/exe"),
        work_dir,
        scratch_mib: 64,
        check_timeout: Duration::from_secs(60),
        full_timeout: Duration::from_secs(120),
        warm: Some(PathBuf::from("/nonexistent/warm.erofs")),
        warm_placeholder: PathBuf::from("/nonexistent/none"),
    }
}

#[test]
fn a_finished_run_is_judged_by_its_exit_status() {
    for (exit, outcome) in [
        (ExitStatus::Code(0), BuildOutcome::Succeeded),
        (ExitStatus::Code(101), BuildOutcome::Failed),
        (ExitStatus::Signal(9), BuildOutcome::Failed),
        (ExitStatus::TimedOut, BuildOutcome::TimedOut),
    ] {
        let end = finished(exit);
        let ended = Ended::try_from(&end).unwrap();

        assert_eq!(ended.outcome, outcome);
        assert_eq!(ended.exit, Some(exit));
        assert_eq!(ended.stdout, b"out");
        assert_eq!(ended.stderr, b"err");
        assert!(ended.truncated);
    }
}

#[test]
fn runs_without_a_report_are_results_without_output() {
    for (end, outcome) in [
        (JobEnd::HostTimeout, BuildOutcome::TimedOut),
        (JobEnd::ResourceLimit, BuildOutcome::ResourceLimit),
        (
            JobEnd::GuestStopped("panic".into()),
            BuildOutcome::GuestStopped,
        ),
    ] {
        let ended = Ended::try_from(&end).unwrap();

        assert_eq!(ended.outcome, outcome);
        assert_eq!(ended.exit, None);
        assert!(ended.stdout.is_empty() && ended.stderr.is_empty());
        assert!(!ended.truncated);
    }
}

#[test]
fn a_crashed_vmm_or_a_touched_decoy_is_a_suspected_compromise() {
    for (end, message) in [
        (
            JobEnd::VmmCrashed("SIGSYS".into()),
            "the VMM crashed: SIGSYS",
        ),
        (
            JobEnd::DecoyTouched,
            "something read the decoy in the jail root",
        ),
    ] {
        let failure = Ended::try_from(&end).unwrap_err();

        assert_eq!(failure.class, FailureClass::SuspectedCompromise);
        assert_eq!(failure.message, message);
        assert_eq!(failure.escalation, None);
    }
}

#[test]
fn a_kvm_error_is_ours_and_raises_an_alert() {
    let failure = Ended::try_from(&JobEnd::KvmError("no /dev/kvm".into())).unwrap_err();

    assert_eq!(failure.class, FailureClass::Infrastructure);
    assert_eq!(failure.message, "KVM error: no /dev/kvm");
    assert_eq!(failure.escalation, Some(HumanEscalation::KvmError));
}

#[test]
fn a_vm_that_vanished_without_a_reason_is_ours() {
    let failure = Ended::try_from(&JobEnd::UnexpectedExit("exit 3".into())).unwrap_err();

    assert_eq!(failure.class, FailureClass::Infrastructure);
    assert_eq!(failure.message, "the VM ended unexpectedly: exit 3");
    assert_eq!(failure.escalation, None);
}

#[test]
fn job_files_live_in_the_work_directory_and_can_be_removed() {
    let dir = std::env::temp_dir().join(format!("cw-jobfiles-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let setup = setup(dir.clone());
    let files = JobFiles::named(&setup, "job-7");

    assert_eq!(files.payload, dir.join("job-7.payload"));
    assert_eq!(files.scratch, dir.join("job-7.scratch"));
    assert_eq!(files.network, dir.join("job-7.network"));
    assert_eq!(files.warm, setup.warm);
    assert_eq!(files.warm_placeholder, setup.warm_placeholder);

    std::fs::write(&files.payload, b"x").unwrap();
    std::fs::write(&files.network, b"x").unwrap();
    files.remove();

    assert!(!files.payload.exists() && !files.scratch.exists() && !files.network.exists());

    // Nothing is left to remove the second time, which is fine.
    files.remove();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_job_input_carries_the_plan_the_tokens_and_the_drives() {
    let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
    let plan = RunPlan::check(Duration::from_secs(90));
    let mut files = JobFiles::named(&setup(PathBuf::from("/work")), "job-1");
    files.warm = None;
    let input = job_input(7, &tokens, &files, &plan, 512);

    assert_eq!(input.spec.job_id, 7);
    assert_eq!(input.spec.argv, plan.argv);
    assert_eq!(input.spec.cwd, guest::PROBE);
    assert_eq!(input.spec.timeout_secs, 90);
    assert_eq!(input.spec.output_limit, OUTPUT_LIMIT);

    let (base, planted) = input.spec.env.split_at(BASE_ENV.len());
    assert_eq!(
        base.first(),
        Some(&("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned()))
    );
    assert_eq!(planted, tokens.env);
    assert_eq!(input.workspace.mounts, job_mounts(false).0);
    assert_eq!(
        input.workspace.directories,
        [job_mounts(false).1, tokens.directories.clone()].concat()
    );
    assert_eq!(input.workspace.files, tokens.files);

    let drives = input.drives.unwrap();
    assert_eq!(drives.payload, files.payload);
    assert_eq!(drives.scratch, files.scratch);
    assert_eq!(drives.warm, files.warm_placeholder);
    assert_eq!(input.network_log, Some(files.network));
    assert_eq!(input.scratch_mib, 512);
}

#[test]
fn a_warm_image_is_mounted_and_replaces_the_placeholder() {
    let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
    let plan = RunPlan::full(Duration::from_secs(3600));
    let files = JobFiles::named(&setup(PathBuf::from("/work")), "job-1");
    let input = job_input(1, &tokens, &files, &plan, 512);

    assert_eq!(input.spec.argv[1], "build");
    assert_eq!(input.spec.timeout_secs, 3600);
    assert_eq!(input.workspace.mounts, job_mounts(true).0);
    assert_eq!(input.drives.unwrap().warm, files.warm.unwrap());
}

fn network_log(name: &str, contents: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cw-netlog-{}-{name}", std::process::id()));
    std::fs::write(&path, contents).unwrap();

    path
}

fn line(kind: EventKind) -> String {
    serde_json::to_string(&Event { ms: 0, kind }).unwrap()
}

fn tcp(dst: &str, sniffed: Sniffed, data: &str, decrypted: Option<&str>) -> EventKind {
    EventKind::Tcp {
        dst: dst.into(),
        sniffed,
        bytes: 10,
        data: hex(data.as_bytes()),
        inner: None,
        decrypted: decrypted.map(|text| hex(text.as_bytes())),
    }
}

fn connection(dst: &str, sniffed: Sniffed) -> Connection {
    Connection {
        dst: dst.into(),
        sniffed,
        bytes: 10,
        inner: None,
    }
}

fn http(host: Option<&str>) -> Sniffed {
    Sniffed::Http {
        method: "GET".into(),
        target: "/".into(),
        host: host.map(Into::into),
        user_agent: None,
    }
}

fn tokens() -> Vec<Token> {
    vec![
        Token {
            kind: "cargo_registry_token",
            value: "cioSECRET".into(),
        },
        Token {
            kind: "ssh_key",
            value: "ssh-SECRET".into(),
        },
    ]
}

fn leak(kind: &str, via: &str) -> Leak {
    Leak {
        kind: kind.into(),
        via: via.into(),
    }
}

#[test]
fn the_network_log_becomes_a_summary_and_leaks() {
    let dns = |name: &str, qtype| EventKind::Dns {
        name: name.into(),
        qtype,
    };

    let tls = |sni: Option<&str>| Sniffed::Tls {
        sni: sni.map(Into::into),
    };

    let lines: Vec<String> = [
        dns("a.example", 1),
        dns("a.example", 28),
        dns("cioSECRET.evil.example", 1),
        tcp(
            "10.0.2.1:8080",
            http(Some("h.example")),
            "x cioSECRET x",
            None,
        ),
        tcp(
            "10.0.2.1:8080",
            http(Some("h.example")),
            "x cioSECRET x",
            None,
        ),
        tcp(
            "10.0.2.1:443",
            tls(Some("t.example")),
            "ssh-SECRET",
            Some("cioSECRET"),
        ),
        tcp("1.2.3.4:80", Sniffed::Unknown, "cioSECRET", None),
        tcp("5.6.7.8:80", http(None), "cioSECRET", None),
        tcp("9.9.9.9:443", tls(None), "no token", None),
        EventKind::Udp {
            bytes: 10,
            data: hex(b"ssh-SECRET"),
        },
        EventKind::Packet {
            summary: "icmp echo".into(),
            bytes: 10,
            data: hex(b"cioSECRET"),
        },
        EventKind::PacketLimit,
        EventKind::Refused { dst: "a".into() },
        EventKind::Refused { dst: "b".into() },
        EventKind::Truncated,
    ]
    .into_iter()
    .map(line)
    .collect();

    let path = network_log("summary", lines.join("\n").as_bytes());
    let (summary, leaked) = analyze_network(&path, &tokens());
    std::fs::remove_file(&path).unwrap();

    assert_eq!(summary.dns, ["a.example", "cioSECRET.evil.example"]);
    assert_eq!(
        summary.connections,
        [
            connection("10.0.2.1:8080", http(Some("h.example"))),
            connection("10.0.2.1:8080", http(Some("h.example"))),
            connection("10.0.2.1:443", tls(Some("t.example"))),
            connection("1.2.3.4:80", Sniffed::Unknown),
            connection("5.6.7.8:80", http(None)),
            connection("9.9.9.9:443", tls(None)),
        ]
    );
    assert_eq!(summary.udp_datagrams, 1);
    assert_eq!(summary.refused, 2);
    assert_eq!(summary.packets, ["icmp echo"]);
    assert!(summary.packets_truncated && summary.truncated);

    // A token is named once per route, however often it is seen.
    assert_eq!(
        leaked,
        [
            leak("cargo_registry_token", "cioSECRET.evil.example"),
            leak("cargo_registry_token", "http://h.example"),
            leak("ssh_key", "tls://t.example"),
            leak("cargo_registry_token", "https://t.example"),
            leak("cargo_registry_token", "1.2.3.4:80"),
            leak("cargo_registry_token", "5.6.7.8:80"),
            leak("ssh_key", "udp"),
            leak("cargo_registry_token", "packet"),
        ]
    );
}

#[test]
fn the_lists_of_the_network_summary_are_bounded() {
    let lines: Vec<String> = (0..MAX_LISTED + 50)
        .flat_map(|i| {
            [
                EventKind::Dns {
                    name: format!("{i}.example"),
                    qtype: 1,
                },
                tcp("1.2.3.4:80", Sniffed::Unknown, "", None),
                EventKind::Packet {
                    summary: format!("packet {i}"),
                    bytes: 1,
                    data: String::new(),
                },
            ]
        })
        .map(line)
        .collect();

    let path = network_log("bounded", lines.join("\n").as_bytes());
    let (summary, leaked) = analyze_network(&path, &tokens());
    std::fs::remove_file(&path).unwrap();

    assert_eq!(summary.dns.len(), MAX_LISTED);
    assert_eq!(summary.connections.len(), MAX_LISTED);
    assert_eq!(summary.packets.len(), MAX_LISTED);
    assert_eq!(
        summary.dns.last().unwrap(),
        &format!("{}.example", MAX_LISTED - 1)
    );
    assert!(leaked.is_empty());
}

#[test]
fn an_unreadable_network_log_ends_the_summary() {
    let read = |name: &str, contents: &[u8]| {
        let path = network_log(name, contents);
        let (summary, _) = analyze_network(&path, &tokens());
        std::fs::remove_file(&path).unwrap();
        summary
    };

    let dns = |name: &str| {
        line(EventKind::Dns {
            name: name.into(),
            qtype: 1,
        })
    };

    // A line that is no event is skipped.
    let skipped = read(
        "skipped",
        format!("{}\nnot json\n{}\n", dns("a"), dns("b")).as_bytes(),
    );

    assert_eq!(skipped.dns, ["a", "b"]);

    // So is a line that is no text.
    let mut bytes = format!("{}\n", dns("a")).into_bytes();
    bytes.extend_from_slice(b"\xff\xfe\n");
    bytes.extend_from_slice(dns("b").as_bytes());

    assert_eq!(read("binary", &bytes).dns, ["a", "b"]);

    // A missing log is an empty summary.
    let missing = std::env::temp_dir().join("cw-netlog-missing");

    assert_eq!(
        analyze_network(&missing, &tokens()).0,
        NetworkSummary::default()
    );
}

#[test]
fn a_token_after_a_flood_is_still_found() {
    // More than the 64 MiB the host used to read.
    let padding = line(EventKind::Tcp {
        dst: "1.2.3.4:80".into(),
        sniffed: Sniffed::Unknown,
        bytes: 1 << 20,
        data: hex(&vec![b'x'; MAX_CAPTURE]),
        inner: None,
        decrypted: None,
    });

    let mut log = vec![padding; 600];
    log.push(line(tcp(
        "1.2.3.4:80",
        Sniffed::Unknown,
        "cioSECRET!",
        None,
    )));
    let path = network_log("flood", log.join("\n").as_bytes());
    let (summary, leaked) = analyze_network(&path, &tokens());
    std::fs::remove_file(&path).unwrap();

    assert_eq!(leaked, [leak("cargo_registry_token", "1.2.3.4:80")]);
    assert_eq!(summary.cut, 600);
    assert!(!summary.log_cut);
    assert_eq!(
        summary.unsearched(),
        ["connections or frames longer than it keeps"]
    );
}

#[test]
fn only_data_the_fake_internet_kept_whole_counts_as_searched() {
    let lines: Vec<String> = [
        tcp("1.2.3.4:80", Sniffed::Unknown, "all of it!", None),
        EventKind::Tcp {
            dst: "1.2.3.4:443".into(),
            sniffed: Sniffed::Tls { sni: None },
            bytes: 10,
            data: hex(b"0123456789"),
            inner: None,
            decrypted: Some(hex(&vec![b'p'; MAX_CAPTURE])),
        },
        EventKind::Packet {
            summary: "icmp echo".into(),
            bytes: 1500,
            data: hex(b"start"),
        },
    ]
    .into_iter()
    .map(line)
    .collect();

    let path = network_log("cut", lines.join("\n").as_bytes());
    let (summary, _) = analyze_network(&path, &tokens());
    std::fs::remove_file(&path).unwrap();

    assert_eq!(summary.cut, 2);
    assert!(NetworkSummary::default().unsearched().is_empty());
}

#[test]
fn leaks_name_the_token_and_where_it_was_seen() {
    let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
    let found = leaks(
        &tokens,
        [
            (1, "tls://x.example".to_owned()),
            (usize::MAX, "nowhere".to_owned()),
        ],
    );

    assert_eq!(
        found,
        [Leak {
            kind: tokens.tokens[1].kind.to_owned(),
            via: "tls://x.example".to_owned(),
        }]
    );
}
