//! Commands that need no database: configuration, the state machine and the integrity manifest.

use super::*;

#[test]
fn config_check_accepts_a_valid_file() {
    run(TOOL, None, &["config", "check", "--config", EXAMPLE]).expect(
        0,
        &format!("{EXAMPLE} is valid\n"),
        "",
    );
}

#[test]
fn a_bad_configuration_exits_78_and_says_why() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let text = std::fs::read_to_string(&site.config).unwrap();
    std::fs::write(
        &site.config,
        text.replace("[instance]", "[instance]\nnickname = 1"),
    )
    .unwrap();
    let ran = site.run(&["config", "check"]);

    assert_eq!((ran.code, ran.out.as_str()), (78, ""));
    assert!(ran.err.contains("nickname"), "{}", ran.err);

    let missing = run(TOOL, None, &["config", "check", "--config", MISSING]);
    missing.expect(
        78,
        "",
        &format!("cannot read {MISSING}: No such file or directory (os error 2)\n"),
    );
}

#[test]
fn every_command_that_reads_the_configuration_exits_78_without_it() {
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-such-pack");
    let out = out.to_str().unwrap();
    let commands: [&[&str]; 11] = [
        &["config", "check", "--config", MISSING],
        &["status", "--config", MISSING],
        &["quarantine", "--config", MISSING, "lift"],
        &["integrity", "--config", MISSING, "record"],
        &["integrity", "--config", MISSING, "check"],
        &["egress", "--config", MISSING],
        &["evidence", "1", "--out", out, "--config", MISSING],
        &["archive", "--out", out, "--config", MISSING],
        &["sbom", "1", "--out", out, "--config", MISSING],
        &["disclosure", "--config", MISSING, "show", "1"],
        &["breaker", "--config", MISSING, "close", "sandbox"],
    ];

    for args in commands {
        let ran = run(TOOL, None, args);

        assert_eq!((ran.code, ran.out.as_str()), (78, ""), "{args:?}");
        assert!(ran.err.contains(MISSING), "{args:?}: {}", ran.err);
    }

    assert!(!Path::new(out).exists());
}

#[test]
fn an_unknown_stage_is_refused_before_the_configuration_is_read() {
    let ran = run(
        TOOL,
        None,
        &["breaker", "--config", MISSING, "close", "bogus"],
    );

    ran.expect(1, "", "unknown stage bogus\n");
}

#[test]
fn state_machine_diagram_prints_the_mermaid_source() {
    let ran = run(TOOL, None, &["state-machine", "diagram"]);
    ran.expect(0, &mermaid_diagram(), "");

    assert!(ran.out.ends_with("\n") && !ran.out.ends_with("\n\n"));
}

#[test]
fn state_machine_states_lists_the_stage_that_owns_each_state() {
    let ran = run(TOOL, None, &["state-machine", "states"]);
    let expected: String = JobState::ALL
        .iter()
        .map(|state| {
            let owner = state
                .stage()
                .map_or("none (terminal)", |stage| stage.name());

            format!("{:<20} {owner}\n", state.name())
        })
        .collect();

    ran.expect(0, &expected, "");

    assert!(ran.out.starts_with("Discovered           fetch\n"));
    assert!(ran.out.ends_with("Failed               none (terminal)\n"));
}

#[test]
fn a_closed_pipe_ends_the_tool_quietly() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = Command::new(TOOL)
        .args(["state-machine", "diagram"])
        .env_remove("CRATEWARD_CONFIG")
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert_eq!(String::from_utf8(output.stderr).unwrap(), "");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn an_unreachable_database_exits_1() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let ran = site.run(&["status"]);

    assert_eq!((ran.code, ran.out.as_str()), (1, ""));
    assert!(ran.err.ends_with('\n') && ran.err.len() > 1, "{}", ran.err);
}

#[test]
fn the_manifest_is_readable_by_other_users_under_a_strict_umask() {
    use std::os::unix::fs::PermissionsExt as _;

    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let tool = site.path("bin/crateward");
    let ran = run(
        "sh",
        Some(&site.config),
        &[
            "-c",
            "umask 077 && exec \"$0\" \"$@\"",
            &tool.display().to_string(),
            "integrity",
            "record",
        ],
    );

    let mode = std::fs::metadata(site.manifest())
        .unwrap()
        .permissions()
        .mode();

    assert_eq!(ran.code, 0, "{}", ran.err);
    assert_eq!(mode & 0o777, 0o644);
}

#[test]
fn the_manifest_is_recorded_and_checked() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let manifest = site.manifest();
    site.run(&["integrity", "record"]).expect(
        0,
        &format!("recorded 7 files in {}\n", manifest.display()),
        "",
    );
    let text = std::fs::read_to_string(&manifest).unwrap();
    let mut expected: Vec<String> = Site::FILES
        .iter()
        .map(|name| site.path(&format!("files/{name}")))
        .chain([site.path("bin/crateward")])
        .map(|path| path.display().to_string())
        .collect();

    expected.sort();
    let recorded: Vec<&str> = text
        .lines()
        .map(|l| l.split_once("  ").unwrap().1)
        .collect();

    assert_eq!(recorded, expected);
    assert!(!site.path("data/integrity.tmp").exists());

    site.run(&["integrity", "check"])
        .expect(0, "7 files match\n", "");

    let kernel = site.path("files/kernel");
    std::fs::write(&kernel, "changed").unwrap();
    site.run(&["integrity", "check"]).expect(
        1,
        &format!("MISMATCH {}: digest differs\n", kernel.display()),
        "1 files differ\n",
    );
    let rootfs = site.path("files/rootfs");
    std::fs::remove_file(&rootfs).unwrap();
    let ran = site.run(&["integrity", "check"]);

    assert_eq!((ran.code, ran.err.as_str()), (1, "2 files differ\n"));

    let lines: Vec<&str> = ran.out.lines().collect();
    assert_eq!(
        lines[0],
        format!("MISMATCH {}: digest differs", kernel.display())
    );
    assert!(lines[1].starts_with(&format!("MISMATCH {}: ", rootfs.display())));
    assert!(lines[1].ends_with("No such file or directory (os error 2)"));
    assert_eq!(lines.len(), 2);
}

#[test]
fn a_manifest_that_is_missing_or_malformed_fails_the_check() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    let manifest = site.manifest();
    site.run(&["integrity", "check"]).expect(
        1,
        "",
        &format!(
            "{}: No such file or directory (os error 2)\n",
            manifest.display()
        ),
    );
    std::fs::write(&manifest, "garbage\n").unwrap();
    site.run(&["integrity", "check"])
        .expect(1, "", "manifest line 1 is malformed\n");
}

#[test]
fn recording_into_a_missing_directory_fails() {
    let site = Site::new("postgresql://nobody@127.0.0.1:1/none");
    std::fs::remove_dir_all(site.path("data")).unwrap();
    let ran = site.run(&["integrity", "record"]);
    let temporary = site.path("data/integrity.tmp");
    let error = format!(
        "{}: No such file or directory (os error 2)\n",
        temporary.display()
    );

    ran.expect(1, "", &error);
}

// The commands that use the job store.
