//! The sandboxed children, end to end.
//!
//! The validation fixtures are inert archives. They are never extracted or
//! executed: the child only reads their headers. The resolution child runs
//! a fake `cargo`, a shell script written by the test that only writes
//! files. The children enter their sandbox before they read input, so a
//! passing test also shows that the sandbox can be entered. Kernels or CI
//! runners without unprivileged user namespaces skip these tests, unless
//! `CRATEWARD_REQUIRE_SANDBOX` is set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use crateward_core::child::ChildError;
use crateward_core::http::{ClientConfig, PoliteClient};
use crateward_core::name::CrateName;
use crateward_core::sandbox;
use crateward_fetcher::archive::{ArchiveFinding, ArchiveReport};
use crateward_fetcher::proxy::IndexCache;
use crateward_fetcher::resolve::{ResolveError, resolve as resolve_in_sandbox};
use crateward_fetcher::sandboxed::{RESOLVE, ResolveOutcome, validate_in_sandbox};

const FETCHER: &str = env!("CARGO_BIN_EXE_crateward_fetcher");

fn crate_file(entries: &[(&str, tar::EntryType, &[u8], &str)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, kind, data, link) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(*kind);
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        if !link.is_empty() {
            header.set_link_name(link).unwrap();
        }
        builder.append_data(&mut header, path, *data).unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&builder.into_inner().unwrap()).unwrap();
    gz.finish().unwrap()
}

fn validate(bytes: &[u8]) -> Option<ArchiveReport> {
    match validate_in_sandbox(Path::new(FETCHER), bytes, "demo", "1.0.0") {
        Ok(report) => Some(report),
        Err(error) if sandbox::unavailable(&error) => None,
        Err(error) => panic!("{error}"),
    }
}

const FILE: tar::EntryType = tar::EntryType::Regular;

#[test]
fn a_normal_crate_is_storable() {
    let bytes = crate_file(&[
        ("demo-1.0.0/Cargo.toml", FILE, b"[package]\n", ""),
        ("demo-1.0.0/src/lib.rs", FILE, b"pub fn f() {}\n", ""),
    ]);
    let Some(report) = validate(&bytes) else {
        return;
    };
    assert!(report.is_storable(), "{report:?}");
    assert!(report.findings.is_empty(), "{report:?}");
    assert_eq!(report.files, 2);
}

#[test]
fn a_hostile_entry_is_a_finding_and_nothing_more() {
    let bytes = crate_file(&[
        ("demo-1.0.0/Cargo.toml", FILE, b"[package]\n", ""),
        (
            "demo-1.0.0/link",
            tar::EntryType::Symlink,
            b"",
            "/etc/passwd",
        ),
    ]);
    let Some(report) = validate(&bytes) else {
        return;
    };
    assert!(report.is_storable(), "{report:?}");
    assert!(
        matches!(&report.findings[..], [ArchiveFinding::Symlink { target, .. }] if target == "/etc/passwd"),
        "{report:?}"
    );
}

#[test]
fn bytes_that_are_no_archive_abort_the_report() {
    let Some(report) = validate(b"this is not a gzip stream") else {
        return;
    };
    assert!(!report.is_storable(), "{report:?}");
}

#[test]
fn a_child_that_fails_is_an_error_with_its_status() {
    let error = validate_in_sandbox(Path::new("/bin/false"), b"", "demo", "1.0.0").unwrap_err();
    assert!(
        matches!(&error, ChildError::Failed { status, .. } if status.code() == Some(1)),
        "{error}"
    );
}

#[test]
fn a_child_that_does_not_exist_is_an_error() {
    let error =
        validate_in_sandbox(Path::new("/nonexistent/fetcher"), b"", "demo", "1.0.0").unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("validation child: starting: "),
        "{error}"
    );
}

#[test]
fn a_resolution_child_that_does_not_exist_is_an_error() {
    let client = PoliteClient::new(&ClientConfig {
        user_agent: "crateward/0.1 (+https://crateward.com/about; security@crateward.com)".into(),
        requests_per_second: 1.0,
        timeout: Duration::from_secs(1),
        allow_plain_http: false,
    })
    .unwrap();
    let work = Path::new(env!("CARGO_TARGET_TMPDIR")).join("resolve-no-child");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let error = runtime
        .block_on(resolve_in_sandbox(
            Path::new("/nonexistent/fetcher"),
            Path::new("/nonexistent/cargo"),
            &work,
            client,
            "https://index.invalid/",
            IndexCache::default(),
            &CrateName::parse("demo").unwrap(),
            &semver::Version::new(1, 0, 0),
        ))
        .unwrap_err();
    assert!(
        matches!(&error, ResolveError::Child(ChildError::Io { child, step, .. })
            if *child == "resolution child" && *step == "running"),
        "{error}"
    );
    assert!(!work.exists());
}

/// Runs the resolution child with a fake `cargo` that runs `script`. Returns
/// the work directory and what the child did, or `None` where the host
/// refuses the sandbox. The environment holds a secret that must not reach
/// cargo.
fn resolve(name: &str, script: &str, mode: u32) -> Option<(PathBuf, Output)> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("resolve-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    let (work, bin) = (dir.join("work"), dir.join("toolchain/bin"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let cargo = bin.join("cargo");
    std::fs::write(&cargo, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(mode)).unwrap();
    let output = Command::new(FETCHER)
        .args([RESOLVE])
        .args([&work, &dir.join("proxy.sock"), &cargo])
        .env_clear()
        .env("SECRET_TOKEN", "hunter2")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() && sandbox::unavailable(&stderr) {
        return None;
    }
    Some((work, output))
}

fn outcome(output: &Output) -> ResolveOutcome {
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn a_cargo_that_succeeds_is_a_resolution() {
    let Some((_, output)) = resolve("ok", "exit 0", 0o755) else {
        return;
    };
    assert_eq!(
        outcome(&output),
        ResolveOutcome {
            ok: true,
            message: String::new()
        }
    );
}

#[test]
fn a_cargo_that_fails_reports_the_end_of_its_output() {
    let script = "i=1; while [ $i -le 30 ]; do echo \"line $i\" >&2; i=$((i+1)); done; exit 101";
    let Some((_, output)) = resolve("fails", script, 0o755) else {
        return;
    };
    let outcome = outcome(&output);
    assert!(!outcome.ok);
    assert!(
        outcome.message.starts_with("cargo exited with "),
        "{outcome:?}"
    );
    assert!(outcome.message.contains("101"), "{outcome:?}");
    assert!(outcome.message.ends_with("line 30"), "{outcome:?}");
    assert!(outcome.message.contains("line 11"), "{outcome:?}");
    assert!(!outcome.message.contains("line 10"), "{outcome:?}");
}

#[test]
fn a_cargo_that_cannot_start_ends_the_child_with_an_error() {
    let Some((_, output)) = resolve("no-exec", "exit 0", 0o644) else {
        return;
    };
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cargo: starting: "), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn cargo_gets_the_relay_and_a_clean_environment() {
    let script = "/usr/bin/cat .cargo/config.toml > seen-config; /usr/bin/env > seen-env";
    let Some((work, output)) = resolve("env", script, 0o755) else {
        return;
    };
    assert!(outcome(&output).ok);
    let config = std::fs::read_to_string(work.join("seen-config")).unwrap();
    assert!(config.contains("sparse+http://127.0.0.1:"), "{config}");
    let env = std::fs::read_to_string(work.join("seen-env")).unwrap();
    assert!(env.contains("RUSTC=/nonexistent/rustc"), "{env}");
    assert!(!env.contains("hunter2") && !env.contains("SECRET"), "{env}");
}

#[test]
fn cargo_can_write_nothing_but_its_work_directory() {
    let escape = Path::new(env!("CARGO_TARGET_TMPDIR")).join("resolve-escape-marker");
    let _ = std::fs::remove_file(&escape);
    let script = format!(
        "if echo escaped > {} 2>/dev/null; then echo escaped > verdict; else echo contained > verdict; fi",
        escape.display()
    );
    let Some((work, output)) = resolve("escape", &script, 0o755) else {
        return;
    };
    assert!(outcome(&output).ok);
    assert_eq!(
        std::fs::read_to_string(work.join("verdict")).unwrap(),
        "contained\n"
    );
    assert!(!escape.exists());
}
