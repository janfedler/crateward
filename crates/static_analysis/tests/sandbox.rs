//! The sandboxed analysis child, end to end, on inert fixture crates.
//!
//! The fixtures are never executed: the child only parses them. The child
//! enters its sandbox before reading input, so a passing test also shows
//! that the sandbox can be entered. Kernels or CI runners without
//! unprivileged user namespaces skip it, unless `CRATEWARD_REQUIRE_SANDBOX`
//! is set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    missing_docs
)]

use std::path::Path;

use crateward_static_analysis::sandboxed::{Outcome, analyze_in_sandbox};

fn fixture(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("fixture-0.1.0/{path}"), *data)
            .unwrap();
    }
    builder.into_inner().unwrap()
}

fn run(tars: Vec<Vec<u8>>) -> Option<Vec<Outcome>> {
    let exe = Path::new(env!("CARGO_BIN_EXE_crateward_static_analysis"));
    match analyze_in_sandbox(exe, tars) {
        Ok(outcomes) => Some(outcomes),
        Err(error)
            if std::env::var("CRATEWARD_REQUIRE_SANDBOX").is_err()
                && error.to_string().contains("namespace") =>
        {
            eprintln!("skipping: {error}");
            None
        }
        Err(error) => panic!("{error}"),
    }
}

#[test]
fn the_child_analyzes_several_archives_in_order() {
    let manifest: (&str, &[u8]) = (
        "Cargo.toml",
        b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );
    let plain = fixture(&[manifest, ("src/lib.rs", b"pub fn f() {}\n")]);
    let build = fixture(&[
        manifest,
        ("build.rs", b"fn main() {}\n"),
        ("src/lib.rs", b""),
    ]);
    let broken = fixture(&[("src/lib.rs", b"")]);
    let Some(outcomes) = run(vec![plain, build, broken]) else {
        return;
    };
    assert_eq!(outcomes.len(), 3);
    let Outcome::Report(first) = &outcomes[0] else {
        panic!("{:?}", outcomes[0]);
    };
    assert!(!first.has_build_time_code());
    let Outcome::Report(second) = &outcomes[1] else {
        panic!("{:?}", outcomes[1]);
    };
    assert!(second.has_build_time_code());
    assert!(matches!(&outcomes[2], Outcome::Error(e) if e.contains("Cargo.toml")));
}

#[test]
fn an_empty_batch_is_fine() {
    if let Some(outcomes) = run(Vec::new()) {
        assert!(outcomes.is_empty());
    }
}
