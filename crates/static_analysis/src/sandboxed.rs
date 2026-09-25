//! The sandboxed analysis child.
//!
//! The service starts itself again as `sandbox-analyze`. The child enters
//! its sandbox before it reads any input: a private network namespace with
//! no interfaces, resource limits, and Landlock without any filesystem
//! access. It then reads crate tars from stdin, each prefixed by its length
//! as a big endian `u64`, and prints one JSON line per tar. Parsing hostile
//! sources and running YARA-X therefore happens in a process that cannot
//! reach the network, the filesystem or the database.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crateward_core::sandbox::{self, FsAccess, Limits};
use serde::{Deserialize, Serialize};

use crate::analyze::{AnalyzeLimits, StaticReport, analyze};
use crate::yara::Rules;

/// First argument of the analysis child.
pub const ANALYZE: &str = "sandbox-analyze";

/// Largest tar the child accepts.
pub const MAX_TAR_BYTES: u64 = 1024 * 1024 * 1024;

/// CPU seconds one child may use in total.
const CPU_SECONDS: u64 = 600;

/// Wall clock limit of one child.
pub const TIMEOUT: Duration = Duration::from_secs(900);

/// The child's answer for one tar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The report.
    Report(Box<StaticReport>),
    /// Why the tar could not be analyzed.
    Error(String),
}

fn fail(message: &str) -> std::process::ExitCode {
    eprintln!("crateward sandbox: {message}");
    std::process::ExitCode::FAILURE
}

/// Runs the child if `args` names it. Returns `None` for a normal start.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<std::process::ExitCode> {
    (args.get(1).map(String::as_str) == Some(ANALYZE)).then(run_child)
}

fn run_child() -> std::process::ExitCode {
    let entered = sandbox::isolate_network()
        .and_then(|()| {
            sandbox::limit(Limits {
                // YARA-X runs its rules as WebAssembly, and the runtime
                // reserves large virtual regions up front; resident memory
                // stays far below this.
                address_space: 16 << 30,
                cpu_seconds: CPU_SECONDS,
                file_size: 0,
                open_files: 32,
            })
        })
        .and_then(|()| sandbox::restrict_fs(&FsAccess::default()));
    if let Err(error) = entered {
        return fail(&error.to_string());
    }
    let rules = match Rules::builtin() {
        Ok(rules) => rules,
        Err(error) => return fail(&error),
    };
    let limits = AnalyzeLimits::default();
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    loop {
        let mut len = [0_u8; 8];
        match stdin.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return fail(&e.to_string()),
        }
        let len = u64::from_be_bytes(len);
        if len > MAX_TAR_BYTES {
            return fail("tar too large");
        }
        let mut tar = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        if let Err(e) = (&mut stdin).take(len).read_to_end(&mut tar) {
            return fail(&e.to_string());
        }
        let outcome = match analyze(&tar, &rules, &limits) {
            Ok(report) => Outcome::Report(Box::new(report)),
            Err(error) => Outcome::Error(error.to_string()),
        };
        let written = serde_json::to_writer(&mut stdout, &outcome)
            .map_err(std::io::Error::other)
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush());
        if let Err(e) = written {
            return fail(&e.to_string());
        }
    }
    std::process::ExitCode::SUCCESS
}

/// Analyzes tars in one sandboxed child, in order.
///
/// # Errors
///
/// Fails if the child cannot start, crashes, exceeds its limits or answers
/// with something other than one outcome per tar.
pub fn analyze_in_sandbox(exe: &Path, tars: Vec<Vec<u8>>) -> std::io::Result<Vec<Outcome>> {
    let expected = tars.len();
    let mut child = Command::new(exe)
        .arg(ANALYZE)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("no stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("no stdout"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("no stderr"))?;
    let writer = std::thread::spawn(move || {
        for tar in tars {
            let len = (tar.len() as u64).to_be_bytes();
            if stdin
                .write_all(&len)
                .and_then(|()| stdin.write_all(&tar))
                .is_err()
            {
                // The child died; its exit status explains why.
                return;
            }
        }
    });
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_string(&mut text);
        text
    });
    // The reader runs on its own thread, so a child that hangs is killed by
    // the deadline below instead of blocking this call forever.
    let reader = std::thread::spawn(move || {
        let mut outcomes = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            outcomes.push(serde_json::from_str::<Outcome>(&line).map_err(std::io::Error::other)?);
        }
        Ok::<_, std::io::Error>(outcomes)
    });
    let deadline = std::time::Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::other("analysis child timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = writer.join();
    let stderr = errors.join().unwrap_or_default();
    let outcomes = reader
        .join()
        .map_err(|_| std::io::Error::other("reader thread panicked"))??;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "analysis child failed ({status}): {}",
            stderr.trim()
        )));
    }
    if outcomes.len() != expected {
        return Err(std::io::Error::other(format!(
            "analysis child answered {} of {expected} tars",
            outcomes.len()
        )));
    }
    Ok(outcomes)
}
