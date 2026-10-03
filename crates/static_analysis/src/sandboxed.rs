//! The sandboxed analysis child.
//!
//! The service starts itself again as `sandbox-analyze`. The child enters
//! its sandbox before it reads any input: a private network namespace with
//! no interfaces, resource limits, and Landlock without any filesystem
//! access. It then reads crate tars from stdin, each prefixed by its length
//! as a big endian `u64`, and prints one JSON line per tar. Parsing hostile
//! sources and running YARA-X therefore happens in a process that cannot
//! reach the network, the filesystem or the database.

use std::error::Error;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::path::Path;
use std::process::{ChildStdin, ChildStdout, ExitCode, Stdio};
use std::time::Duration;

use crateward_core::child::{self, Child, ChildError};
use crateward_core::sandbox::{self, FsAccess, Limits};
use serde::{Deserialize, Serialize};

use crate::analyze::{AnalyzeLimits, StaticReport, analyze};
use crate::yara::Rules;

/// First argument of the analysis child.
pub const ANALYZE: &str = "sandbox-analyze";

/// The child in error messages.
const NAME: &str = "analysis child";

/// Largest tar the child accepts.
pub const MAX_TAR_BYTES: u64 = 1024 * 1024 * 1024;

/// What one child may use in total. YARA-X runs its rules as WebAssembly,
/// and the runtime reserves large virtual regions up front. Resident memory
/// stays far below the address space.
const LIMITS: Limits = Limits {
    address_space: 16 << 30,
    cpu_seconds: 600,
    file_size: 0,
    open_files: 32,
};

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

/// Runs the child if `args` names it. Returns `None` for a normal start.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    (args.get(1).map(String::as_str) == Some(ANALYZE)).then(|| child::exit(serve()))
}

fn serve() -> Result<(), Box<dyn Error>> {
    sandbox::enter(LIMITS, &FsAccess::default())?;
    let rules = Rules::builtin()?;
    let limits = AnalyzeLimits::default();
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    while let Some(tar) = read_tar(&mut stdin)? {
        let outcome = match analyze(&tar, &rules, &limits) {
            Ok(report) => Outcome::Report(Box::new(report)),
            Err(error) => Outcome::Error(error.to_string()),
        };
        serde_json::to_writer(&mut stdout, &outcome)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

/// The next tar, or `None` at the end of the input.
fn read_tar(input: &mut impl Read) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let mut len = [0_u8; 8];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u64::from_be_bytes(len);
    if len > MAX_TAR_BYTES {
        return Err("tar too large".into());
    }
    let mut tar = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    input.by_ref().take(len).read_to_end(&mut tar)?;
    Ok(Some(tar))
}

/// Analyzes tars in one sandboxed child, in order.
///
/// # Errors
///
/// Fails if the child cannot start, crashes, exceeds its limits or answers
/// with something other than one outcome per tar.
pub fn analyze_in_sandbox(exe: &Path, tars: Vec<Vec<u8>>) -> Result<Vec<Outcome>, ChildError> {
    let expected = tars.len();
    let mut command = child::command(exe);
    command
        .arg(ANALYZE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = Child::spawn(NAME, command)?;
    let (stdin, stdout) = (child.stdin()?, child.stdout()?);
    let writer = std::thread::spawn(move || send(stdin, &tars));
    // The reader runs on its own thread, so a child that hangs is killed by
    // the deadline below instead of blocking this call forever.
    let reader = std::thread::spawn(move || read_outcomes(stdout));
    child.finish(Some(TIMEOUT))?;
    // A failed write means the child died, and `finish` has explained why.
    let _ = writer.join();
    let outcomes = reader
        .join()
        .map_err(|_| ChildError::answer(NAME, "the reader thread panicked"))??;
    if outcomes.len() != expected {
        let got = outcomes.len();
        return Err(ChildError::answer(
            NAME,
            format!("{got} of {expected} tars"),
        ));
    }
    Ok(outcomes)
}

fn send(mut stdin: ChildStdin, tars: &[Vec<u8>]) -> io::Result<()> {
    for tar in tars {
        stdin.write_all(&(tar.len() as u64).to_be_bytes())?;
        stdin.write_all(tar)?;
    }
    Ok(())
}

fn read_outcomes(stdout: ChildStdout) -> Result<Vec<Outcome>, ChildError> {
    BufReader::new(stdout)
        .lines()
        .map(|line| {
            let line = line.map_err(ChildError::io(NAME, "reading an outcome"))?;
            serde_json::from_str(&line).map_err(|e| ChildError::answer(NAME, e))
        })
        .collect()
}
