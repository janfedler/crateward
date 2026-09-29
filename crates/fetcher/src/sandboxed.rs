//! The fetcher's sandboxed child processes.
//!
//! The fetcher starts itself again with a first argument naming a child
//! mode. Each mode enters its sandbox before reading any input:
//!
//! * `sandbox-validate <name> <version>`: reads a `.crate` file on stdin,
//!   validates it (see [`crate::archive`]) and prints the report as JSON. No
//!   network, no filesystem access at all.
//! * `sandbox-resolve <workdir> <proxy-socket> <cargo>`: runs
//!   `cargo generate-lockfile` in `workdir`. The only network is a relay
//!   from `127.0.0.1` inside a private network namespace to the index proxy
//!   socket. Landlock limits the filesystem to the toolchain, system
//!   libraries and the work directory. `RUSTC` points to a path that does
//!   not exist, so nothing can be compiled.

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use crateward_core::child::{self, Child, ChildError};
use crateward_core::sandbox::{self, FsAccess, Limits};
use serde::{Deserialize, Serialize};

use crate::archive::{ArchiveLimits, ArchiveReport, validate};

/// First argument of the validation child.
pub const VALIDATE: &str = "sandbox-validate";
/// First argument of the resolution child.
pub const RESOLVE: &str = "sandbox-resolve";

/// The validation child in error messages.
const VALIDATE_NAME: &str = "validation child";

/// Largest `.crate` file the validation child reads.
pub const MAX_CRATE_BYTES: u64 = 128 * 1024 * 1024;

/// Largest report the fetcher reads from the validation child. An honest
/// report is a few kilobytes.
const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

/// What the validation child may use.
const VALIDATE_LIMITS: Limits = Limits {
    address_space: 1 << 30,
    cpu_seconds: 120,
    file_size: 0,
    open_files: 16,
};

/// What the resolution child and its cargo may use in total.
const RESOLVE_LIMITS: Limits = Limits {
    address_space: 4 << 30,
    cpu_seconds: 180,
    file_size: 64 << 20,
    open_files: 512,
};

/// Wall clock limit of one resolution.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(180);

/// Lines of cargo's error output that a failed resolution reports.
const ERROR_LINES: usize = 20;

/// What the resolution child reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveOutcome {
    /// Whether `Cargo.lock` was written.
    pub ok: bool,
    /// The end of cargo's error output when it failed.
    pub message: String,
}

/// Runs a child mode if `args` names one. Returns `None` for a normal start.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        [_, VALIDATE, name, version] => run_validate(name, version),
        [_, RESOLVE, workdir, socket, cargo] => {
            run_resolve(Path::new(workdir), Path::new(socket), Path::new(cargo))
        }
        [_, VALIDATE, ..] => Err("usage: sandbox-validate <name> <version>".into()),
        [_, RESOLVE, ..] => Err("usage: sandbox-resolve <workdir> <proxy-socket> <cargo>".into()),
        _ => return None,
    };
    Some(child::exit(result))
}

fn run_validate(name: &str, version: &str) -> Result<(), Box<dyn Error>> {
    sandbox::enter(VALIDATE_LIMITS, &FsAccess::default())?;
    let stdin = io::stdin().lock().take(MAX_CRATE_BYTES);
    let report = validate(stdin, name, version, &ArchiveLimits::default());
    write_json(&report)
}

fn write_json(value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.flush()?;
    Ok(())
}

/// Copies bytes both ways between a TCP connection and the proxy socket.
fn relay(tcp: TcpStream, socket: &Path) {
    let Ok(unix) = UnixStream::connect(socket) else {
        return;
    };
    let (Ok(mut tcp_read), Ok(mut unix_write)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let upstream = std::thread::spawn(move || {
        let _ = io::copy(&mut tcp_read, &mut unix_write);
        let _ = unix_write.shutdown(Shutdown::Write);
    });
    let (mut tcp_write, mut unix_read) = (tcp, unix);
    let _ = io::copy(&mut unix_read, &mut tcp_write);
    let _ = tcp_write.shutdown(Shutdown::Write);
    let _ = upstream.join();
}

/// Brings up the loopback device of the private network namespace and
/// relays a port on it to the index proxy socket. Returns the port.
fn serve_relay(socket: &Path) -> Result<u16, Box<dyn Error>> {
    // Loopback is down in a new network namespace.
    let up = child::command("/usr/sbin/ip")
        .args(["link", "set", "lo", "up"])
        .status();
    if !up.is_ok_and(|status| status.success()) {
        return Err("cannot bring loopback up".into());
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let socket = socket.to_path_buf();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let socket = socket.clone();
            std::thread::spawn(move || relay(stream, &socket));
        }
    });
    Ok(port)
}

/// Points cargo at the relay instead of crates.io.
fn write_cargo_config(workdir: &Path, port: u16) -> io::Result<()> {
    let dir = workdir.join(".cargo");
    std::fs::create_dir_all(&dir)?;
    let config = format!(
        "[source.crates-io]\nreplace-with = \"crateward-proxy\"\n\n\
         [source.crateward-proxy]\nregistry = \"sparse+http://127.0.0.1:{port}/index/\"\n\n\
         [net]\nretry = 1\n"
    );
    std::fs::write(dir.join("config.toml"), config)
}

fn resolve_access(workdir: &Path, cargo: &Path) -> FsAccess {
    let toolchain = cargo
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("/nonexistent"), Path::to_path_buf);
    FsAccess {
        read: vec![
            toolchain,
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/etc".into(),
            "/proc".into(),
        ],
        write: vec![workdir.to_path_buf(), "/dev/null".into()],
    }
}

fn run_resolve(workdir: &Path, socket: &Path, cargo: &Path) -> Result<(), Box<dyn Error>> {
    // Not `sandbox::enter`: the relay and the cargo configuration need the
    // network namespace and a writable disk before Landlock closes both.
    sandbox::isolate_network()?;
    let port = serve_relay(socket)?;
    write_cargo_config(workdir, port)?;
    sandbox::limit(RESOLVE_LIMITS)?;
    sandbox::restrict_fs(&resolve_access(workdir, cargo))?;
    write_json(&run_cargo(workdir, cargo)?)
}

/// Runs `cargo generate-lockfile`. A cargo that fails or takes too long is a
/// failed resolution; a cargo that cannot run at all is an error.
fn run_cargo(workdir: &Path, cargo: &Path) -> Result<ResolveOutcome, ChildError> {
    let mut command = child::command(cargo);
    command
        .args(["generate-lockfile", "--quiet"])
        .current_dir(workdir)
        .env("CARGO_HOME", workdir.join("cargo-home"))
        .env("HOME", workdir)
        .env("RUSTC", "/nonexistent/rustc")
        .env("RUSTC_WRAPPER", "")
        .env("CARGO_TERM_COLOR", "never")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    let failure = match Child::spawn("cargo", command)?.finish(Some(RESOLVE_TIMEOUT)) {
        Ok(()) => None,
        Err(ChildError::Failed { status, stderr, .. }) => Some(format!(
            "cargo exited with {status}: {}",
            last_lines(&stderr, ERROR_LINES)
        )),
        Err(ChildError::TimedOut { .. }) => Some("cargo generate-lockfile timed out".to_owned()),
        Err(other) => return Err(other),
    };
    Ok(ResolveOutcome {
        ok: failure.is_none(),
        message: failure.unwrap_or_default(),
    })
}

fn last_lines(text: &str, count: usize) -> String {
    let mut lines: Vec<&str> = text.lines().rev().take(count).collect();
    lines.reverse();
    lines.join("\n")
}

/// Runs the validation child on a `.crate` file.
///
/// # Errors
///
/// Fails if the child cannot run or its report does not parse.
pub fn validate_in_sandbox(
    exe: &Path,
    crate_file: &[u8],
    name: &str,
    version: &str,
) -> Result<ArchiveReport, ChildError> {
    let mut command = child::command(exe);
    command
        .args([VALIDATE, name, version])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = Child::spawn(VALIDATE_NAME, command)?;
    let mut stdin = child.stdin()?;
    let report = std::thread::scope(|scope| {
        // The child may stop reading early (an aborted archive); a broken
        // pipe is expected then.
        scope.spawn(move || {
            let _ = stdin.write_all(crate_file);
        });
        child.output(MAX_REPORT_BYTES)
    })?;
    serde_json::from_slice(&report).map_err(|e| ChildError::answer(VALIDATE_NAME, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_end_of_cargos_output_is_kept() {
        assert_eq!(last_lines("a\nb\nc\nd", 2), "c\nd");
        assert_eq!(last_lines("a\nb", 5), "a\nb");
        assert_eq!(last_lines("", 5), "");
    }
}
