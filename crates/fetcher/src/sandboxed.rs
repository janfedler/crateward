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

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crateward_core::sandbox::{self, FsAccess, Limits};
use serde::{Deserialize, Serialize};

use crate::archive::{ArchiveLimits, validate};

/// First argument of the validation child.
pub const VALIDATE: &str = "sandbox-validate";
/// First argument of the resolution child.
pub const RESOLVE: &str = "sandbox-resolve";

/// Largest `.crate` file the validation child reads.
pub const MAX_CRATE_BYTES: u64 = 128 * 1024 * 1024;

/// Wall clock limit of one resolution.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(180);

/// What the resolution child reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveOutcome {
    /// Whether `Cargo.lock` was written.
    pub ok: bool,
    /// The end of cargo's error output when it failed.
    pub message: String,
}

fn fail(message: &str) -> std::process::ExitCode {
    eprintln!("crateward sandbox: {message}");
    std::process::ExitCode::FAILURE
}

/// Runs a child mode if `args` names one. Returns `None` for a normal start.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<std::process::ExitCode> {
    match args.get(1).map(String::as_str) {
        Some(VALIDATE) => Some(match (args.get(2), args.get(3)) {
            (Some(name), Some(version)) => run_validate(name, version),
            _ => fail("usage: sandbox-validate <name> <version>"),
        }),
        Some(RESOLVE) => Some(match (args.get(2), args.get(3), args.get(4)) {
            (Some(workdir), Some(socket), Some(cargo)) => {
                run_resolve(Path::new(workdir), Path::new(socket), Path::new(cargo))
            }
            _ => fail("usage: sandbox-resolve <workdir> <proxy-socket> <cargo>"),
        }),
        _ => None,
    }
}

fn run_validate(name: &str, version: &str) -> std::process::ExitCode {
    let entered = sandbox::isolate_network()
        .and_then(|()| {
            sandbox::limit(Limits {
                address_space: 1 << 30,
                cpu_seconds: 120,
                file_size: 0,
                open_files: 16,
            })
        })
        .and_then(|()| sandbox::restrict_fs(&FsAccess::default()));
    if let Err(error) = entered {
        return fail(&error.to_string());
    }
    let stdin = std::io::stdin().lock().take(MAX_CRATE_BYTES);
    let report = validate(stdin, name, version, &ArchiveLimits::default());
    match serde_json::to_writer(std::io::stdout().lock(), &report) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => fail(&error.to_string()),
    }
}

/// Copies bytes both ways between a TCP connection and the proxy socket.
fn relay(tcp: std::net::TcpStream, socket: &Path) {
    let Ok(unix) = UnixStream::connect(socket) else {
        return;
    };
    let (Ok(mut tcp_read), Ok(mut unix_write)) = (tcp.try_clone(), unix.try_clone()) else {
        return;
    };
    let upstream = std::thread::spawn(move || {
        let _ = std::io::copy(&mut tcp_read, &mut unix_write);
        let _ = unix_write.shutdown(std::net::Shutdown::Write);
    });
    let (mut tcp_write, mut unix_read) = (tcp, unix);
    let _ = std::io::copy(&mut unix_read, &mut tcp_write);
    let _ = tcp_write.shutdown(std::net::Shutdown::Write);
    let _ = upstream.join();
}

fn run_resolve(workdir: &Path, socket: &Path, cargo: &Path) -> std::process::ExitCode {
    let report = |ok: bool, message: String| {
        let outcome = ResolveOutcome { ok, message };
        match serde_json::to_writer(std::io::stdout().lock(), &outcome) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => fail(&error.to_string()),
        }
    };
    if let Err(error) = sandbox::isolate_network() {
        return fail(&error.to_string());
    }
    // Loopback is down in a new network namespace.
    let lo = Command::new("/usr/sbin/ip")
        .args(["link", "set", "lo", "up"])
        .env_clear()
        .status();
    if !lo.is_ok_and(|s| s.success()) {
        return fail("cannot bring loopback up");
    }
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) => return fail(&error.to_string()),
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(error) => return fail(&error.to_string()),
    };
    let socket_path = socket.to_path_buf();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let socket = socket_path.clone();
            std::thread::spawn(move || relay(stream, &socket));
        }
    });

    let config_dir = workdir.join(".cargo");
    let config = format!(
        "[source.crates-io]\nreplace-with = \"crateward-proxy\"\n\n\
         [source.crateward-proxy]\nregistry = \"sparse+http://127.0.0.1:{port}/index/\"\n\n\
         [net]\nretry = 1\n"
    );
    if let Err(error) = std::fs::create_dir_all(&config_dir)
        .and_then(|()| std::fs::write(config_dir.join("config.toml"), config))
    {
        return fail(&error.to_string());
    }

    let toolchain = cargo
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("/nonexistent"), Path::to_path_buf);
    let access = FsAccess {
        read: vec![
            toolchain,
            "/usr".into(),
            "/lib".into(),
            "/lib64".into(),
            "/etc".into(),
            "/proc".into(),
        ],
        write: vec![workdir.to_path_buf(), "/dev/null".into()],
    };
    let entered = sandbox::limit(Limits {
        address_space: 4 << 30,
        cpu_seconds: 180,
        file_size: 64 << 20,
        open_files: 512,
    })
    .and_then(|()| sandbox::restrict_fs(&access));
    if let Err(error) = entered {
        return fail(&error.to_string());
    }

    let child = Command::new(cargo)
        .args(["generate-lockfile", "--quiet"])
        .current_dir(workdir)
        .env_clear()
        .env("CARGO_HOME", workdir.join("cargo-home"))
        .env("HOME", workdir)
        .env("RUSTC", "/nonexistent/rustc")
        .env("RUSTC_WRAPPER", "")
        .env("CARGO_TERM_COLOR", "never")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => return fail(&format!("starting cargo: {error}")),
    };
    let mut stderr = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(stderr) = stderr.as_mut() {
            let _ = stderr.take(64 * 1024).read_to_string(&mut text);
        }
        text
    });
    let deadline = Instant::now() + RESOLVE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => return fail(&error.to_string()),
        }
    };
    let text = reader.join().unwrap_or_default();
    let tail: String = text
        .lines()
        .rev()
        .take(20)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    match status {
        Some(status) if status.success() => report(true, String::new()),
        Some(status) => report(false, format!("cargo exited with {status}: {tail}")),
        None => report(false, "cargo generate-lockfile timed out".into()),
    }
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
) -> std::io::Result<crate::archive::ArchiveReport> {
    let mut child = Command::new(exe)
        .args([VALIDATE, name, version])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("no stdin"))?;
    let input = crate_file.to_vec();
    let writer = std::thread::spawn(move || {
        // The child may stop reading early (an aborted archive); a broken
        // pipe is expected then.
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output()?;
    let _ = writer.join();
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "validation child failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(std::io::Error::other)
}
