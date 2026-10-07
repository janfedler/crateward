//! The two ends of a sandboxed child process.
//!
//! A host worker that handles hostile input starts itself again with a first
//! argument that names a child mode. The child enters its sandbox
//! ([`crate::sandbox::enter`]) before it reads anything, answers on stdout
//! and ends with [`exit`]. The parent runs it as a [`Child`]: an empty
//! environment ([`command`]), the start of stderr kept for the error
//! message, an optional deadline, and no process left behind on any path.
//!
//! Enabled with the `sandbox` feature.

use std::ffi::OsStr;
use std::fmt::Display;
use std::io::{self, Read};
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitCode, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How much of a child's stderr the parent keeps for its error message.
const STDERR_LIMIT: u64 = 64 * 1024;

/// How often a child with a deadline is checked.
const POLL: Duration = Duration::from_millis(20);

/// Why running a child failed.
#[derive(Debug, thiserror::Error)]
pub enum ChildError {
    /// The child could not be started, fed, read or waited for.
    #[error("{child}: {step}: {source}")]
    Io {
        /// The child.
        child: &'static str,
        /// What was being done.
        step: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// The child exited with success, but its answer is incomplete or does
    /// not decode.
    #[error("{child} gave a bad answer: {reason}")]
    Answer {
        /// The child.
        child: &'static str,
        /// What is wrong with the answer.
        reason: String,
    },
    /// The child ran past its deadline and was killed.
    #[error("{child} timed out after {} s", .limit.as_secs())]
    TimedOut {
        /// The child.
        child: &'static str,
        /// The deadline it missed.
        limit: Duration,
    },
    /// The child exited with a failure status.
    #[error("{child} failed ({status}): {stderr}")]
    Failed {
        /// The child.
        child: &'static str,
        /// How it ended.
        status: ExitStatus,
        /// The start of what it printed to stderr.
        stderr: String,
    },
}

impl ChildError {
    /// For `map_err`: an [`ChildError::Io`] of `child` while doing `step`.
    pub fn io<E: Into<io::Error>>(
        child: &'static str,
        step: &'static str,
    ) -> impl FnOnce(E) -> Self {
        move |source| Self::Io {
            child,
            step,
            source: source.into(),
        }
    }

    /// A bad [`ChildError::Answer`] of `child`.
    pub fn answer(child: &'static str, reason: impl Display) -> Self {
        Self::Answer {
            child,
            reason: reason.to_string(),
        }
    }
}

impl From<ChildError> for io::Error {
    fn from(error: ChildError) -> Self {
        Self::other(error)
    }
}

/// A command that starts with an empty environment, so nothing the parent
/// holds in its own reaches a child.
#[must_use]
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();

    command
}

/// Ends a child mode: success for `Ok`. An error goes to stderr, where the
/// parent keeps it for its own error message.
#[must_use]
pub fn exit(result: Result<(), impl Display>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crateward sandbox: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Keeps the start of stderr and discards the rest, so a chatty child
/// neither blocks on a full pipe nor dies of a closed one.
fn drain(mut pipe: ChildStderr) -> String {
    let mut kept = Vec::new();
    let _ = pipe.by_ref().take(STDERR_LIMIT).read_to_end(&mut kept);
    let _ = io::copy(&mut pipe, &mut io::sink());

    String::from_utf8_lossy(&kept).trim().to_owned()
}

/// A running child. Dropping it kills and reaps the process.
#[derive(Debug)]
pub struct Child {
    name: &'static str,
    process: std::process::Child,
    stderr: Option<JoinHandle<String>>,
}

impl Child {
    /// Starts `command`, called `name` in error messages. Stdin and stdout
    /// are the caller's choice. Standard error is captured.
    ///
    /// The command is consumed: its own copies of the child's pipe ends
    /// close at once. Kept open, they would stop the process at the other
    /// end of a pipe from ever seeing EOF or a broken pipe.
    ///
    /// # Errors
    ///
    /// Fails if the process cannot be started.
    pub fn spawn(name: &'static str, mut command: Command) -> Result<Self, ChildError> {
        let mut process = command
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ChildError::io(name, "starting"))?;

        let stderr = process
            .stderr
            .take()
            .map(|pipe| std::thread::spawn(move || drain(pipe)));

        Ok(Self {
            name,
            process,
            stderr,
        })
    }

    fn not_piped(&self, stream: &'static str) -> ChildError {
        ChildError::Io {
            child: self.name,
            step: stream,
            source: io::Error::other("not a pipe"),
        }
    }

    /// Takes the child's stdin, which the command must have piped. Dropping
    /// it ends the child's input.
    ///
    /// # Errors
    ///
    /// Fails if stdin is not a pipe or was taken already.
    pub fn stdin(&mut self) -> Result<ChildStdin, ChildError> {
        self.process
            .stdin
            .take()
            .ok_or_else(|| self.not_piped("stdin"))
    }

    /// Takes the child's stdout, which the command must have piped.
    ///
    /// # Errors
    ///
    /// Fails if stdout is not a pipe or was taken already.
    pub fn stdout(&mut self) -> Result<ChildStdout, ChildError> {
        self.process
            .stdout
            .take()
            .ok_or_else(|| self.not_piped("stdout"))
    }

    /// Reads at most `limit` bytes of the child's stdout, then waits for it
    /// to exit without a deadline.
    ///
    /// # Errors
    ///
    /// Fails like [`Child::finish`], which wins over what was read.
    pub fn output(&mut self, limit: u64) -> Result<Vec<u8>, ChildError> {
        let mut out = Vec::new();
        self.stdout()?
            .take(limit)
            .read_to_end(&mut out)
            .map_err(ChildError::io(self.name, "reading stdout"))?;
        self.finish(None)?;

        Ok(out)
    }

    /// Waits for the child to exit with success. With a `timeout` the child
    /// is killed when it passes.
    ///
    /// # Errors
    ///
    /// [`ChildError::TimedOut`] after the deadline, and
    /// [`ChildError::Failed`] with what the child printed to stderr for a
    /// failure status.
    pub fn finish(&mut self, timeout: Option<Duration>) -> Result<(), ChildError> {
        let status = match timeout {
            None => self
                .process
                .wait()
                .map_err(ChildError::io(self.name, "waiting"))?,
            Some(limit) => self.wait_for(limit)?,
        };

        if status.success() {
            return Ok(());
        }

        let stderr = self
            .stderr
            .take()
            .and_then(|thread| thread.join().ok())
            .unwrap_or_default();

        Err(ChildError::Failed {
            child: self.name,
            status,
            stderr,
        })
    }

    fn wait_for(&mut self, limit: Duration) -> Result<ExitStatus, ChildError> {
        let deadline = Instant::now() + limit;

        loop {
            let polled = self.process.try_wait();
            if let Some(status) = polled.map_err(ChildError::io(self.name, "waiting"))? {
                return Ok(status);
            }

            if Instant::now() >= deadline {
                self.kill();
                return Err(ChildError::TimedOut {
                    child: self.name,
                    limit,
                });
            }

            std::thread::sleep(POLL);
        }
    }

    fn kill(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn shell(script: &str) -> Command {
        let mut shell = command("/bin/sh");
        shell
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null());

        shell
    }

    fn shell_with_stdout(script: &str) -> Command {
        let mut shell = shell(script);
        shell.stdout(Stdio::piped());

        shell
    }

    #[test]
    fn a_child_that_succeeds_is_fine() {
        let mut child = Child::spawn("shell", shell("exit 0")).unwrap();
        child.finish(None).unwrap();
    }

    #[test]
    fn a_failure_carries_its_status_and_stderr() {
        let mut child = Child::spawn("shell", shell("echo boom >&2; exit 3")).unwrap();
        let error = child.finish(None).unwrap_err();

        assert!(
            matches!(&error, ChildError::Failed { status, .. } if status.code() == Some(3)),
            "{error}"
        );
        assert_eq!(error.to_string(), "shell failed (exit status: 3): boom");
    }

    #[test]
    fn a_child_that_cannot_start_is_an_error() {
        let error = Child::spawn("ghost", command("/nonexistent/binary")).unwrap_err();

        assert!(
            error.to_string().starts_with("ghost: starting: "),
            "{error}"
        );
    }

    #[test]
    fn a_child_past_its_deadline_is_killed() {
        let mut child = Child::spawn("shell", shell("exec sleep 30")).unwrap();
        let started = Instant::now();
        let error = child.finish(Some(Duration::from_millis(100))).unwrap_err();

        assert!(matches!(error, ChildError::TimedOut { .. }), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_chatty_child_neither_blocks_nor_dies() {
        // Four times what the parent keeps and what a pipe holds.
        let script = "yes | head -c 262144 >&2; exit 1";
        let mut child = Child::spawn("shell", shell(script)).unwrap();
        let Err(ChildError::Failed { stderr, .. }) = child.finish(Some(Duration::from_secs(20)))
        else {
            panic!("the child should have failed");
        };

        assert!(
            (60_000..=64 * 1024).contains(&stderr.len()),
            "{}",
            stderr.len()
        );
    }

    #[test]
    fn the_environment_starts_empty() {
        let mut env = command("/usr/bin/env");
        env.stdin(Stdio::null()).stdout(Stdio::piped());
        let mut child = Child::spawn("env", env).unwrap();

        assert!(child.output(1024).unwrap().is_empty());
    }

    #[test]
    fn output_is_read_before_the_exit_status_is_checked() {
        let failing = shell_with_stdout("echo out; echo err >&2; exit 2");
        let error = Child::spawn("shell", failing)
            .unwrap()
            .output(1024)
            .unwrap_err();

        assert_eq!(error.to_string(), "shell failed (exit status: 2): err");

        let fine = shell_with_stdout("echo out");
        let mut child = Child::spawn("shell", fine).unwrap();

        assert_eq!(child.output(1024).unwrap(), b"out\n");
    }

    #[test]
    fn a_reader_that_ends_early_breaks_the_writers_pipe() {
        let mut writer = Child::spawn("writer", shell_with_stdout("yes")).unwrap();
        let mut reader = shell("exit 0");
        reader.stdin(writer.stdout().unwrap());
        Child::spawn("reader", reader)
            .unwrap()
            .finish(None)
            .unwrap();

        // Nobody holds the read end any more, so `yes` dies of SIGPIPE
        // instead of blocking on a full pipe until the deadline.
        let error = writer.finish(Some(Duration::from_secs(20))).unwrap_err();

        assert!(matches!(error, ChildError::Failed { .. }), "{error}");
    }

    #[test]
    fn dropping_a_child_kills_it() {
        let child = Child::spawn("shell", shell("exec sleep 30")).unwrap();
        let pid = child.process.id();
        drop(child);

        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
}
