//! Runs one job and streams its output to the host.
//!
//! The job runs in its own process group with a cleared environment and, in
//! the VM, as the unprivileged `builder` user. Two reader threads forward
//! stdout and stderr through a channel, so the connection has exactly one
//! writer. Output beyond the job's limit is dropped after one
//! `OutputTruncated` message. The process keeps running, because a crate
//! that writes a lot of output is behavior worth observing, not an error.
//!
//! With tracing active, a third thread streams the eBPF trace through the
//! same channel. After the job's process group is gone, the trace is
//! drained and closed with `TraceEnd` before `Exited`.

use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crateward_core::protocol::{
    ExitStatus, GuestMessage, JobSpec, MAX_OUTPUT_CHUNK, OutputStream, TraceTotals, write_message,
};

use crate::AgentError;
use crate::trace::{Batch, Tracer, monotonic_ns};

/// How long the agent waits for the trace to drain after the job ended.
const TRACE_DRAIN: Duration = Duration::from_secs(10);

/// How the job's process is started.
#[derive(Debug, Clone, Copy)]
pub struct RunOptions {
    /// User and group to switch to, or `None` to keep the agent's identity
    /// (used by tests on the host).
    pub identity: Option<(u32, u32)>,
}

enum Event {
    Output(OutputStream, Vec<u8>),
    Closed,
    Trace(Batch),
}

/// Forwards events to the host and keeps the output budget.
struct Forwarder<'a, W> {
    out: &'a mut W,
    limit: u64,
    forwarded: u64,
    truncated: bool,
    open_streams: u32,
    totals: Option<TraceTotals>,
}

impl<'a, W: Write> Forwarder<'a, W> {
    fn new(out: &'a mut W, limit: u32) -> Self {
        Self {
            out,
            limit: u64::from(limit),
            forwarded: 0,
            truncated: false,
            open_streams: 2,
            totals: None,
        }
    }

    /// Drains the trace for up to `TRACE_DRAIN` when tracing, then writes
    /// `TraceEnd` (when tracing) and `Exited`.
    fn finish(
        mut self,
        tracing: bool,
        events: &mpsc::Receiver<Event>,
        exit: ExitStatus,
    ) -> Result<(), AgentError> {
        let drain_until = Instant::now() + TRACE_DRAIN;
        while tracing && self.totals.is_none() {
            let left = drain_until.saturating_duration_since(Instant::now());
            match events.recv_timeout(left) {
                Ok(event) => self.handle(event)?,
                Err(_) => break,
            }
        }

        if tracing {
            let totals = self.totals.unwrap_or_default();
            write_message(self.out, &GuestMessage::TraceEnd(totals))?;
        }

        write_message(self.out, &GuestMessage::Exited(exit))?;
        Ok(())
    }

    fn handle(&mut self, event: Event) -> Result<(), AgentError> {
        match event {
            Event::Output(stream, data) => {
                let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
                if self.forwarded.saturating_add(len) <= self.limit {
                    self.forwarded += len;
                    write_message(self.out, &GuestMessage::Output { stream, data })?;
                } else if !self.truncated {
                    self.truncated = true;
                    write_message(self.out, &GuestMessage::OutputTruncated)?;
                }
            }
            Event::Closed => self.open_streams = self.open_streams.saturating_sub(1),
            Event::Trace(Batch::Events(events)) => {
                write_message(self.out, &GuestMessage::Trace(events))?;
            }
            Event::Trace(Batch::Done(totals)) => self.totals = Some(totals),
        }

        Ok(())
    }
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    stream: OutputStream,
    events: mpsc::Sender<Event>,
) {
    std::thread::spawn(move || {
        let mut buffer = vec![0_u8; MAX_OUTPUT_CHUNK];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = buffer.get(..n).unwrap_or_default().to_vec();
                    if events.send(Event::Output(stream, chunk)).is_err() {
                        break;
                    }
                }
            }
        }

        let _ = events.send(Event::Closed);
    });
}

fn kill_group(pid: u32) {
    if let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

/// Runs the job and writes `Started`, `Output`, `OutputTruncated`,
/// `Trace`, `TraceEnd` and `Exited` messages to `out`. A job that cannot be
/// started produces an `Error` message instead.
///
/// # Errors
///
/// Fails only if writing to `out` fails.
pub fn run_job<W: Write>(
    spec: &JobSpec,
    options: RunOptions,
    mut tracer: Option<&mut Tracer>,
    out: &mut W,
) -> Result<(), AgentError> {
    let Some((program, args)) = spec.argv.split_first() else {
        write_message(out, &GuestMessage::Error("empty argv".into()))?;
        return Ok(());
    };

    let tracing = tracer.is_some();

    if let Some(tracer) = tracer.as_deref_mut() {
        tracer.clear();
    }

    let start_ns = monotonic_ns();
    let mut child = match command(spec, program, args, options).spawn() {
        Ok(child) => child,
        Err(error) => {
            let message = format!("cannot start {program}: {error}");
            write_message(out, &GuestMessage::Error(message))?;
            return Ok(());
        }
    };

    let pid = child.id();
    write_message(out, &GuestMessage::Started { pid })?;

    let (sender, events) = mpsc::channel();

    if let Some(stdout) = child.stdout.take() {
        spawn_reader(stdout, OutputStream::Stdout, sender.clone());
    }

    if let Some(stderr) = child.stderr.take() {
        spawn_reader(stderr, OutputStream::Stderr, sender.clone());
    }

    let stop = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(u64::from(spec.timeout_secs));
    let mut forwarder = Forwarder::new(out, spec.output_limit);
    std::thread::scope(|scope| {
        if let Some(tracer) = tracer {
            let sender = sender.clone();
            let stop = &stop;
            scope.spawn(move || {
                tracer.stream(start_ns, stop, |batch| {
                    sender.send(Event::Trace(batch)).is_ok()
                });
            });
        }

        drop(sender);
        let result = supervise(&mut child, pid, deadline, &events, &mut forwarder);

        // The trace ends only after the job's process group is gone.
        stop.store(true, Ordering::Release);
        let exit = result?;

        // What the job wrote must reach the scratch disk before the host
        // reads it. The VM ends without unmounting. Tests on the host run
        // without an identity and must not sync the host's disks.
        if options.identity.is_some() {
            rustix::fs::sync();
        }

        forwarder.finish(tracing, &events, exit)
    })
}

/// The job's process: its own group, a cleared environment and piped output.
fn command(spec: &JobSpec, program: &str, args: &[String], options: RunOptions) -> Command {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some((uid, gid)) = options.identity {
        command.uid(uid).gid(gid);
    }

    command
}

/// Forwards events until the job's streams close and its process exits,
/// or the deadline passes. Kills the process group either way.
fn supervise<W: Write>(
    child: &mut std::process::Child,
    pid: u32,
    deadline: Instant,
    events: &mpsc::Receiver<Event>,
    forwarder: &mut Forwarder<'_, W>,
) -> Result<ExitStatus, AgentError> {
    let mut timed_out = false;

    while forwarder.open_streams > 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(remaining) {
            Ok(event) => forwarder.handle(event)?,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                kill_group(pid);
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // A job can close both streams and keep running, so the deadline also
    // applies while waiting for the process itself.
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(AgentError::io("waiting for the job"))?
        {
            break status;
        }

        if !timed_out && Instant::now() >= deadline {
            timed_out = true;
            kill_group(pid);
        }

        match events.recv_timeout(Duration::from_millis(20)) {
            Ok(event) => forwarder.handle(event)?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };

    // Nothing of the job may outlive it: processes that stayed in the group
    // are killed here. A process that left the group with `setsid` dies with
    // the VM, which ends after every job.
    kill_group(pid);
    Ok(if timed_out {
        ExitStatus::TimedOut
    } else if let Some(code) = status.code() {
        ExitStatus::Code(code)
    } else {
        ExitStatus::Signal(status.signal().unwrap_or(0))
    })
}

#[cfg(test)]
mod tests {
    use crateward_core::protocol::{MAX_FRAME_LEN, WallClock, read_message};

    use super::*;

    fn spec(script: &str, timeout_secs: u32, output_limit: u32) -> JobSpec {
        JobSpec {
            job_id: 1,
            wall_clock: WallClock { secs: 0, nanos: 0 },
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            env: vec![("MARKER".into(), "visible".into())],
            cwd: "/".into(),
            timeout_secs,
            output_limit,
        }
    }

    fn run(spec: &JobSpec) -> Vec<GuestMessage> {
        let mut wire = Vec::new();
        run_job(spec, RunOptions { identity: None }, None, &mut wire).unwrap();
        let mut reader = wire.as_slice();
        let mut messages = Vec::new();
        while let Some(m) = read_message(&mut reader, MAX_FRAME_LEN).unwrap() {
            messages.push(m);
        }

        messages
    }

    fn stdout_of(messages: &[GuestMessage]) -> String {
        messages
            .iter()
            .filter_map(|m| match m {
                GuestMessage::Output {
                    stream: OutputStream::Stdout,
                    data,
                } => Some(String::from_utf8_lossy(data).into_owned()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn reports_output_and_exit_code_with_a_clean_environment() {
        let messages = run(&spec("echo $MARKER; echo ${HOME:-unset}; exit 3", 10, 1024));

        assert!(matches!(
            messages.first(),
            Some(GuestMessage::Started { .. })
        ));
        assert_eq!(stdout_of(&messages), "visible\nunset\n");
        assert_eq!(
            messages.last(),
            Some(&GuestMessage::Exited(ExitStatus::Code(3)))
        );
    }

    #[test]
    fn truncates_output_beyond_the_limit_once() {
        let messages = run(&spec("head -c 100000 /dev/zero", 10, 1000));
        let truncations = messages
            .iter()
            .filter(|m| **m == GuestMessage::OutputTruncated)
            .count();

        assert_eq!(truncations, 1);
        assert_eq!(
            messages.last(),
            Some(&GuestMessage::Exited(ExitStatus::Code(0)))
        );
    }

    #[test]
    fn kills_the_whole_group_on_timeout() {
        let started = Instant::now();
        let messages = run(&spec("sleep 60 & sleep 60", 1, 1024));

        assert_eq!(
            messages.last(),
            Some(&GuestMessage::Exited(ExitStatus::TimedOut))
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn deadline_applies_after_the_streams_close() {
        let started = Instant::now();
        let messages = run(&spec("exec >/dev/null 2>&1; sleep 60", 1, 1024));

        assert_eq!(
            messages.last(),
            Some(&GuestMessage::Exited(ExitStatus::TimedOut))
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn an_empty_argv_is_an_error_message() {
        let mut job = spec("", 1, 1);
        job.argv.clear();

        assert_eq!(run(&job), [GuestMessage::Error("empty argv".into())]);
    }

    #[test]
    fn forwards_stderr_and_runs_in_the_given_directory() {
        let mut job = spec("pwd; echo oops >&2; kill -9 $$", 10, 1024);
        job.cwd = "/tmp".into();
        let messages = run(&job);

        assert_eq!(stdout_of(&messages), "/tmp\n");

        let stderr: Vec<u8> = messages
            .iter()
            .filter_map(|m| match m {
                GuestMessage::Output {
                    stream: OutputStream::Stderr,
                    data,
                } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect();

        assert_eq!(stderr, b"oops\n");
        assert_eq!(
            messages.last(),
            Some(&GuestMessage::Exited(ExitStatus::Signal(9)))
        );
    }

    #[test]
    fn missing_program_is_an_error_message() {
        let mut job = spec("", 1, 1);
        job.argv = vec!["/nonexistent/program".into()];
        let messages = run(&job);

        assert!(matches!(messages.as_slice(), [GuestMessage::Error(_)]));
    }
}
