//! The vsock server: one conversation per host connection.
//!
//! A conversation starts with `Hello` in both directions. After that the
//! host may send `Ping` (readiness check before a snapshot), `Run` (a job)
//! or `Shutdown`. When the host closes the connection, the agent goes back
//! to `accept`, which is exactly the state a snapshot captures: a snapshot
//! resets established vsock connections but keeps listening sockets.

use std::io::{Read, Write};

use crateward_core::paths::guest::{BUILDER_GID, BUILDER_UID};
use crateward_core::protocol::{
    GuestMessage, HostMessage, JobSpec, MAX_FRAME_LEN, PROTOCOL_VERSION, ProtocolError,
    TracingStatus, read_message, write_message,
};
use vsock::{VMADDR_CID_ANY, VsockListener};

use crate::AgentError;
use crate::runner::{RunOptions, run_job};
use crate::trace::{TraceError, Tracer};

/// What the agent does after a conversation ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Wait for the next connection.
    Accept,
    /// Shut the VM down.
    ShutDown,
}

/// Sets the guest clock from the host's wall clock. The snapshot's clock
/// would otherwise be stale by the time since the snapshot was taken.
fn set_clock(spec: &JobSpec) {
    let time = rustix::time::Timespec {
        tv_sec: i64::try_from(spec.wall_clock.secs).unwrap_or(i64::MAX),
        tv_nsec: i64::from(spec.wall_clock.nanos),
    };

    if let Err(errno) = rustix::time::clock_settime(rustix::time::ClockId::Realtime, time) {
        eprintln!("crateward agent: cannot set the clock: {errno}");
    }
}

/// Handles one conversation.
///
/// # Errors
///
/// Fails on protocol errors or when the connection breaks.
pub fn converse<S: Read + Write>(
    stream: &mut S,
    options: RunOptions,
    tracer: &mut Result<Tracer, TraceError>,
) -> Result<Next, AgentError> {
    match read_message::<_, HostMessage>(stream, MAX_FRAME_LEN)? {
        Some(HostMessage::Hello { version }) if version == PROTOCOL_VERSION => {}
        Some(HostMessage::Hello { version }) => {
            write_message(
                stream,
                &GuestMessage::Error(format!("unsupported protocol version {version}")),
            )?;
            return Err(ProtocolError::UnsupportedVersion(version).into());
        }
        Some(_) => {
            write_message(stream, &GuestMessage::Error("expected Hello".into()))?;
            return Ok(Next::Accept);
        }
        None => return Ok(Next::Accept),
    }

    write_message(
        stream,
        &GuestMessage::Hello {
            version: PROTOCOL_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            tracing: match tracer {
                Ok(_) => TracingStatus::Active,
                Err(reason) => TracingStatus::Unavailable(reason.to_string()),
            },
        },
    )?;

    loop {
        match read_message::<_, HostMessage>(stream, MAX_FRAME_LEN)? {
            None => return Ok(Next::Accept),
            Some(HostMessage::Ping) => write_message(stream, &GuestMessage::Pong)?,
            Some(HostMessage::Prepare(workspace)) => {
                // Tests on the host must not mount anything.
                let result = if options.identity.is_some() {
                    crate::workspace::prepare(&workspace)
                } else {
                    crate::workspace::validate(&workspace)
                };

                match result {
                    Ok(()) => write_message(stream, &GuestMessage::Prepared)?,
                    Err(error) => write_message(stream, &GuestMessage::Error(error.to_string()))?,
                }
            }
            Some(HostMessage::Run(spec)) => {
                if options.identity.is_some() {
                    set_clock(&spec);
                }

                run_job(&spec, options, tracer.as_mut().ok(), stream)?;
            }
            Some(HostMessage::Shutdown) => return Ok(Next::ShutDown),
            Some(HostMessage::Hello { .. }) => {
                write_message(stream, &GuestMessage::Error("duplicate Hello".into()))?;
            }
        }
    }
}

/// Listens on the agent port and serves connections until the host asks
/// for a shutdown.
///
/// # Errors
///
/// Fails if the listening socket cannot be created or accept fails.
pub fn serve(port: u32) -> Result<(), AgentError> {
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, port)
        .map_err(AgentError::io("binding the vsock port"))?;
    let options = RunOptions {
        identity: Some((BUILDER_UID, BUILDER_GID)),
    };

    // Loaded before the first connection, so the base snapshot contains
    // the attached programs.
    let mut tracer = Tracer::start(BUILDER_UID);
    if let Err(reason) = &tracer {
        eprintln!("crateward agent: tracing unavailable: {reason}");
    }

    loop {
        let (mut stream, _) = listener
            .accept()
            .map_err(AgentError::io("accepting a vsock connection"))?;
        match converse(&mut stream, options, &mut tracer) {
            Ok(Next::Accept) => {}
            Ok(Next::ShutDown) => return Ok(()),
            // A broken conversation ends only that connection. The host
            // decides what happens next.
            Err(error) => eprintln!("crateward agent: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crateward_core::protocol::{WallClock, encode};

    use super::*;

    /// A fake connection: reads scripted host messages, records replies.
    struct Script {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn script(messages: &[HostMessage]) -> Script {
        let input = messages.iter().flat_map(|m| encode(m).unwrap()).collect();

        Script {
            input: Cursor::new(input),
            output: Vec::new(),
        }
    }

    fn replies(output: &[u8]) -> Vec<GuestMessage> {
        let mut reader = output;
        let mut all = Vec::new();
        while let Some(m) = read_message(&mut reader, MAX_FRAME_LEN).unwrap() {
            all.push(m);
        }

        all
    }

    const HOST: RunOptions = RunOptions { identity: None };

    /// What a host test has instead of a tracer.
    fn untraced() -> Result<Tracer, TraceError> {
        Err(TraceError::NoProgram("host test"))
    }

    #[test]
    fn ping_and_close_returns_to_accept() {
        let mut s = script(&[
            HostMessage::Hello {
                version: PROTOCOL_VERSION,
            },
            HostMessage::Ping,
        ]);

        assert_eq!(
            converse(&mut s, HOST, &mut untraced()).unwrap(),
            Next::Accept
        );

        let r = replies(&s.output);
        assert!(matches!(
            r.as_slice(),
            [GuestMessage::Hello { .. }, GuestMessage::Pong]
        ));
    }

    #[test]
    fn wrong_version_is_refused() {
        let mut s = script(&[HostMessage::Hello { version: 99 }]);

        assert!(converse(&mut s, HOST, &mut untraced()).is_err());
        assert!(matches!(
            replies(&s.output).as_slice(),
            [GuestMessage::Error(_)]
        ));
    }

    #[test]
    fn runs_a_job_then_shuts_down() {
        let job = JobSpec {
            job_id: 1,
            wall_clock: WallClock { secs: 0, nanos: 0 },
            argv: vec!["/bin/true".into()],
            env: vec![],
            cwd: "/".into(),
            timeout_secs: 5,
            output_limit: 1024,
        };

        let mut s = script(&[
            HostMessage::Hello {
                version: PROTOCOL_VERSION,
            },
            HostMessage::Run(job),
            HostMessage::Shutdown,
        ]);

        assert_eq!(
            converse(&mut s, HOST, &mut untraced()).unwrap(),
            Next::ShutDown
        );

        let r = replies(&s.output);
        assert!(r.contains(&GuestMessage::Exited(
            crateward_core::protocol::ExitStatus::Code(0)
        )));
    }
}
