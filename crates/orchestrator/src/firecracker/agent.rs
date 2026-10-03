//! The host side of the single vsock connection to the guest agent.
//!
//! Firecracker exposes the guest's vsock ports through one Unix socket per
//! VM. The host connects, writes `CONNECT <port>\n` and reads `OK <port>\n`
//! (Firecracker `docs/vsock.md`). After that the stream carries the frames of
//! `crateward_core::protocol`. Every byte from the guest goes through the
//! bounded [`Decoder`], and the host keeps its own copy of the output limit
//! instead of trusting the agent to honor it.

use std::path::Path;
use std::time::Duration;

use crateward_core::protocol::{
    Decoder, ExitStatus, GuestMessage, HostMessage, JobSpec, Limits, OutputStream,
    PROTOCOL_VERSION, ProtocolError, TracingStatus, Workspace, encode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout};

/// Longest line Firecracker sends in the vsock handshake.
const MAX_HANDSHAKE_LINE: usize = 32;

/// Bytes read from the socket per call.
const READ_CHUNK: usize = 16 * 1024;

/// Why talking to the agent failed.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Nobody listens on the port yet, or the socket is not there.
    #[error("agent not reachable: {0}")]
    NotReady(String),
    /// The protocol was violated.
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// The agent answered something unexpected.
    #[error("unexpected message from the agent: {0}")]
    Unexpected(String),
    /// The agent reported an error.
    #[error("agent error: {0}")]
    Agent(String),
    /// The connection closed.
    #[error("connection closed")]
    Closed,
    /// A deadline passed.
    #[error("timed out while {0}")]
    Timeout(&'static str),
    /// Socket I/O failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// What a job produced, as seen by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// How the process ended.
    pub exit: ExitStatus,
    /// Standard output, up to the output limit.
    pub stdout: Vec<u8>,
    /// Standard error, up to the output limit.
    pub stderr: Vec<u8>,
    /// Whether output was dropped, by the agent or by the host.
    pub truncated: bool,
    /// The guest's eBPF trace.
    pub trace: Box<crate::trace::TraceSummary>,
}

/// An open conversation with the guest agent.
#[derive(Debug)]
pub struct AgentConnection {
    stream: UnixStream,
    decoder: Decoder<GuestMessage>,
    /// On the heap: as an array in `recv` it made every future awaiting it
    /// 16 KiB larger.
    buffer: Box<[u8]>,
    /// Version reported by the agent.
    pub agent_version: String,
    /// Whether the agent's tracing works.
    pub tracing: TracingStatus,
}

async fn handshake(stream: &mut UnixStream, port: u32) -> Result<(), AgentError> {
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await?;
    let mut line = Vec::with_capacity(MAX_HANDSHAKE_LINE);
    let mut byte = [0_u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Err(AgentError::NotReady("no listener on the vsock port".into()));
        }
        if byte == *b"\n" {
            break;
        }
        line.extend_from_slice(&byte);
        if line.len() > MAX_HANDSHAKE_LINE {
            return Err(AgentError::Unexpected("overlong vsock handshake".into()));
        }
    }
    if line.starts_with(b"OK ") {
        Ok(())
    } else {
        Err(AgentError::Unexpected(
            String::from_utf8_lossy(&line).into_owned(),
        ))
    }
}

impl AgentConnection {
    /// Connects once: vsock handshake, then `Hello` in both directions.
    ///
    /// # Errors
    ///
    /// [`AgentError::NotReady`] if the agent does not listen yet.
    pub async fn connect(uds: &Path, port: u32, limits: Limits) -> Result<Self, AgentError> {
        let mut stream = UnixStream::connect(uds)
            .await
            .map_err(|e| AgentError::NotReady(e.to_string()))?;
        handshake(&mut stream, port).await?;
        let mut connection = Self {
            stream,
            decoder: Decoder::new(limits),
            buffer: vec![0; READ_CHUNK].into_boxed_slice(),
            agent_version: String::new(),
            tracing: TracingStatus::Unavailable("no Hello yet".into()),
        };
        connection
            .send(&HostMessage::Hello {
                version: PROTOCOL_VERSION,
            })
            .await?;
        match connection.recv().await? {
            GuestMessage::Hello {
                version,
                agent_version,
                tracing,
            } if version == PROTOCOL_VERSION => {
                connection.agent_version = agent_version;
                connection.tracing = tracing;
                Ok(connection)
            }
            GuestMessage::Hello { version, .. } => {
                Err(ProtocolError::UnsupportedVersion(version).into())
            }
            other => Err(AgentError::Unexpected(other.name().into())),
        }
    }

    /// Connects, retrying while the agent is not ready, until `deadline`.
    ///
    /// # Errors
    ///
    /// Fails with the last error once the deadline passes, or immediately on
    /// errors other than [`AgentError::NotReady`].
    pub async fn connect_until(
        uds: &Path,
        port: u32,
        limits: Limits,
        deadline: Instant,
    ) -> Result<Self, AgentError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match timeout(remaining, Self::connect(uds, port, limits)).await {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(AgentError::NotReady(reason))) => {
                    if Instant::now() >= deadline {
                        return Err(AgentError::NotReady(reason));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(Err(other)) => return Err(other),
                Err(_) => return Err(AgentError::Timeout("connecting to the agent")),
            }
        }
    }

    async fn send(&mut self, message: &HostMessage) -> Result<(), AgentError> {
        self.stream.write_all(&encode(message)?).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<GuestMessage, AgentError> {
        loop {
            if let Some(message) = self.decoder.next_message()? {
                return Ok(message);
            }
            let read = self.stream.read(&mut self.buffer).await?;
            if read == 0 {
                return Err(AgentError::Closed);
            }
            self.decoder
                .push(self.buffer.get(..read).unwrap_or_default())?;
        }
    }

    /// Confirms the agent is responsive.
    ///
    /// # Errors
    ///
    /// Fails if the agent does not answer `Pong`.
    pub async fn ping(&mut self) -> Result<(), AgentError> {
        self.send(&HostMessage::Ping).await?;
        match self.recv().await? {
            GuestMessage::Pong => Ok(()),
            other => Err(AgentError::Unexpected(other.name().into())),
        }
    }

    /// Prepares the job's workspace in the guest.
    ///
    /// # Errors
    ///
    /// Fails if the agent refuses or does not answer `Prepared`.
    pub async fn prepare(&mut self, workspace: Workspace) -> Result<(), AgentError> {
        self.send(&HostMessage::Prepare(workspace)).await?;
        match self.recv().await? {
            GuestMessage::Prepared => Ok(()),
            GuestMessage::Error(message) => Err(AgentError::Agent(message)),
            other => Err(AgentError::Unexpected(other.name().into())),
        }
    }

    /// Runs a job and collects its output, keeping at most
    /// `spec.output_limit` bytes regardless of what the agent sends.
    ///
    /// # Errors
    ///
    /// Fails on protocol violations or a closed connection. The caller
    /// applies its own wall clock limit around this call.
    pub async fn run(&mut self, spec: JobSpec) -> Result<RunOutcome, AgentError> {
        let limit = usize::try_from(spec.output_limit).unwrap_or(usize::MAX);
        self.send(&HostMessage::Run(spec)).await?;
        let mut outcome = RunOutcome {
            exit: ExitStatus::Code(-1),
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
            trace: Box::default(),
        };
        let mut trace = crate::trace::TraceBuilder::default();
        loop {
            match self.recv().await? {
                GuestMessage::Started { .. } => {}
                GuestMessage::Output { stream, data } => {
                    let kept = outcome.stdout.len() + outcome.stderr.len();
                    let room = limit.saturating_sub(kept);
                    if data.len() > room {
                        outcome.truncated = true;
                    }
                    let take = data.get(..data.len().min(room)).unwrap_or_default();
                    match stream {
                        OutputStream::Stdout => outcome.stdout.extend_from_slice(take),
                        OutputStream::Stderr => outcome.stderr.extend_from_slice(take),
                    }
                }
                GuestMessage::OutputTruncated => outcome.truncated = true,
                GuestMessage::Trace(events) => {
                    for event in &events {
                        trace.add(event);
                    }
                }
                GuestMessage::TraceEnd(totals) => trace.end(totals),
                GuestMessage::Exited(exit) => {
                    outcome.exit = exit;
                    outcome.trace = Box::new(trace.finish());
                    return Ok(outcome);
                }
                GuestMessage::Error(message) => return Err(AgentError::Agent(message)),
                other => return Err(AgentError::Unexpected(other.name().into())),
            }
        }
    }

    /// Asks the agent to shut the VM down. The VM exits afterwards.
    ///
    /// # Errors
    ///
    /// Fails if the message cannot be sent.
    pub async fn shutdown(mut self) -> Result<(), AgentError> {
        self.send(&HostMessage::Shutdown).await
    }
}
