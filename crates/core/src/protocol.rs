//! Wire protocol between the orchestrator and the guest agent.
//!
//! There is exactly one channel between a microVM and the host: one vsock
//! stream that the host opens after the VM starts or is restored. Everything
//! the guest sends over it is hostile input, because the crate under
//! analysis may control the guest by the time it speaks. The format is
//! therefore deliberately small and strict:
//!
//! * A frame is a big endian `u32` length followed by that many bytes of
//!   `postcard` encoded payload.
//! * A frame larger than [`MAX_FRAME_LEN`] is rejected before any of it is
//!   buffered, so a hostile length prefix cannot make the host allocate.
//! * A [`Decoder`] enforces a budget of frames and bytes per connection, so a
//!   flood of small valid frames ends the connection instead of the host.
//! * A payload must be consumed exactly; trailing bytes are an error.
//! * Both sides start with a `Hello` carrying [`PROTOCOL_VERSION`]. A
//!   mismatch ends the connection.
//!
//! The decoder is a fuzz target (milestone M7) and is covered by property
//! tests below.

use std::io::{Read, Write};
use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Version of this protocol. Bumped on any incompatible change.
pub const PROTOCOL_VERSION: u16 = 3;

/// The vsock port the guest agent listens on.
pub const AGENT_PORT: u32 = 1024;

/// Largest payload of one frame, in bytes.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

/// Largest chunk of process output carried by one frame.
pub const MAX_OUTPUT_CHUNK: usize = 16 * 1024;

/// Messages from the host to the guest agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostMessage {
    /// Opens the conversation.
    Hello {
        /// The host's protocol version.
        version: u16,
    },
    /// Asks the agent to confirm it is ready. Used before taking a snapshot.
    Ping,
    /// Prepares the workspace of a job: mounts its drives, creates
    /// directories and writes files such as honeytokens. Sent after every
    /// restore and before `Run`.
    Prepare(Workspace),
    /// Runs a job.
    Run(JobSpec),
    /// Asks the agent to shut the VM down.
    Shutdown,
}

/// What the guest agent runs. Sent after every restore, so nothing in it is
/// part of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    /// The job this run belongs to.
    pub job_id: i64,
    /// Host wall clock, so the guest does not keep the snapshot's time.
    pub wall_clock: WallClock,
    /// Program and arguments.
    pub argv: Vec<String>,
    /// Environment. The agent clears its own environment first.
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub cwd: String,
    /// Wall clock limit enforced inside the guest. The host enforces its own
    /// limit independently.
    pub timeout_secs: u32,
    /// Total output bytes the agent forwards before truncating.
    pub output_limit: u32,
}

/// What a job's workspace consists of. All paths are absolute guest paths
/// without `..`; the agent refuses anything else.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    /// Block devices to mount, in order.
    pub mounts: Vec<MountSpec>,
    /// Directories to create, parents first.
    pub directories: Vec<PathSpec>,
    /// Files to write.
    pub files: Vec<FileSpec>,
}

/// One mount of a block device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountSpec {
    /// Device, `/dev/vd` followed by one letter from `b` on.
    pub device: String,
    /// Mount point; must exist.
    pub target: String,
    /// `erofs` or `ext4`.
    pub fstype: String,
    /// Mount read only.
    pub read_only: bool,
}

/// A directory with its owner and mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathSpec {
    /// Path.
    pub path: String,
    /// Owner user and group ID.
    pub owner: u32,
    /// Permission bits.
    pub mode: u32,
}

/// A file with its contents, owner and mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSpec {
    /// Where and how.
    pub path: PathSpec,
    /// Contents.
    pub contents: Vec<u8>,
}

/// A point in time, as seconds and nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WallClock {
    /// Seconds since the epoch.
    pub secs: u64,
    /// Nanoseconds within the second.
    pub nanos: u32,
}

/// Which output stream a chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// How the job's process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    /// Exited with a code.
    Code(i32),
    /// Killed by a signal.
    Signal(i32),
    /// Killed by the agent after the guest side timeout.
    TimedOut,
}

/// Messages from the guest agent to the host. Hostile by assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestMessage {
    /// Answers the host's `Hello`.
    Hello {
        /// The agent's protocol version.
        version: u16,
        /// The agent's package version.
        agent_version: String,
        /// Whether the eBPF tracing is attached.
        tracing: TracingStatus,
    },
    /// Answers `Ping`.
    Pong,
    /// The workspace is ready.
    Prepared,
    /// The job's process started.
    Started {
        /// Process ID inside the guest.
        pid: u32,
    },
    /// A chunk of process output, at most [`MAX_OUTPUT_CHUNK`] bytes.
    Output {
        /// The stream.
        stream: OutputStream,
        /// The bytes.
        data: Vec<u8>,
    },
    /// Output beyond the job's limit was dropped.
    OutputTruncated,
    /// Events the eBPF programs recorded, in order. Only sent while
    /// tracing is active.
    Trace(Vec<TraceEvent>),
    /// The trace of the job is complete. Sent before `Exited` when tracing
    /// is active.
    TraceEnd(TraceTotals),
    /// The job's process ended.
    Exited(ExitStatus),
    /// The agent could not do what was asked.
    Error(String),
}

/// Whether the agent's eBPF tracing works.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TracingStatus {
    /// The programs are loaded and attached.
    Active,
    /// Tracing could not start, and why.
    Unavailable(String),
}

/// One event recorded by the eBPF programs (ADR 0017). Process and user IDs
/// are the guest's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Milliseconds since the job started.
    pub ms: u32,
    /// Process ID.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Real user ID.
    pub uid: u32,
    /// What happened.
    pub kind: TraceKind,
}

/// What a traced process did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceKind {
    /// It started a new process.
    Fork {
        /// The new process.
        child: u32,
    },
    /// It executed a program.
    Exec {
        /// The path the kernel executed, as given to `execve`.
        filename: Vec<u8>,
        /// The argument vector of the new program, possibly cut short.
        argv: Vec<Vec<u8>>,
    },
    /// It ended.
    Exit {
        /// Kernel exit code: status in bits 8 to 15, signal in 0 to 6.
        code: u32,
    },
    /// It opened a file.
    Open {
        /// The path the kernel resolved, possibly cut short.
        path: Vec<u8>,
        /// `O_*` flags.
        flags: u32,
    },
    /// It connected a socket.
    Connect {
        /// `SOCK_*` type.
        sock_type: u32,
        /// The destination.
        address: SocketAddress,
    },
    /// It sent a message with an explicit destination.
    Send {
        /// `SOCK_*` type.
        sock_type: u32,
        /// The destination.
        address: SocketAddress,
    },
    /// It used the `bpf` system call.
    Bpf {
        /// The command.
        cmd: u32,
    },
    /// It asked for ptrace access to another process.
    Ptrace {
        /// The target process.
        target: u32,
        /// The access mode.
        mode: u32,
    },
    /// It tried to mount a filesystem.
    Mount {
        /// The filesystem type.
        fstype: Vec<u8>,
    },
}

/// A socket destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocketAddress {
    /// IPv4 or IPv6.
    Ip(std::net::SocketAddr),
    /// A Unix socket path; abstract names start with a NUL byte.
    Unix(Vec<u8>),
    /// Another address family.
    Other(u16),
}

/// Counters that end a job's trace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceTotals {
    /// Events sent.
    pub events: u64,
    /// Events the kernel dropped because the ring buffer was full.
    pub dropped_in_kernel: u64,
    /// Events the agent dropped over its own limit.
    pub dropped_by_agent: u64,
    /// Records that did not decode.
    pub malformed: u64,
}

/// Budgets for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest payload of one frame.
    pub max_frame_len: u32,
    /// Largest number of frames.
    pub max_frames: u64,
    /// Largest number of bytes, headers included.
    pub max_total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_len: MAX_FRAME_LEN,
            max_frames: 1_000_000,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Why a frame could not be sent or received.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// A length prefix announced a frame above the limit.
    #[error("frame of {len} bytes exceeds the limit of {max} bytes")]
    FrameTooLarge {
        /// Announced length.
        len: u32,
        /// The limit.
        max: u32,
    },
    /// The connection sent more frames or bytes than its budget allows.
    #[error("connection exceeded its budget of {0}")]
    BudgetExceeded(&'static str),
    /// A payload did not decode, or left bytes over.
    #[error("malformed frame: {0}")]
    Malformed(String),
    /// The peer speaks another protocol version.
    #[error("protocol version {0} is not supported")]
    UnsupportedVersion(u16),
    /// The stream ended in the middle of a frame.
    #[error("connection closed in the middle of a frame")]
    Truncated,
    /// Reading or writing failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Encodes a message as one frame: length prefix and payload.
///
/// # Errors
///
/// Fails if the message does not serialize or exceeds [`MAX_FRAME_LEN`].
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload =
        postcard::to_allocvec(message).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    if len > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, ProtocolError> {
    let (value, rest) =
        postcard::take_from_bytes(payload).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(ProtocolError::Malformed(format!(
            "{} trailing bytes after the payload",
            rest.len()
        )))
    }
}

/// Incremental decoder for a byte stream that arrives in arbitrary chunks.
#[derive(Debug)]
pub struct Decoder<T> {
    buffer: Vec<u8>,
    limits: Limits,
    frames: u64,
    bytes: u64,
    _message: PhantomData<fn() -> T>,
}

impl<T: DeserializeOwned> Decoder<T> {
    /// A decoder with the given budgets.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            buffer: Vec::new(),
            limits,
            frames: 0,
            bytes: 0,
            _message: PhantomData,
        }
    }

    /// Adds received bytes.
    ///
    /// # Errors
    ///
    /// Fails when the byte budget is exhausted.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if self.bytes > self.limits.max_total_bytes {
            return Err(ProtocolError::BudgetExceeded("bytes"));
        }
        self.buffer.extend_from_slice(bytes);
        // Fail as soon as a header announces an oversized frame.
        self.check_header().map(|_| ())
    }

    fn check_header(&self) -> Result<Option<usize>, ProtocolError> {
        let Some(header) = self.buffer.first_chunk::<4>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*header);
        if len > self.limits.max_frame_len {
            return Err(ProtocolError::FrameTooLarge {
                len,
                max: self.limits.max_frame_len,
            });
        }
        Ok(Some(usize::try_from(len).unwrap_or(usize::MAX)))
    }

    /// Returns the next complete message, if one is buffered.
    ///
    /// # Errors
    ///
    /// Fails on an oversized or malformed frame, or when the frame budget is
    /// exhausted. After an error the connection must be dropped.
    pub fn next_message(&mut self) -> Result<Option<T>, ProtocolError> {
        let Some(len) = self.check_header()? else {
            return Ok(None);
        };
        let Some(payload) = self.buffer.get(4..4 + len) else {
            return Ok(None);
        };
        self.frames += 1;
        if self.frames > self.limits.max_frames {
            return Err(ProtocolError::BudgetExceeded("frames"));
        }
        let message = decode_payload(payload)?;
        self.buffer.drain(..4 + len);
        Ok(Some(message))
    }

    /// Whether bytes of an unfinished frame are buffered.
    #[must_use]
    pub fn has_partial_frame(&self) -> bool {
        !self.buffer.is_empty()
    }
}

/// Writes one message to a blocking writer.
///
/// # Errors
///
/// Fails if encoding or writing fails.
pub fn write_message<W: Write, T: Serialize>(
    writer: &mut W,
    message: &T,
) -> Result<(), ProtocolError> {
    writer.write_all(&encode(message)?)?;
    writer.flush()?;
    Ok(())
}

/// Reads one message from a blocking reader. Returns `None` on a clean end
/// of stream between frames.
///
/// # Errors
///
/// Fails on an oversized, truncated or malformed frame.
pub fn read_message<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    max_frame_len: u32,
) -> Result<Option<T>, ProtocolError> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        let slot = header.get_mut(filled..).unwrap_or_default();
        match reader.read(slot)? {
            0 if filled == 0 => return Ok(None),
            0 => return Err(ProtocolError::Truncated),
            n => filled += n,
        }
    }
    let len = u32::from_be_bytes(header);
    if len > max_frame_len {
        return Err(ProtocolError::FrameTooLarge {
            len,
            max: max_frame_len,
        });
    }
    let mut payload = vec![0_u8; usize::try_from(len).unwrap_or(usize::MAX)];
    reader.read_exact(&mut payload).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ProtocolError::Truncated
        } else {
            ProtocolError::Io(e)
        }
    })?;
    decode_payload(&payload).map(Some)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn sample_messages() -> Vec<GuestMessage> {
        vec![
            GuestMessage::Hello {
                version: PROTOCOL_VERSION,
                agent_version: "0.1.0".into(),
                tracing: TracingStatus::Unavailable("no BTF".into()),
            },
            GuestMessage::Pong,
            GuestMessage::Trace(vec![TraceEvent {
                ms: 3,
                pid: 10,
                tid: 11,
                uid: 1000,
                kind: TraceKind::Connect {
                    sock_type: 1,
                    address: SocketAddress::Ip("10.0.2.1:443".parse().unwrap()),
                },
            }]),
            GuestMessage::TraceEnd(TraceTotals::default()),
            GuestMessage::Started { pid: 42 },
            GuestMessage::Output {
                stream: OutputStream::Stderr,
                data: vec![1, 2, 3],
            },
            GuestMessage::OutputTruncated,
            GuestMessage::Exited(ExitStatus::Signal(9)),
            GuestMessage::Error("boom".into()),
        ]
    }

    #[test]
    fn blocking_round_trip() {
        let spec = HostMessage::Run(JobSpec {
            job_id: 7,
            wall_clock: WallClock {
                secs: 1_790_000_000,
                nanos: 5,
            },
            argv: vec!["cargo".into(), "check".into()],
            env: vec![("CARGO_INCREMENTAL".into(), "0".into())],
            cwd: "/work".into(),
            timeout_secs: 900,
            output_limit: 1 << 20,
        });
        let mut wire = Vec::new();
        write_message(&mut wire, &spec).unwrap();
        let mut reader = wire.as_slice();
        let back: HostMessage = read_message(&mut reader, MAX_FRAME_LEN).unwrap().unwrap();
        assert_eq!(back, spec);
        assert!(
            read_message::<_, HostMessage>(&mut reader, MAX_FRAME_LEN)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn oversized_header_is_rejected_before_buffering() {
        let mut decoder = Decoder::<GuestMessage>::new(Limits::default());
        let err = decoder.push(&u32::MAX.to_be_bytes()).unwrap_err();
        assert!(matches!(err, ProtocolError::FrameTooLarge { .. }));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut frame = encode(&GuestMessage::Pong).unwrap();
        frame.push(0);
        let len = u32::try_from(frame.len() - 4).unwrap();
        frame[..4].copy_from_slice(&len.to_be_bytes());
        let mut decoder = Decoder::<GuestMessage>::new(Limits::default());
        decoder.push(&frame).unwrap();
        assert!(matches!(
            decoder.next_message(),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn frame_budget_is_enforced() {
        let limits = Limits {
            max_frames: 2,
            ..Limits::default()
        };
        let mut decoder = Decoder::<GuestMessage>::new(limits);
        for _ in 0..3 {
            decoder.push(&encode(&GuestMessage::Pong).unwrap()).unwrap();
        }
        assert!(decoder.next_message().unwrap().is_some());
        assert!(decoder.next_message().unwrap().is_some());
        assert!(matches!(
            decoder.next_message(),
            Err(ProtocolError::BudgetExceeded("frames"))
        ));
    }

    #[test]
    fn truncated_stream_is_reported() {
        let frame = encode(&GuestMessage::Started { pid: 1 }).unwrap();
        let mut reader = &frame[..frame.len() - 1];
        assert!(matches!(
            read_message::<_, GuestMessage>(&mut reader, MAX_FRAME_LEN),
            Err(ProtocolError::Truncated)
        ));
    }

    proptest! {
        #[test]
        fn messages_survive_arbitrary_chunking(splits in prop::collection::vec(1_usize..64, 1..40)) {
            let messages = sample_messages();
            let wire: Vec<u8> = messages.iter().flat_map(|m| encode(m).unwrap()).collect();
            let mut decoder = Decoder::<GuestMessage>::new(Limits::default());
            let mut decoded = Vec::new();
            let mut rest = wire.as_slice();
            let mut splits = splits.into_iter().cycle();
            while !rest.is_empty() {
                let take = splits.next().unwrap().min(rest.len());
                let (chunk, tail) = rest.split_at(take);
                decoder.push(chunk).unwrap();
                while let Some(message) = decoder.next_message().unwrap() {
                    decoded.push(message);
                }
                rest = tail;
            }
            prop_assert_eq!(decoded, messages);
            prop_assert!(!decoder.has_partial_frame());
        }

        #[test]
        fn decoder_never_panics_on_hostile_bytes(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            let mut decoder = Decoder::<GuestMessage>::new(Limits::default());
            if decoder.push(&bytes).is_ok() {
                while let Ok(Some(_)) = decoder.next_message() {}
            }
            let mut reader = bytes.as_slice();
            while let Ok(Some(_)) = read_message::<_, GuestMessage>(&mut reader, MAX_FRAME_LEN) {}
        }
    }
}
