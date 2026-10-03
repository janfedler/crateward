//! The per slot server: DNS, a TCP sink and a UDP sink, each on its own
//! thread, writing one JSON line per event.
//!
//! nftables in the slot's network namespace redirects the guest's DNS
//! queries to [`SlotConfig::dns_port`], every other UDP datagram to
//! [`SlotConfig::udp_port`] and every TCP connection to
//! [`SlotConfig::tcp_port`]. The original TCP destination comes back
//! through `SO_ORIGINAL_DST`. Everything the guest sends is bounded: events,
//! log bytes, concurrent connections, bytes and seconds per connection.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::dns;
use crate::sniff::{Sniffed, content_length, http_header_end, sniff};

/// Bytes of a connection or datagram kept in the log.
pub const MAX_CAPTURE: usize = 64 * 1024;
/// Events logged per run. Later ones are counted, not logged.
pub const MAX_EVENTS: u32 = 5_000;
/// Concurrent TCP connections.
const MAX_CONNECTIONS: usize = 32;
/// How long one TCP connection may take.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(10);

const HTTP_RESPONSE: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Where the server listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotConfig {
    /// The host side address of the tap link.
    pub address: Ipv4Addr,
    /// DNS port.
    pub dns_port: u16,
    /// TCP sink port.
    pub tcp_port: u16,
    /// UDP sink port.
    pub udp_port: u16,
}

impl Default for SlotConfig {
    fn default() -> Self {
        Self {
            address: Ipv4Addr::new(10, 0, 2, 1),
            dns_port: 5353,
            tcp_port: 8080,
            udp_port: 5354,
        }
    }
}

/// One logged event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Milliseconds since the server started.
    pub ms: u64,
    /// What happened.
    #[serde(flatten)]
    pub kind: EventKind,
}

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    /// A DNS question.
    Dns {
        /// Name asked for.
        name: String,
        /// Query type.
        qtype: u16,
    },
    /// A TCP connection.
    Tcp {
        /// The destination the guest dialed.
        dst: String,
        /// What it looked like.
        #[serde(flatten)]
        sniffed: Sniffed,
        /// Bytes received.
        bytes: u64,
        /// The first [`MAX_CAPTURE`] bytes, hex encoded.
        data: String,
        /// Inside TLS: what the plain text looked like.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inner: Option<Box<Sniffed>>,
        /// Inside TLS: the first [`MAX_CAPTURE`] plain text bytes, hex
        /// encoded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decrypted: Option<String>,
    },
    /// A UDP datagram other than DNS.
    Udp {
        /// Bytes received.
        bytes: u64,
        /// The first [`MAX_CAPTURE`] bytes, hex encoded.
        data: String,
    },
    /// A connection refused because too many were open.
    Refused {
        /// The destination the guest dialed.
        dst: String,
    },
    /// A frame no proxy saw: IPv6, ICMP, another IP protocol or raw
    /// Ethernet ([`crate::capture`]).
    Packet {
        /// What it was, for example `ipv6 tcp [fd00::2]:40000 -> [2001:db8::1]:443`.
        summary: String,
        /// Length of the frame.
        bytes: u64,
        /// The first [`crate::capture::PACKET_CAPTURE`] bytes of the frame,
        /// hex encoded.
        data: String,
    },
    /// Frames beyond [`crate::capture::MAX_PACKETS`] were only counted.
    PacketLimit,
    /// Events beyond [`MAX_EVENTS`] were not logged.
    Truncated,
}

/// Hex encoding of a byte slice.
#[must_use]
pub fn hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decodes [`hex`] output. Invalid input gives `None`.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[a, b]| {
            let digit = |c: u8| char::from(c).to_digit(16);
            u8::try_from(digit(*a)? * 16 + digit(*b)?).ok()
        })
        .collect()
}

struct Log {
    out: Box<dyn Write + Send>,
    start: Instant,
    events: u32,
}

impl Log {
    fn emit(&mut self, kind: EventKind) {
        self.events = self.events.saturating_add(1);
        let kind = match self.events {
            n if n < MAX_EVENTS => kind,
            MAX_EVENTS => EventKind::Truncated,
            _ => return,
        };
        let event = Event {
            ms: u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX),
            kind,
        };
        if let Ok(mut line) = serde_json::to_vec(&event) {
            line.push(b'\n');
            // A full disk or a closed log ends logging, not the sinks.
            let _ = self.out.write_all(&line).and_then(|()| self.out.flush());
        }
    }
}

type Shared = Arc<Mutex<Log>>;

fn emit(log: &Shared, kind: EventKind) {
    if let Ok(mut log) = log.lock() {
        log.emit(kind);
    }
}

fn serve_dns(socket: &UdpSocket, address: Ipv4Addr, log: &Shared) {
    let mut buffer = [0_u8; 4096];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let query = buffer.get(..len).unwrap_or_default();
        let Some(question) = dns::parse_query(query) else {
            continue;
        };
        if let Some(reply) = dns::answer(query, &question, address) {
            let _ = socket.send_to(&reply, from);
        }
        emit(
            log,
            EventKind::Dns {
                name: question.name,
                qtype: question.qtype,
            },
        );
    }
}

fn serve_udp(socket: &UdpSocket, log: &Shared) {
    let mut buffer = vec![0_u8; MAX_CAPTURE];
    loop {
        let Ok((len, _)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let data = buffer.get(..len).unwrap_or_default();
        emit(
            log,
            EventKind::Udp {
                bytes: len as u64,
                data: hex(data),
            },
        );
    }
}

/// Whether a request read so far is complete: an HTTP request with its
/// body, the capture limit, or (for raw bytes) a TLS ClientHello.
fn complete(data: &[u8], plaintext: bool) -> bool {
    if data.len() >= MAX_CAPTURE {
        return true;
    }
    if let Some(end) = http_header_end(data) {
        let body = content_length(data.get(..end).unwrap_or_default()).unwrap_or(0);
        return data.len() >= end.saturating_add(body);
    }
    !plaintext && matches!(sniff(data), Sniffed::Tls { .. })
}

/// Reads until [`complete`], end of stream, an error or `deadline`. Returns
/// the kept bytes and the total count. `timeout` sets the underlying
/// socket's read timeout before every read.
fn read_request(
    reader: &mut impl Read,
    mut timeout: impl FnMut(Duration) -> bool,
    deadline: Instant,
    plaintext: bool,
) -> (Vec<u8>, u64) {
    let mut data = Vec::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || !timeout(left) {
            break;
        }
        let Ok(read) = reader.read(&mut buffer) else {
            break;
        };
        if read == 0 {
            break;
        }
        total += read as u64;
        let room = MAX_CAPTURE.saturating_sub(data.len());
        data.extend_from_slice(buffer.get(..read.min(room)).unwrap_or_default());
        if complete(&data, plaintext) {
            break;
        }
    }
    (data, total)
}

/// A socket whose first bytes were already read: they are replayed before
/// the socket is read again, so TLS can start from the ClientHello.
struct Replay<'a> {
    prefix: &'a [u8],
    stream: &'a mut TcpStream,
}

impl Read for Replay<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.prefix.is_empty() {
            return self.stream.read(buf);
        }
        let n = self.prefix.len().min(buf.len());
        let (head, rest) = self.prefix.split_at(n);
        if let Some(target) = buf.get_mut(..n) {
            target.copy_from_slice(head);
        }
        self.prefix = rest;
        Ok(n)
    }
}

impl Write for Replay<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// Completes the TLS handshake with a certificate for the requested name
/// and reads the request in plain text. Returns what was read, or `None`
/// if the handshake failed (for example because the client does not trust
/// the authority).
fn terminate(
    config: &Arc<rustls::ServerConfig>,
    hello: &[u8],
    stream: &mut TcpStream,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut conn = rustls::ServerConnection::new(Arc::clone(config)).ok()?;
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut io = Replay {
        prefix: hello,
        stream,
    };
    let (plain, _) = {
        let mut tls = rustls::Stream::new(&mut conn, &mut io);
        read_request(&mut tls, |_| true, deadline, true)
    };
    if conn.is_handshaking() {
        return None;
    }
    if matches!(sniff(&plain), Sniffed::Http { .. }) {
        let mut tls = rustls::Stream::new(&mut conn, &mut io);
        let _ = tls.write_all(HTTP_RESPONSE);
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
    Some(plain)
}

/// Reads what the guest sends on one connection, answers HTTP requests
/// with 404 (inside TLS too, when an authority is loaded), and logs it.
fn handle(mut stream: TcpStream, log: &Shared, tls: Option<&Arc<rustls::ServerConfig>>) {
    let dst = rustix::net::sockopt::ip_original_dst(&stream)
        .map_or_else(|_| "unknown".to_owned(), |a| a.to_string());
    let deadline = Instant::now() + CONNECTION_DEADLINE;
    let timeouts = stream.try_clone();
    let (data, total) = read_request(
        &mut stream,
        |left| {
            timeouts
                .as_ref()
                .is_ok_and(|s| s.set_read_timeout(Some(left)).is_ok())
        },
        deadline,
        false,
    );
    let sniffed = sniff(&data);
    let mut decrypted = None;
    match (&sniffed, tls) {
        (Sniffed::Http { .. }, _) => {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = stream.write_all(HTTP_RESPONSE);
        }
        (Sniffed::Tls { .. }, Some(config)) => {
            let left = deadline.saturating_duration_since(Instant::now());
            if !left.is_zero() && stream.set_read_timeout(Some(left)).is_ok() {
                decrypted = terminate(config, &data, &mut stream, deadline);
            }
        }
        _ => {}
    }
    emit(
        log,
        EventKind::Tcp {
            dst,
            sniffed,
            bytes: total,
            data: hex(&data),
            inner: decrypted.as_deref().map(|d| Box::new(sniff(d))),
            decrypted: decrypted.as_deref().map(hex),
        },
    );
}

fn serve_tcp(listener: &TcpListener, log: &Shared, tls: Option<&Arc<rustls::ServerConfig>>) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let dst = rustix::net::sockopt::ip_original_dst(&stream)
                .map_or_else(|_| "unknown".to_owned(), |a| a.to_string());
            emit(log, EventKind::Refused { dst });
            continue;
        }
        let log = Arc::clone(log);
        let active = Arc::clone(&active);
        let tls = tls.cloned();
        let spawned = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                handle(stream, &log, tls.as_ref());
                active.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            // The thread and its counter slot were never used.
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Binds the sinks and serves until the process is killed. Events go to
/// `out`, one JSON line each. With `tls`, TLS connections are terminated.
/// With `capture`, a packet socket, frames that no proxy sees are logged.
///
/// # Errors
///
/// Fails if a socket cannot be bound.
pub fn serve(
    config: SlotConfig,
    out: Box<dyn Write + Send>,
    tls: Option<Arc<rustls::ServerConfig>>,
    capture: Option<std::os::fd::OwnedFd>,
) -> std::io::Result<()> {
    let at = |port| SocketAddr::from((config.address, port));
    let dns_socket = UdpSocket::bind(at(config.dns_port))?;
    let udp_socket = UdpSocket::bind(at(config.udp_port))?;
    let listener = TcpListener::bind(at(config.tcp_port))?;
    let log: Shared = Arc::new(Mutex::new(Log {
        out,
        start: Instant::now(),
        events: 0,
    }));
    let dns_log = Arc::clone(&log);
    let address = config.address;
    std::thread::spawn(move || serve_dns(&dns_socket, address, &dns_log));
    let udp_log = Arc::clone(&log);
    std::thread::spawn(move || serve_udp(&udp_socket, &udp_log));
    if let Some(socket) = capture {
        let packet_log = Arc::clone(&log);
        std::thread::spawn(move || {
            crate::capture::run(&socket, |packet| {
                let kind = match packet {
                    Some((summary, bytes, data)) => EventKind::Packet {
                        summary,
                        bytes,
                        data: hex(data),
                    },
                    None => EventKind::PacketLimit,
                };
                emit(&packet_log, kind);
            });
        });
    }
    serve_tcp(&listener, &log, tls.as_ref());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let data = b"\x00\xffabc";
        assert_eq!(unhex(&hex(data)).unwrap(), data);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    /// A shared buffer the test can read after the server wrote to it.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn http_on_the_sink_is_answered_and_logged() {
        let sink = Sink::default();
        let config = SlotConfig {
            address: Ipv4Addr::LOCALHOST,
            dns_port: 0,
            tcp_port: 0,
            udp_port: 0,
        };
        // Bind to ephemeral ports by hand to learn the TCP port.
        let listener = TcpListener::bind((config.address, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let log: Shared = Arc::new(Mutex::new(Log {
            out: Box::new(sink.clone()),
            start: Instant::now(),
            events: 0,
        }));
        let server_log = Arc::clone(&log);
        std::thread::spawn(move || serve_tcp(&listener, &server_log, None));
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let request = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\ntoken";
        client.write_all(request).unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 404"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while sink.0.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        let event: Event = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let EventKind::Tcp {
            sniffed,
            data,
            bytes,
            ..
        } = event.kind
        else {
            panic!("{text}");
        };
        assert!(matches!(sniffed, Sniffed::Http { .. }));
        assert_eq!(bytes, request.len() as u64);
        assert!(unhex(&data).unwrap().ends_with(b"token"));
    }
}
