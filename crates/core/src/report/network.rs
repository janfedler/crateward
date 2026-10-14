//! The guest's network activity, as the fake internet saw it, and the
//! honeytokens found in it.

use serde::{Deserialize, Serialize};

/// Guest side address of the link between guest and host. Every slot uses
/// the same addresses in its own network namespace.
pub const GUEST_ADDRESS: &str = "10.0.2.2";

/// Host side address of that link: the guest's gateway and resolver, where
/// the fake internet answers. Every name the guest looks up resolves to it.
pub const HOST_ADDRESS: &str = "10.0.2.1";

/// What the first bytes of a connection look like.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum Sniffed {
    /// A plain HTTP request.
    Http {
        /// Method.
        method: String,
        /// Request target.
        target: String,
        /// The `Host` header, if present.
        host: Option<String>,
        /// The `User-Agent` header, if present.
        user_agent: Option<String>,
    },
    /// A TLS ClientHello.
    Tls {
        /// Server name indication, if present.
        sni: Option<String>,
    },
    /// Anything else, or nothing yet.
    Unknown,
}

/// The guest's network activity, as the fake internet saw it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Names looked up, in order, without repeats.
    pub dns: Vec<String>,
    /// TCP connections, in order.
    pub connections: Vec<Connection>,
    /// UDP datagrams other than DNS.
    pub udp_datagrams: u32,
    /// Connections refused because too many were open.
    pub refused: u32,
    /// Frames no proxy saw (IPv6, ICMP, other protocols), described.
    #[serde(default)]
    pub packets: Vec<String>,
    /// More such frames arrived than the fake internet logs.
    #[serde(default)]
    pub packets_truncated: bool,
    /// The log hit its event limit.
    pub truncated: bool,
    /// Connections and frames the guest sent more of than the fake
    /// internet keeps.
    #[serde(default)]
    pub cut: u32,
    /// The log was longer than the host reads.
    #[serde(default)]
    pub log_cut: bool,
}

impl NetworkSummary {
    /// Why the honeytoken search did not see everything the guest sent.
    /// A guest can make the log drop what follows by flooding it, so any
    /// of these may hide a leak.
    #[must_use]
    pub fn unsearched(&self) -> Vec<&'static str> {
        [
            (self.truncated, "more events than the fake internet logs"),
            (self.packets_truncated, "more raw frames than it logs"),
            (self.refused > 0, "connections it refused"),
            (self.cut > 0, "connections or frames longer than it keeps"),
            (self.log_cut, "a log longer than the host reads"),
        ]
        .into_iter()
        .filter_map(|(hit, reason)| hit.then_some(reason))
        .collect()
    }
}

/// One TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// Destination the guest dialed.
    pub dst: String,
    /// What it sent, as recognized.
    #[serde(flatten)]
    pub sniffed: Sniffed,
    /// Bytes it sent.
    pub bytes: u64,
    /// Inside TLS, when the fake internet could terminate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner: Option<Box<Sniffed>>,
}

/// A honeytoken found outside the VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leak {
    /// Which token.
    pub kind: String,
    /// Where it was seen: a DNS name, a TCP destination or `udp`.
    pub via: String,
}
