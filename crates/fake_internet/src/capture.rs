//! Frames on the tap device that the proxies do not see.
//!
//! nftables hands every IPv4 TCP and UDP packet of the guest to the sinks.
//! Everything else the guest sends (IPv6, ICMP, other IP protocols, raw
//! Ethernet) reaches no socket, so without this module it would leave no
//! trace on the host. A packet socket on the tap device reads every frame.
//! Frames the host itself sent (source MAC [`HOST_MAC`]), ARP, and IPv4 TCP
//! and UDP are skipped, the rest is logged with its first bytes.
//!
//! Nothing captured here can go anywhere: the namespace has no uplink. The
//! log records the attempt. A guest that forges the host's MAC as its source
//! hides such an attempt, and still reaches nothing.

use std::os::fd::OwnedFd;

use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType, eth, recv, socket_with};

/// The tap device's MAC address on the host side. The launcher sets it, so
/// frames the host sent can be told apart from the guest's.
pub const HOST_MAC: [u8; 6] = [0x02, 0x63, 0x77, 0x00, 0x00, 0x01];

/// Packets logged per run. Later ones are only counted.
pub const MAX_PACKETS: u32 = 1_000;

/// Bytes of each frame kept in the log.
pub const PACKET_CAPTURE: usize = 1024;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// Opens a packet socket for all protocols. Needs `CAP_NET_RAW` in the
/// network namespace, so it is called before privileges are dropped. The
/// namespace holds only the loopback and the tap device, and nothing uses
/// the loopback.
///
/// # Errors
///
/// Fails if the socket cannot be created.
pub fn open() -> std::io::Result<OwnedFd> {
    Ok(socket_with(
        AddressFamily::PACKET,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(eth::ALL),
    )?)
}

fn name(proto: u8) -> String {
    match proto {
        PROTO_ICMP => "icmp".into(),
        PROTO_TCP => "tcp".into(),
        PROTO_UDP => "udp".into(),
        PROTO_ICMPV6 => "icmpv6".into(),
        other => format!("ip protocol {other}"),
    }
}

fn ports(proto: u8, payload: &[u8]) -> Option<(u16, u16)> {
    if !matches!(proto, PROTO_TCP | PROTO_UDP) {
        return None;
    }

    let src = u16::from_be_bytes(payload.get(0..2)?.try_into().ok()?);
    let dst = u16::from_be_bytes(payload.get(2..4)?.try_into().ok()?);

    Some((src, dst))
}

/// Describes a frame the guest sent, or returns `None` for a frame that is
/// skipped: sent by the host, ARP, IPv4 TCP or UDP, or too short to be
/// Ethernet.
#[must_use]
pub fn describe(frame: &[u8]) -> Option<String> {
    let src_mac = frame.get(6..12)?;
    if src_mac == HOST_MAC {
        return None;
    }

    let ethertype = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
    let packet = frame.get(14..).unwrap_or_default();

    match ethertype {
        ETHERTYPE_ARP => None,
        ETHERTYPE_IPV4 => {
            let proto = *packet.get(9)?;
            if matches!(proto, PROTO_TCP | PROTO_UDP) {
                return None;
            }

            let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            Some(format!(
                "ipv4 {} {} -> {}",
                name(proto),
                std::net::Ipv4Addr::from(src),
                std::net::Ipv4Addr::from(dst)
            ))
        }
        ETHERTYPE_IPV6 => {
            let (Some(&proto), Some(src), Some(dst)) =
                (packet.get(6), packet.get(8..24), packet.get(24..40))
            else {
                return Some("ipv6 (truncated)".into());
            };
            let src: [u8; 16] = src.try_into().ok()?;
            let dst: [u8; 16] = dst.try_into().ok()?;
            let (src, dst) = (std::net::Ipv6Addr::from(src), std::net::Ipv6Addr::from(dst));
            let payload = packet.get(40..).unwrap_or_default();
            Some(match ports(proto, payload) {
                Some((sp, dp)) => format!("ipv6 {} [{src}]:{sp} -> [{dst}]:{dp}", name(proto)),
                None => format!("ipv6 {} {src} -> {dst}", name(proto)),
            })
        }
        other => Some(format!("ethertype {other:#06x}")),
    }
}

/// Reads frames until the socket fails and passes each logged one to
/// `emit` with its description, length and first bytes. After
/// [`MAX_PACKETS`], `emit` is called once more with `None`.
pub fn run(socket: &OwnedFd, mut emit: impl FnMut(Option<(String, u64, &[u8])>)) {
    let mut buffer = vec![0_u8; 65_536];
    let mut logged = 0_u32;

    loop {
        let Ok((read, len)) = recv(socket, &mut buffer[..], RecvFlags::TRUNC) else {
            return;
        };

        let frame = buffer.get(..read).unwrap_or_default();
        let Some(summary) = describe(frame) else {
            continue;
        };

        logged = logged.saturating_add(1);

        if logged <= MAX_PACKETS {
            let kept = frame.get(..PACKET_CAPTURE).unwrap_or(frame);
            emit(Some((summary, len as u64, kept)));
        } else if logged == MAX_PACKETS + 1 {
            emit(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(src_mac: [u8; 6], ethertype: u16, packet: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(packet);

        f
    }

    const GUEST: [u8; 6] = [0x06, 0, 0, 0, 0, 2];

    fn ipv4(proto: u8) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend_from_slice(&[10, 0, 2, 2, 10, 0, 2, 1]);

        p
    }

    #[test]
    fn skips_what_the_proxies_see_and_host_frames() {
        assert!(describe(&frame(GUEST, ETHERTYPE_IPV4, &ipv4(PROTO_TCP))).is_none());
        assert!(describe(&frame(GUEST, ETHERTYPE_IPV4, &ipv4(PROTO_UDP))).is_none());
        assert!(describe(&frame(GUEST, ETHERTYPE_ARP, &[0; 28])).is_none());
        assert!(describe(&frame(HOST_MAC, ETHERTYPE_IPV4, &ipv4(PROTO_ICMP))).is_none());
        assert!(describe(&[0; 10]).is_none());
    }

    #[test]
    fn describes_icmp_ipv6_and_other_frames() {
        assert_eq!(
            describe(&frame(GUEST, ETHERTYPE_IPV4, &ipv4(PROTO_ICMP))).unwrap(),
            "ipv4 icmp 10.0.2.2 -> 10.0.2.1"
        );

        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, PROTO_TCP, 64];
        v6.extend_from_slice(&"fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        v6.extend_from_slice(&[0x30, 0x39, 0x01, 0xbb]);

        assert_eq!(
            describe(&frame(GUEST, ETHERTYPE_IPV6, &v6)).unwrap(),
            "ipv6 tcp [fd00::2]:12345 -> [2001:db8::1]:443"
        );
        assert_eq!(
            describe(&frame(GUEST, ETHERTYPE_IPV6, &v6[..20])).unwrap(),
            "ipv6 (truncated)"
        );
        assert_eq!(
            describe(&frame(GUEST, 0x88b5, &[1, 2, 3])).unwrap(),
            "ethertype 0x88b5"
        );
    }
}
