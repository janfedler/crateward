# 0018: Logging frames the proxies do not see

* Status: Accepted
* Date: 2026-09-25

## Context

nftables in each slot's network namespace hands every IPv4 TCP and UDP
packet of the guest to the fake internet (ADR 0016). Everything else, such
as IPv6, ICMP, other IP protocols or raw Ethernet, reached no socket and
left no trace on the host. The eBPF trace (ADR 0017) shows such attempts
from inside the guest, but a guest that controls its own kernel can hide
them there.

Facts verified on 2026-09-25:

* `rustix` 1.1 opens `AF_PACKET` sockets but offers no safe way to bind one
  to an interface or to read a frame's direction.
* In the namespace, a packet socket opened with the namespace's privileges
  sees the tap device's frames in both directions.
* After a restore, the guest kernel sent IPv6 duplicate address detection
  and multicast listener frames on every run, unless IPv6 is disabled on
  its interfaces.

## Decision

1. The launcher starts the fake internet with the namespace's privileges.
   It opens a packet socket for all protocols, then switches to the slot's
   user (which clears its capabilities) before it reads anything from the
   guest, and only then enters its Landlock and resource limit sandbox.
2. The launcher gives the tap device a fixed host side MAC address and no
   IPv6 link local address. Frames with that source MAC are the host's and
   are skipped; the host sends no IPv6 at all.
3. ARP, and IPv4 TCP and UDP (which the proxies log), are skipped. Every
   other frame is logged with a description (for example
   `ipv6 tcp [fd00::2]:40000 -> [2001:db8::1]:443`), its length and its
   first 1 KiB, up to 1000 frames per run. The orchestrator searches those
   bytes for the job's honeytokens like any other traffic.
4. The guest agent disables IPv6 on the guest's interfaces at boot, so a
   normal run logs no frames here. A program that tries IPv6 fails inside
   the guest and appears in the trace; guest root that turns IPv6 back on
   appears on the host.

## Consequences

* The fake internet holds `CAP_NET_RAW` in its own namespace for the few
  instructions between start and the user switch, before any guest input.
* A guest that forges the host's MAC address as its source hides a frame
  from this log. Such a frame still reaches nothing: the namespace has no
  uplink.
* Nothing here gives the guest IPv6 connectivity. That would need an
  address and a route in the guest and IPv6 listeners in the fake internet,
  which no crate observed so far has needed.

## Sources

* Linux `packet(7)`, `socket(7)` (`SO_BINDTODEVICE` is not supported for
  packet sockets), `ip-link(8)` (`addrgenmode`), `Documentation/networking/ip-sysctl.rst`
  (`disable_ipv6`)
* `rustix` 1.1.5 `src/net` (`socket_with`, `recv`, `eth::ALL`)
