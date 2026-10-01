# 0026: SSH as the only admin access, without WireGuard

* Status: Accepted
* Date: `2026-10-01`

## Context

ADR 0009 put WireGuard in front of SSH: one UDP port that answers nothing
to unauthenticated packets, with SSH reachable through the tunnel only once
the maintainer confirmed it worked. The deployment carried the interface,
its keys, a peer, an `sshd` drop in and a two step first setup for that.

The maintainer decided on 2026-10-01 to drop WireGuard entirely. It adds a
second key pair to keep safe, a client on every machine the maintainer
administers from, and a setup step that can lock them out, while SSH with
keys only is already the access the server needs.

## Options

* **Keep WireGuard in front of SSH.** Hides SSH from scanners and from
  unauthenticated bugs in `sshd`; costs the setup above.
* **SSH with keys only on the public interface.** One service, one key,
  the standard for a single server.
* **SSH on a port other than 22.** Fewer log entries from scanners, no
  real protection; the port is configurable (`ssh_port`) either way.

## Decision

SSH with keys only is the only inbound service. WireGuard is removed from
the playbook, the firewall, the variables and the documentation. This
supersedes the admin access part of ADR 0009 and the WireGuard mentions in
ADR 0017 and ADR 0022.

## Consequences

* SSH is reachable from the whole internet. Passwords and keyboard
  interactive logins stay disabled and root logs in with a key only. An
  unauthenticated `sshd` vulnerability would now be exposed, so security
  updates matter: unattended upgrades install them, and the maintainer
  watches OpenSSH advisories.
* The dashboard is unchanged: loopback only, reached through an SSH tunnel
  that the SSH key authenticates (ADR 0022).
* The first setup has one step less, and nothing on the server can lock the
  maintainer out through a broken tunnel.
* Per source rate limits for new SSH connections or an `AllowUsers` list
  can be added later without changing this decision.

## Sources

* `deploy/ansible/site.yml`, `deploy/nftables/crateward.nft` and
  `deploy/ansible/templates/sshd-crateward.conf.j2`, as changed with this
  record.
* ADR 0009 and ADR 0022.
