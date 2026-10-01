# 0009: One server; GitHub Pages, healthchecks.io and ntfy.sh instead of a VPS

* Status: Accepted (maintainer decision, 2026-09-24); admin access superseded by [0026](0026-ssh-without-wireguard.md), heartbeat by [0027](0027-no-external-heartbeat.md)
* Date: 2026-09-24

## Context

The original design put the public site and an external heartbeat monitor
on a small VPS. The maintainer removed the VPS for cost reasons. The scanner
still must have no inbound internet exposure apart from administration, the
public view must be a one way static export, and an outage of the server
must still produce an alert.

## Decision

* **Public site:** a static export (aggregate statistics and disclosed
  findings only) pushed to a separate repository, `janfedler/crateward-site`,
  and served by GitHub Pages at crateward.com. The server holds a deploy key
  with write access to that repository only.
* **Heartbeat:** healthchecks.io as the dead man's switch. Per its README it
  "listens for HTTP requests ... from your cron jobs" and "when a ping does
  not arrive on time, Healthchecks sends out alerts". The server pings every
  minute.
* **Alerts:** ntfy.sh. Its documentation states that without access control
  "the topic is essentially a password", so the topic is at least 32 random
  characters (enforced by configuration validation). healthchecks.io has an
  ntfy integration, so heartbeat alerts arrive in the same place.
* **Admin access:** WireGuard terminates on the server itself, on one UDP
  port. WireGuard does not answer unauthenticated packets.

## Consequences

* Alert text leaves the server through a third party, so alerts carry no
  crate names or details before disclosure: "1 item needs you: verdict".
  Details stay on the dashboard behind WireGuard.
* A compromised external service can deface the site or suppress or forge
  alerts. It cannot reach the server or undisclosed findings.
* Remote unlock of encrypted disks would have had no helper host; since
  [ADR 0013](0013-ext4-on-md-raid-without-encryption.md) the disks are not
  encrypted, so the question no longer arises.
* Egress now includes `github.com`, `ntfy.sh` and `hc-ping.com`, each
  allowlisted for one service user.

## Sources

* healthchecks `README.md` and `hc/integrations/ntfy`,
  `https://github.com/healthchecks/healthchecks`
* ntfy `docs/publish.md` and `docs/faq.md`, `https://github.com/binwiederhier/ntfy`
