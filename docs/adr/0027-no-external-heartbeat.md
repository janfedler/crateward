# 0027: No external heartbeat

* Status: Accepted
* Date: `2026-10-01`

## Context

ADR 0009 and ADR 0020 made healthchecks.io a dead man's switch: the
supervisor pinged a secret URL every minute while its rounds succeeded, and
healthchecks.io alerted through ntfy when the pings stopped. It was the only
alert that worked while the server itself was down.

The maintainer decided on 2026-10-01 to remove healthchecks.io entirely:
one external service, one secret and one egress host less.

## Options

* **Keep healthchecks.io.** Notices a dead server, but costs an account, a
  secret URL and an allowlisted host.
* **No external heartbeat.** Simpler; a dead server, a stopped supervisor
  or an unreachable database goes unnoticed until the maintainer looks.
* **Another monitor** (a second server, an uptime service polling a public
  endpoint). The server has no public endpoint, and a second host is what
  ADR 0009 avoids.

## Decision

No external heartbeat. The `[heartbeat]` configuration table, the
supervisor's ping task, the `hc-ping.com` egress host and the install
prompt are removed. This supersedes the heartbeat parts of ADR 0009 and
ADR 0020.

## Consequences

* Every alert comes from the supervisor on the server. If the server, the
  supervisor or its database connection is down, no alert arrives.
* The maintainer checks `crateward status` now and then; the canary times
  it prints show whether the pipeline is alive.
* A configuration that still has a `[heartbeat]` table is rejected by
  `crateward config check`, because unknown fields are refused.
* An external monitor can come back later as a separate component without
  changing the alert list in `crateward_core::escalation`.

## Sources

* `crates/supervisor/src/lib.rs`, `crates/core/src/config.rs` and
  `crates/cli/src/egress.rs`, as changed with this record.
* ADR 0009 and ADR 0020.
