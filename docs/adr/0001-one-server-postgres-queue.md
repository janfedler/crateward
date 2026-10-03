# 0001: One server, Postgres as the queue, few external services

* Status: Accepted
* Date: 2026-09-24, updated 2026-10-01

## Context

Each crate version moves through five stages with their own worker pools,
retries and leases. Job state must survive crashes, no stage may lose or
duplicate work, and the dashboard must be able to query it all. The load is
hundreds of versions per hour, not thousands per second. One maintainer
runs it, on one rented bare metal server, without a budget for a second
host.

## Decision

1. **One server** runs the whole pipeline. It has no public service except
   SSH (ADR 0003).
2. **The job row is the queue.** One Postgres row per crate version holds
   the state. Workers claim rows with `SELECT ... FOR UPDATE SKIP LOCKED`,
   and leases are columns (`lease_owner`, `lease_expires_at`) renewed by
   heartbeats. A state change and the queue movement happen in one
   transaction.
3. **Two external services, each with one narrow secret.** The public site
   is a static export of counts, pushed to `janfedler/crateward-site` and
   served by GitHub Pages. The server's deploy key writes to that
   repository only. Alerts go through ntfy.sh, whose topic name is the
   password, so configuration validation requires 32 to 64 random
   characters.

## Alternatives

* **A broker** (Redis streams, RabbitMQ, NATS JetStream) next to Postgres:
  two systems to keep consistent (the dual write problem), and one more
  service to secure, back up and update.
* **SQLite:** one writer at a time, and no separate read only role for the
  dashboard.
* **A small VPS** for the site and a monitor: dropped for cost.
* **healthchecks.io as a dead man's switch:** removed on 2026-10-01 to save
  one service, one secret and one egress host.

## Consequences

* There is no redundancy. An outage pauses scanning, and nothing outside
  the server notices: the maintainer checks `crateward status`, whose
  canary times show whether the pipeline is alive.
* Alert text leaves the server through a third party, so alerts carry a
  category and a short title, never a crate name or a job number.
* A compromised external service can deface the site or forge or suppress
  alerts. It cannot reach the server or undisclosed findings.
* Frequent updates bloat the job table. Autovacuum keeps up at this load.

## Sources

* PostgreSQL, `SELECT`, "The Locking Clause": skipping locked rows avoids
  lock contention between several consumers of a queue table.
* ntfy `docs/publish.md` and `docs/faq.md`,
  `https://github.com/binwiederhier/ntfy`
