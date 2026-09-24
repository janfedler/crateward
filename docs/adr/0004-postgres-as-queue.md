# 0004: Postgres as the job queue

* Status: Accepted
* Date: 2026-09-24

## Context

Each crate version moves through five stages, each with its own worker pool,
concurrency limit, retries and leases. The state of a job must survive
crashes, and a stage must never lose or duplicate work. Results and job
state also have to be queryable by the dashboard.

## Options

1. **Postgres table as the queue.** One row per crate version; workers claim
   rows with `SELECT ... FOR UPDATE SKIP LOCKED`.
2. **A separate broker** (Redis streams, RabbitMQ, NATS JetStream) plus
   Postgres for state.
3. **SQLite.**

## Decision

Option 1. The job row is both the state and the queue entry.

## Rationale

* The PostgreSQL documentation describes the use case directly. Skipping
  locked rows, it says,
  "can be used to avoid lock contention with multiple consumers accessing a queue-like table".
* State change and queue movement happen in one transaction. A broker would
  require keeping two systems consistent, the classic dual write problem.
* The load is small: hundreds of versions per hour, not thousands per
  second.
* One fewer service to secure, monitor, back up and update on a single
  server.
* The dashboard reads the same table through a read only role.
* SQLite allows one writer at a time and would need its own solution for
  the separate read only role and for access from sandboxed processes.

## Consequences

* Leases are columns (`lease_owner`, `lease_expires_at`) renewed by
  heartbeats; the supervisor reclaims expired leases, which counts as a
  failed attempt (see `crateward_core::job`).
* Workers poll with a short interval and can use `LISTEN`/`NOTIFY` to wake
  up early.
* Frequent updates cause table bloat; autovacuum settings for the job table
  are part of M5 and are measured in M7.

## Sources

* PostgreSQL documentation, `SELECT`, "The Locking Clause"
  (`doc/src/sgml/ref/select.sgml` in `https://github.com/postgres/postgres`)
