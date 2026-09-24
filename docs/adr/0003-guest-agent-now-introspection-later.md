# 0003: In guest agent now, agentless introspection later

* Status: Accepted
* Date: 2026-09-24

## Context

Dynamic analysis needs to see which processes a build starts, which files it
touches and which connections it opens. There are two places to observe
from: inside the guest (an agent) or from the hypervisor (introspection of
guest memory and vCPU state, without any guest component).

## Options

1. **In guest agent.** A static binary in the guest traces the build and
   streams events to the host.
2. **Agentless introspection.** The host reconstructs guest behavior from
   memory and vCPU state.

## Decision

Option 1 now. The trace source is a trait (`TraceSource`), so introspection
can become a second implementation later.

## Rationale

* Firecracker's API has no guest memory or vCPU introspection endpoint. The
  26 paths in its API definition cover configuration, devices, metrics,
  MMDS, snapshots and VM state. Introspection would mean patching the VMM or
  analyzing snapshot memory files offline, both research projects.
* The project specification assumes that build time behavior is rarely
  evasive, because build time malware targets developer machines and CI
  runners, where no monitoring agent is expected. This is an assumption, not
  a measurement. The host side ground truth below exists for the cases where
  it is wrong.
* The agent's weaknesses are covered by design: crate code runs as an
  unprivileged user, the guest kernel has no module support, and the host
  records ground truth the guest cannot hide from (tap capture, disk diff).

## Consequences

* A crate that gains guest root can tamper with the agent's view. The
  analyzer compares agent events with host ground truth, and a mismatch is
  itself a high severity signal.
* The host treats every byte from the agent as hostile (see
  [the threat model](../THREAT_MODEL.md), boundary B3).
* A later introspection backend could start from `PUT /snapshot/create`,
  which writes guest memory to a file, without changing the analyzer.

## Sources

* Firecracker `src/firecracker/swagger/firecracker.yaml` (list of API paths)
* Firecracker `docs/snapshotting/snapshot-support.md`
