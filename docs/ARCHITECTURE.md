# Architecture

This document describes how Crateward is put together and why. Decisions with
real alternatives are recorded in [the ADR folder](adr/README.md). This page
links to them instead of repeating them.

## Goals in one paragraph

Crateward watches crates.io for new versions, analyzes each one statically,
runs the build time code of the interesting ones inside Firecracker microVMs,
scores the risk with reasons linked to evidence, and shows the results on a
dashboard. It runs unattended and interrupts the maintainer only for the
closed list of reasons in `crateward_core::escalation`.

## Hardware and its consequences

Three properties of the host shape everything below.

* **SMT is disabled.** The CPU is affected by L1TF and MDS. The kernel
  documentation calls `mds=full,nosmt` "the complete mitigation" and states
  that preventing the SMT issues of L1TF "might" require disabling SMT
  completely. One core is kept for host services, the others run microVMs.
  See [ADR 0002](adr/0002-firecracker-rootless-jail.md).
* **The hot path lives in RAM.** Hard disks cannot serve the random reads
  of snapshot memory files or the writes of scratch disks. Promoted images
  and per job scratch disks live in tmpfs. The disks hold durable data.
* **No ECC, plain ext4.** The memory has no ECC, and the disks are an md
  RAID1 with ext4, unencrypted ([ADR 0003](adr/0003-debian-ansible-ssh.md)).
  Neither checksums data, so Crateward does:
  * content addressed blobs by their BLAKE3 digest on every read,
  * images by BLAKE3 manifests,
  * crate files by the index SHA-256,
  * PostgreSQL pages by data checksums.

## Zones

The server is split into three zones plus the guest. A component's zone
decides what it may touch. `crateward_core::component` encodes this mapping
and a unit test checks that only the guest executes crate code.

| Zone | Components | Executes crate code | Internet |
|------|------------|---------------------|----------|
| Trusted | feed, fetcher, static analysis | never | crates.io hosts only (fetcher) |
| Untrusted | orchestrator, fake internet | only inside microVMs | none |
| Control plane | analyzer, api, supervisor, cli, Postgres | never | the alert service, GitHub (export) |
| Guest | guest agent, crate under analysis | yes | none. The fake internet only |

```mermaid
flowchart LR
    subgraph internet[Internet]
        cio[crates.io<br/>index, CDN, RSS, dump]
        ext[ntfy.sh<br/>GitHub Pages]
    end
    subgraph trusted[Trusted zone]
        feed[feed]
        fetcher[fetcher]
        sa[static analysis<br/>sandboxed process]
    end
    subgraph untrusted[Untrusted zone]
        orch[orchestrator<br/>rootless jail]
        subgraph slot[slot netns]
            vm[Firecracker microVM<br/>guest agent]
        end
        fi[fake internet<br/>netns without uplink]
    end
    subgraph control[Control plane]
        pg[(Postgres<br/>job table)]
        an[analyzer]
        api[api and web]
        sup[supervisor<br/>notifier]
    end
    cio --> feed
    cio --> fetcher
    feed --> pg
    fetcher --> pg
    sa --> pg
    pg --> orch
    orch --> vm
    vm -- tap --> fi
    vm -- one vsock stream --> orch
    orch --> pg
    pg --> an
    an --> pg
    pg --> api
    sup --> ext
    api -. static export .-> ext
```

## Data flow

One Postgres row per crate version tracks the whole pipeline
([ADR 0001](adr/0001-one-server-postgres-queue.md)). Every stage:

* claims rows in its input state with `SELECT ... FOR UPDATE SKIP LOCKED`,
* holds a lease renewed by heartbeats,
* performs an idempotent step,
* and reports an event to the state machine.

The stages in order:

1. **feed** sees a new version in the RSS feeds, confirms it in the sparse
   index, and creates the job. The daily database dump reconciles anything
   the feeds missed and provides the popularity data behind priorities.
2. **fetcher** downloads the `.crate` file and verifies its SHA-256 against
   the index, and records its SHA-512 for SBOMs. It validates the archive
   in a sandboxed child without extracting it.

   It then resolves all dependencies for all targets with
   `cargo generate-lockfile` on a generated consumer probe (sandboxed, no
   compiler). Every locked crate is fetched, validated and stored as a
   content addressed blob ([ADR 0004](adr/0004-resolve-fetch-validate.md)).
3. **static analysis** parses every Rust file with `syn` across all `cfg`
   branches in a sandboxed child, runs detectors and YARA-X rules, diffs
   against the previous version, and decides the triage: dynamic, static
   only, or not applicable on Linux
   ([ADR 0005](adr/0005-static-analysis-and-triage.md)).
4. The job becomes ready for the sandbox, or goes straight to scoring.
5. **orchestrator** claims the job when a VM slot is free
   ([ADR 0006](adr/0006-dynamic-runs.md)). It builds the job's read only
   payload image and scratch disk and restores the base snapshot. The
   snapshot's placeholder drives are pointed at them, and the agent mounts
   them and plants fresh honeytokens.
6. **guest agent** runs `cargo check` as an unprivileged user. It streams
   the output and an eBPF trace over the single vsock connection
   ([ADR 0007](adr/0007-guest-agent-ebpf.md)). The trace covers processes,
   file opens, connections and tamper attempts.

   Two host side views complete the picture. The fake internet records
   every network attempt, including frames no proxy sees. After the run the
   host reads the scratch disk in a sandboxed child.
7. **analyzer** scores static findings, dynamic events and the version diff,
   may escalate once to a full build and test, and stores a behavior profile.
8. **analyzer** finalizes ([ADR 0009](adr/0009-scoring-and-dashboard.md)):
   * High and critical verdicts wait in the "needs you" inbox of the
     dashboard (**api**).
   * The **supervisor** raises alerts from the closed escalation list.
   * The analyzer writes the job's CycloneDX SBOM, which the api serves
     with a findings document that points into it
     ([ADR 0012](adr/0012-cyclonedx-sbom-and-vex.md)).
   * The api exports aggregate numbers to the public site.

## Job state machine

The state machine lives in `crateward_core::job` as a pure function. The
diagram below is generated from that function by
`cargo xtask state-diagram --write`, and CI fails if it drifts.

<!-- BEGIN GENERATED: job state diagram, run `cargo xtask state-diagram --write` -->
```mermaid
stateDiagram-v2
    [*] --> Discovered
    Discovered --> Discovered: retry
    Discovered --> Fetched: fetched
    Discovered --> Done: unavailable
    Discovered --> Failed: gave up
    Fetched --> Fetched: retry
    Fetched --> StaticallyAnalyzed: triage static only
    Fetched --> ReadyForSandbox: triage dynamic
    Fetched --> Failed: gave up
    StaticallyAnalyzed --> StaticallyAnalyzed: retry
    StaticallyAnalyzed --> Scored: scored
    StaticallyAnalyzed --> Failed: gave up
    ReadyForSandbox --> StaticallyAnalyzed: dynamic deadline expired
    ReadyForSandbox --> ReadyForSandbox: retry
    ReadyForSandbox --> Running: VM slot claimed
    ReadyForSandbox --> Failed: gave up
    Running --> ReadyForSandbox: retry run
    Running --> DynamicallyAnalyzed: run finished
    Running --> Failed: gave up
    DynamicallyAnalyzed --> ReadyForSandbox: escalate to full build
    DynamicallyAnalyzed --> DynamicallyAnalyzed: retry
    DynamicallyAnalyzed --> Scored: scored
    DynamicallyAnalyzed --> Failed: gave up
    Scored --> Scored: retry
    Scored --> Done: finalized
    Scored --> Failed: gave up
    Done --> [*]
    Failed --> [*]
```
<!-- END GENERATED: job state diagram -->

Notes on the design:

* States name what has been achieved. Each stage claims the state its
  predecessor produced. `Running` is the exception: a VM run owns host
  resources (slot, tap device, jail) that startup reconciliation must match
  against rows.
* `DynamicallyAnalyzed` is one state more than the specification lists. It
  stores raw VM results before scoring, so an analyzer crash never forces an
  expensive, non deterministic VM rerun.
* "retry" edges keep the stage and consume one attempt (transient failure or
  expired lease) or one infrastructure retry. Attempts reset only when a
  stage completes. A run that fails after the VM started goes back to the
  slot queue with its attempts intact, so it cannot loop forever.
* An expired lease counts as a failed attempt because a hostile crate can
  crash a worker on purpose.
* A suspected compromise ends the job in `Failed` and puts the pipeline into
  quarantine, in the same transaction. The job is never retried
  automatically, since that would execute the suspicious crate again.
* Infrastructure failures feed a circuit breaker per stage. An open breaker
  or a pause (quarantine, a failed canary, a full scratch filesystem, burst
  mode) stops
  claiming in the affected stages only. The supervisor decides from the job
  events and delivers alerts
  ([ADR 0008](adr/0008-autonomy-and-escape-detection.md)).
* Escape tripwires outside the VM also quarantine the pipeline: a read of
  the decoy in a jail root ends the job as a suspected compromise, and the
  supervisor watches decoys on the host, processes with a slot UID and the
  integrity manifest of the binaries and images
  ([ADR 0008](adr/0008-autonomy-and-escape-detection.md)).
* Each supervisor round trims the raw data of old unflagged run reports.
  Verdicts and evidence stay.
* A crate that fails to build is a result (`BuildOutcome::Failed`), not a
  failure of the pipeline.
* Escalation to a full build and test happens at most once. Together with
  bounded retries this makes every path finite. A property test checks it.

## Triage and capacity

There are far more new versions than VM slots, so:

* Every version gets static analysis.
* A version gets a VM run only if it has build time code of its own (a build
  script, `proc-macro = true`, or `links`), has a high severity finding, or
  locks an unfamiliar dependency with build time code
  ([ADR 0005](adr/0005-static-analysis-and-triage.md)).
* New crates and updates of popular crates get a higher priority, so they
  run first.
* A job that waits longer than `triage.dynamic_deadline_hours` for a slot is
  scored as static only, and its label says why.
* The dashboard publishes the share of versions with dynamic results.

A version without build time code of its own executes nothing of its own
during `cargo check`. Labeling it "static only, no build time code" loses
little.

Its dependencies' build scripts are analyzed as their own versions.

## MicroVM lifecycle

The orchestrator drives Firecracker 1.17 through its API socket and always
starts it in a rootless jail ([ADR 0002](adr/0002-firecracker-rootless-jail.md)).

* **No root.** A single threaded launcher, `crateward-vmjail`, prepares
  each VM:
  1. It joins the slot's cgroup.
  2. It creates a user namespace in which the slot's own subordinate UID
     stands for Firecracker, then mount, network, IPC and UTS namespaces.
  3. It bind mounts exactly the kernel, the images and `/dev/kvm`, and
     creates the slot's tap device.
  4. It calls `pivot_root`, drops every capability, sets `no_new_privs` and
     executes Firecracker, whose own seccomp filter then applies.

  Namespaces and tap devices die with the process.
* **Restore, then personalize.** Jobs restore a Full snapshot of a clean
  boot (Diff snapshots are a developer preview).

  Firecracker's documentation calls resuming one snapshot many times
  insecure for uniqueness. So the job identity, honeytokens and wall clock
  are sent over vsock after restore, and the guest waits for the VMGenID
  reseed.

  `PUT /snapshot/load` supports `network_overrides` and `vsock_override`,
  and each jail provides the same relative paths the snapshot expects.
* **Payload.** The host builds a read only EROFS image of the job's vendored
  sources in tmpfs and swaps it in with `PATCH /drives/{id}` after restore.
  The warm build cache is a third drive, switched the same way. Inside the
  guest, overlayfs stacks its target directory under the job's own
  writable layer.
* **One channel.** The host initiates the only vsock connection
  (`CONNECT <port>`). It never listens on `<uds_path>_<port>`, so every guest
  initiated vsock connection is refused by Firecracker.
* **Limits.** cgroup v2 `cpu.max`, `memory.max` and `pids.max`, Firecracker
  rate limiters on drives and the network device, a fixed size scratch disk,
  and a wall clock limit enforced with `cgroup.kill`.
* **Cleanup.** Every resource is named after its slot. On startup the
  supervisor kills orphan VMs, removes stale tap devices, namespaces, jails
  and scratch files, and verifies free disk space.

## Network

Each slot has its own network namespace, created by the rootless jail
([ADR 0006](adr/0006-dynamic-runs.md)). All clones share the guest IP
(`10.0.2.2`) and MAC address baked into the snapshot. This works because
the namespaces are isolated.

The namespace holds only:

* the tap device (`10.0.2.1` on the host side),
* one fake internet process, running as the slot's user without filesystem
  access.

There is no uplink and no route out, so a guest cannot reach the real
internet at all.

nftables in the namespace redirects every DNS query, TCP connection and UDP
datagram to the fake internet. It recovers the intended TCP destination
with `SO_ORIGINAL_DST` and logs each attempt with its first 64 KiB. After
the run, that log serves as ground truth and is searched for the job's
honeytokens.

TLS is terminated with Crateward's own authority, which the guest image
trusts, so the content of HTTPS requests is logged too. IPv6 logging is
still open.

## Build cache

At startup the orchestrator replays the dependency builds of recent jobs in
a VM, with each crate under analysis replaced by a stub
([ADR 0006](adr/0006-dynamic-runs.md)). It packs the resulting target
directory into a read only image. Every job mounts it under its own
writable layer and compiles only what the image lacks.

A version enters the image only if Crateward has stored it for two weeks,
seen it in several jobs and found no high severity static findings. The
warm build is analyzed like a job, and a promotion check guards its use.

In the measurement, run time fell by 28 percent.

## Storage layout

See the [storage layout in OPERATIONS.md](OPERATIONS.md#storage-layout).

## Egress

Every allowlist is enforced per service user by nftables sets that are filled
from DNS (`deploy/nftables/crateward.nft`).

* `crateward egress` derives the hosts from the configuration.
* A root timer loads them every two minutes.
* A packet from a slot UID on the host network is logged and dropped.

| Service user | Destinations | Purpose |
|--------------|--------------|---------|
| fetcher | `index.crates.io`, `static.crates.io`, `cloudfront-static.crates.io` | index, crate files, dump |
| feed | `static.crates.io`, `index.crates.io` | RSS feeds, index files |
| image builder (weekly) | `static.rust-lang.org`, `snapshot.debian.org`, kernel source | guest image, pinned by hash |
| supervisor | `ntfy.sh` | alerts |
| exporter | `github.com` | one way push of the public site |
| everything else | none | |

The only inbound path is SSH with keys only. See
[ADR 0003](adr/0003-debian-ansible-ssh.md).

## Package map

| Package | Zone |
|---------|------|
| `crateward_core` | shared |
| `crateward_feed` | trusted |
| `crateward_fetcher` | trusted |
| `crateward_static_analysis` | trusted |
| `crateward_orchestrator` | untrusted |
| `crateward_guest_agent` | guest |
| `crateward_guest_ebpf` | guest |
| `crateward_fake_internet` | untrusted |
| `crateward_analyzer` | control plane |
| `crateward_api` | control plane |
| `crateward_supervisor` | control plane |
| `crateward_cli` | control plane |
| `crateward_xtask` | development |
