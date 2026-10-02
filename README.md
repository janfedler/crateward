# Crateward

[![CI](https://github.com/janfedler/crateward/actions/workflows/ci.yml/badge.svg)](https://github.com/janfedler/crateward/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust 1.98.1](https://img.shields.io/badge/rust-1.98.1-orange.svg)](rust-toolchain.toml)
[![Website](https://img.shields.io/badge/web-crateward.com-blue.svg)](https://crateward.com)

Watches crates.io for new versions, analyzes each one statically, runs the
build time code of the interesting ones in a fresh, offline microVM, and
scores the risk with reasons that link to file, line and trace evidence.

## Features

* **Every new version, statically.** Build scripts, proc macros and library
  code are parsed with `syn` across all `cfg` branches and checked with
  YARA-X rules and a diff against the previous version, without executing
  anything on the host.
* **Build time code, dynamically.** Versions whose build runs their own code
  are built with `cargo check` in a fresh Firecracker microVM, restored from
  a clean snapshot in about 65 ms and destroyed afterwards.
* **Kernel level tracing.** eBPF programs in the guest record processes,
  file opens, connections, `ptrace`, `bpf` and mounts.
* **A fake internet.** The VM has no uplink, so DNS, HTTP, HTTPS and raw
  packets reach a sink that answers and records everything.
* **Honeytokens.** Each job gets fresh decoy credentials whose appearance
  on the network, in the trace or on the scratch disk is evidence of theft.
* **Explainable verdicts.** Every score lists its reasons with links to the
  evidence and states its coverage, never just "clean".
* **Runs without a human.** Retries, circuit breakers, hourly canary crates
  and quarantine on any escape indicator keep it going, with alerts only for
  what needs the maintainer.
* **Defense in depth.** A rootless jail, cgroup limits, seccomp, Landlock
  sandboxed parsers, a host integrity manifest and 13 fuzz targets stand
  between hostile input and the host, and no secret ever enters the guest.

## How it works

```mermaid
flowchart LR
    cio[crates.io<br/>RSS, sparse index,<br/>CDN, daily dump]
    subgraph server[Single bare metal server]
        direction LR
        subgraph trusted[Trusted zone: never runs crate code]
            feed[feed] --> fetcher[fetcher<br/>verify, extract, vendor]
            fetcher --> sa[static analysis<br/>syn over all cfg branches,<br/>YARA-X, version diff]
        end
        subgraph untrusted[Untrusted zone]
            orch[orchestrator<br/>rootless jail, limits, cleanup] --> vm[Firecracker microVM<br/>cargo check, eBPF tracing,<br/>honeytokens]
            vm --> fi[fake internet<br/>no uplink]
        end
        subgraph control[Control plane]
            pg[(Postgres<br/>one job row per version)]
            an[analyzer<br/>explainable scoring]
            web[dashboard<br/>htmx, SSE]
            sup[supervisor<br/>canaries, breakers, alerts]
        end
        sa --> pg --> orch
        vm -- vsock events --> orch --> pg --> an --> pg --> web
    end
    cio --> feed
    sup -- alerts --> ext[ntfy.sh]
    web -. static export .-> pages[crateward.com<br/>GitHub Pages]
```

Each crate version is one job row in Postgres that moves through an explicit
state machine; every service claims work with a lease, so a crashed service
loses nothing. The details, including the state diagram and the network
design, are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Workspace

| Crate | What it does |
|-------|--------------|
| [`crateward_core`](crates/core) | Shared types, typed configuration, the job state machine, the Postgres store, sandboxing primitives |
| [`crateward_feed`](crates/feed) | Discovers new versions from the RSS feeds, the sparse index and the daily dump |
| [`crateward_fetcher`](crates/fetcher) | Downloads, verifies, safely extracts and vendors crates |
| [`crateward_static_analysis`](crates/static_analysis) | Parses sources without executing them and produces findings with evidence |
| [`crateward_orchestrator`](crates/orchestrator) | Runs jobs in jailed Firecracker microVMs and guarantees their cleanup |
| [`crateward_guest_agent`](crates/guest_agent) | Runs inside the VM: executes the job offline and streams output and trace to the host |
| [`crateward_guest_ebpf`](crates/guest_ebpf) | The eBPF programs the guest agent loads |
| [`crateward_fake_internet`](crates/fake_internet) | DNS, HTTP and HTTPS sinks that stand in for the internet |
| [`crateward_analyzer`](crates/analyzer) | Scores runs with explainable reasons and keeps behavior profiles |
| [`crateward_supervisor`](crates/supervisor) | Health checks, breakers, canaries, retention and alerts |
| [`crateward_api`](crates/api) | The dashboard: server rendered HTML with htmx and server sent events |
| [`crateward_cli`](crates/cli) | `crateward`, the maintainer's command line tool |
| [`crateward_xtask`](crates/xtask) | Local CI, documentation checks, guest images and release bundles |

## Getting started

### Requirements

* Linux on `x86_64`. The toolchain is pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml); `rustup` installs it with the
  `x86_64-unknown-linux-musl` target.
* PostgreSQL 17 for the database tests. Without it they are skipped.
* For real microVMs only: `/dev/kvm`, subordinate user and group IDs, a
  delegated cgroup and `mkfs.erofs`. Firecracker, the guest kernel and the
  root filesystem are built from pins by `cargo xtask`.

### Build and test

```sh
git clone https://github.com/janfedler/crateward
cd crateward
cargo build --workspace
cargo test --workspace

# With Postgres, the store, feed, CLI and dashboard tests run too:
CRATEWARD_TEST_DATABASE_URL="host=/var/run/postgresql dbname=crateward_test" \
CRATEWARD_REQUIRE_DB=1 cargo test --workspace --all-features

# Every check CI runs, in the same order (needs cargo-deny, cargo-audit
# and cargo-vet):
cargo xtask ci
```

Crate code is never executed outside a microVM, not even in tests: fixture
crates are inert archives, and CI tests the orchestrator against a fake VM
backend. See [`docs/TESTING.md`](docs/TESTING.md).

### Running microVMs

On a host with KVM:

```sh
cargo xtask firecracker     # pinned release, SHA-256 verified
cargo xtask guest-kernel    # pinned kernel source
cargo xtask rootfs          # pinned Debian snapshot, agent as PID 1, eBPF programs
cargo test -p crateward_orchestrator --test firecracker -- --ignored --test-threads 1
cargo xtask soak --jobs 50  # sequential jailed jobs, then a check for leaks
cargo xtask canary          # a crate that steals a honeytoken must be caught
```

### Running the pipeline

The pipeline is seven long running systemd services and two timers on one
server, each service with its own user. [`deploy/`](deploy/) has the Ansible playbook, hardened units and the
firewall; `cargo xtask release` builds a release bundle with an SBOM and an
`install.sh` that installs, updates and removes it.
Start from [`config/crateward.example.toml`](config/crateward.example.toml)
and follow [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Usage

The `crateward` command line tool covers what the dashboard shows, so
recovery works over SSH:

```sh
crateward config check --config /etc/crateward/crateward.toml
crateward status                     # pauses, breakers, canaries, pending alerts
crateward state-machine diagram      # the job state machine in Mermaid
crateward evidence 42454 --out pack  # evidence pack of a job, for a report
crateward integrity check            # compare the host against its manifest
crateward quarantine lift            # only after the cause is understood
```

## Design

**Goals.** Analyze every new version statically. Observe what build time
code really does on Linux. Assume a hostile crate tries to escape, and make
an escape gain nothing: no secrets, no internet, no persistence, no
influence on later jobs. Run unattended. Label coverage honestly. Disclose
responsibly: findings go to the crates.io team and RustSec first. Record
every decision in an [ADR](docs/adr/README.md).

**Non goals.**

* Windows, macOS, iOS and Android guests. Firecracker runs Linux guests, so
  code for other targets is only type checked with `cargo check`.
* Agentless hypervisor introspection. The trace source sits behind a trait
  so it can come later ([ADR 0007](docs/adr/0007-guest-agent-ebpf.md)).
* Registries other than crates.io.
* Building every version. Triage decides, and the dashboard shows the
  coverage.

**Limitations.**

* **Capacity.** Four cores with SMT disabled, three of them for microVMs,
  against about 500 new versions per hour at busy times. Most versions end
  up "static only", with the reason.
* **Evasion.** A crate can detect the sandbox and stay dormant. Host side
  ground truth (packet capture, disk scans) limits what an active crate can
  hide, not what a dormant one never does.
* **Host kernel.** Debian 13's 6.12 kernel is outside Firecracker's
  validated host kernels; soak tests and hourly canaries compensate
  ([ADR 0003](docs/adr/0003-debian-ansible-ssh.md)).
* **One server, no ECC memory.** No redundancy; durable data has end to end
  checksums, results in flight do not.

## Project status

Milestones M0 to M7 are done and M8 (launch) is built. Since 2026-09-24 the
pipeline has processed every new crates.io version on a development host.
Deploying to the production server is the remaining step.

<details>
<summary>Milestones</summary>

| Milestone | Scope | State |
|-----------|-------|-------|
| M0 | Foundation: workspace, CI, config, core types, state machine, docs | done |
| M1 | Firecracker platform: guest kernel and rootfs, orchestrator, rootless jail, limits, cleanup | done |
| M1.5 | Build cache warmer: prewarmed snapshot | done: 28% less run time measured ([ADR 0006](docs/adr/0006-dynamic-runs.md)) |
| M2 | Ingest: feed, fetcher, safe extraction, vendoring, content addressed store | done |
| M3 | Static analysis: findings with evidence, cfg coverage, diffs | done |
| M4 | Dynamic analysis: guest agent, eBPF trace, fake internet, honeytokens, ground truth | done |
| M5 | Autonomy: retries, breakers, quarantine, canaries, deadlines, alerts | done |
| M6 | Analyzer and web: scoring, review inbox, dashboard, public export | done |
| M7 | Hardening and storage: security checklist, fuzzing, escape detection, retention | done; the offsite backup target is open |
| M8 | Launch: Ansible, hardened units, firewall, release bundles with SBOM, disclosure workflow, write up | built, not deployed |

</details>

## Documentation

* [Architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md)
* [Architecture decision records](docs/adr/README.md)
* [Testing](docs/TESTING.md), [operations](docs/OPERATIONS.md) and [runbook](docs/RUNBOOK.md)
* [Security checklist](docs/SECURITY_CHECKLIST.md) and [disclosure workflow](docs/DISCLOSURE.md)
* [Dependencies](docs/DEPENDENCIES.md), with one line of justification each
* [Deployment](deploy/README.md) and the [launch write up](docs/WRITEUP.md) (draft)

## Security

Crateward runs hostile code for a living, so reports about sandbox escapes,
parser bugs or anything that lets a crate influence the host are especially
welcome. Please report privately through GitHub's private vulnerability
reporting, not in a public issue. Details are in
[`docs/SECURITY.md`](docs/SECURITY.md).

## Contributing

Issues and pull requests are welcome. Before a pull request, run
`cargo xtask ci`; it includes `rustfmt`, `clippy` with the workspace lints,
the tests, the documentation style check and the supply chain checks.
Larger design changes start with an
[architecture decision record](docs/adr/README.md).

## License

Licensed under either of

* Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([`LICENSE-MIT`](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

The eBPF programs in [`crates/guest_ebpf`](crates/guest_ebpf) are licensed
under the GNU General Public License, version 2 only
([`crates/guest_ebpf/LICENSE`](crates/guest_ebpf/LICENSE)), because the
kernel requires a GPL compatible license for the helpers they call. The
guest agent loads them as a separate object at run time
([ADR 0010](docs/adr/0010-license.md)).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions. Contributions to `crates/guest_ebpf` are licensed under
GPL-2.0-only.
