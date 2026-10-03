# Testing

## The one rule

**Crate code is never executed outside a microVM.** That includes tests and
CI. Fixture crates are inert, stored as archives, and never workspace
members, so `cargo test` at the root can never build them. CI tests the
orchestrator against a fake Firecracker backend. Real VMs run only on the
server.

## Layers

| Layer | What | Where |
|-------|------|-------|
| Unit tests | Pure logic: names, digests, config validation, state machine paths | `#[cfg(test)]` modules |
| Property tests | Parsers and the state machine under arbitrary input | `proptest`, for example `crates/core/tests/state_machine.rs` |
| Documentation checks | Writing style, generated diagram up to date | `cargo xtask docs-lint`, `cargo xtask state-diagram` |
| Integration tests | The feed against a mock crates.io, the job store, the static analysis worker, the dashboard and the `crateward` tool on a real PostgreSQL. The sandboxed children of the fetcher, static analysis and the orchestrator | `crates/*/tests/`, for example `crates/feed/tests/feed.rs`. The database tests need `CRATEWARD_TEST_DATABASE_URL` |
| Canary tests | A known bad crate must be caught and a known good one must come out clean, built in a real microVM | `crates/orchestrator/tests/canary.rs` through `cargo xtask canary`, on the server. The orchestrator also runs them every `sandbox.canary_interval_minutes` |
| Fuzz targets | Every host parser of hostile input: archives, static analysis, Rust sources, manifests, lockfiles, index lines, RSS, the scratch disk, BTF, the vsock protocol, trace records, the fake internet's DNS parser and sniffer | `fuzz/` (`cargo fuzz`, pinned nightly). `cargo xtask fuzz` runs each target briefly, and at least 150 seconds each before a release |
| Firecracker tests | Boot, run jobs through the agent, snapshot and restore twice with fresh state, clock and randomness | `crates/orchestrator/tests/firecracker.rs`, ignored by default and run on the server with `--ignored` |
| Deployment checks | The playbooks parse, the units verify with `systemd-analyze`, the firewall loads in a throwaway network namespace. Unit tests keep the playbook's pins and unit list in sync | `cargo xtask deploy-check`, in CI |
| Soak test | Sequential jailed jobs, a host side timeout and crash reconciliation, then checks for leaked processes, cgroups, directories, network interfaces, file descriptors and memory | `cargo xtask soak --jobs 50`, on the server |

## State machine properties

The job state machine is a deterministic finite automaton. Its states are
the job states together with the bounded retry counters, its input alphabet
is the set of job events, and its transition function is partial.
`crates/core/tests/state_machine.rs` runs it on arbitrary event sequences
and checks these properties:

* An event without a transition is rejected and leaves the job unchanged.
* Terminal states have no outgoing transitions.
* The transition graph is acyclic, because every retry increments a
  bounded counter. Every run therefore reaches a terminal state within a
  fixed number of steps (termination).
* Every reachable state is coreachable: a few events of the happy path lead
  from it to a terminal state, so the automaton has no trap states.
* Transient failures end in `Failed` after at most `max_attempts`.
* Escalation to a full build happens at most once.
* The coverage label is "dynamic on Linux" exactly when a VM run completed.

## Real microVM tests

These need `/dev/kvm`, so CI skips them. On the server:

```sh
cargo xtask firecracker     # pinned release, SHA-256 verified
cargo xtask guest-kernel    # pinned source, fragment checked
cargo xtask rootfs          # pinned Debian snapshot, agent as PID 1, eBPF programs
cargo test -p crateward_orchestrator --test firecracker -- --ignored --test-threads 1
cargo xtask soak --jobs 50  # needs a delegated cgroup, so xtask starts a systemd user scope
```

The only programs these tests start inside the VM are the guest agent and
standard tools of the guest image.

## Canary test

`cargo xtask canary` runs both canaries on the server, through
`crates/orchestrator/tests/canary.rs`. Their sources exist only as strings
in `crates/orchestrator/src/canary.rs`, and they are compiled and run only
inside a microVM.

The known bad canary has a build script that reads the job's cargo token
and posts it to a made up host, and has `curl` post the AWS credentials
over HTTPS. It also copies the token into its `OUT_DIR` and drops an
autostart file into the home directory. The test passes when:

* The fake internet recorded the lookup.
* The orchestrator found both tokens in what left the VM.
* The eBPF trace shows the build script reading the cargo credentials and
  connecting out, and `curl`, started by the build script, reading the AWS
  file.
* The host's scan of the scratch disk found the copied token and the
  autostart file.

The known good canary must come out with nothing flagged. The orchestrator
also runs both canaries on a schedule (ADR 0008).

## Running the checks

```sh
cargo xtask ci
```

runs formatting, clippy with warnings denied, all tests, rustdoc with
warnings denied, the static musl build of the guest agent, the eBPF
programs (format, clippy and build with the pinned nightly and
`bpf-linker`), the documentation checks, `cargo deny` for both lockfiles,
`cargo audit` and `cargo vet`, in the same order as CI.

## Writing style

Documentation, code comments and configuration comments are English, in
short and precise sentences, with no em dashes, no hyphenated compounds and
no semicolons. `cargo xtask docs-lint` enforces the last three rules in the
Markdown files, the Rust comments and `config/*.toml`:

* Write "read only", "content addressed", "build time" instead of joining
  words with hyphens.
* Put names that contain hyphens (crates, tools, flags, targets) and code
  in inline code, for example `cargo-deny`.
* End a sentence with a full stop where a semicolon would join two.
* Text inside double quotes is a quotation of a source and is not checked.
