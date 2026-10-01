# Testing

## The one rule

**Crate code is never executed outside a microVM.** That includes tests and
CI. Fixture crates are inert, stored as archives, and never workspace
members, so `cargo test` at the root can never build them. CI tests the
orchestrator against a fake Firecracker backend; real VMs run only on the
server.

## Layers

| Layer | What | Where |
|-------|------|-------|
| Unit tests | Pure logic: names, digests, config validation, state machine paths | `#[cfg(test)]` modules |
| Property tests | Parsers and the state machine under arbitrary input | `proptest`, for example `crates/core/tests/state_machine.rs` |
| Documentation checks | Writing style, generated diagram up to date | `cargo xtask docs-lint`, `cargo xtask state-diagram` |
| Integration tests | Feed and fetcher against a mock crates.io; Postgres job store | M2 |
| End to end tests | Canary crates through the whole pipeline with the fake VM backend | M5 |
| Fuzz targets | Every host parser of hostile input: archives, static analysis, Rust sources, manifests, lockfiles, index lines, RSS, the scratch disk, BTF, the vsock protocol, trace records, the fake internet's DNS parser and sniffer | `fuzz/` (`cargo fuzz`, pinned nightly); `cargo xtask fuzz` runs each target briefly, and at least 150 seconds each before a release |
| Firecracker tests | Boot, run jobs through the agent, snapshot and restore twice with fresh state, clock and randomness | `crates/orchestrator/tests/firecracker.rs`, ignored by default; run on the server with `--ignored` |
| Deployment checks | The playbooks parse, the units verify with `systemd-analyze`, the firewall loads in a throwaway network namespace; unit tests keep the playbook's pins and unit list in sync | `cargo xtask deploy-check`, in CI |
| Soak test | Sequential jailed jobs, a host side timeout and crash reconciliation, then checks for leaked processes, cgroups, directories, network interfaces, file descriptors and memory | `cargo xtask soak --jobs 50`, on the server |

## State machine properties

`crates/core/tests/state_machine.rs` drives the job state machine with
arbitrary event sequences and checks:

* rejected events leave the job unchanged;
* terminal states accept no event;
* every sequence of valid events reaches a terminal state within a fixed
  bound, so there is no infinite path;
* transient failures end in `Failed` after at most `max_attempts`;
* escalation to a full build happens at most once;
* the coverage label is "dynamic on Linux" exactly when a VM run completed.

## Real microVM tests

These need `/dev/kvm`, so CI skips them. On the server:

```sh
cargo xtask firecracker     # pinned release, SHA-256 verified
cargo xtask guest-kernel    # pinned source, fragment checked
cargo xtask rootfs          # pinned Debian snapshot, agent as PID 1, eBPF programs
cargo test -p crateward_orchestrator --test firecracker -- --ignored --test-threads 1
cargo xtask soak --jobs 50  # needs a delegated cgroup; xtask starts a systemd user scope
```

Results on the production server (2026-09-24): boot to a ready agent in
about 430 ms; restore of a snapshot into a new jail, including the jail
setup and cgroup, to a ready agent in 60 to 68 ms at the median and at most
92 ms; 50 jobs in about 12.5 seconds; resident memory of the test process
grew by 4 KiB over 50 jobs, and nothing was left behind.

The only programs these tests start inside the VM are the guest agent and
standard tools of the guest image.

## Sandboxed children

Six child modes of three services handle hostile input: the fetcher's
validation and resolution children, the static analyzer's child, and the
orchestrator's scratch scanner, export and image builder. Each child enters
its sandbox (user and network namespaces, rlimits, Landlock) before it reads
input, through `crateward_core::sandbox::enter`. The parents start them
through `crateward_core::child`, which gives them an empty environment,
keeps the start of their stderr and enforces the deadline.

The tests run the real child binaries on inert fixtures; nothing in a
fixture is ever executed. They live in `crates/fetcher/tests/sandbox.rs`,
`crates/static_analysis/tests/sandbox.rs` and
`crates/orchestrator/tests/sandbox.rs`. The resolution child runs a fake
`cargo`, a shell script that the test writes. A kernel or CI runner without
unprivileged user namespaces skips these tests, and so does a host without
`mkfs.erofs`, unless `CRATEWARD_REQUIRE_SANDBOX` is set, which the server's
own runs do. `crateward_core::sandbox::unavailable` decides that for all of
them.

`cargo xtask canary` runs the end to end canary on the server: a fixture
crate whose build script reads the job's cargo token and posts it to a
made up host and has `curl` post the AWS credentials over HTTPS. Its
source exists only as strings in `crates/orchestrator/tests/canary.rs`; it
is compiled and run only inside a microVM. The test passes when the fake
internet recorded the lookup, the orchestrator found both tokens in what
left the VM, and the eBPF trace shows the build script reading the cargo
credentials and connecting out, and `curl`, started by the build script,
reading the AWS file. The build script also copies the token into its
`OUT_DIR` and drops an autostart file into the home directory; the host's
scan of the scratch disk must find both.

The same test also runs the known good canary, which must come out with
nothing flagged. The orchestrator runs both canaries on a schedule
(ADR 0008); their fixtures live in `crates/orchestrator/src/canary.rs`.

The eBPF programs themselves only run in the guest kernel. On the host,
tests cover the agent's record decoder (including every truncation of a
record), its BTF reader (on built fixtures and on the host kernel's own
BTF) and the orchestrator's bounded trace summary.

Detectors are tested on fixtures too, including the false positives found
on live crates (URLs in doc comments and error messages, bidi characters
in images, `toast.txt` as an exfiltration host), so they stay fixed.

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

Documentation, rustdoc comments and configuration comments are English, in
short and precise sentences, with no em dashes and no hyphenated compounds.
`cargo xtask docs-lint` enforces the last two rules:

* write "read only", "content addressed", "build time" instead of joining
  words with hyphens;
* put names that contain hyphens (crates, tools, flags, targets) in inline
  code, for example `cargo-deny`;
* text inside double quotes is a quotation of a source and is not checked.
