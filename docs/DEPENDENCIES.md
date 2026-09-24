# Dependencies

Every dependency needs a reason. Prefer boring, well maintained crates, and
add one only when the alternative is a worse hand written version. `cargo
deny`, `cargo audit` and `cargo vet` check all of them in CI.

## Rust crates

| Crate | Used by | Why |
|-------|---------|-----|
| `serde` | core | Derived, well audited (de)serialization for configuration and events. |
| `toml` | core | Parses the configuration file; the format Cargo users already know. |
| `thiserror` | core | Typed error enums without boilerplate, no runtime cost. |
| `secrecy` | core | Secret strings whose `Debug` output is redacted, so logs cannot leak them. |
| `url` | core | Correct URL parsing for configuration validation; the WHATWG reference parser for Rust. |
| `rand` | core | Jitter for retry backoff with an injectable, seedable generator. |
| `clap` | core (`app` feature), cli, xtask | Command line parsing with derive; the de facto standard. |
| `tracing` | core (`app` feature) | Structured logging facade used by the whole async ecosystem. |
| `tracing-subscriber` | core (`app` feature) | JSON and human readable log output with environment based filters. |
| `proptest` | core (tests) | Property tests for parsers and the state machine. |
| `postcard` | core | Compact, schema driven encoding of the host and guest protocol; `no_std` friendly and strict about trailing bytes. |
| `rustix` | guest agent | Safe wrappers for `mount`, `reboot`, `clock_settime` and process groups, so the agent needs no unsafe code. |
| `vsock` | guest agent | Blocking `AF_VSOCK` listener for the agent; a small wrapper maintained by the `rust-vmm` community. |
| `tokio` | orchestrator | Async runtime for supervising many VMs, timers and sockets at once. |
| `hyper`, `hyper-util`, `http-body-util`, `bytes` | orchestrator | HTTP/1.1 client for the Firecracker API over its Unix socket, with bounded response bodies. |
| `serde_json` | orchestrator | JSON bodies of the Firecracker API. |
| `blake3` | xtask | Fast digests that identify every image Crateward builds. |
| `sha2` | xtask | Verifies SHA-256 checksums published by third parties, such as Firecracker releases. |

## Tools

| Tool | Why |
|------|-----|
| `cargo-deny` | License, ban, source and advisory policy for the dependency graph. |
| `cargo-audit` | Checks `Cargo.lock` against the RustSec advisory database. |
| `cargo-vet` | Requires an audit or a trusted import for every dependency version. |

## GitHub Actions

All pinned by commit SHA.

| Action | Why |
|--------|-----|
| `actions/checkout` | Checks out the repository. |
| `Swatinem/rust-cache` | Caches build output between CI runs. |
| `taiki-e/install-action` | Installs prebuilt, checksum verified `cargo-deny`, `cargo-audit` and `cargo-vet` binaries. |

## Third party binaries (planned)

| Binary | Why |
|--------|-----|
| Firecracker 1.17 | The microVM monitor ([ADR 0002](adr/0002-firecracker-over-cloud-hypervisor-and-cratera.md)); jailed without its jailer ([ADR 0012](adr/0012-rootless-jail.md)). |
| `newuidmap`, `newgidmap` (Debian `uidmap`) | Write the ID maps of each jail's user namespace. |
| PostgreSQL | Job queue and result store ([ADR 0004](adr/0004-postgres-as-queue.md)). |
