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
| Firecracker and jailer 1.17 | The microVM monitor and its sandbox ([ADR 0002](adr/0002-firecracker-over-cloud-hypervisor-and-cratera.md)). |
| PostgreSQL | Job queue and result store ([ADR 0004](adr/0004-postgres-as-queue.md)). |
