# Dependencies

Every dependency needs a reason. Prefer boring, well maintained crates, and
add one only when the alternative is a worse hand written version. `cargo
deny`, `cargo audit` and `cargo vet` check all of them in CI.

## Rust crates

| Crate | Used by | Why |
|-------|---------|-----|
| `serde` | core | Derived, well audited (de)serialization for configuration and events. |
| `toml` | core, orchestrator | Parses the configuration file. The format Cargo users already know. The orchestrator rewrites manifests into stubs for the warm build. |
| `thiserror` | core | Typed error enums without boilerplate, no runtime cost. |
| `secrecy` | core | Secret strings whose `Debug` output is redacted, so logs cannot leak them. |
| `url` | core | Correct URL parsing for configuration validation. The WHATWG reference parser for Rust. |
| `rand` | core | Jitter for retry backoff with an injectable, seedable generator. |
| `clap` | core (`app` feature), cli, xtask | Command line parsing with derive. The de facto standard. |
| `tracing` | core (`app` feature) | Structured logging facade used by the whole async ecosystem. |
| `tracing-subscriber` | core (`app` feature) | JSON and human readable log output with environment based filters. |
| `proptest` | core (tests) | Property tests for parsers and the state machine. |
| `postcard` | core | Compact, schema driven encoding of the host and guest protocol. `no_std` friendly and strict about trailing bytes. |
| `rustix` | guest agent | Safe wrappers for `mount`, `reboot`, `clock_settime` and process groups, so the agent needs no unsafe code. |
| `vsock` | guest agent | Blocking `AF_VSOCK` listener for the agent. A small wrapper maintained by the `rust-vmm` community. |
| `tokio` | orchestrator | Async runtime for supervising many VMs, timers and sockets at once. |
| `hyper`, `hyper-util`, `http-body-util`, `bytes` | orchestrator | HTTP/1.1 client for the Firecracker API over its Unix socket, with bounded response bodies. |
| `serde_json` | orchestrator | JSON bodies of the Firecracker API. |
| `blake3` | xtask, core (`blobs`) | Fast digests that name images and content addressed blobs. |
| `tokio-postgres` | core (`store`) | Asynchronous PostgreSQL client from the `rust-postgres` project. Plain SQL, no query builder or code generation. |
| `semver` | core (`cratesio`, `store`) | The reference implementation of Cargo's version rules. |
| `quick-xml` | core (`cratesio`) | Streaming XML parser for the RSS feeds. |
| `reqwest` | core (`http`) | HTTP client with rustls and the platform certificate verifier. |
| `landlock` | core (`sandbox`) | Official Rust bindings for Landlock, from its maintainers. |
| `tar`, `flate2` | fetcher, static analysis, orchestrator, xtask | Reading crate archives. `flate2` uses the pure Rust `miniz_oxide` backend. |
| `zstd` | core (`blobs`) | Compression of stored blobs. Binds the reference zstd library. |
| `syn`, `proc-macro2` | static analysis | The parser the Rust ecosystem uses for Rust source. Parses without evaluating `cfg`, and `span-locations` gives line numbers for evidence. |
| `yara-x` | static analysis | VirusTotal's Rust rewrite of YARA for byte patterns in any file. Default features off, only the rule compiler options it needs. |
| `rustls` | fake internet | Terminates the guest's TLS connections. Pure Rust, with the `ring` provider so the static musl build needs no C library. |
| `rcgen` | fake internet, xtask | Issues the fake internet's certificates per server name and creates its authority. From the rustls project. |
| `aya` | guest agent | Loads and attaches the eBPF programs and reads their ring buffer. Pure Rust, no libbpf ([ADR 0007](adr/0007-guest-agent-ebpf.md)). |
| `aya-ebpf` | guest eBPF programs | The Rust side of aya for writing the programs themselves. The only dependency of `crateward_guest_ebpf`, which has its own lockfile. |
| `ext4-view` | orchestrator | Reads the guest written scratch disk in a sandboxed child. Read only, no unsafe code, designed not to panic on invalid data. |
| `axum` | api | The dashboard's HTTP server, from the tokio project. Default features off. |
| `askama` | api | Compile time templates that escape HTML by default (ADR 0009). |
| `futures-util` | api | The stream behind the dashboard's server sent events. |
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
| Firecracker 1.17 | The microVM monitor ([ADR 0002](adr/0002-firecracker-rootless-jail.md)). Jailed without its jailer ([ADR 0002](adr/0002-firecracker-rootless-jail.md)). |
| `newuidmap`, `newgidmap` (Debian `uidmap`) | Write the ID maps of each jail's user namespace. |
| PostgreSQL | Job queue and result store ([ADR 0001](adr/0001-one-server-postgres-queue.md)). |
| htmx 2.0.11 and `htmx-ext-sse` 2.2.4 (0BSD) | Vendored in `crates/api/static`, checked against the npm registry's SHA-512 when added and pinned by SHA-256 in a test ([ADR 0009](adr/0009-scoring-and-dashboard.md)). |
| Lobster, DM Sans and JetBrains Mono (OFL 1.1), from Fontsource 5.3.0 | The design system's webfonts, latin subset, served by the dashboard and copied into the public site so no page loads anything from elsewhere. Vendored in `crates/api/static` with `OFL.txt`, checked against the npm registry's SHA-512 when added and pinned by SHA-256 in a test. |
| `bpf-linker` 0.11.1 | Links the eBPF programs. Pinned by SHA-256 in `guest/bpf-linker.toml` together with the nightly compiler whose LLVM it matches ([ADR 0007](adr/0007-guest-agent-ebpf.md)). |
