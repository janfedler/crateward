# 0008: Prewarmed base snapshot and read only sccache

* Status: Proposed. Becomes Accepted or Rejected with the M1.5 measurements.
* Date: 2026-09-24

## Context

Most crates depend on the same few hundred crates (`serde`, `syn`,
`quote`, `proc-macro2`, `libc` and similar). Compiling them from a cold VM for every job
would dominate the per job cost on a server with three vCPUs for VMs. The
alternative, sharing build output between jobs, is a deliberate exception to
"compile nothing until the job runs" and creates a cache poisoning risk.

## Facts that shape the design

* sccache caches Rust compilations only when `--emit` includes `link`; only
  `link`, `metadata` and `dep-info` are supported. `bin`, `dylib`, `cdylib`
  and `proc-macro` crates are never cached, and incremental compilation must
  be off. `cargo check` emits metadata without `link`, so its units are
  **not** cacheable by sccache. The host builds of proc macro and build
  script dependencies (`syn`, `quote`, `proc-macro2`) do emit `link` and
  are cacheable.
* sccache supports a read only local cache (`SCCACHE_LOCAL_RW_MODE=READ_ONLY`)
  and `basedirs` to strip path prefixes from cache keys.
* Cargo's fingerprint includes the rustc version, profile, enabled and
  declared features, dependency hashes, RUSTFLAGS and the target source path
  relative to the workspace. Registry dependencies do not track source file
  mtimes. Whether vendored directory sources behave like registry sources
  here must be measured.

## Options

1. **Cold builds.** Every job compiles every dependency.
2. **Prewarmed target directory in the base image plus read only sccache.**
3. **sccache only.**

## Decision (proposed)

Option 2:

* The warmer compiles the warm set (default: the 150 most depended upon
  crates, from the dump's dependency graph) with `cargo check` and a full
  build inside a VM, at identical paths (`/cw/vendor/<name>-<version>`) to
  what jobs use.
* Its outputs (target directory, sccache directory, vendored sources) become
  read only images sealed with a BLAKE3 manifest signed by the warmer key.
* The base snapshot is taken from a **fresh clean boot** with those images
  attached, never from the VM that ran build scripts, so no memory state
  from executed crate code reaches job VMs.
* Only versions at least 14 days old that Crateward itself scored low risk
  enter the warm set.
* Jobs see the warm target directory through overlayfs with a per job
  writable upper layer; sccache runs with `SCCACHE_LOCAL_RW_MODE=READ_ONLY`.
* The warm set is rebuilt with the weekly image refresh and promoted only if
  the canaries pass.

## Consequences

* The benefit for `cargo check` depends on fingerprint reuse, not on
  sccache. M1.5 measures per job compile time and scratch usage for a
  representative sample of new versions, cold versus warm.
* The warm images cost memory: they live in the images tmpfs
  (`sandbox.images_tmpfs_mib`). Their size is budgeted and published in
  OPERATIONS.md.
* A compromised warm set version would affect later jobs. Age and verdict
  gating, clean boot snapshots and signed manifests reduce the risk; they do
  not remove it.

## Sources

* sccache `docs/Rust.md`, `docs/Local.md`, `docs/Configuration.md`
  (version 0.18), `https://github.com/mozilla/sccache`
* Cargo `src/cargo/core/compiler/fingerprint/mod.rs` module documentation,
  read from the published `cargo` 0.99.0 crate
* Firecracker `docs/snapshotting/snapshot-support.md` (snapshot uniqueness)
