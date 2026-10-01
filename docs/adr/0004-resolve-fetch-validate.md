# 0004: Resolve with Cargo, fetch and validate ourselves, never extract

* Status: Accepted
* Date: 2026-09-24

## Context

The fetch stage must hand later stages a crate's sources and every
dependency for every target, without running crate code and without
letting a hostile archive or manifest touch the host. Verified on the
server: `cargo generate-lockfile` succeeds with `RUSTC` pointing at a path
that does not exist, so resolution runs no compiler and no crate code; the
lockfile lists every package for every target with its SHA-256.

## Decision

1. **Resolve with Cargo, in a sandbox.** The fetcher writes a consumer
   probe that depends on exactly the version under analysis and runs
   `cargo generate-lockfile` in a child with its own user and network
   namespaces, resource limits and Landlock. Its only network path is a
   relay to an index proxy in the fetcher. As a registry dependency, the
   crate cannot ship configuration that Cargo reads.
2. **The index proxy** passes the sparse index through, except that it
   clears the yanked flag of the version under analysis: malware is often
   yanked quickly, and Cargo does not resolve yanked versions.
3. **Fetch locked crates ourselves** with the polite client, verifying the
   SHA-256 from the lockfile and the index.
4. **Validate, never extract.** Each archive streams through a validator in
   a sandboxed child without filesystem or network. It reports traversal,
   links, devices, special modes, duplicates, case collisions and paths
   outside `<name>-<version>/`, and aborts on decompression bombs. Findings
   are evidence, not errors.
5. **Store tar blobs**, zstd compressed and named by the BLAKE3 digest of
   the tar, verified on every read. Later stages read archives, never
   directories.

## Alternatives

* **`cargo vendor`**, as the specification suggested: it resolves,
  downloads and unpacks every dependency onto the host in one step.

## Consequences

* Static analysis parses entries straight from the tar stream, and the VM
  payload is built with `mkfs.erofs --tar`; no crate file is ever written
  to the host as a file.
* Dependencies are stored once and shared. First live run: 73 jobs, median
  113 locked packages each, 1,768 distinct crate files in 249 MB, about 2
  seconds per job once the store was warm.
* A version whose dependencies do not resolve is a result, recorded with
  the error, not a failure.

## Sources

* Cargo book, `reference/registry-index.md` and `reference/config.md`
* Experiments on the server, 2026-09-24
