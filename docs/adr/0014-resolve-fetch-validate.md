# 0014: Resolve with Cargo, fetch and validate ourselves, never extract

* Status: Accepted
* Date: 2026-09-24

## Context

The fetch stage must give later stages a crate's sources and every
dependency for every target, without executing crate code and without
letting a hostile archive or manifest touch the host. The specification
suggested `cargo vendor`. `cargo vendor` both resolves and downloads and
unpacks every dependency on the host.

Facts verified on the server on 2026-09-24:

* `cargo generate-lockfile` succeeds with `RUSTC` pointing at a path that
  does not exist: resolution invokes no compiler and no crate code.
* The lockfile lists every package for every target (for example
  `windows-sys` on a Linux host), each with its SHA-256.
* Crates.io downloads need the name exactly as published (`Inflector`);
  the lowercase form returns HTTP 403.

## Decision

1. **Resolve with Cargo, in a sandbox.** The fetcher writes a consumer
   probe package that depends on exactly the version under analysis, and
   runs `cargo generate-lockfile` in a child process with its own user and
   network namespaces, resource limits and a Landlock ruleset. The only
   network path is a loopback relay to an index proxy served by the
   fetcher. Because the crate is a registry dependency of the probe, Cargo
   never reads configuration shipped inside the crate.
2. **The index proxy** passes crates.io's sparse index through unchanged,
   except that it clears the yanked flag of the version under analysis
   (malware is often yanked quickly, and Cargo does not resolve yanked
   versions). It serves no downloads.
3. **Fetch locked crates ourselves.** The fetcher downloads every locked
   package with its polite client and verifies the SHA-256 from the
   lockfile (and from the index for the target).
4. **Validate, never extract.** Each archive is streamed through a
   validator in a sandboxed child with no filesystem and no network. It
   reports traversal, links, devices, special modes, duplicates, case
   collisions and paths outside `<name>-<version>/`, and aborts on
   decompression bombs. Findings are evidence, not errors. Nothing is
   ever unpacked onto the host filesystem.
5. **Store tar blobs.** Validated archives are stored as zstd compressed
   tar, named by the BLAKE3 digest of the tar, and verified on every read.
   Original `.crate` files of analyzed versions are kept as evidence.

## Consequences

* Downstream stages read archives, not directories: static analysis parses
  entries from the tar stream (M3), and the VM payload is built from tar
  with `mkfs.erofs --tar` (M4), which writes nothing to the host
  filesystem either.
* Dependencies are stored once and shared by all jobs. First live run: 73
  jobs, median 113 locked packages each, 1,768 distinct crate files in
  249 MB; about 2 seconds per job once the cache is warm.
* A crate whose dependencies do not resolve is a result (recorded with the
  error), not a failure.
* Resolution depends on the host's `ip` binary to bring loopback up inside
  the namespace, and on the pinned toolchain's `cargo`.

## Sources

* Cargo book, `reference/registry-index.md` and `reference/config.md`
  (source replacement, configuration discovery)
* Tests on the server, 2026-09-24 (`RUSTC` experiment, download casing)
