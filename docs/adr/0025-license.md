# 0025: MIT OR Apache-2.0, with GPL-2.0-only for the eBPF programs

* Status: Accepted
* Date: `2026-10-01`

## Context

Until now only `crateward_guest_ebpf` had a license (ADR 0017); everything
else was all rights reserved, so nobody could use or contribute to the
code. The maintainer is publishing the repository as an open source
project.

* Most Rust projects, including the Rust compiler and the crates Crateward
  depends on, use `MIT OR Apache-2.0`. Users pick either; Apache-2.0 adds
  an explicit patent grant, MIT keeps compatibility with GPL-2.0 projects.
* The kernel lets LSM BPF programs call the helpers they need only when the
  program declares a GPL compatible license (ADR 0006). aya, which loads
  the programs, follows the same split: userspace code under permissive
  licenses, eBPF programs under a GPL compatible one.
* The guest agent does not link the eBPF programs. It reads the compiled
  object from `/usr/lib/crateward/guest-ebpf.o` at run time and hands it to
  the kernel, so the programs stay a separate work.

## Options

* **`MIT OR Apache-2.0` for the workspace, `GPL-2.0-only` for the eBPF
  programs.** The ecosystem default, plus what the kernel requires.
* **`MIT OR Apache-2.0` everywhere, with `MIT OR GPL-2.0` for the eBPF
  programs.** Also accepted by the kernel, but it changes a license that
  ADR 0017 already chose, for no gain to users.
* **A copyleft license for everything (GPL-3.0 or AGPL-3.0).** Forces
  changes to a hosted scanner to be shared, but keeps the project out of
  most company codebases and away from the ecosystem's conventions.

## Decision

The workspace is `MIT OR Apache-2.0`. `crateward_guest_ebpf` stays
`GPL-2.0-only`. This supersedes the sentence in ADR 0017 that the rest of
the project stays unlicensed.

## Consequences

* The workspace `Cargo.toml` sets `license` once, and every member
  inherits it; `crates/guest_ebpf` and `fuzz` set theirs directly. The
  release SBOM lists the license of each package.
* `LICENSE-MIT` and `LICENSE-APACHE` are at the root; the GPL text is in
  `crates/guest_ebpf/LICENSE`.
* Contributions are accepted under the same terms, as Apache-2.0 section 5
  provides: the README says so.
* The eBPF programs must stay a separate object loaded at run time. Linking
  them into the guest agent would mix the licenses.
* Packages are still `publish = false`. Publishing any of them to crates.io
  is a separate decision.

## Sources

* `crates/guest_ebpf/Cargo.toml` and `crates/guest_ebpf/src/main.rs`, the
  `license` section the kernel reads.
* `crates/guest_agent/src/trace.rs`, `OBJECT_PATH`: the object is read at
  run time.
* ADR 0006 and ADR 0017, with the kernel's BPF licensing documentation
  cited there.
