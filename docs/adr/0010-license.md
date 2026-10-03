# 0010: MIT OR Apache-2.0, with GPL-2.0-only for the eBPF programs

* Status: Accepted
* Date: 2026-10-01

## Context

The repository is published as an open source project. Most Rust projects,
including the crates Crateward depends on, use `MIT OR Apache-2.0`. The
kernel lets LSM BPF programs call the helpers they need only when the
program declares a GPL compatible license, and aya follows the same split.
The guest agent does not link the eBPF programs: it reads the object from
`/usr/lib/crateward/guest-ebpf.o` at run time, so they stay a separate work.

## Decision

The workspace is `MIT OR Apache-2.0`. `crateward_guest_ebpf` is
`GPL-2.0-only`.

## Alternatives

* **`MIT OR GPL-2.0` for the eBPF programs:** also accepted by the kernel,
  with no gain for users.
* **A copyleft license for everything** (GPL-3.0 or AGPL-3.0): keeps the
  code out of most company codebases and away from the ecosystem's
  conventions.

## Consequences

* The workspace `Cargo.toml` sets `license` once. `crates/guest_ebpf` and
  `fuzz` set theirs. Release bundles carry all three license texts.
* Contributions come under the same terms (Apache-2.0, section 5).
* The eBPF object must stay separate. Linking it into the agent would mix
  the licenses. Packages remain `publish = false`.

## Sources

* `crates/guest_ebpf/Cargo.toml` and the `license` section in
  `crates/guest_ebpf/src/main.rs`
* Linux `Documentation/bpf/bpf_licensing.rst`
