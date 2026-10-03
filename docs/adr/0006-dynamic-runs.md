# 0006: Dynamic runs with a fake internet, honeytokens and host side ground truth

* Status: Accepted
* Date: 2026-09-25

## Context

A job that triage marks dynamic gets a `cargo check` in a microVM restored
from the base snapshot. Its code must see a normal developer machine:
sources, a toolchain, credentials worth stealing and an internet to talk to.
None of it may be real, and the host must learn what the code did even if
the guest lies. Compiling the same popular dependencies in every cold VM
dominates the run time.

## Decision

1. **Payload image.** The orchestrator writes a tar from the blob store
   with its own headers: the consumer probe and lockfile from the fetch
   stage, a `.cargo/config.toml` that points crates.io at `/cw/vendor`
   offline, and every locked crate. A sandboxed `mkfs.erofs --tar` turns it
   into an image. Nothing is extracted on the host.
2. **Drives by fixed path.** The base snapshot boots with placeholder
   drives. Each restore binds the job's payload and scratch images there
   and sends `PATCH /drives`, so nothing job specific is in the snapshot.
3. **Honeytokens.** Every job gets fresh values where stealers look: cargo
   credentials, an SSH key, AWS credentials, git credentials and
   `GITHUB_TOKEN`. They pass format checks, are valid nowhere, and are
   stored per job, so a value found anywhere names its job.
4. **A fake internet per slot.** nftables in the slot's namespace redirects
   all DNS, TCP and UDP from the tap device to `crateward_fake_internet`,
   which answers DNS, HTTP and HTTPS. TLS is terminated with the
   installation's own authority, which the guest image trusts, so the plain
   text is logged. Every other frame (IPv6, ICMP, raw Ethernet) is captured
   from a packet socket. The tap is the only way out, so a guest that owns
   its kernel still cannot send anything unlogged.
5. **Scratch disk scan.** After the run, a sandboxed child reads the
   scratch image with `ext4-view`, never mounting it, and reports files
   outside the build, executables, set ID files, devices, links leaving the
   disk, and honeytokens copied anywhere.
6. **Warm build cache.** At start the orchestrator replays recent jobs'
   builds with the crate under analysis replaced by an empty stub, in a VM
   analyzed like any job, and packs `/target` into a read only image that
   later jobs mount under an overlay. Only dependencies locked by several
   jobs, stored for two weeks and without high severity findings go in, and
   a promotion check must pass first. No job runs yet, so the warm build's
   VM gets the vCPUs of every slot and as much memory as the slots would
   use, from its own base snapshot that is deleted afterwards. Each replay
   may take as long as a job's `cargo check`. One that takes longer is
   ended and named in the log, and the others continue.

## Alternatives

* **Real network access, filtered:** a downloader would reach its payload
  server, and nothing would prove what it sent.
* **sccache:** does not cache `cargo check`, which emits no `link` output.
* **Mounting the scratch disk on the host:** puts the kernel's filesystem
  code in front of a disk the guest wrote.

## Consequences

* The canary (`cargo xtask canary`) runs a fixture crate whose build script
  posts the cargo token over HTTP and has `curl` post AWS credentials over
  HTTPS. Both must be caught end to end.
* Clients with their own root list (`webpki-roots`) or pinned certificates
  refuse the fake certificates. Their server names are still logged.
* The TLS authority differs per installation and is part of the release
  bundle, so bundles must not be published.
* The warm cache cut total run time by 28 percent on 125 live jobs (median
  run from 53 s to 29 s). A compromised version inside it would affect
  later jobs. The gates reduce that risk, they do not remove it.

## Sources

* Firecracker v1.17.0 `docs/api_requests/patch-block.md`
* `mkfs.erofs(1)` (`--tar=f`), `nft(8)`, `packet(7)`
* `ext4-view` 1.0 `README.md`, `https://github.com/nicholasbishop/ext4-view-rs`
* sccache `docs/Rust.md` and Cargo `fingerprint/mod.rs` module documentation
