# 0016: Dynamic runs with payload images, a fake internet per slot and honeytokens

* Status: Accepted
* Date: 2026-09-25

## Context

M4 turns a job that triage marked dynamic into a `cargo check` inside a
microVM restored from the base snapshot, and records what the build did.
The job's code must see a normal developer machine: sources, a toolchain,
credentials worth stealing and an internet to talk to. None of it may be
real, and the host must learn what the code did even if the guest lies.

Facts verified on the server on 2026-09-25:

* Firecracker 1.17 cannot add devices after a snapshot restore. Its
  documentation for `PATCH /drives` describes exactly the pattern needed:
  a placeholder drive at boot, replaced after restore, with a virtio
  reconfiguration that tells the guest the new size.
* `mkfs.erofs --tar=f` (`erofs-utils` 1.8.6) reads a tar from stdin and
  creates missing parent directories. It writes past 1 TiB (sparse) while
  building even a one file image, so `RLIMIT_FSIZE` cannot bound it.
* In an unprivileged user and network namespace, `ip tuntap add` and an
  nftables `redirect` rule work without host root.
* A jail has no `/dev/null` and no dynamic loader: everything started in
  one must be static and must not open `/dev/null` by path.
* On 76 live jobs, a restore to a ready agent took 70 to 110 ms and a
  `cargo check` 17 to 160 s. One build script (`zwo-eaf-sys`) resolved
  `github.com` and opened a TLS connection with that server name to fetch
  an SDK; the fake internet recorded both.

## Decision

1. **Payload image.** The orchestrator writes a tar from the blob store
   with its own headers (root owned, fixed modes, time zero): the consumer
   probe from the fetch stage (ADR 0014) with its lockfile, a
   `.cargo/config.toml` that replaces crates.io with `/cw/vendor` and sets
   `offline`, and every locked crate with a `.cargo-checksum.json` whose
   `package` matches the lockfile. A crate's own checksum file is dropped.
   The tar streams into `mkfs.erofs` in a sandboxed child (no network,
   Landlock limited to system directories and the output directory). No
   crate archive is extracted on the host.
2. **Drives by fixed path.** The base snapshot is booted with placeholder
   drives `payload` and `scratch` at fixed paths in the jail. A restore
   binds the job's files to those paths and sends `PATCH /drives` for both
   before the agent is asked to mount anything. The scratch disk is a
   sparse ext4 image on tmpfs, formatted on the host and writable only by
   the slot's UID (POSIX ACL).
3. **Workspace message.** Protocol version 2 adds `Prepare`: mounts
   (`/dev/vd[b-z]`, `erofs` or `ext4`, the payload `noexec`), directories
   and files, all with absolute plain paths the agent checks. It runs after
   restore, so nothing job specific is in the snapshot.
4. **Honeytokens.** Every job gets fresh values in the places stealers
   read: `~/.cargo/credentials.toml`, `~/.ssh/id_ed25519`,
   `~/.aws/credentials`, `~/.git-credentials` and `GITHUB_TOKEN`. The
   formats pass the usual format checks; none is valid anywhere. Values are
   stored per job (`job_honeytokens`, unique), so a value found anywhere
   names the job that took it.
5. **A fake internet per slot.** The jail launcher gives the tap device
   `10.0.2.1/30`, loads nftables rules that redirect all DNS, TCP and UDP
   from the tap to three local ports, and starts `crateward_fake_internet`
   as the slot's user with Landlock (no filesystem) and resource limits.
   DNS answers every `A` question with the sink, HTTP gets a 404, TLS is
   logged by its server name, and the first 64 KiB of every connection and
   datagram go to a JSON lines log that the orchestrator owns. The guest's
   resolver is pinned to `10.0.2.1` in the image.
6. **Host side ground truth.** After the run, the orchestrator reads that
   log, summarizes names and connections, and searches every captured byte
   and every DNS name for the job's honeytokens. Because the tap is the
   only way out of the VM, a guest that controls its own kernel still
   cannot send anything without it appearing in the log.
7. **Guest image.** The Rust toolchain of `rust-toolchain.toml`, verified
   by the SHA-256 in its signed channel manifest, plus the build tools and
   headers that build scripts commonly expect, including `curl` and `wget`
   so that a downloader tries and is recorded.

## Consequences

* A canary test (`cargo xtask canary`) runs a fixture crate whose build
  script steals the cargo token and posts it to a made up host. It must be
  caught end to end. Its source lives only in the test file and runs only
  inside the microVM.
* HTTPS content is invisible until TLS is terminated with a certificate
  authority baked into the guest image; a token sent over HTTPS is seen
  only as a connection with a server name. Planned next.
* The fake internet runs as the slot's user, like Firecracker. A guest
  that compromises it gains nothing it could not reach by escaping
  Firecracker, and the network namespace has no uplink either way.
* eBPF tracing inside the guest (ADR 0006) waits for a license decision:
  its programs must carry a GPL compatible license.

## Sources

* Firecracker v1.17.0 `docs/api_requests/patch-block.md` and
  `src/firecracker/swagger/firecracker.yaml` (`PartialDrive`,
  `NetworkInterface`, `SnapshotLoadParams`).
* `mkfs.erofs(1)` from `erofs-utils` 1.8.6 (`--tar=f`).
* `nft(8)`, redirect statement; Linux `ip(8)` `tuntap`.
* Linux `Documentation/admin-guide/nfs/nfsroot.rst` (the `ip=` kernel
  parameter).
* Rust release channel manifest `dist/channel-rust-1.98.1.toml` and its
  signature, `https://static.rust-lang.org/`.
