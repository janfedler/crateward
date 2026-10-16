# 0002: Firecracker microVMs in a rootless jail

* Status: Accepted
* Date: 2026-09-24, updated 2026-10-16

## Context

Crateward runs code that must be assumed hostile, many times per hour, on
one server. The virtual machine monitor is the most important security
boundary. It needs fast restores from a snapshot, a network device for the
fake internet, a vsock channel and per VM limits. The server's CPU is
affected by L1TF and MDS, and its memory has no ECC.

## Decision

1. **Firecracker**, behind a `VmBackend` trait. Its design assumes that
   "all vCPU threads are considered to be running malicious code", and its
   device model is small: virtio block, net, vsock and rng, a serial
   console, nothing hot pluggable.
2. **A rootless jail** (`crateward-vmjail`) does the jailer's job without
   root, one jail per VM:
   * The slot's own subordinate UID through `newuidmap`. Switching every
     UID away from 0 clears the capabilities, and `no_new_privs` is set.
   * A new mount namespace with bind mounts of exactly the kernel, the
     images and the device nodes, then `pivot_root`, no `/proc`. The root
     itself stays writable for Firecracker's sockets and snapshots, but is
     `nosuid`, `nodev` and `noexec`.
   * The slot's cgroup in the orchestrator's delegated subtree.
   * A network namespace owned by the jail, with the tap device inside.
   * A PID namespace in which Firecracker is PID 1. The launcher's first
     stage waits outside it without privileges, and the jail dies with it.
   * Only stdin, stdout and stderr cross `exec`. The launcher refuses to
     start Firecracker if any other descriptor lacks close on exec.
   * Resource limits and an empty environment. Firecracker's own seccomp
     filter stays.
   Tests check from the host on every run: the slot's UID, `CapEff` and
   `CapPrm` zero, `NoNewPrivs` 1, `Seccomp` 2, Firecracker as PID 1 of its
   namespace, no tap device in the host's namespace, and that killing the
   launcher kills Firecracker.
3. **SMT off** (`nosmt`, `mds=full,nosmt`, `l1tf=full,force`): one core
   for the host and the others for VM slots of one vCPU each. **Hot path in
   RAM:** images, the snapshot and the scratch disks live in tmpfs, copied
   from the disk and verified with BLAKE3.
4. **Guest kernel** from a pinned commit of Amazon Linux's
   `amazon-6.18.y/mainline` branch, the line Firecracker's configuration
   comes from, with that configuration vendored unchanged and Crateward's
   changes in a fragment that `cargo xtask guest-kernel` checks line by
   line.
5. **Guest versions.** Each release installs its kernel, root filesystem
   and TLS authority under `/usr/local/lib/crateward/guest/<digest>/`, with
   `current` and `previous` links. The orchestrator resolves them once at
   start and runs the canaries before any job. `./install.sh rollback`
   swaps the links. The image is refreshed weekly by routine
   (`cargo xtask bump-debian-snapshot`, rebuild, canary, release).

## Alternatives

* **Cloud Hypervisor:** a larger device model (hotplug, VFIO, vhost user)
  that Crateward does not need. Every device is attack surface.
* **cratera:** guests have no network device, and its coordinator runs as
  root.
* **Containers or gVisor:** a shared host kernel is exactly what a hostile
  build script would attack.
* **Firecracker's jailer**, the documented production path: it must run
  as root, so a root helper would sit one socket away from the
  orchestrator.
* **The newest public Amazon Linux kernel tag** (6.18.25, 28 stable
  releases behind) or **upstream 6.18** (outside what Firecracker
  validates) for the guest.
* **SMT on:** with L1TF and MDS, a guest on a sibling thread could read the
  host's or another guest's data.

## Consequences

* No process runs as root for the sandbox. Namespaces and tap devices die
  with the Firecracker process. Only the slot directory and cgroup need
  cleanup.
* Unprivileged user namespaces must stay enabled, so every other service
  runs with `RestrictNamespaces=yes`. `crateward_core::sandbox` holds the
  project's only `unsafe` code.
* Leaving the documented jailer path makes the checks above the contract.
  Revisit it if Firecracker gains a rootless mode.
* SMT off halves throughput. Most versions end up static only, with the
  reason on their label. A power loss empties the tmpfs, which is rebuilt
  from the verified copies.
* Measured: boot to a ready agent in about 430 ms. Restore into a new jail
  in 60 to 68 ms at the median.

## Sources

* Firecracker v1.17.0: `docs/design.md`, `docs/jailer.md`,
  `docs/prod-host-setup.md`, `docs/kernel-policy.md`,
  `docs/snapshotting/snapshot-support.md`
* Cloud Hypervisor `README.md` and cratera `README.md`
* `user_namespaces(7)`, `newuidmap(1)`, `capabilities(7)`, `pivot_root(2)`
* Linux `Documentation/admin-guide/hw-vuln/l1tf.rst` and `mds.rst`
* Tags and branches of `https://github.com/amazonlinux/linux`
