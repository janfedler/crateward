# 0002: Firecracker directly, not Cloud Hypervisor or cratera

* Status: Accepted
* Date: 2026-09-24

## Context

Crateward executes code that must be assumed hostile, many times per hour,
on one server. The virtual machine monitor is the most important security
boundary in the system. It also needs fast, repeatable starts (snapshot
restore), a network device (the fake internet needs one), a vsock channel,
and per VM resource limits.

## Options

1. **Firecracker**, driven directly through its API socket and jailer.
2. **Cloud Hypervisor**, a Rust VMM built on the same `rust-vmm` crates.
3. **cratera**, a Rust code execution engine built on Firecracker.
4. Containers or gVisor. Rejected early: a shared host kernel is exactly
   the attack surface a hostile build script would target.

## Decision

Option 1. Crateward uses Firecracker 1.17 directly, always started through
the jailer, behind a `VmBackend` trait so that another VMM can be added later.
cratera is used as a reading reference for jailer and snapshot handling only.

## Rationale

* **Threat model fit.** Firecracker's design document states that "all vCPU
  threads are considered to be running malicious code as soon as they have
  been started" and describes nested trust zones separated by barriers. That
  is Crateward's threat model.
* **Small device model.** Firecracker offers virtio block, net, vsock, rng,
  balloon and pmem, a serial console and a partial i8042 for reset. Cloud
  Hypervisor's objectives include CPU, memory and PCI hotplug and machine to
  machine migration, and its device model adds VFIO, virtio IOMMU and
  several vhost user devices. Crateward needs none of those, and every
  device is attack surface.
* **Jailer.** Firecracker ships a jailer that builds a chroot, creates
  cgroups, unshares a mount namespace, optionally joins a prepared network
  namespace and creates a PID namespace, applies resource limits and drops
  privileges before starting the VMM. Cloud Hypervisor sandboxes itself with seccomp and
  Landlock, which is good, but the jailer's namespaces and cgroups match the
  per slot isolation Crateward needs.
* **Snapshots.** Full snapshots are generally available; restore supports
  `network_overrides` and `vsock_override`, which per slot isolation needs.
* **cratera** makes fixed choices that conflict with Crateward: guests have
  no network device at all (Crateward needs a tap device to observe network
  behavior through the fake internet), and its coordinator runs as root to
  manage KVM and the jailer. Crateward confines root to a small helper with a
  closed command set.

## Consequences

* Windows guests, which Cloud Hypervisor supports, stay out of reach; they
  are a non goal anyway.
* Crateward owns the jailer integration, the snapshot lifecycle and cleanup,
  and must test them on real hardware (milestone M1).
* Firecracker validates specific host and guest kernels only; see
  [ADR 0007](0007-ansible-on-debian.md) for the consequence of running a
  different host kernel.

## Sources

* Firecracker `docs/design.md` (threat containment, device model),
  `docs/jailer.md`, `docs/snapshotting/snapshot-support.md`,
  `docs/prod-host-setup.md`, `src/firecracker/swagger/firecracker.yaml`,
  `CHANGELOG.md` (1.17.0), `https://github.com/firecracker-microvm/firecracker`
* Cloud Hypervisor `README.md` (objectives, guest OS support),
  `docs/device_model.md`, `docs/landlock.md`,
  `https://github.com/cloud-hypervisor/cloud-hypervisor`
* cratera `README.md`, `https://github.com/cratera-project/cratera`
