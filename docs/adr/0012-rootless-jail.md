# 0012: A rootless jail instead of Firecracker's jailer

* Status: Accepted (maintainer decision, 2026-09-24)
* Date: 2026-09-24
* Supersedes the jailer and root helper parts of
  [ADR 0002](0002-firecracker-over-cloud-hypervisor-and-cratera.md).

## Context

Firecracker's documentation says that in production Firecracker "should be
started only via the jailer binary". The jailer must run as root: it creates
device nodes, changes root and switches user. The original plan (ADR 0002)
therefore had a small root helper start the jailer on the orchestrator's
behalf. That puts a root process one socket away from the orchestrator, and
every change to it needs the maintainer's review before it can be tested.

On the production server, an unprivileged process that is mapped to a
subordinate UID with `newuidmap` keeps its supplementary groups as long as
it never calls `setgroups`, and can therefore still open `/dev/kvm`
(verified on 2026-09-24).

## Options

1. **Firecracker's jailer, started by a root helper.** The vendor's
   documented path; a root daemon we write and maintain.
2. **A rootless jail** built from unprivileged user namespaces, doing the
   jailer's job without root.

## Decision

Option 2. `crateward-vmjail`, a single threaded launcher, builds one jail
per VM and then executes Firecracker (`crateward_orchestrator::jail`).

| Jailer duty | Rootless jail |
|-------------|---------------|
| Distinct UID per VM | inside UID 1 maps to the slot's own subordinate UID through `newuidmap`; no two slots share one |
| Drop privileges | switching every UID from 0 to 1 clears the capability sets; `no_new_privs` is set before `exec` |
| chroot with only the needed files | new mount namespace, bind mounts of exactly the kernel, images and device nodes, `pivot_root`, old root detached; no `/proc` inside |
| `mknod` of `/dev/kvm` and `/dev/net/tun` | bind mounts of the host device nodes |
| cgroups | the launcher joins the slot's cgroup in the orchestrator's delegated subtree before anything else |
| Network namespace | a new network namespace owned by the jail's user namespace, with the slot's tap device created inside |
| Resource limits | `RLIMIT_NOFILE` and `RLIMIT_FSIZE` set before `exec` |
| Clean environment | environment cleared; only the log, `/dev/null` and the control pipe exist at `exec` time |
| Seccomp | unchanged: Firecracker installs its own filter |

The integration tests check the result from the host on every run: the
Firecracker process has the slot's UID, `CapEff` and `CapPrm` are zero,
`NoNewPrivs` is 1, `Seccomp` is 2 (filter), and the tap device does not
exist in the host's network namespace.

## Consequences

* No process on the host runs as root for the sandbox. The only privileged
  pieces are the distribution's `newuidmap` and `newgidmap` helpers and the
  one time host configuration (subordinate ID ranges, `kvm` group, cgroup
  delegation), all done by Ansible.
* Namespaces and tap devices belong to the Firecracker process and vanish
  with it, so they cannot leak; only the slot directory and the cgroup
  need cleanup.
* Unprivileged user namespaces must stay enabled on the host (the Debian
  default). That exposes more kernel code to every local user, so every
  other Crateward service runs with systemd's `RestrictNamespaces=yes`.
* Firecracker keeps the orchestrator user's supplementary groups. That user
  must have `kvm` as its only supplementary group; on the development
  account this is not the case (it is also in `systemd-journal`).
* This departs from Firecracker's documented production path. The table
  above is the contract, and each row that can be checked from the host is
  checked by a test. The departure is revisited if Firecracker adds a
  rootless mode or the kernel restricts unprivileged user namespaces.
* `crateward_core::sandbox` wraps `unshare(2)` in the project's only
  `unsafe` block, documented and limited to flags that exclude
  `CLONE_FILES`.

## Sources

* Firecracker `docs/jailer.md` and `docs/prod-host-setup.md` (v1.17.0)
* `user_namespaces(7)`, `unshare(2)`, `pivot_root(2)`, `newuidmap(1)`,
  `capabilities(7)` (effect of changing UIDs from 0 to non zero)
* Kernel `include/uapi/linux/posix_acl_xattr.h` (ACL format used for the
  slot root directory)
