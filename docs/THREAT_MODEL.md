# Threat model

Crateward exists to run hostile code. The design assumes that a crate will
eventually try to escape, and aims for an escape to gain nothing: no
credentials, no internet, no persistence, no influence on later jobs.

Every mitigation below has a status. **Planned** means designed but not
built; **Built** means implemented; **Tested** means covered by an automated
test. Nothing is marked Built before the code exists.

## Assets

| ID | Asset | Why it matters |
|----|-------|----------------|
| A1 | Host integrity (kernel, services, keys) | A compromised host can forge every result and attack others. |
| A2 | Integrity of results and evidence | False negatives hide malware; false positives harm maintainers. |
| A3 | Confidentiality of undisclosed findings | Publishing early helps attackers and breaks coordinated disclosure. |
| A4 | Isolation between jobs | One crate must not influence the verdict of another. |
| A5 | Shared build cache and warm snapshot | Poisoning them would affect every later job. |
| A6 | Admin access: WireGuard keys, passkeys, SSH keys | Full control of the system. |
| A7 | Deploy key of the public site repository | Allows defacing crateward.com. |
| A8 | ntfy topic and healthchecks.io ping URL | Allow reading or forging alerts and heartbeats. |
| A9 | Availability of the pipeline | Crateward is only useful if it keeps up. |
| A10 | Reputation with crates.io | Violating the data access policy would get Crateward blocked. |

## Adversaries

| ID | Adversary | Capabilities |
|----|-----------|--------------|
| T1 | Malicious crate author | Arbitrary code in build scripts, proc macros and tests; full control of the guest once that code runs, including guest root through a guest kernel exploit; can try to detect the sandbox and stay dormant. |
| T2 | Malicious crate content aimed at the host | Archive bombs, path traversal, symlinks, device files, pathological source code for `syn` and YARA-X, huge dependency graphs, hostile `Cargo.toml` and `.cargo/config.toml`. |
| T3 | VM escape attacker | T1 plus exploits against the virtio device model, KVM, or CPU side channels. |
| T4 | Cache poisoner | T1 targeting the build cache or warm snapshot so that a later job trusts poisoned artifacts. |
| T5 | Network attacker or compromised CDN | Tampers with downloads from crates.io. |
| T6 | Compromised external service | GitHub Pages, ntfy.sh or healthchecks.io behaving maliciously. |
| T7 | Supply chain attack on Crateward itself | A malicious dependency of Crateward's own code. |
| T8 | Internet scanner | Probes the server's public address. |

## Trust boundaries

| ID | Boundary | Crossing |
|----|----------|----------|
| B1 | Guest to Firecracker | virtio block, net, vsock and rng devices; the serial console |
| B2 | Firecracker to host kernel | system calls, filtered by Firecracker's seccomp filters; the jailer's chroot, namespaces and cgroup |
| B3 | Guest agent to orchestrator | one length limited vsock stream |
| B4 | Guest network to fake internet | tap device, veth, nftables redirect |
| B5 | Crate archive to extraction and static analysis | untrusted bytes into sandboxed subprocesses |
| B6 | Warmer output to job VMs | read only images, sealed with a signed BLAKE3 manifest |
| B7 | Server to internet | allowlisted egress per service user; WireGuard inbound |
| B8 | Server to public site | one way push of a sanitized static export |
| B9 | Admin to control plane | WireGuard plus passkey |

## Mitigations

### Guest and VMM (T1, T3; B1, B2)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| Fresh microVM per job from a clean snapshot; never reused | Planned | M1 |
| Firecracker always started by the jailer: chroot, cgroup v2, new PID and network namespaces, distinct uid per slot | Planned | M1 |
| Firecracker's default seccomp filters; never `--no-seccomp` | Planned | M1 |
| Orchestrator unprivileged; root helper with a closed command set that accepts slot numbers, not paths | Planned | M1 |
| Hard limits: `cpu.max`, `memory.max`, `pids.max`, drive and net rate limiters, fixed size scratch, wall clock with `cgroup.kill` | Planned | M1 |
| SMT disabled (`nosmt`), L1D flush and current microcode against L1TF and MDS | Planned | M1 |
| KSM disabled, no swap, as the Firecracker production guide recommends | Planned | M1 |
| Guest kernel without module support, so guest root cannot load a rootkit module | Planned | M1 |
| Check that guest visible CPU mitigations match the host; the stock Debian 6.12 host kernel is outside Firecracker's validated matrix | Planned | M1 |
| Unexpected VM exits, Firecracker crashes and seccomp violations raise a sandbox escape indicator | Planned | M5 |
| Host honeytokens and integrity monitoring detect a successful escape | Planned | M7 |

### The single host channel (T1; B3)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| Host initiated vsock connection only; no host listener for guest initiated connections | Planned | M4 |
| Frames with a u32 length prefix, a 64 KiB frame cap and per job byte and frame budgets | Planned | M4 |
| Schema validated decoding with a version field; the decoder is a fuzz target | Planned | M4 |
| No host secret ever enters the guest; the guest agent does not link the host configuration harness | Built | M0 |

### Network (T1; B4)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| Per slot namespace whose only route leads to the fake internet namespace, which has no uplink | Planned | M4 |
| Host address, private ranges and metadata addresses dropped explicitly; IPv6 dropped and logged | Planned | M4 |
| Fake internet runs unprivileged; its DNS and HTTP parsers are fuzz targets | Planned | M4 |
| Tap capture on the host as ground truth, independent of the guest | Planned | M4 |

### Hostile content on the host (T2; B5)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| Crate names validated before use as paths or URLs | Tested | M0 |
| SHA-256 digests parsed as fixed size values and compared exactly | Tested | M0 |
| Checksum verified against the index before extraction | Planned | M2 |
| Extraction in a sandboxed subprocess; reject traversal, links, devices and special files; cap size, count, depth and ratio | Planned | M2 |
| Vendoring through a generated consumer package, run from an empty directory with a fixed `CARGO_HOME`, so cargo never reads configuration shipped in the crate | Planned | M2 |
| Vendoring subprocess reaches only a local registry proxy | Planned | M2 |
| Static analysis in a separate process with rlimits, Landlock and seccomp | Planned | M3 |
| Guest disk images parsed on the host only in a sandboxed subprocess | Planned | M4 |
| No README or other crate text rendered as raw HTML; autoescaping templates; strict CSP | Planned | M6 |

### Cache poisoning (T4; B6)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| Cache and warm images mounted read only into job VMs; written only by the warmer | Planned | M1.5 |
| Warm snapshot taken from a fresh clean boot, never from the VM that ran build scripts | Planned | M1.5 |
| Warm set limited to versions at least 14 days old that Crateward scored low risk | Planned | M1.5 |
| Images sealed with a BLAKE3 manifest signed by the warmer key; verified on promotion and on every copy into tmpfs | Planned | M1.5 |
| Promotion gated on canaries; automatic rollback | Planned | M5 |

### Downloads (T5; B7)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| TLS to crates.io hosts; checksums from the index verified for every file | Planned | M2 |
| Repeated checksum mismatches open the fetch circuit breaker | Planned | M5 |
| Egress allowlisted per service user with nftables | Planned | M1 |

### External services and the public site (T6, T8; B7, B8, B9)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| No inbound service except WireGuard on one UDP port | Planned | M1 |
| Admin dashboard binds to the WireGuard address; configuration rejects all interfaces | Tested | M0 |
| Passkey authentication for the admin view | Planned | M6 |
| Alerts carry no crate names or details before disclosure; details stay behind WireGuard | Planned | M5 |
| ntfy topic of at least 32 random characters; configuration rejects shorter topics | Tested | M0 |
| Secrets redacted from `Debug` output and logs | Tested | M0 |
| Public site is a static export of aggregate statistics and disclosed findings only, pushed with a deploy key limited to one repository | Planned | M6 |

A compromised external service can deface the public site, suppress alerts or
forge them. It cannot reach the server or read undisclosed findings.

### Crateward's own supply chain (T7)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| `Cargo.lock` committed; every build uses `--locked` | Built | M0 |
| `cargo deny`, `cargo audit` and `cargo vet` in CI | Built | M0 |
| GitHub Actions pinned by commit SHA; workflow token read only | Built | M0 |
| `unsafe_code` denied workspace wide; forbidden in every package so far | Built | M0 |
| Vendored sources attached to signed releases; SBOM published | Planned | M8 |

### Integrity without ECC (A2)

| Mitigation | Status | Milestone |
|------------|--------|-----------|
| btrfs raid1 checksums with repair from the good copy | Planned | M1 |
| PostgreSQL data checksums | Planned | M2 |
| BLAKE3 manifests for images and evidence, verified on read | Planned | M1.5 |

## Residual risks

* A crate that detects the sandbox (VM artifacts, fake network, fresh uptime,
  snapshot clock skew) can stay dormant. Host side ground truth limits what
  an active crate can hide, not what a dormant crate never does.
* A zero day in KVM or the Firecracker device model could escape the VM. The
  jailer, seccomp and the unprivileged, air gapped slot namespace limit what
  such an escape reaches, but do not make it impossible.
* The host kernel (Debian 13 stock 6.12) is outside Firecracker's validated
  host kernel matrix. See [ADR 0007](adr/0007-ansible-on-debian.md).
* The CPU is old. Whether Intel still ships security microcode for 7th
  generation Core parts is not verified yet; M1 records the kernel's
  vulnerability report and the RUNBOOK tracks it.
* Without ECC, a memory error can corrupt a result in flight before any
  checksum covers it.
