# Threat model

Crateward exists to run hostile code. The design assumes that a crate will
eventually try to escape, and aims for an escape to gain nothing: no
credentials, no internet, no persistence, no influence on later jobs.

Every mitigation below has a status. **Built** means implemented. **Tested** means covered by an automated
test. Nothing is marked Built before the code exists.

## Assets

| ID | Asset | Why it matters |
|----|-------|----------------|
| A1 | Host integrity (kernel, services, keys) | A compromised host can forge every result and attack others. |
| A2 | Integrity of results and evidence | False negatives hide malware. False positives harm maintainers. |
| A3 | Confidentiality of undisclosed findings | Publishing early helps attackers and breaks coordinated disclosure. |
| A4 | Isolation between jobs | One crate must not influence the verdict of another. |
| A5 | Shared build cache and warm snapshot | Poisoning them would affect every later job. |
| A6 | Admin access: SSH keys | Full control of the system. |
| A7 | Deploy key of the public site repository | Allows defacing crateward.com. |
| A8 | ntfy topic | Allows reading or forging alerts. |
| A9 | Availability of the pipeline | Crateward is only useful if it keeps up. |
| A10 | Reputation with crates.io | Violating the data access policy would get Crateward blocked. |

## Adversaries

| ID | Adversary | Capabilities |
|----|-----------|--------------|
| T1 | Malicious crate author | Arbitrary code in build scripts, proc macros and tests. Full control of the guest once that code runs, including guest root through a guest kernel exploit. Can try to detect the sandbox and stay dormant. |
| T2 | Malicious crate content aimed at the host | Archive bombs, path traversal, symlinks, device files, pathological source code for `syn` and YARA-X, huge dependency graphs, hostile `Cargo.toml` and `.cargo/config.toml`. |
| T3 | VM escape attacker | T1 plus exploits against the virtio device model, KVM, or CPU side channels. |
| T4 | Cache poisoner | T1 targeting the build cache or warm snapshot so that a later job trusts poisoned artifacts. |
| T5 | Network attacker or compromised CDN | Tampers with downloads from crates.io. |
| T6 | Compromised external service | GitHub Pages or ntfy.sh behaving maliciously. |
| T7 | Supply chain attack on Crateward itself | A malicious dependency of Crateward's own code. |
| T8 | Internet scanner | Probes the server's public address. |

## Trust boundaries

| ID | Boundary | Crossing |
|----|----------|----------|
| B1 | Guest to Firecracker | virtio block, net, vsock and rng devices, and the serial console |
| B2 | Firecracker to host kernel | system calls, filtered by Firecracker's seccomp filters, and the rootless jail's namespaces, `pivot_root`, cgroup and distinct UID |
| B3 | Guest agent to orchestrator | one length limited vsock stream |
| B4 | Guest network to fake internet | tap device and nftables redirect in the slot's network namespace |
| B5 | Crate archive to validation and static analysis | untrusted bytes into sandboxed subprocesses |
| B6 | Warm build output to job VMs | read only images named by their BLAKE3 digest, built and used within one orchestrator process |
| B7 | Server to internet | allowlisted egress per service user, and SSH inbound |
| B8 | Server to public site | one way push of a sanitized static export |
| B9 | Admin to control plane | SSH. The dashboard listens on loopback only and is reached through an SSH tunnel |

## Mitigations

### Guest and VMM (T1, T3, B1, B2)

| Mitigation | Status |
|------------|--------|
| Fresh microVM per job from a clean snapshot. Never reused | Built |
| Firecracker always started in the rootless jail: distinct subordinate UID per slot, mount, network, IPC, UTS and PID namespaces, only stdio inherited, `pivot_root` with only the needed files, no capabilities, `no_new_privs` ([ADR 0002](adr/0002-firecracker-rootless-jail.md)) | Tested |
| Firecracker's default seccomp filters. Never `--no-seccomp` | Tested |
| No process runs as root for the sandbox. The orchestrator and the launcher are unprivileged | Built |
| Serial console output rate limited, since it carries guest controlled text into the host log | Built |
| Per slot cgroup: `cpu.max`, `memory.max`, `memory.swap.max` 0, `pids.max`. Host side wall clock that ends a slot with `cgroup.kill` | Tested |
| Fixed size scratch disk per job: a sparse ext4 image on tmpfs, writable only by the slot's UID, deleted after the run ([ADR 0006](adr/0006-dynamic-runs.md)) | Built |
| Drive and network rate limiters: 256 MiB/s and 50,000 operations per second per drive, 4 MiB/s and 2000 packets per second on the network | Built |
| SMT disabled (`nosmt`), L1D flush and current microcode against L1TF and MDS | Built (verified on the host) |
| KSM disabled, no swap, as the Firecracker production guide recommends | Built |
| Nested virtualization disabled in the host's KVM (`kvm_intel.nested=0`, `kvm_amd.nested=0`), so its emulation of VMX and SVM is not reachable from a compromised guest kernel | Built (applied by the maintainer with `deploy/ansible`) |
| Guest kernel without module support (`CONFIG_MODULES` off), so guest root cannot load a rootkit module | Built |
| Check that guest visible CPU mitigations are not weaker than the host's. The stock Debian 6.12 host kernel is outside Firecracker's validated matrix | Tested |
| Startup reconciliation removes slot cgroups and directories left by a crash. Namespaces and tap devices cannot outlive their process | Tested |
| eBPF programs loaded at boot trace every process of the job, its file opens, socket destinations and tamper attempts (`bpf`, `ptrace`, `mount`). A base snapshot is refused when tracing does not start ([ADR 0007](adr/0007-guest-agent-ebpf.md)) | Tested (canary) |
| The trace is the guest's account and can be blinded by guest root. It is read next to host ground truth, and a trace without its closing totals is marked incomplete | Built |
| Firecracker exits after a forbidden system call or a fatal signal quarantine the pipeline and raise a sandbox escape indicator. A guest that stops itself is a result, never retried, so it cannot pause the sandbox stage ([ADR 0008](adr/0008-autonomy-and-escape-detection.md)) | Tested |
| Escape tripwires: a decoy in every jail root whose access time shows a read, decoys on the host watched with inotify, processes with a slot UID that the jail did not start, and a BLAKE3 manifest of the binaries and images the sandbox trusts. Any finding quarantines the pipeline ([ADR 0008](adr/0008-autonomy-and-escape-detection.md)) | Tested |

### The single host channel (T1, B3)

| Mitigation | Status |
|------------|--------|
| Host initiated vsock connection only. No host listener for guest initiated connections | Built |
| Frames with a u32 length prefix, a 64 KiB frame cap and per job byte and frame budgets | Tested |
| Schema validated decoding with a version field | Tested |
| The decoder and the trace records as fuzz targets (`fuzz/`, run before every release) | Built |
| Workspace paths checked by the agent: absolute, no `..`, only the job's drives, the payload mounted `noexec` | Tested |
| No host secret ever enters the guest. The guest agent does not link the host configuration harness | Built |
| Trace events from the guest are bounded on the host (processes, list entries, string lengths) and rendered with control and bidirectional characters escaped | Tested |

### Network (T1, B4)

| Mitigation | Status |
|------------|--------|
| Per slot network namespace with only the tap device and the fake internet. No uplink and no route out ([ADR 0006](adr/0006-dynamic-runs.md)) | Built |
| Every guest DNS query, TCP connection and UDP datagram redirected to the fake internet by nftables in the slot namespace. Nothing else is reachable | Built |
| Frames no proxy sees (IPv6, ICMP, other protocols, raw Ethernet) logged by a packet socket on the tap, opened before the fake internet drops to the slot user. IPv6 attempts also appear in the eBPF trace ([ADR 0006](adr/0006-dynamic-runs.md)) | Tested (canary) |
| Fake internet runs as the slot's user with Landlock (no filesystem) and rlimits. Its DNS, HTTP and TLS parsers are property tested | Tested |
| The fake internet's DNS parser and protocol sniffer as fuzz targets | Built |
| The fake internet's log (every DNS query, connection and datagram with its first 64 KiB) is owned by the orchestrator and read after the run as ground truth. The job's honeytokens are searched in it | Tested (canary) |
| TLS terminated with Crateward's own authority, which the guest image trusts, so HTTPS content is visible. The private key reaches the fake internet only through a pipe | Tested (canary) |

### Hostile content on the host (T2, B5)

| Mitigation | Status |
|------------|--------|
| Crate names validated before use as paths or URLs | Tested |
| Every name, version and checksum from crates.io parsed into typed values. Parsers property tested | Tested |
| SHA-256 digests parsed as fixed size values and compared exactly | Tested |
| SHA-256 verified against the index or lockfile for every crate file | Built |
| Archives never extracted on the host. Validated in a sandboxed child (no filesystem, no network, rlimits). Traversal, links, devices, special modes and case collisions reported. Bombs aborted ([ADR 0004](adr/0004-resolve-fetch-validate.md)) | Tested |
| Resolution through a generated consumer probe, so cargo never reads configuration shipped in the crate. `RUSTC` points nowhere, so nothing compiles | Built |
| Resolution child: own user and network namespaces, only a loopback relay to the fetcher's index proxy, Landlock, rlimits | Built |
| Static analysis in a sandboxed child: own user and network namespaces, rlimits, no filesystem access (Landlock) ([ADR 0005](adr/0005-static-analysis-and-triage.md)) | Tested |
| Evidence escapes control, bidi and invisible characters, so stored and displayed findings cannot hide code (Trojan Source) | Tested |
| Payload images written from the blob store with Crateward's own tar headers and built by `mkfs.erofs` in a sandboxed child. No crate archive is extracted on the host | Built |
| Guest disk images parsed on the host only in a sandboxed subprocess: the scratch disk is read with `ext4-view` in a child without network or filesystem access, with bounded walks ([ADR 0006](adr/0006-dynamic-runs.md)) | Tested (canary) |
| Host parsers of hostile input as fuzz targets: archives, static analysis, Rust sources, manifests, lockfiles, index lines, the RSS feed, the scratch disk, BTF. The scratch disk target found a superblock that made `ext4-view` reserve 8 GiB. Its geometry is now checked against the image first | Tested |
| No README or other crate text rendered as raw HTML: autoescaping templates and a strict CSP | Tested |

### Cache poisoning (T4, B6)

| Mitigation | Status |
|------------|--------|
| The warm image is mounted read only under each job's own writable overlay layer. Only the warm build writes it, packed from its scratch disk by sandboxed children without mounting ([ADR 0006](adr/0006-dynamic-runs.md)) | Tested |
| The base snapshot is a fresh clean boot. The warm image is a drive switched in per job, so no memory of the VM that ran build scripts reaches a job | Built |
| Warm set limited to versions Crateward stored at least 14 days ago, locked by several recent jobs, with a static report without high findings. The crate under analysis is replaced by a stub and its units are never cached | Tested |
| The warm build is analyzed like a job (trace, fake internet, honeytokens, scratch scan) and used only if all are clean. A promotion check runs one job with the image before any other job sees it | Tested |
| Warm images named by their BLAKE3 digest and never outliving the orchestrator process, so no signed manifest is needed ([ADR 0002](adr/0002-firecracker-rootless-jail.md)) | Built |
| Hourly canaries (known bad, known good). A wrong result pauses the producing stages until they pass again. After every start no slot takes a job before the first canaries ran, so a new guest version is promoted only by passing them. `deploy/ansible/rollback.yml` switches back ([ADR 0002](adr/0002-firecracker-rootless-jail.md)) | Built |

### Downloads (T5, B7)

| Mitigation | Status |
|------------|--------|
| TLS to crates.io hosts (the client refuses plain HTTP). Checksums from the index verified for every file | Built |
| Repeated checksum mismatches open the fetch circuit breaker: a mismatch is an infrastructure failure, which the breaker counts, and does not use up the job's attempts | Tested |
| Egress allowlisted per service user with nftables. The sets follow the configuration (`deploy/nftables`, `crateward egress`) | Built (applied by the maintainer with `deploy/ansible`) |

### External services and the public site (T6, T8, B7, B8, B9)

| Mitigation | Status |
|------------|--------|
| No inbound service except SSH with keys only. Passwords and keyboard interactive logins are off ([ADR 0003](adr/0003-debian-ansible-ssh.md)) | Built (applied by the maintainer with `deploy/ansible`) |
| Admin dashboard binds to loopback only. Configuration rejects any other address. Reaching it needs an SSH login, whose key authenticates the maintainer ([ADR 0009](adr/0009-scoring-and-dashboard.md)) | Tested |
| Dashboard: Host check against DNS rebinding, same origin checks for writes, strict Content Security Policy, compile time escaping, read only page queries | Tested |
| Alerts carry no crate names or details before disclosure. Details stay on the server, behind SSH | Tested |
| ntfy topic of at least 32 random characters. Configuration rejects shorter topics | Tested |
| Secrets redacted from `Debug` output and logs | Tested |
| Public site is a static export of aggregate statistics and disclosed findings only, pushed with a deploy key limited to one repository. A finding is listed only after it was reported and resolved. The database refuses to publish it earlier (`crateward disclosure`) | Tested (push waits for the repository) |

A compromised external service can deface the public site, suppress alerts or
forge them. It cannot reach the server or read undisclosed findings.

### Crateward's own supply chain (T7)

| Mitigation | Status |
|------------|--------|
| `Cargo.lock` committed. Every build uses `--locked` | Built |
| `cargo deny`, `cargo audit` and `cargo vet` in CI | Built |
| GitHub Actions pinned by commit SHA. Workflow token read only | Built |
| `unsafe_code` denied workspace wide. One documented `unsafe` block (`crateward_core::sandbox`, wrapping `unshare(2)`) | Built |
| Release bundles with vendored sources (reproducible archive), a CycloneDX SBOM of every locked package and the pinned sandbox parts, and `SHA256SUMS` (`cargo xtask release`), signed by the maintainer and verified by `install.sh` | Built |

### Integrity without ECC (A2)

| Mitigation | Status |
|------------|--------|
| md RAID1 with a monthly `mdcheck` scrub (detects, cannot choose the right copy) | Built |
| Content addressed blobs verified by BLAKE3 on every read | Tested |
| PostgreSQL data checksums (`data_checksums` is on) | Built (verified on the host) |
| BLAKE3 manifests: warm images named by digest. The guest kernel, root filesystem and host binaries in the integrity manifest, checked every hour. Evidence in PostgreSQL relies on data checksums | Partly built |
| Raw run data (process lists, output tails) of unflagged runs trimmed after `storage.raw_log_retention_days`. Flagged runs and all evidence kept ([ADR 0008](adr/0008-autonomy-and-escape-detection.md)) | Tested |

## Residual risks

* A crate that detects the sandbox (VM artifacts, fake network, fresh uptime,
  snapshot clock skew) can stay dormant. Host side ground truth limits what
  an active crate can hide, not what a dormant crate never does.
* A crate whose behavior a reviewer marked as a false positive can repeat
  exactly that behavior in later versions without scoring, for example a
  token sent to the same host. New behavior still scores, and the dismissed
  evidence stays on the job page ([ADR 0009](adr/0009-scoring-and-dashboard.md)).
* A zero day in KVM or the Firecracker device model could escape the VM. The
  rootless jail, seccomp and the unprivileged, air gapped slot namespace limit what
  such an escape reaches, but do not make it impossible.
* The host kernel (Debian 13 stock 6.12) is outside Firecracker's validated
  host kernel matrix. See [ADR 0003](adr/0003-debian-ansible-ssh.md).
* The CPU is old. Whether Intel still ships security microcode for 7th
  generation Core parts is not verified. The RUNBOOK tracks the kernel's
  vulnerability report.
* Without ECC, a memory error can corrupt a result in flight before any
  checksum covers it.
* The disks are not encrypted ([ADR 0003](adr/0003-debian-ansible-ssh.md)).
  A disk that leaves the data center carries Crateward's secrets, crate
  files, evidence and undisclosed findings. Secrets are scoped and
  rotatable, and the RUNBOOK wipes all disks before the server is
  cancelled.
