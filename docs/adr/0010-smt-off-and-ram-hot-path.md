# 0010: SMT disabled and the hot path in RAM

* Status: Accepted (maintainer decision on SMT, 2026-09-24)
* Date: 2026-09-24

## Context

The server has an Intel Core i7-7700 (Kaby Lake: 4 cores, 8 threads), 64 GiB
RAM without ECC, and two 2 TB HDDs in software RAID. It runs code from
untrusted guests continuously.

## Decision

1. **SMT off** (`nosmt`, with the kernel's L1TF and MDS mitigations and
   current microcode). This leaves 4 cores: 1 for host services and 3 for
   microVMs, by default as 3 slots of 1 vCPU each.
2. **Hot path in RAM.** Promoted images (kernel, rootfs, warm images,
   snapshot state and memory file) are copied sparsely into a tmpfs,
   verified by BLAKE3 while copying. Per job scratch disks are sparse files
   in a size capped tmpfs. The HDDs hold only durable data.

## Rationale

* Kaby Lake is affected by L1TF and MDS. The kernel documentation calls
  `mds=full,nosmt` "the complete mitigation" and says that preventing the
  SMT issues of L1TF "it might be necessary to disable SMT completely".
  Firecracker's production host guide recommends disabling SMT as well.
  With SMT on, a hostile guest on a sibling thread could read data of the
  host or of another guest.
* Snapshot restore maps the memory file and faults pages in on demand; on a
  spinning disk those are random reads. Scratch disks see random writes.
  Both would make HDD latency the bottleneck.
* With 64 GiB there is room: about 12 GiB for host services and Postgres,
  14 GiB of images, 3 VMs of 4 GiB and 3 scratch disks capped at 4 GiB, as
  checked by configuration validation (`sandbox.host_memory_budget_mib`).

## Consequences

* Throughput halves compared with SMT on. Most versions will be static only;
  triage and the dynamic deadline handle it, and the dashboard shows the
  coverage.
* A power loss loses the tmpfs contents; they are rebuilt from the verified
  archive on the HDDs at startup.
* Without ECC, bit flips in RAM are possible. Durable data carries end to end
  checksums (BLAKE3 digests of blobs and images, PostgreSQL data checksums);
  see [ADR 0013](0013-ext4-on-md-raid-without-encryption.md).

## Sources

* Linux `Documentation/admin-guide/hw-vuln/l1tf.rst` and `mds.rst`
* Firecracker `docs/prod-host-setup.md` (disable SMT, disable KSM, no swap)
