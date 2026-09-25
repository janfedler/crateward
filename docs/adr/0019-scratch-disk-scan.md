# 0019: Reading the scratch disk after a run

* Status: Accepted
* Date: 2026-09-25

## Context

The scratch disk is the only writable disk of a job (ADR 0016). What the
job left there is host side ground truth that a compromised guest kernel
cannot hide after the fact: persistence files, dropped executables,
honeytokens copied into build outputs. The image is written entirely by the
guest, so it must be read like any other hostile input: never mounted on
the host, and parsed only in a sandboxed process (the threat model's row
for guest disk images).

Facts verified on 2026-09-25:

* `ext4-view` 1.0 reads ext2, ext3 and ext4 without unsafe code, states as
  a design goal that invalid data never causes a panic or an endless loop,
  applies the journal in memory, and depends only on `bitflags` and `crc`.
* The guest page cache holds a job's writes until they are synced; the VM
  ends without unmounting.
* In the canary run, a `cargo check` left 43 files on the scratch disk;
  besides the target directory, cargo itself wrote only its lock files,
  its cache database and `registry/CACHEDIR.TAG` in `CARGO_HOME`.

## Decision

1. The guest agent calls `sync` after the job's process group is gone and
   before it reports the exit.
2. After every run, the orchestrator starts itself as `sandbox-scratch`
   with the image as stdin and the scan parameters (honeytoken values, the
   planted files, the directories the agent created) as one JSON argument.
   The child enters a new user and network namespace, sets resource limits
   (2 GiB of address space, 300 CPU seconds, no file writes, 16 open files)
   and Landlock with no filesystem access before it parses anything, and
   prints a JSON report.
3. The scan walks the whole image, bounded to 200,000 entries, a depth of
   64, 16 MiB of contents per file and 1 GiB in total. It reports entries
   outside the target directory and cargo's own state, executables (by mode
   or ELF header) outside the target directory, set user or group ID files,
   device nodes, FIFOs and sockets, symbolic links that point outside the
   disk, planted honeytoken files that changed or disappeared, and
   honeytoken values found in any other file.
4. A failed scan is logged and leaves the report without a scratch section;
   it never fails the job, and an unreadable image is itself reported.

## Consequences

* Honeytokens copied to disk inside the VM are found even when nothing
  left the VM, and persistence attempts are visible regardless of what the
  guest's trace says.
* The scan adds a process start and a read of the image (tens of
  milliseconds for a small build) to every run.
* Only the scratch disk is covered. Memory of the guest (for example `/tmp`)
  ends with the VM unread.

## Sources

* `ext4-view` 1.0.0 `README.md` and sources,
  `https://github.com/nicholasbishop/ext4-view-rs`
* Linux `Documentation/filesystems/ext4/`, `sync(2)`
