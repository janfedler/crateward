# Crateward: building every new crate version in a microVM

*Draft of the launch write up. The numbers come from the first two days of
live crates.io data on the development host (24 to 26 September 2026); the
production server is not deployed yet. Publish only after the maintainer
has reviewed the open verdicts below.*

## Why

A crate can run code on your machine before you ever call it: its build
script and its procedural macros run during `cargo build`, and so do those
of every dependency. Most malicious packages in other ecosystems used
exactly that moment. Static rules catch a lot, but a build script that
downloads its second stage, or reads `~/.cargo/credentials.toml` only on
some machines, shows its intent only when it runs.

Crateward runs it, somewhere it cannot hurt.

## What it does

Every new version on crates.io is fetched, verified against the index
checksum, and analyzed statically: build scripts, procedural macros and
the crate's own code, across all `cfg` branches, with file and line
evidence. A version whose build runs its own code, or depends on a crate
that does and is neither popular nor locked by an earlier version, is then
built with `cargo check` inside a Firecracker microVM:

* a fresh VM per job, restored from a snapshot of a clean boot, and
  destroyed afterwards;
* no internet: a fake internet in the VM's own network namespace answers
  DNS, HTTP and TLS (with its own authority, which the guest trusts) and
  records every attempt, including frames no proxy sees;
* fake credentials planted where build scripts look for them, each unique
  to the job, so finding one anywhere names the job that took it;
* eBPF programs in the guest that record every process, file open and
  socket, read next to what the host saw itself: the fake internet's log
  and the scratch disk, parsed after the run in a sandboxed child.

A verdict is a score with its reasons, each linked to evidence, and it says
what the analysis covered. A high verdict from `cargo check` is confirmed
automatically by a full build and test in another fresh VM, then waits for
a human.

## Assume it escapes

Crateward is built on the assumption that a crate will eventually get out
of its VM, and tries to make that worthless. Firecracker runs in a rootless
jail: its own user, namespaces, `pivot_root`, no capabilities, its default
seccomp filter. Nothing on the host holds a credential worth stealing from
there, the sandbox user has no route to the internet, and the host watches
for the step after an escape: a decoy file in every jail root whose access
time shows a read, decoys on the host watched with inotify, processes
running as a slot's user that the jail did not start, and a digest
manifest of every binary and image the sandbox trusts. Any of them
quarantines the whole pipeline until a human looks.

## First numbers

| | |
|---|---|
| Versions seen | 5161 |
| Versions with a verdict | 5140 |
| Static analysis only, no build time code | 3905 (76 percent) |
| Static analysis only, dependencies did not resolve | 69 |
| Built and traced in a microVM | 1156 (22 percent) |
| `cargo check` run, median and 90th percentile | 30 s and 227 s |
| Confirmation runs (full build and test) | 49 |
| Verdicts none, low, medium | 3410, 1646, 76 |
| Verdicts high or critical, waiting for review | 8 |

A high verdict is not a finding. Known false positives are `-sys` crates
that download prebuilt libraries and build scripts that probe the network
for feature detection. None of the eight has been reviewed yet, and none will be named before it was
reported and handled ([DISCLOSURE.md](DISCLOSURE.md)).

## What hardening found

* Thirteen fuzz targets cover every parser of hostile input on the host.
  The one for scratch disks found a crafted ext4 superblock that made the
  parser reserve 8 GiB; it ran in a child limited to 2 GiB, so the child
  died and nothing else, and the geometry is now checked first.
* A review of the escape tripwires found that a cleanup error after a run
  could replace a touched decoy with an ordinary infrastructure error, and
  so retry the crate instead of quarantining. One function now decides a
  run's result, and an escape indicator outranks every error.
* A second orchestrator started during a restart cleared the first one's
  jails. The orchestrator now holds a lock in the slot directory.

## Limits

* A crate that detects the sandbox can stay dormant. Host side ground
  truth limits what an active crate can hide, not what a dormant one never
  does.
* Only Linux is executed; Windows and macOS code is covered statically.
* One server with three VM slots: roughly one version in five needs a VM,
  and a version that waits more than 12 hours is scored statically and
  labeled that way.

The design, the threat model and every decision are in the repository:
[ARCHITECTURE.md](ARCHITECTURE.md), [THREAT_MODEL.md](THREAT_MODEL.md) and
the [decision records](adr/README.md).
