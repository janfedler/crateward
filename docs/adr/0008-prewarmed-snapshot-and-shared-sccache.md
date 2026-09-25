# 0008: A warm build cache from replayed dependency builds

* Status: Accepted (measured on 2026-09-25; see Measurements)
* Date: 2026-09-24, revised 2026-09-25

## Context

Most crates depend on the same few hundred crates. Compiling them in a cold
VM for every job dominates the cost of a dynamic run. Sharing build output
between jobs is a deliberate exception to "compile nothing until the job
runs" and creates a cache poisoning risk.

Facts that shaped the design:

* sccache caches Rust compilations only when `--emit` includes `link`;
  `cargo check` emits metadata without `link`, so its units are not
  cacheable by sccache. Only a prebuilt target directory helps `cargo check`.
* Cargo names every unit by a hash of its package ID, features, profile,
  target, compiler and dependencies, not of its location or of the root
  crate. For registry packages (which vendored sources remain, through
  source replacement) it checks no source file times. A unit built at the
  same paths with the same inputs is therefore reusable by any job.
* `cargo check -p <dependency>` panicked in cargo's feature resolver on
  real lockfiles (2026-09-25), so dependencies cannot be selected one by
  one.
* Demand, from 60 days of the crates.io database dump: 7,384 new versions
  per day on average (5,136 to 10,027), 298 per hour at the median and 474
  at the 95th percentile. Triage sends between 30 and 55 percent of them
  to a VM, depending on how much of their dependency graph Crateward has
  seen before.
* Cold runs on the server (one vCPU per VM): about 75 s on average, of
  which 75 percent is spent compiling dependencies and about 10 percent on
  the crate itself. Three slots then handle about 3,500 runs per day, at
  or below demand.

## Decision

1. **Replay, do not guess.** The warm build replays recent jobs' builds:
   each replay is the job's own probe and lockfile, with the crate under
   analysis replaced by a stub (its manifest without build script, `links`,
   binaries or other targets, and an empty library). Cargo resolves
   dependencies and features exactly as in the job and compiles nothing of
   the crate itself. The stubs' units never enter the image: they carry the
   real crate's hashes.
2. **Gate.** A job is replayed only if every package it locks, other than
   the crate itself, is locked by at least `min_jobs` sampled jobs and was
   stored by Crateward at least `min_age_hours` ago (two weeks in
   production), with a static report without high severity findings. A
   crate version is never a stub and a real dependency in the same build.
3. **Built like a job.** The warm build runs in a VM restored from the
   clean base snapshot, with honeytokens, the fake internet, the eBPF trace
   and the scratch disk scan. Its result is used only if all of them are
   clean: no network traffic at all (the build is offline), no sensitive
   file, no write outside the build, no tamper attempt, no honeytoken
   anywhere, nothing unexpected on the disk.
4. **Packed on the host without mounting.** Sandboxed children read the
   scratch image (`ext4-view`) and write `/target` as a tar with
   Crateward's own headers (no set ID bits, no links or devices, time zero)
   into `mkfs.erofs`. The image is named by its BLAKE3 digest.
5. **Promotion check.** Before any job sees the image, one replayed probe
   runs again as an ordinary job with the image mounted. It must succeed,
   be clean and compile at most five units itself.
6. **Mounted read only under a writable layer.** The image is a third job
   drive, switched per restore like the payload and scratch drives, so the
   base snapshot never changes with it. The agent mounts it at
   `/work/.warm/image` and an overlay with the job's own upper directory on
   the scratch disk at `/work/target`.
7. **Rebuilt at start.** The orchestrator builds the image at startup;
   until it is ready, and whenever a step fails, jobs build cold.

## Measurements

Measured on the production server on 2026-09-25, one vCPU per VM, with the
dev database of live crates.io versions:

* **Warm build.** 60 replayed jobs, about 740 crate versions and 1,494
  units, took 12.6 minutes in one VM and produced a 3.4 GiB image. The
  promotion check compiled 2 units in under one second.
* **Same jobs, cold and warm.** 125 jobs that had a cold run were run
  again with the image; none of them was among the replayed jobs, so the
  image had not seen their exact dependency graphs. Total run time fell
  from 11,377 s to 8,234 s (28 percent), the median run from 53 s to 29 s.
  About 40 percent of each job's units came from the image (median 37,
  mean 43 percent, over the 80 jobs with unit lists). The build outcome was
  unchanged for 124 jobs; the other one hit the 900 s limit cold and failed
  just below it warm.
* **Limits of the measurement.** The dev database is one day old, so it
  ran with `min_age_hours = 0`; in production the two week age gate keeps
  the newest releases of popular crates out of the image, which lowers the
  hit rate. A larger `max_probes` raises it at the cost of a longer warm
  build and a larger image: from the traces of cold runs, a warm set of the
  150 most frequent exact versions would cover up to 47 percent of run
  time, 300 up to 60 percent.
* **Capacity.** Cutting run time by a quarter to a third moves three
  slots from about 3,500 to about 4,800 runs per day, above the measured
  demand of 2,200 to 4,000 dynamic runs per day.

The decision is therefore accepted.

## Consequences

* A compromised version inside the warm set would affect later jobs that
  depend on it. Age, frequency and static analysis gates, a build that is
  itself analyzed like a job, and a promotion check reduce the risk; they
  do not remove it.
* A job no longer runs the build scripts of dependencies the image
  covers; they ran in the warm build, which is analyzed like a job. The
  crate under analysis always builds in full, its own build script
  included.
* Overlayfs does work in the job's name. The eBPF programs therefore skip
  files the kernel opens for itself (`FMODE_BACKING`, `FMODE_NOACCOUNT`;
  the job's own open of the overlay file is still recorded) and take the
  user from the task's objective credentials, since overlayfs switches the
  subjective ones to root during a copy up (ADR 0017). The scratch scan
  accepts overlayfs whiteouts (character devices) below `/work/.warm`.
* Scratch disks live on tmpfs and their pages are charged to the slot's
  cgroup; the slot memory limit now includes the scratch size.
* The image lives in the images tmpfs and ends with the orchestrator. A
  persistent image (reused across restarts, and then signed) is left for
  M8, when the orchestrator runs as a service.

## Sources

* sccache `docs/Rust.md`, `docs/Local.md` (version 0.18)
* Cargo `src/cargo/core/compiler/fingerprint/mod.rs` module documentation
  (`cargo` 0.99.0) and `src/cargo/core/compiler/build_runner/compilation_files.rs`
* Linux 6.18 `fs/overlayfs/`, `fs/backing-file.c`, `include/linux/fs.h`
* crates.io database dump, `https://static.crates.io/db-dump.tar.gz`,
  read on 2026-09-25
