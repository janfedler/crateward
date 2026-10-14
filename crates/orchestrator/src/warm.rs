//! The warm build cache (ADR 0006).
//!
//! Most of a job's `cargo check` time goes into dependencies that other
//! jobs compiled already, with the same versions and features. The warm
//! build replays the dependency builds of recent jobs in a VM (never the
//! crate under analysis itself: each replay is `cargo check -p` for the
//! locked dependencies only), and the resulting target directory becomes a
//! read only image that every later job sees under its own writable layer.
//!
//! What may enter:
//!
//! * A crate version must be locked by at least `min_jobs` of the sampled
//!   jobs, and Crateward must have stored its file at least `min_age_hours`
//!   ago, with a static report and no high severity finding.
//! * Every dependency of it, in that job's lockfile, must qualify too, so
//!   nothing that fails the gate is compiled as a side effect.
//!
//! The warm build runs like a job, with honeytokens, the fake internet, the
//! eBPF trace and the scratch disk scan. Its result is used only if all of
//! them are clean: no network attempt at all (the build is offline), no
//! sensitive file, no write outside the build areas, no tamper attempt, no
//! honeytoken anywhere. The image is then packed from the scratch disk by
//! sandboxed children and never mounted on the host.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crateward_core::bytes::hex;
use crateward_core::child::ChildError;
use crateward_core::config::{SandboxConfig, WarmConfig};
use crateward_core::digest::Sha256Digest;
use crateward_core::failure::Failure;
use crateward_core::job::BuildOutcome;
use crateward_core::name::CrateName;
use crateward_core::paths::guest;
use crateward_core::report::run::RunReport;
use crateward_core::report::scratch::ScratchReport;
use crateward_core::report::trace::TraceSummary;
use crateward_core::store::Store;

use crate::honeytokens::Honeytokens;
use crate::payload::{Package, PayloadSpec, ProbeSpec};
use crate::worker::{JobFiles, Locked, RunPlan, Sandbox};

/// A crate version.
type Key = (String, String);

/// The replays of one warm build.
#[derive(Debug, Clone, Default)]
pub struct Plan {
    /// Probes, replayed in order.
    pub probes: Vec<ProbeSpec>,
    /// The crates under analysis of those probes, written as stubs
    /// (`<name>-<version>`), whose units never enter the image.
    pub stubs: Vec<String>,
    /// Every package any probe locks.
    pub packages: Vec<Package>,
    /// Crate versions the replays compile, counted once.
    pub units: usize,
}

/// One sampled job.
#[derive(Debug, Clone)]
pub struct Sample {
    /// The crate under analysis.
    pub name: String,
    /// Its version.
    pub version: String,
    /// Its lockfile.
    pub lockfile: String,
    /// Its locked packages with checksums.
    pub locked: Vec<(Key, String)>,
}

/// Chooses the replays. A sample qualifies when every package it locks,
/// except the crate under analysis, is locked by at least `min_jobs`
/// samples and its checksum is in `eligible` (the age and static analysis
/// gate). `blobs` maps every stored checksum to its blob. A sample with a
/// package that is not stored is skipped.
#[must_use]
pub fn plan(
    samples: &[Sample],
    eligible: &HashSet<String>,
    blobs: &HashMap<String, String>,
    min_jobs: u32,
    max_probes: u32,
) -> Plan {
    let mut seen: HashMap<Key, u32> = HashMap::new();
    for s in samples {
        let unique: HashSet<&Key> = s.locked.iter().map(|(k, _)| k).collect();
        for key in unique {
            *seen.entry(key.clone()).or_default() += 1;
        }
    }

    let mut result = Plan::default();
    let mut packages: HashMap<Key, Package> = HashMap::new();
    let mut stubbed: HashSet<Key> = HashSet::new();
    let mut built: HashSet<Key> = HashSet::new();

    for s in samples {
        if result.probes.len() >= usize::try_from(max_probes).unwrap_or(usize::MAX) {
            break;
        }

        let own: Key = (s.name.clone(), s.version.clone());
        let deps: Vec<&(Key, String)> = s.locked.iter().filter(|(k, _)| *k != own).collect();
        let qualifies = s.locked.iter().any(|(k, _)| *k == own)
            && s.locked.iter().all(|(_, sum)| blobs.contains_key(sum))
            && deps.iter().all(|(k, sum)| {
                seen.get(k).copied().unwrap_or(0) >= min_jobs && eligible.contains(sum)
            })
            // One vendored directory per version: a stub here cannot be a
            // real dependency elsewhere, and the other way round.
            && !built.contains(&own)
            && deps.iter().all(|(k, _)| !stubbed.contains(k));

        let (Ok(name), Ok(version)) = (CrateName::parse(&s.name), s.version.parse()) else {
            continue;
        };

        if !qualifies {
            continue;
        }

        for ((n, v), sum) in &s.locked {
            if let Some(blake3) = blobs.get(sum) {
                packages
                    .entry((n.clone(), v.clone()))
                    .or_insert_with(|| Package {
                        name: n.clone(),
                        version: v.clone(),
                        checksum: sum.clone(),
                        blake3: blake3.clone(),
                    });
            }
        }

        built.extend(deps.iter().map(|(k, _)| k.clone()));
        stubbed.insert(own.clone());
        result.stubs.push(format!("{}-{}", own.0, own.1));
        result.probes.push(ProbeSpec {
            name,
            version,
            lockfile: s.lockfile.clone(),
        });
    }

    let mut packages: Vec<Package> = packages.into_values().collect();
    packages.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    result.packages = packages;
    result.units = built.len();

    result
}

/// The script that runs the replays, one `cargo check` per probe, each
/// limited to `probe_secs`. A failing replay (for example a missing system
/// library) does not stop the others, nor does a slow one: `timeout` ends
/// its whole process group, build scripts included, and the units finished
/// so far stay. The probes that ran out of time are named last, so they
/// show in the logged end of the output.
fn script(plan: &Plan, probe_secs: u64) -> String {
    let mut out = String::from("#!/bin/sh\nslow=\n");

    for (i, stub) in plan.stubs.iter().enumerate() {
        let dir = if i == 0 {
            guest::PROBE.to_owned()
        } else {
            format!("{}/probes/{}", guest::PAYLOAD, i - 1)
        };

        out.push_str(&format!(
            "cd {dir} && timeout -k 10 {probe_secs} cargo check --locked --offline --keep-going\n\
             case $? in 124|137) slow=\"$slow {stub}\" ;; esac\n"
        ));
    }

    out.push_str("[ -z \"$slow\" ] || echo \"crateward-warm: timed out:$slow\" >&2\n");

    out
}

/// Why a warm build's result is not used, or `None` if it is clean.
#[must_use]
pub fn rejection(report: &RunReport) -> Option<String> {
    if let Some(why) = behavior_problem(report) {
        return Some(format!("{why}: {}", first_example(&report.trace)));
    }

    let Some(scratch) = &report.scratch else {
        return Some("the scratch disk was not scanned".into());
    };

    if scratch.units.is_empty() {
        return Some("the replays compiled nothing".into());
    }

    let entry = unexpected_entry(scratch)?;

    Some(format!(
        "the scratch disk holds unexpected entries: {entry}"
    ))
}

/// The first thing the run did that a clean build never does.
fn behavior_problem(report: &RunReport) -> Option<&'static str> {
    let t = &report.trace;
    let n = &report.network;
    let problems = [
        (!t.complete, "the trace is incomplete"),
        (!t.sockets.is_empty(), "a process used a socket"),
        (
            !t.sensitive_opens.is_empty(),
            "a process opened a sensitive file",
        ),
        (
            !t.writes_outside_work.is_empty(),
            "a process wrote outside the build",
        ),
        (!t.tamper.is_empty(), "a process tried to tamper"),
        (
            t.processes.iter().any(|p| p.became_root),
            "a process ran as root",
        ),
        (
            !report.leaked.is_empty()
                || !report.tokens_in_trace.is_empty()
                || !report.tokens_on_disk.is_empty(),
            "a honeytoken was used",
        ),
        (
            !n.dns.is_empty()
                || !n.connections.is_empty()
                || !n.packets.is_empty()
                || n.udp_datagrams > 0,
            "the fake internet saw traffic",
        ),
    ];

    problems
        .into_iter()
        .find(|(bad, _)| *bad)
        .map(|(_, why)| why)
}

/// The first entry of the trace's lists, rendered by the trace summary
/// already, or an empty string.
fn first_example(t: &TraceSummary) -> String {
    t.sockets
        .first()
        .map(|x| format!("{} {}", x.exe, x.address))
        .or_else(|| {
            let x = t.sensitive_opens.first()?;
            Some(format!("{} {}", x.exe, x.path))
        })
        .or_else(|| {
            let x = t.writes_outside_work.first()?;
            Some(format!("{} {}", x.exe, x.path))
        })
        .or_else(|| t.tamper.first().map(|x| x.what.clone()))
        .unwrap_or_default()
}

/// The first entry the scratch scan flags, list by list.
fn unexpected_entry(s: &ScratchReport) -> Option<String> {
    s.error
        .clone()
        .or_else(|| s.outside_build.first().map(|e| e.path.clone()))
        .or_else(|| s.executables_outside_target.first().map(|e| e.path.clone()))
        .or_else(|| s.setid.first().map(|e| e.path.clone()))
        .or_else(|| {
            s.special
                .first()
                .map(|e| format!("{} ({})", e.path, e.kind))
        })
        .or_else(|| s.links_outside.first().map(|e| e.path.clone()))
        .or_else(|| s.planted_changed.first().cloned())
}

/// Loads the samples and the gate from the store and plans a warm build.
///
/// # Errors
///
/// Fails on database errors.
pub async fn plan_from_store(
    store: &Store,
    config: &WarmConfig,
) -> Result<Plan, crateward_core::store::StoreError> {
    let fetches = store.recent_fetches(i64::from(config.sample_jobs)).await?;
    let mut samples = Vec::new();
    let mut checksums: HashSet<String> = HashSet::new();

    for (_, name, version, lockfile, packages) in fetches {
        let locked: Vec<Locked> = serde_json::from_value(packages).unwrap_or_default();
        let locked: Vec<(Key, String)> = locked
            .into_iter()
            .map(|l| ((l.name, l.version), l.checksum))
            .collect();

        checksums.extend(locked.iter().map(|(_, c)| c.clone()));
        samples.push(Sample {
            name,
            version,
            lockfile,
            locked,
        });
    }

    let digests: Vec<Vec<u8>> = checksums
        .iter()
        .filter_map(|c| c.parse::<Sha256Digest>().ok())
        .map(|d| d.as_bytes().to_vec())
        .collect();

    let age = config.min_age_hours.saturating_mul(3600) as f64;
    let eligible: HashSet<String> = store
        .warm_eligible(&digests, age)
        .await?
        .into_iter()
        .map(|(sha, _)| hex(&sha))
        .collect();

    let blobs: HashMap<String, String> = store
        .crate_blobs(&digests)
        .await?
        .into_iter()
        .map(|(sha, blake3)| (hex(&sha), blake3))
        .collect();

    Ok(plan(
        &samples,
        &eligible,
        &blobs,
        config.min_jobs,
        config.max_probes,
    ))
}

/// vCPUs and guest memory of the warm build's VM. It runs before any job,
/// so it gets the vCPUs of every slot, and as much memory as fits into
/// what the slots would use: their memory and scratch disks, less the
/// warm build's larger scratch disk, halved because the memory counts
/// twice (the snapshot file in tmpfs and the pages the VM writes). `None`
/// when that is not more than one slot has, which then runs the build.
#[must_use]
pub fn machine(sandbox: &SandboxConfig, config: &WarmConfig) -> Option<(u8, u32)> {
    let slots = u64::from(sandbox.slots);
    let share = slots.saturating_mul(
        sandbox
            .memory_mib_per_slot
            .saturating_add(sandbox.scratch_mib_per_slot),
    );

    let memory = (share.saturating_sub(scratch_mib(config)) / 2)
        .min(slots.saturating_mul(sandbox.memory_mib_per_slot));
    if sandbox.slots < 2 || memory < sandbox.memory_mib_per_slot {
        return None;
    }

    let vcpus = sandbox.slots.saturating_mul(sandbox.vcpus_per_slot);

    Some((u8::try_from(vcpus).ok()?, u32::try_from(memory).ok()?))
}

/// Size of the warm build's scratch disk: room for the target directory up
/// to the image limit, plus the rest of what a build writes.
#[must_use]
pub fn scratch_mib(config: &WarmConfig) -> u64 {
    config.max_image_mib.saturating_add(2048)
}

/// Why no warm image was produced.
#[derive(Debug, thiserror::Error)]
pub enum WarmError {
    /// The build could not run.
    #[error("warm build: {0}")]
    Build(#[from] Failure),
    /// The build ran, but its result is not clean.
    #[error("warm build rejected: {0}")]
    Rejected(String),
    /// The packing task panicked or was cancelled.
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    /// A child that packs the image failed.
    #[error(transparent)]
    Pack(#[from] ChildError),
    /// The image file could not be read or moved.
    #[error("{}: {source}", .path.display())]
    Image {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The image is above the size limit.
    #[error("the warm image has {0} bytes, above the limit")]
    TooLarge(u64),
    /// A job with the image mounted did not come out clean.
    #[error("promotion check failed: {0}")]
    Check(#[from] CheckError),
}

/// Why the promotion check refused an image.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The plan has no probe to check with.
    #[error("no probe to check with")]
    NoProbe,
    /// The check build could not run.
    #[error(transparent)]
    Run(#[from] Failure),
    /// The check build did not succeed.
    #[error("the check build ended {}: {stderr}", outcome.name())]
    Ended {
        /// How it ended.
        outcome: BuildOutcome,
        /// What it printed last.
        stderr: String,
    },
    /// The image did not cover the dependencies.
    #[error("the check build compiled {0} units itself")]
    Compiled(usize),
    /// The check build was not clean.
    #[error("{0}")]
    Rejected(String),
}

fn image_io(path: &Path) -> impl FnOnce(std::io::Error) -> WarmError {
    let path = path.to_path_buf();

    move |source| WarmError::Image { path, source }
}

/// Builds the warm image and returns its path, or `None` when there is
/// nothing to warm. The replays run on `builder` (see [`machine`]), the
/// promotion check as an ordinary job on `sandbox`. The image lands in the
/// work directory.
///
/// # Errors
///
/// Describes why no image was produced: an infrastructure failure, a
/// rejected build, or an image above the size limit.
pub async fn build(
    sandbox: &Sandbox,
    builder: &Sandbox,
    config: &WarmConfig,
    plan: &Plan,
) -> Result<Option<PathBuf>, WarmError> {
    let Some((first, rest)) = plan.probes.split_first() else {
        return Ok(None);
    };

    let spec = PayloadSpec {
        name: first.name.clone(),
        version: first.version.clone(),
        lockfile: first.lockfile.clone(),
        packages: plan.packages.clone(),
        extra_probes: rest.to_vec(),
        files: vec![(
            "warm.sh".into(),
            script(plan, sandbox.setup.check_timeout.as_secs()).into_bytes(),
        )],
        stubs: plan.stubs.clone(),
    };

    let files = JobFiles {
        warm: None,
        ..JobFiles::named(&sandbox.setup, "warm")
    };

    let result = replay(sandbox, builder, config, plan, spec, &files).await;
    files.remove();

    result.map(Some)
}

/// Replays the probes in a VM, packs the target directory they leave and
/// checks the image with an ordinary job.
async fn replay(
    sandbox: &Sandbox,
    builder: &Sandbox,
    config: &WarmConfig,
    plan: &Plan,
    spec: PayloadSpec,
    files: &JobFiles,
) -> Result<PathBuf, WarmError> {
    let mut warming = builder.clone();
    warming.setup.scratch_mib = scratch_mib(config);
    let run = RunPlan {
        argv: vec![guest::SHELL.into(), format!("{}/warm.sh", guest::PAYLOAD)],
        cwd: guest::PAYLOAD.into(),
        timeout: Duration::from_secs(config.timeout_secs),
    };

    let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
    let report = warming.execute(0, spec, &tokens, files, &run).await?;
    tracing::info!(
        run_ms = report.run_ms,
        outcome = ?report.outcome,
        units = report.scratch.as_ref().map_or(0, |s| s.units.len()),
        stderr = %crate::trace::render(
            report
                .stderr_tail
                .as_bytes()
                .get(report.stderr_tail.len().saturating_sub(3000)..)
                .unwrap_or_default()
        ),
        "warm build finished"
    );

    if let Some(why) = rejection(&report) {
        return Err(WarmError::Rejected(why));
    }

    let image = pack(sandbox, config, plan, &files.scratch).await?;
    if let Err(error) = promotion_check(sandbox, plan, &image).await {
        let _ = std::fs::remove_file(&image);
        return Err(error.into());
    }

    Ok(image)
}

/// Packs the target directory of the scratch disk into an image named after
/// its digest, in the work directory. The stubs and the probe stay out.
async fn pack(
    sandbox: &Sandbox,
    config: &WarmConfig,
    plan: &Plan,
    scratch: &Path,
) -> Result<PathBuf, WarmError> {
    let work = &sandbox.setup.work_dir;
    let staging = work.join("warm-staging.erofs");
    let exe = sandbox.setup.exe.clone();
    let (disk, out) = (scratch.to_path_buf(), staging.clone());
    let mut excluded: Vec<String> = plan
        .stubs
        .iter()
        .filter_map(|dir| dir.rsplit_once('-').map(|(name, _)| name.to_owned()))
        .collect();

    excluded.push("crateward-probe".into());
    tokio::task::spawn_blocking(move || {
        crate::scratch::export_to_erofs(&exe, &disk, &out, &excluded)
    })
    .await??;
    let size = std::fs::metadata(&staging)
        .map_err(image_io(&staging))?
        .len();
    if size > config.max_image_mib.saturating_mul(1024 * 1024) {
        let _ = std::fs::remove_file(&staging);
        return Err(WarmError::TooLarge(size));
    }

    let digest = blake3_file(&staging).map_err(image_io(&staging))?;
    let named = work.join(format!(
        "warm-{}.erofs",
        digest.get(..16).unwrap_or_default()
    ));

    std::fs::rename(&staging, &named).map_err(image_io(&staging))?;
    sandbox
        .backend
        .grant_shared(&named)
        .map_err(image_io(&named))?;

    Ok(named)
}

/// Units a job may still compile itself when the warm image covers its
/// dependencies: the stub and the probe, with some room.
const PROMOTION_MAX_UNITS: usize = 5;

/// Replays the first probe as an ordinary job with the new image mounted.
/// The image is used only if that job is clean, succeeds and compiles
/// almost nothing itself. A broken image would otherwise fail every job.
async fn promotion_check(sandbox: &Sandbox, plan: &Plan, image: &Path) -> Result<(), CheckError> {
    let (Some(first), Some(stub)) = (plan.probes.first(), plan.stubs.first()) else {
        return Err(CheckError::NoProbe);
    };

    let spec = PayloadSpec {
        name: first.name.clone(),
        version: first.version.clone(),
        lockfile: first.lockfile.clone(),
        packages: plan.packages.clone(),
        extra_probes: Vec::new(),
        files: Vec::new(),
        stubs: vec![stub.clone()],
    };

    let files = JobFiles {
        warm: Some(image.to_path_buf()),
        ..JobFiles::named(&sandbox.setup, "warm-check")
    };

    let tokens = Honeytokens::generate(&mut rand::rng(), guest::BUILDER_UID);
    let run = RunPlan::check(sandbox.setup.check_timeout);
    let result = sandbox.execute(0, spec, &tokens, &files, &run).await;
    files.remove();
    let report = result?;
    let compiled = report
        .scratch
        .as_ref()
        .map_or(usize::MAX, |s| s.units.len());

    tracing::info!(
        outcome = ?report.outcome,
        run_ms = report.run_ms,
        compiled,
        "warm build cache promotion check"
    );

    if report.outcome != BuildOutcome::Succeeded {
        return Err(CheckError::Ended {
            outcome: report.outcome,
            stderr: crate::trace::render(report.stderr_tail.as_bytes()),
        });
    }

    if compiled > PROMOTION_MAX_UNITS {
        return Err(CheckError::Compiled(compiled));
    }

    // Everything but the unit count applies as for the warm build.
    match rejection(&report).filter(|w| !w.contains("compiled nothing")) {
        Some(why) => Err(CheckError::Rejected(why)),
        None => Ok(()),
    }
}

fn blake3_file(path: &Path) -> std::io::Result<String> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(std::fs::File::open(path)?)?;

    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests;
