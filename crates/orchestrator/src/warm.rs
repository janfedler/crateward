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

use crateward_core::child::ChildError;
use crateward_core::config::{SandboxConfig, WarmConfig};
use crateward_core::digest::Sha256Digest;
use crateward_core::job::BuildOutcome;
use crateward_core::name::CrateName;
use crateward_core::paths::guest;
use crateward_core::store::Store;
use crateward_fake_internet::server::hex;

use crate::honeytokens::Honeytokens;
use crate::payload::{Package, PayloadSpec, ProbeSpec};
use crate::scratch::ScratchReport;
use crate::trace::TraceSummary;
use crate::worker::{Failure, JobFiles, Locked, RunPlan, RunReport, Sandbox};

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
        argv: vec!["/bin/sh".into(), format!("{}/warm.sh", guest::PAYLOAD)],
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
mod tests {
    use super::*;

    fn sample(name: &str, deps: &[(&str, &str)]) -> Sample {
        let mut locked = vec![((name.to_owned(), "1.0.0".to_owned()), format!("sum-{name}"))];
        locked.extend(
            deps.iter()
                .map(|(n, v)| (((*n).to_owned(), (*v).to_owned()), format!("sum-{n}-{v}"))),
        );
        Sample {
            name: name.into(),
            version: "1.0.0".into(),
            lockfile: "version = 4\n".into(),
            locked,
        }
    }

    fn stored(samples: &[Sample]) -> HashMap<String, String> {
        samples
            .iter()
            .flat_map(|s| {
                s.locked
                    .iter()
                    .map(|(_, c)| (c.clone(), format!("blob-{c}")))
            })
            .collect()
    }

    #[test]
    fn only_fully_qualifying_samples_are_replayed_with_stubs() {
        let serde = ("serde", "1.0.0");
        let rare = ("rare", "0.1.0");
        let samples = vec![
            sample("a", &[serde]),
            sample("b", &[serde, rare]),
            sample("c", &[serde]),
        ];
        let blobs = stored(&samples);
        let all: HashSet<String> = blobs.keys().cloned().collect();
        let plan = plan(&samples, &all, &blobs, 2, 10);
        // `b` locks `rare`, which only one sample locks.
        assert_eq!(plan.stubs, ["a-1.0.0", "c-1.0.0"]);
        assert_eq!(plan.units, 1);
        let text = script(&plan, 900);
        assert!(text.contains(
            "cd /cw/probe && timeout -k 10 900 cargo check --locked --offline --keep-going\n\
             case $? in 124|137) slow=\"$slow a-1.0.0\" ;; esac\n"
        ));
        assert!(text.contains("cd /cw/probes/0 && "));
        assert!(text.ends_with("echo \"crateward-warm: timed out:$slow\" >&2\n"));
        // The gate: nothing eligible, nothing replayed.
        assert!(
            super::plan(&samples, &HashSet::new(), &blobs, 2, 10)
                .probes
                .is_empty()
        );
    }

    #[test]
    fn the_warm_vm_takes_what_the_slots_would_use() {
        let mut config = crateward_core::config::Config::from_toml(include_str!(
            "../../../config/crateward.example.toml"
        ))
        .unwrap();
        let warm = config.sandbox.warm.take().unwrap();
        // Three slots of 1 vCPU, 4 GiB and a 4 GiB scratch disk: 24 GiB,
        // less the 8 GiB scratch disk of the warm build, halved.
        assert_eq!(machine(&config.sandbox, &warm), Some((3, 8192)));
        config.sandbox.scratch_mib_per_slot = 2048;
        assert_eq!(machine(&config.sandbox, &warm), Some((3, 5120)));
        // Not more than one slot has.
        config.sandbox.scratch_mib_per_slot = 512;
        assert_eq!(machine(&config.sandbox, &warm), None);
        config.sandbox.scratch_mib_per_slot = 4096;
        config.sandbox.slots = 1;
        assert_eq!(machine(&config.sandbox, &warm), None);
    }

    #[test]
    fn a_crate_is_never_both_a_stub_and_a_dependency() {
        let samples = vec![
            sample("a", &[("serde", "1.0.0")]),
            // Depends on `a` 1.0.0, which the first probe stubs.
            sample("x", &[("serde", "1.0.0"), ("a", "1.0.0")]),
            sample("y", &[("serde", "1.0.0"), ("a", "1.0.0")]),
        ];
        let blobs = stored(&samples);
        let mut blobs = blobs;
        blobs.insert("sum-a-1.0.0".into(), "blob".into());
        let all: HashSet<String> = blobs.keys().cloned().collect();
        let plan = plan(&samples, &all, &blobs, 2, 10);
        assert_eq!(plan.stubs, ["a-1.0.0"]);
    }

    #[test]
    fn an_image_that_cannot_be_read_names_its_path() {
        let path = Path::new("/nonexistent/warm.erofs");
        let error = blake3_file(path).map_err(image_io(path)).unwrap_err();
        assert!(matches!(error, WarmError::Image { .. }));
        assert!(error.to_string().starts_with("/nonexistent/warm.erofs: "));
    }

    #[test]
    fn a_missing_blob_skips_the_sample() {
        let samples = vec![
            sample("a", &[("serde", "1.0.0")]),
            sample("b", &[("serde", "1.0.0")]),
        ];
        let blobs: HashMap<String, String> =
            [("sum-serde-1.0.0".to_owned(), "b".to_owned())].into();
        let all: HashSet<String> = blobs.keys().cloned().collect();
        assert!(plan(&samples, &all, &blobs, 2, 10).probes.is_empty());
    }
    use crate::scratch::Entry;
    use crate::trace::{FileAccess, Process, Role, SocketUse, Tamper};
    use crate::worker::{Connection, Leak, NetworkSummary};

    /// A run the warm build accepts.
    fn clean() -> RunReport {
        RunReport {
            outcome: BuildOutcome::Succeeded,
            end: String::new(),
            exit: None,
            restore_ms: 0,
            run_ms: 0,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            truncated: false,
            payload_files: 0,
            payload_bytes: 0,
            missing_packages: Vec::new(),
            network: NetworkSummary::default(),
            leaked: Vec::new(),
            trace: TraceSummary {
                complete: true,
                ..TraceSummary::default()
            },
            tokens_in_trace: Vec::new(),
            scratch: Some(ScratchReport {
                units: vec!["libserde-0123456789abcdef.rmeta".into()],
                ..ScratchReport::default()
            }),
            tokens_on_disk: Vec::new(),
        }
    }

    fn access(exe: &str, path: &str) -> FileAccess {
        FileAccess {
            pid: 7,
            exe: exe.into(),
            path: path.into(),
            flags: 0,
            ms: 0,
        }
    }

    fn socket(exe: &str, address: &str) -> SocketUse {
        SocketUse {
            pid: 7,
            exe: exe.into(),
            how: "connect".into(),
            address: address.into(),
            sock_type: 1,
            ms: 0,
        }
    }

    fn tamper(what: &str) -> Tamper {
        Tamper {
            pid: 7,
            what: what.into(),
            ms: 0,
        }
    }

    fn root() -> Process {
        Process {
            pid: 7,
            ppid: Some(1),
            exe: "/bin/sh".into(),
            argv: Vec::new(),
            role: Role::Other,
            started_ms: 0,
            exit: None,
            ended_ms: None,
            became_root: true,
        }
    }

    fn leak() -> Leak {
        Leak {
            kind: "aws_access_key_id".into(),
            via: "udp".into(),
        }
    }

    fn connection() -> Connection {
        Connection {
            dst: "1.2.3.4:80".into(),
            sniffed: crateward_fake_internet::sniff::Sniffed::Unknown,
            bytes: 0,
            inner: None,
        }
    }

    fn entry(path: &str, kind: &str) -> Entry {
        Entry {
            path: path.into(),
            kind: kind.into(),
            size: 0,
            mode: 0o644,
            uid: 0,
            target: None,
        }
    }

    type Edit<T> = fn(&mut T);

    fn rejected(change: Edit<RunReport>) -> Option<String> {
        let mut report = clean();
        change(&mut report);
        rejection(&report)
    }

    #[test]
    fn a_clean_run_is_used() {
        assert_eq!(rejection(&clean()), None);
    }

    #[test]
    fn each_problem_of_the_run_is_named_with_its_example() {
        let cases: [(&str, Edit<RunReport>); 13] = [
            ("the trace is incomplete: ", |r| r.trace.complete = false),
            ("a process used a socket: curl 1.2.3.4:80", |r| {
                r.trace.sockets = vec![socket("curl", "1.2.3.4:80")];
            }),
            ("a process opened a sensitive file: cat /etc/shadow", |r| {
                r.trace.sensitive_opens = vec![access("cat", "/etc/shadow")];
            }),
            ("a process wrote outside the build: tee /etc/motd", |r| {
                r.trace.writes_outside_work = vec![access("tee", "/etc/motd")];
            }),
            ("a process tried to tamper: bpf cmd 5", |r| {
                r.trace.tamper = vec![tamper("bpf cmd 5")];
            }),
            ("a process ran as root: ", |r| {
                r.trace.processes = vec![root()];
            }),
            ("a honeytoken was used: ", |r| {
                r.leaked = vec![leak()];
            }),
            ("a honeytoken was used: ", |r| {
                r.tokens_in_trace = vec![leak()];
            }),
            ("a honeytoken was used: ", |r| {
                r.tokens_on_disk = vec![leak()];
            }),
            ("the fake internet saw traffic: ", |r| {
                r.network.dns = vec!["example.com".into()];
            }),
            ("the fake internet saw traffic: ", |r| {
                r.network.connections = vec![connection()];
            }),
            ("the fake internet saw traffic: ", |r| {
                r.network.packets = vec!["icmp".into()];
            }),
            ("the fake internet saw traffic: ", |r| {
                r.network.udp_datagrams = 1;
            }),
        ];
        for (expected, change) in cases {
            assert_eq!(rejected(change).as_deref(), Some(expected));
        }
    }

    #[test]
    fn problems_are_reported_in_a_fixed_order() {
        let mut report = clean();
        report.trace.complete = false;
        report.trace.sockets = vec![socket("curl", "1.2.3.4:80")];
        report.trace.sensitive_opens = vec![access("cat", "/etc/shadow")];
        report.trace.writes_outside_work = vec![access("tee", "/etc/motd")];
        report.trace.tamper = vec![tamper("bpf cmd 5")];
        report.trace.processes = vec![root()];
        report.leaked = vec![leak()];
        report.network.udp_datagrams = 1;
        report.scratch = None;
        let steps: [(&str, Edit<RunReport>); 9] = [
            ("the trace is incomplete: curl 1.2.3.4:80", |r| {
                r.trace.complete = true;
            }),
            ("a process used a socket: curl 1.2.3.4:80", |r| {
                r.trace.sockets.clear();
            }),
            ("a process opened a sensitive file: cat /etc/shadow", |r| {
                r.trace.sensitive_opens.clear();
            }),
            ("a process wrote outside the build: tee /etc/motd", |r| {
                r.trace.writes_outside_work.clear();
            }),
            ("a process tried to tamper: bpf cmd 5", |r| {
                r.trace.tamper.clear();
            }),
            ("a process ran as root: ", |r| r.trace.processes.clear()),
            ("a honeytoken was used: ", |r| r.leaked.clear()),
            ("the fake internet saw traffic: ", |r| {
                r.network.udp_datagrams = 0;
            }),
            ("the scratch disk was not scanned", |r| {
                r.scratch = Some(ScratchReport::default());
            }),
        ];
        for (expected, fix) in steps {
            assert_eq!(rejection(&report).as_deref(), Some(expected));
            fix(&mut report);
        }
        assert_eq!(
            rejection(&report).as_deref(),
            Some("the replays compiled nothing")
        );
    }

    #[test]
    fn the_scratch_disk_must_hold_compiled_units() {
        assert_eq!(
            rejected(|r| r.scratch = None).as_deref(),
            Some("the scratch disk was not scanned")
        );
        assert_eq!(
            rejected(|r| r.scratch = Some(ScratchReport::default())).as_deref(),
            Some("the replays compiled nothing")
        );
    }

    #[test]
    fn unexpected_scratch_entries_are_reported_in_a_fixed_order() {
        let mut report = clean();
        let scratch = report.scratch.as_mut().unwrap();
        scratch.error = Some("reading the image: bad".into());
        scratch.outside_build = vec![entry("/etc/outside", "file")];
        scratch.executables_outside_target = vec![entry("/work/tool", "file")];
        scratch.setid = vec![entry("/work/su", "file")];
        scratch.special = vec![entry("/work/pipe", "fifo")];
        scratch.links_outside = vec![entry("/work/link", "symlink")];
        scratch.planted_changed = vec!["/work/home/.aws/credentials".into()];
        let steps: [(&str, Edit<ScratchReport>); 7] = [
            ("reading the image: bad", |s| s.error = None),
            ("/etc/outside", |s| s.outside_build.clear()),
            ("/work/tool", |s| s.executables_outside_target.clear()),
            ("/work/su", |s| s.setid.clear()),
            ("/work/pipe (fifo)", |s| s.special.clear()),
            ("/work/link", |s| s.links_outside.clear()),
            ("/work/home/.aws/credentials", |s| s.planted_changed.clear()),
        ];
        for (expected, fix) in steps {
            assert_eq!(
                rejection(&report),
                Some(format!(
                    "the scratch disk holds unexpected entries: {expected}"
                ))
            );
            fix(report.scratch.as_mut().unwrap());
        }
        assert_eq!(rejection(&report), None);
    }
}
