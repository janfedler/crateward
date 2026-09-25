//! The warm build cache (ADR 0008).
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

use crateward_core::blobs::BlobStore;
use crateward_core::config::WarmConfig;
use crateward_core::digest::Sha256Digest;
use crateward_core::name::CrateName;
use crateward_core::store::Store;

use crate::backend::FirecrackerBackend;
use crate::honeytokens::Honeytokens;
use crate::payload::{Package, PayloadSpec, ProbeSpec};
use crate::worker::{BUILDER, JobFiles, Locked, RunPlan, RunReport, WorkerSetup, execute};

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
/// gate). `blobs` maps every stored checksum to its blob; a sample with a
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

/// The script that runs the replays, one `cargo check` per probe. A failing
/// replay (for example a missing system library) does not stop the others.
fn script(plan: &Plan) -> String {
    let mut out = String::from("#!/bin/sh\n");
    for i in 0..plan.probes.len() {
        let dir = if i == 0 {
            "/cw/probe".to_owned()
        } else {
            format!("/cw/probes/{}", i - 1)
        };
        out.push_str(&format!(
            "cd {dir} && cargo check --locked --offline --keep-going || true\n"
        ));
    }
    out
}

/// Why a warm build's result is not used, or `None` if it is clean.
#[must_use]
pub fn rejection(report: &RunReport) -> Option<String> {
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
    if let Some((_, why)) = problems.iter().find(|(bad, _)| *bad) {
        // Name the first entry, rendered by the trace summary already.
        let example = t
            .sockets
            .first()
            .map(|x| format!("{} {}", x.exe, x.address))
            .or_else(|| {
                t.sensitive_opens
                    .first()
                    .map(|x| format!("{} {}", x.exe, x.path))
            })
            .or_else(|| {
                t.writes_outside_work
                    .first()
                    .map(|x| format!("{} {}", x.exe, x.path))
            })
            .or_else(|| t.tamper.first().map(|x| x.what.clone()))
            .unwrap_or_default();
        return Some(format!("{why}: {example}"));
    }
    let Some(s) = &report.scratch else {
        return Some("the scratch disk was not scanned".into());
    };
    if s.units.is_empty() {
        return Some("the replays compiled nothing".into());
    }
    let unexpected = s
        .error
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
        .or_else(|| s.planted_changed.first().cloned());
    if let Some(entry) = unexpected {
        return Some(format!(
            "the scratch disk holds unexpected entries: {entry}"
        ));
    }
    None
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Size of the warm build's scratch disk: room for the target directory up
/// to the image limit, plus the rest of what a build writes.
#[must_use]
pub fn scratch_mib(config: &WarmConfig) -> u64 {
    config.max_image_mib.saturating_add(2048)
}

/// Builds the warm image in `slot` and returns its path, or `None` when
/// there is nothing to warm. The image lands in `setup.work_dir`.
///
/// # Errors
///
/// Describes why no image was produced: an infrastructure failure, a
/// rejected build, or an image above the size limit.
pub async fn build(
    backend: &FirecrackerBackend,
    slot: u32,
    setup: &WorkerSetup,
    blobs: &BlobStore,
    config: &WarmConfig,
    plan: &Plan,
) -> Result<Option<PathBuf>, String> {
    let Some((first, rest)) = plan.probes.split_first() else {
        return Ok(None);
    };
    let spec = PayloadSpec {
        name: first.name.clone(),
        version: first.version.clone(),
        lockfile: first.lockfile.clone(),
        packages: plan.packages.clone(),
        extra_probes: rest.to_vec(),
        files: vec![("warm.sh".into(), script(plan).into_bytes())],
        stubs: plan.stubs.clone(),
    };
    let work = &setup.work_dir;
    let files = JobFiles {
        payload: work.join("warm.payload"),
        scratch: work.join("warm.scratch"),
        network: work.join("warm.network"),
        warm: None,
        warm_placeholder: setup.warm_placeholder.clone(),
    };
    let mut warm_setup = setup.clone();
    warm_setup.warm = None;
    warm_setup.scratch_mib = scratch_mib(config);
    let run = RunPlan {
        argv: vec!["/bin/sh".into(), "/cw/warm.sh".into()],
        cwd: "/cw".into(),
        timeout: Duration::from_secs(config.timeout_secs),
    };
    let tokens = Honeytokens::generate(&mut rand::rng(), BUILDER);
    let result = async {
        let report = execute(
            backend,
            slot,
            &warm_setup,
            blobs,
            0,
            spec,
            &tokens,
            &files,
            &run,
        )
        .await
        .map_err(|f| format!("warm build: {f:?}"))?;
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
            return Err(format!("warm build rejected: {why}"));
        }
        let image = work.join("warm-staging.erofs");
        let exe = setup.exe.clone();
        let scratch = files.scratch.clone();
        let out = image.clone();
        let mut excluded: Vec<String> = plan
            .stubs
            .iter()
            .filter_map(|dir| dir.rsplit_once('-').map(|(name, _)| name.to_owned()))
            .collect();
        excluded.push("crateward-probe".into());
        tokio::task::spawn_blocking(move || {
            crate::scratch::export_to_erofs(&exe, &scratch, &out, &excluded)
        })
        .await
        .map_err(|e| e.to_string())??;
        let size = std::fs::metadata(&image).map_err(|e| e.to_string())?.len();
        if size > config.max_image_mib.saturating_mul(1024 * 1024) {
            let _ = std::fs::remove_file(&image);
            return Err(format!("the warm image has {size} bytes, above the limit"));
        }
        let digest = blake3_file(&image)?;
        let named = work.join(format!(
            "warm-{}.erofs",
            digest.get(..16).unwrap_or_default()
        ));
        std::fs::rename(&image, &named).map_err(|e| e.to_string())?;
        if let Err(error) = promotion_check(backend, slot, setup, blobs, plan, &named).await {
            let _ = std::fs::remove_file(&named);
            return Err(format!("promotion check failed: {error}"));
        }
        Ok(Some(named))
    }
    .await;
    for file in [&files.payload, &files.scratch, &files.network] {
        let _ = std::fs::remove_file(file);
    }
    result
}

/// Units a job may still compile itself when the warm image covers its
/// dependencies: the stub and the probe, with some room.
const PROMOTION_MAX_UNITS: usize = 5;

/// Replays the first probe as an ordinary job with the new image mounted.
/// The image is used only if that job is clean, succeeds and compiles
/// almost nothing itself; a broken image would otherwise fail every job.
async fn promotion_check(
    backend: &FirecrackerBackend,
    slot: u32,
    setup: &WorkerSetup,
    blobs: &BlobStore,
    plan: &Plan,
    image: &Path,
) -> Result<(), String> {
    let (Some(first), Some(stub)) = (plan.probes.first(), plan.stubs.first()) else {
        return Err("no probe to check with".into());
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
    let work = &setup.work_dir;
    let files = JobFiles {
        payload: work.join("warm-check.payload"),
        scratch: work.join("warm-check.scratch"),
        network: work.join("warm-check.network"),
        warm: Some(image.to_path_buf()),
        warm_placeholder: setup.warm_placeholder.clone(),
    };
    let tokens = Honeytokens::generate(&mut rand::rng(), BUILDER);
    let run = RunPlan::check(setup.check_timeout);
    let result = execute(backend, slot, setup, blobs, 0, spec, &tokens, &files, &run).await;
    for file in [&files.payload, &files.scratch, &files.network] {
        let _ = std::fs::remove_file(file);
    }
    let report = result.map_err(|f| format!("{f:?}"))?;
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
    if report.outcome != crateward_core::job::BuildOutcome::Succeeded {
        return Err(format!(
            "the check build ended {:?}: {}",
            report.outcome,
            crate::trace::render(report.stderr_tail.as_bytes())
        ));
    }
    if compiled > PROMOTION_MAX_UNITS {
        return Err(format!("the check build compiled {compiled} units itself"));
    }
    // Everything but the unit count applies as for the warm build.
    if let Some(why) = rejection(&report).filter(|w| !w.contains("compiled nothing")) {
        return Err(why);
    }
    Ok(())
}

fn blake3_file(path: &Path) -> Result<String, String> {
    let mut hasher = blake3::Hasher::new();
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hasher
        .update_reader(file)
        .map_err(|e| format!("{}: {e}", path.display()))?;
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
        let text = script(&plan);
        assert!(
            text.contains("cd /cw/probe && cargo check --locked --offline --keep-going || true")
        );
        assert!(text.contains("cd /cw/probes/0 && "));
        // The gate: nothing eligible, nothing replayed.
        assert!(
            super::plan(&samples, &HashSet::new(), &blobs, 2, 10)
                .probes
                .is_empty()
        );
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
}
