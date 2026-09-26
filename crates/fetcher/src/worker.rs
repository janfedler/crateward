//! The fetch stage worker.

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crateward_core::cratesio::download_url;
use crateward_core::digest::Sha256Digest;
use crateward_core::failure::FailureClass;
use crateward_core::http::{HttpError, PoliteClient};
use crateward_core::job::{JobEvent, Stage};
use crateward_core::name::CrateName;
use crateward_core::store::{CrateFile, Policies, Store, StoreError, StoredJob, heartbeat};
use sha2::Digest as _;

use crate::archive::ArchiveLimits;
use crate::proxy::IndexCache;
use crate::resolve::{Resolution, locked_packages, resolve};
use crate::sandboxed::{MAX_CRATE_BYTES, validate_in_sandbox};
use crateward_core::blobs::BlobStore;

/// How a fetch failed. The class decides the automated response.
#[derive(Debug, thiserror::Error)]
#[error("{class:?}: {message}")]
pub struct FetchFailure {
    /// Failure class for the state machine.
    pub class: FailureClass,
    /// What happened.
    pub message: String,
}

impl FetchFailure {
    /// A download whose digest differs from the index. The body arrived
    /// complete, so crates.io, its CDN or the path to it served the wrong
    /// bytes: an infrastructure failure. It does not use up the job's
    /// attempts and counts toward the fetch circuit breaker, so a tampered
    /// or broken mirror stops the stage and raises an alert instead of
    /// failing job after job (THREAT_MODEL, downloads).
    fn checksum_mismatch(name: &CrateName, version: &semver::Version) -> Self {
        Self::infrastructure(format!("checksum mismatch for {name} {version}"))
    }

    fn infrastructure(message: impl std::fmt::Display) -> Self {
        Self {
            class: FailureClass::Infrastructure,
            message: message.to_string(),
        }
    }
}

impl From<HttpError> for FetchFailure {
    fn from(error: HttpError) -> Self {
        let class = if error.is_transient() {
            FailureClass::Transient
        } else {
            FailureClass::Permanent
        };
        Self {
            class,
            message: error.to_string(),
        }
    }
}

impl From<StoreError> for FetchFailure {
    fn from(error: StoreError) -> Self {
        Self::infrastructure(error)
    }
}

/// What fetching one job produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchResult {
    /// Stored and resolved (or resolution failed, which is recorded).
    Fetched,
    /// The version no longer exists on crates.io.
    Unavailable,
}

/// Paths and tools of the fetcher.
#[derive(Debug, Clone)]
pub struct FetcherSetup {
    /// The fetcher's own executable, started again for sandboxed children.
    pub exe: PathBuf,
    /// The real `cargo` binary.
    pub cargo: PathBuf,
    /// Scratch space for resolutions (tmpfs).
    pub work_root: PathBuf,
    /// Where original `.crate` files are kept, if at all.
    pub originals: Option<PathBuf>,
    /// The index's `dl` template.
    pub dl: String,
    /// Sparse index root, ending in `/`.
    pub index_root: String,
}

/// The fetch stage worker.
#[derive(Debug)]
pub struct Fetcher {
    store: Store,
    /// A second connection, for heartbeats while `store` is busy.
    heartbeats: Arc<Store>,
    downloads: PoliteClient,
    index: PoliteClient,
    blobs: BlobStore,
    cache: IndexCache,
    setup: FetcherSetup,
    /// Retry budgets and backoff.
    pub policies: Policies,
    /// This worker's lease owner name.
    pub worker: String,
    /// Lease duration.
    pub lease: Duration,
}

fn gunzip(bytes: &[u8], limit: u64) -> std::io::Result<Vec<u8>> {
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(limit)
        .read_to_end(&mut tar)?;
    Ok(tar)
}

impl Fetcher {
    /// A fetcher.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Store,
        heartbeats: Store,
        downloads: PoliteClient,
        index: PoliteClient,
        blobs: BlobStore,
        setup: FetcherSetup,
        policies: Policies,
        worker: String,
        lease: Duration,
    ) -> Self {
        Self {
            store,
            heartbeats: Arc::new(heartbeats),
            downloads,
            index,
            blobs,
            cache: IndexCache::default(),
            setup,
            policies,
            worker,
            lease,
        }
    }

    /// The job store, for reaping expired leases.
    pub fn store(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Claims and processes one job. Returns `false` when there was none.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails while claiming or completing.
    pub async fn run_once(&mut self) -> Result<bool, StoreError> {
        let Some(job) = self
            .store
            .claim(Stage::Fetch, &self.worker, self.lease)
            .await?
        else {
            return Ok(false);
        };
        let beat = heartbeat(
            Arc::clone(&self.heartbeats),
            job.id,
            self.worker.clone(),
            self.lease,
            self.lease / 4,
        );
        let result = self.fetch(&job).await;
        beat.abort();
        let event = match result {
            Ok(FetchResult::Fetched) => JobEvent::Fetched,
            Ok(FetchResult::Unavailable) => JobEvent::Unavailable,
            Err(failure) => {
                tracing::warn!(job = job.id.0, name = %job.name, version = %job.version, %failure, "fetch failed");
                JobEvent::StageFailed {
                    class: failure.class,
                }
            }
        };
        let worker = self.worker.clone();
        let policies = self.policies.clone();
        self.store
            .complete(job.id, &worker, event, &policies, false)
            .await?;
        Ok(true)
    }

    /// Fetches one job's crate and dependencies.
    ///
    /// # Errors
    ///
    /// Returns the failure class for the state machine.
    pub async fn fetch(&self, job: &StoredJob) -> Result<FetchResult, FetchFailure> {
        let name = CrateName::parse(&job.name).map_err(|e| FetchFailure {
            class: FailureClass::Permanent,
            message: e.to_string(),
        })?;
        let version = semver::Version::parse(&job.version).map_err(|e| FetchFailure {
            class: FailureClass::Permanent,
            message: e.to_string(),
        })?;
        let keep = self.setup.originals.is_some();
        if self
            .ensure_crate(&name, &version, &job.cksum, keep)
            .await?
            .is_none()
        {
            return Ok(FetchResult::Unavailable);
        }
        let work = self.setup.work_root.join(format!("job-{}", job.id.0));
        let resolution = resolve(
            &self.setup.exe,
            &self.setup.cargo,
            &work,
            self.index.clone(),
            &self.setup.index_root,
            self.cache.clone(),
            &name,
            &version,
        )
        .await
        .map_err(FetchFailure::infrastructure)?;
        let (lockfile, mut error, packages) = match &resolution {
            Resolution::Locked(lock) => match locked_packages(lock) {
                Ok(packages) => (Some(lock.as_str()), None, packages),
                Err(e) => (Some(lock.as_str()), Some(e), Vec::new()),
            },
            Resolution::Failed(message) => (None, Some(message.clone()), Vec::new()),
        };
        for package in &packages {
            if package.name == name.as_str() && package.version == version.to_string() {
                continue;
            }
            let (Ok(dep_name), Ok(dep_version), Ok(sha)) = (
                CrateName::parse(&package.name),
                semver::Version::parse(&package.version),
                package.checksum.parse::<Sha256Digest>(),
            ) else {
                error.get_or_insert_with(|| format!("invalid locked package {package:?}"));
                continue;
            };
            if self
                .ensure_crate(&dep_name, &dep_version, &sha, false)
                .await?
                .is_none()
            {
                error.get_or_insert_with(|| {
                    format!(
                        "{} {} is missing on crates.io",
                        package.name, package.version
                    )
                });
            }
        }
        let packages_json = serde_json::to_value(&packages).unwrap_or_default();
        self.store
            .record_fetch(job.id, lockfile, error.as_deref(), &packages_json)
            .await?;
        tracing::info!(
            job = job.id.0,
            name = %name,
            version = %version,
            dependencies = packages.len(),
            resolved = error.is_none(),
            "fetched"
        );
        Ok(FetchResult::Fetched)
    }

    /// Makes sure a crate file is downloaded, verified, validated and
    /// stored. Returns `None` if crates.io no longer has it.
    async fn ensure_crate(
        &self,
        name: &CrateName,
        version: &semver::Version,
        sha256: &Sha256Digest,
        keep_original: bool,
    ) -> Result<Option<CrateFile>, FetchFailure> {
        if let Some(file) = self.store.crate_file(sha256).await? {
            return Ok(Some(file));
        }
        let url = download_url(&self.setup.dl, name, version);
        let Some(mut response) = self.downloads.stream(&url).await? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        let mut hasher = sha2::Sha256::new();
        while let Some(chunk) = response.chunk().await.map_err(HttpError::from)? {
            if u64::try_from(bytes.len() + chunk.len()).unwrap_or(u64::MAX) > MAX_CRATE_BYTES {
                return Err(FetchFailure {
                    class: FailureClass::Permanent,
                    message: format!("{name} {version} exceeds {MAX_CRATE_BYTES} bytes"),
                });
            }
            hasher.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if &Sha256Digest::from_bytes(digest) != sha256 {
            tracing::warn!(%name, %version, expected = %sha256, "checksum mismatch");
            return Err(FetchFailure::checksum_mismatch(name, version));
        }
        let exe = self.setup.exe.clone();
        let (n, v) = (name.to_string(), version.to_string());
        let blobs = self.blobs.clone();
        let (report, blob) = tokio::task::spawn_blocking(move || {
            let report = validate_in_sandbox(&exe, &bytes, &n, &v)?;
            let blob = if report.is_storable() {
                let tar = gunzip(&bytes, ArchiveLimits::default().max_unpacked_bytes * 2)?;
                Some(blobs.put(&tar).map_err(std::io::Error::other)?)
            } else {
                None
            };
            Ok::<_, std::io::Error>((report, blob, bytes))
        })
        .await
        .map_err(FetchFailure::infrastructure)?
        .map(|(report, blob, bytes)| {
            if keep_original && let Some(dir) = &self.setup.originals {
                let path = dir.join(format!("{sha256}.crate"));
                if let Err(error) =
                    std::fs::create_dir_all(dir).and_then(|()| std::fs::write(&path, &bytes))
                {
                    tracing::warn!(%error, "cannot keep the original crate file");
                }
            }
            (report, blob)
        })
        .map_err(FetchFailure::infrastructure)?;
        if !report.findings.is_empty() || report.aborted.is_some() {
            tracing::warn!(%name, %version, findings = report.findings.len(), aborted = ?report.aborted, "archive findings");
        }
        let file = CrateFile {
            sha256: *sha256,
            name: name.to_string(),
            version: version.to_string(),
            blake3: blob.as_ref().map(|b| b.blake3.clone()),
            compressed_bytes: i64::try_from(report.compressed_bytes).unwrap_or(i64::MAX),
            unpacked_bytes: i64::try_from(report.unpacked_bytes).unwrap_or(i64::MAX),
            stored_bytes: blob.map(|b| i64::try_from(b.stored_bytes).unwrap_or(i64::MAX)),
            report: serde_json::to_value(&report).unwrap_or_default(),
        };
        self.store.record_crate_file(&file).await?;
        Ok(Some(file))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_mismatches_feed_the_circuit_breaker() {
        let name: CrateName = "serde".parse().unwrap();
        let failure = FetchFailure::checksum_mismatch(&name, &semver::Version::new(1, 0, 0));
        // Only infrastructure failures are counted by the breaker
        // (`Store::stage_counts`).
        assert_eq!(failure.class, FailureClass::Infrastructure);
        assert_eq!(failure.message, "checksum mismatch for serde 1.0.0");
    }
}
