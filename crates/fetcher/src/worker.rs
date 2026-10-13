//! The fetch stage worker.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crateward_core::bytes::hex;
use crateward_core::cratesio::download_url;
use crateward_core::digest::Sha256Digest;
use crateward_core::failure::Failure;
use crateward_core::http::{HttpError, PoliteClient};
use crateward_core::job::{JobEvent, Stage};
use crateward_core::name::CrateName;
use crateward_core::store::{CrateFile, Policies, Store, StoreError, StoredJob, heartbeat};
use sha2::Digest as _;

use crate::archive::{ArchiveLimits, ArchiveReport};
use crate::proxy::Index;
use crate::resolve::{LockedPackage, Resolution, locked_packages, resolve};
use crate::sandboxed::{MAX_CRATE_BYTES, validate_in_sandbox};
use crateward_core::blobs::{Blob, BlobStore};

/// A download whose digest differs from the index. The body arrived
/// complete, so crates.io, its CDN or the path to it served the wrong bytes:
/// an infrastructure failure. It does not use up the job's attempts and
/// counts toward the fetch circuit breaker, so a tampered or broken mirror
/// stops the stage and raises an alert instead of failing job after job
/// (THREAT_MODEL, downloads).
fn checksum_mismatch(name: &CrateName, version: &semver::Version) -> Failure {
    Failure::infrastructure(format!("checksum mismatch for {name} {version}"))
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
    /// Where the crate files are stored.
    pub blobs: BlobStore,
}

/// The fetch stage worker.
#[derive(Debug)]
pub struct Fetcher {
    store: Store,
    /// A second connection, for heartbeats while `store` is busy.
    heartbeats: Arc<Store>,
    downloads: PoliteClient,
    index: Index,
    setup: FetcherSetup,
    /// Retry budgets and backoff.
    pub policies: Policies,
    /// This worker's lease owner name.
    pub worker: String,
    /// Lease duration.
    pub lease: Duration,
    /// Crate files whose SHA-512 cannot be computed.
    unhashable: HashSet<Sha256Digest>,
}

fn gunzip(bytes: &[u8], limit: u64) -> std::io::Result<Vec<u8>> {
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(limit)
        .read_to_end(&mut tar)?;

    Ok(tar)
}

/// Keeps the original `.crate` file, named by its digest.
fn keep_original(dir: &Path, sha256: &Sha256Digest, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;

    std::fs::write(dir.join(format!("{sha256}.crate")), bytes)
}

impl Fetcher {
    /// A fetcher.
    #[must_use]
    pub fn new(
        store: Store,
        heartbeats: Store,
        downloads: PoliteClient,
        index: Index,
        setup: FetcherSetup,
        policies: Policies,
        lease: Duration,
    ) -> Self {
        Self {
            store,
            heartbeats: Arc::new(heartbeats),
            downloads,
            index,
            setup,
            policies,
            worker: format!("fetcher-{}", std::process::id()),
            lease,
            unhashable: HashSet::new(),
        }
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

        self.store
            .complete(job.id, &self.worker, event, &self.policies, false)
            .await?;

        Ok(true)
    }

    /// Fetches one job's crate and dependencies.
    ///
    /// # Errors
    ///
    /// Returns the failure class for the state machine.
    pub async fn fetch(&self, job: &StoredJob) -> Result<FetchResult, Failure> {
        let name = CrateName::parse(&job.name).map_err(Failure::permanent)?;
        let version = semver::Version::parse(&job.version).map_err(Failure::permanent)?;
        let originals = self.setup.originals.as_deref();
        if self
            .ensure_crate(&name, &version, &job.cksum, originals)
            .await?
            .is_none()
        {
            return Ok(FetchResult::Unavailable);
        }

        let work = self.setup.work_root.join(format!("job-{}", job.id.0));
        let index = self.index.clone();
        let resolution = resolve(
            &self.setup.exe,
            &self.setup.cargo,
            &work,
            index,
            &name,
            &version,
        )
        .await
        .map_err(Failure::infrastructure)?;

        let (lockfile, error, packages) = match &resolution {
            Resolution::Locked(lock) => match locked_packages(lock) {
                Ok(packages) => (Some(lock.as_str()), None, packages),
                Err(e) => (Some(lock.as_str()), Some(e.to_string()), Vec::new()),
            },
            Resolution::Failed(message) => (None, Some(message.clone()), Vec::new()),
        };

        let missing = self.fetch_dependencies(&name, &version, &packages).await?;
        let error = error.or(missing);
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

    /// Fetches the packages of a lockfile, except the crate itself. Returns
    /// the first problem with a package, which the job records but does not
    /// fail on.
    async fn fetch_dependencies(
        &self,
        name: &CrateName,
        version: &semver::Version,
        packages: &[LockedPackage],
    ) -> Result<Option<String>, Failure> {
        let mut problem = None;

        for package in packages {
            if package.name == name.as_str() && package.version == version.to_string() {
                continue;
            }

            let (Ok(dep_name), Ok(dep_version), Ok(sha)) = (
                CrateName::parse(&package.name),
                semver::Version::parse(&package.version),
                package.checksum.parse::<Sha256Digest>(),
            ) else {
                problem.get_or_insert_with(|| format!("invalid locked package {package:?}"));
                continue;
            };

            if self
                .ensure_crate(&dep_name, &dep_version, &sha, None)
                .await?
                .is_none()
            {
                problem.get_or_insert_with(|| {
                    format!(
                        "{} {} is missing on crates.io",
                        package.name, package.version
                    )
                });
            }
        }

        Ok(problem)
    }

    /// Makes sure a crate file is downloaded, verified, validated and
    /// stored. Returns `None` if crates.io no longer has it. The original
    /// file is kept in `originals`, if given.
    async fn ensure_crate(
        &self,
        name: &CrateName,
        version: &semver::Version,
        sha256: &Sha256Digest,
        originals: Option<&Path>,
    ) -> Result<Option<CrateFile>, Failure> {
        if let Some(file) = self.store.crate_file(sha256).await? {
            return Ok(Some(file));
        }

        let Some((bytes, sha512)) = self.download(name, version, sha256).await? else {
            return Ok(None);
        };

        let bytes = Arc::new(bytes);
        let (report, blob) = self.validate(name, version, Arc::clone(&bytes)).await?;

        if let Some(dir) = originals
            && let Err(error) = keep_original(dir, sha256, &bytes)
        {
            tracing::warn!(%error, "cannot keep the original crate file");
        }

        if !report.findings.is_empty() || report.aborted.is_some() {
            tracing::warn!(%name, %version, findings = report.findings.len(), aborted = ?report.aborted, "archive findings");
        }

        let file = CrateFile {
            sha256: *sha256,
            sha512: Some(sha512),
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

    /// Downloads a crate file and checks it against the digest from the
    /// index. Returns the bytes and their SHA-512 in hex, which SBOMs need
    /// (ADR 0012), or `None` if crates.io no longer has it.
    async fn download(
        &self,
        name: &CrateName,
        version: &semver::Version,
        sha256: &Sha256Digest,
    ) -> Result<Option<(Vec<u8>, String)>, Failure> {
        let url = download_url(&self.setup.dl, name, version);
        let Some(mut response) = self.downloads.stream(&url).await? else {
            return Ok(None);
        };

        let mut bytes = Vec::new();
        let mut hasher = sha2::Sha256::new();
        let mut sha512 = sha2::Sha512::new();

        while let Some(chunk) = response.chunk().await.map_err(HttpError::from)? {
            if u64::try_from(bytes.len() + chunk.len()).unwrap_or(u64::MAX) > MAX_CRATE_BYTES {
                return Err(Failure::permanent(format!(
                    "{name} {version} exceeds {MAX_CRATE_BYTES} bytes"
                )));
            }

            hasher.update(&chunk);
            sha512.update(&chunk);
            bytes.extend_from_slice(&chunk);
        }

        let digest: [u8; 32] = hasher.finalize().into();
        if &Sha256Digest::from_bytes(digest) != sha256 {
            tracing::warn!(%name, %version, expected = %sha256, "checksum mismatch");
            return Err(checksum_mismatch(name, version));
        }

        let sha512 = hex(&sha512.finalize());

        Ok(Some((bytes, sha512)))
    }

    /// Downloads one crate file fetched before SHA-512 was computed and
    /// records its SHA-512, so older SBOMs can be completed. Files that
    /// crates.io no longer serves or that fail are skipped until the
    /// fetcher restarts. Returns `false` when there was nothing to hash.
    ///
    /// # Errors
    ///
    /// Fails only if the store fails.
    pub async fn hash_one(&mut self) -> Result<bool, StoreError> {
        let limit = i64::try_from(self.unhashable.len() + 1).unwrap_or(i64::MAX);
        let Some(file) = self
            .store
            .unhashed_crate_files(limit)
            .await?
            .into_iter()
            .find(|f| !self.unhashable.contains(&f.sha256))
        else {
            return Ok(false);
        };

        let (Ok(name), Ok(version)) = (
            CrateName::parse(&file.name),
            semver::Version::parse(&file.version),
        ) else {
            self.unhashable.insert(file.sha256);
            return Ok(true);
        };

        match self.download(&name, &version, &file.sha256).await {
            Ok(Some((_, sha512))) => self.store.record_sha512(&file.sha256, &sha512).await?,
            Ok(None) => {
                tracing::info!(%name, %version, "gone from crates.io, no SHA-512");
                self.unhashable.insert(file.sha256);
            }
            Err(failure) => {
                tracing::warn!(%name, %version, %failure, "cannot compute the SHA-512");
                self.unhashable.insert(file.sha256);
            }
        }

        Ok(true)
    }

    /// Validates a downloaded crate file in the sandbox. A sound archive is
    /// also unpacked into the blob store.
    async fn validate(
        &self,
        name: &CrateName,
        version: &semver::Version,
        bytes: Arc<Vec<u8>>,
    ) -> Result<(ArchiveReport, Option<Blob>), Failure> {
        let exe = self.setup.exe.clone();
        let blobs = self.setup.blobs.clone();
        let (name, version) = (name.to_string(), version.to_string());

        tokio::task::spawn_blocking(move || {
            let report = validate_in_sandbox(&exe, &bytes, &name, &version)?;
            let blob = if report.is_storable() {
                let tar = gunzip(&bytes, ArchiveLimits::default().max_unpacked_bytes * 2)?;
                Some(blobs.put(&tar).map_err(std::io::Error::other)?)
            } else {
                None
            };

            Ok::<_, std::io::Error>((report, blob))
        })
        .await
        .map_err(Failure::infrastructure)?
        .map_err(Failure::infrastructure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crateward_core::failure::FailureClass;

    #[test]
    fn checksum_mismatches_feed_the_circuit_breaker() {
        let name: CrateName = "serde".parse().unwrap();
        let failure = checksum_mismatch(&name, &semver::Version::new(1, 0, 0));

        // Only infrastructure failures are counted by the breaker
        // (`Store::stage_counts`).
        assert_eq!(failure.class, FailureClass::Infrastructure);
        assert_eq!(failure.message, "checksum mismatch for serde 1.0.0");
    }

    #[test]
    fn originals_are_named_by_their_digest() {
        let dir = std::env::temp_dir().join(format!("cw-originals-{}", std::process::id()));
        let sha256 = Sha256Digest::from_bytes([7; 32]);
        keep_original(&dir.join("nested"), &sha256, b"crate").unwrap();
        let path = dir.join("nested").join(format!("{sha256}.crate"));

        assert_eq!(std::fs::read(path).unwrap(), b"crate");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unpacking_stops_at_the_limit() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&[0; 1000]).unwrap();
        let bytes = gz.finish().unwrap();

        assert_eq!(gunzip(&bytes, 1_000_000).unwrap().len(), 1000);
        assert_eq!(gunzip(&bytes, 10).unwrap().len(), 10);
    }
}
