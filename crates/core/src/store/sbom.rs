//! Stored SBOMs and the facts they are made from (ADR 0012).

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Store, StoreError, digest_column};
use crate::cyclonedx::{self, FileFacts, Sbom, SbomInput};
use crate::digest::Sha256Digest;
use crate::job::JobId;
use crate::package::PackageMeta;

/// A stored SBOM.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSbom {
    /// `urn:uuid:...`.
    pub serial: String,
    /// The document's version, from 1.
    pub version: i32,
    /// How many of TR-03183-2's fields the data lacked.
    pub gaps: i32,
    /// The document.
    pub document: Value,
}

/// What [`Store::refresh_sbom`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SbomOutcome {
    /// The job has no fetch record, so there is nothing to list.
    NotFetched,
    /// A stored SBOM was kept: it is complete, or the new one is no better.
    Kept,
    /// The SBOM was written with this version. The gaps are what is still
    /// missing.
    Written {
        /// The document's version.
        version: i32,
        /// What TR-03183-2 asks for and the data lacks.
        gaps: Vec<String>,
    },
}

/// How many fields an SBOM lacks, as the `gaps` column stores it.
fn gap_count(sbom: &Sbom) -> i32 {
    i32::try_from(sbom.gaps.len()).unwrap_or(i32::MAX)
}

/// What a job's SBOM is made from.
struct SbomSource {
    name: String,
    version: String,
    sha256: Sha256Digest,
    lockfile: Option<String>,
    /// The database's clock, in seconds since the epoch.
    now: i64,
}

impl Store {
    /// The SHA-512 and manifest facts of crate files. Files that are not
    /// recorded are missing from the map.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn file_facts(
        &self,
        files: &[Sha256Digest],
    ) -> Result<BTreeMap<Sha256Digest, FileFacts>, StoreError> {
        let keys: Vec<&[u8]> = files.iter().map(|f| f.as_bytes().as_slice()).collect();
        let rows = self
            .client
            .query(
                "SELECT f.sha256, f.sha512, r.report -> 'manifest' -> 'package'
                 FROM crate_files f LEFT JOIN static_reports r ON r.sha256 = f.sha256
                 WHERE f.sha256 = ANY($1)",
                &[&keys],
            )
            .await?;

        rows.into_iter()
            .map(|r| {
                let meta: Option<Value> = r.try_get(2)?;
                let facts = FileFacts {
                    sha512: r.try_get(1)?,
                    meta: meta.and_then(|m| serde_json::from_value::<PackageMeta>(m).ok()),
                };

                Ok((digest_column(r.try_get(0)?)?, facts))
            })
            .collect()
    }

    /// The stored SBOM of a job's crate file and lockfile.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn job_sbom(&self, job: JobId) -> Result<Option<StoredSbom>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT s.serial, s.version, s.gaps, s.document
                 FROM jobs j JOIN job_fetches f ON f.job_id = j.id
                 JOIN sboms s ON s.crate_sha256 = j.cksum
                     AND s.lockfile_key = f.lockfile_key
                 WHERE j.id = $1",
                &[&job.0],
            )
            .await?;

        row.map(|r| {
            Ok(StoredSbom {
                serial: r.try_get(0)?,
                version: r.try_get(1)?,
                gaps: r.try_get(2)?,
                document: r.try_get(3)?,
            })
        })
        .transpose()
    }

    /// What the SBOM of a job is made from, if the job was fetched.
    async fn sbom_source(&self, job: JobId) -> Result<Option<SbomSource>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT j.crate_name, j.version, j.cksum, f.lockfile,
                        extract(epoch FROM now())::bigint
                 FROM jobs j JOIN job_fetches f ON f.job_id = j.id WHERE j.id = $1",
                &[&job.0],
            )
            .await?;

        row.map(|r| {
            Ok(SbomSource {
                name: r.try_get(0)?,
                version: r.try_get(1)?,
                sha256: digest_column(r.try_get(2)?)?,
                lockfile: r.try_get(3)?,
                now: r.try_get(4)?,
            })
        })
        .transpose()
    }

    /// Writes the SBOM of a job, unless a stored one is complete or the new
    /// one lacks as much. A replaced document keeps its serial number and
    /// gets the next version.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn refresh_sbom(
        &self,
        job: JobId,
        tool_version: &str,
    ) -> Result<SbomOutcome, StoreError> {
        let Some(source) = self.sbom_source(job).await? else {
            return Ok(SbomOutcome::NotFetched);
        };

        let stored = self.job_sbom(job).await?;
        if stored.as_ref().is_some_and(|s| s.gaps == 0) {
            return Ok(SbomOutcome::Kept);
        }

        let mut sbom = self.build_sbom(&source, tool_version).await?;
        let key = cyclonedx::lockfile_key(source.lockfile.as_deref());
        let gaps = gap_count(&sbom);

        if stored.as_ref().is_some_and(|s| s.gaps <= gaps) {
            self.client
                .execute(
                    "UPDATE sboms SET checked_at = now()
                     WHERE crate_sha256 = $1 AND lockfile_key = $2",
                    &[&source.sha256.as_bytes().as_slice(), &key.as_slice()],
                )
                .await?;

            return Ok(SbomOutcome::Kept);
        }

        let next = stored.map_or(1, |s| s.version + 1);
        if let Some(document) = sbom.document.as_object_mut() {
            document.insert("version".into(), next.into());
        }

        self.write_sbom(&source.sha256, &key, &sbom, next).await?;

        Ok(SbomOutcome::Written {
            version: next,
            gaps: sbom.gaps,
        })
    }

    /// Builds the SBOM of a job from its lockfile and the facts of its
    /// crate files.
    async fn build_sbom(
        &self,
        source: &SbomSource,
        tool_version: &str,
    ) -> Result<Sbom, StoreError> {
        let lockfile = source.lockfile.as_deref();
        let locked = lockfile.and_then(cyclonedx::locked);
        let mut wanted = vec![source.sha256];
        wanted.extend(locked.iter().flatten().filter_map(|p| p.checksum));
        let files = self.file_facts(&wanted).await?;

        Ok(cyclonedx::sbom(&SbomInput {
            name: &source.name,
            version: &source.version,
            sha256: source.sha256,
            lockfile,
            files: &files,
            timestamp: source.now,
            tool_version,
        }))
    }

    /// Stores an SBOM, unless the stored one has no more gaps.
    async fn write_sbom(
        &self,
        sha256: &Sha256Digest,
        key: &[u8],
        sbom: &Sbom,
        version: i32,
    ) -> Result<(), StoreError> {
        let gaps = gap_count(sbom);
        self.client
            .execute(
                "INSERT INTO sboms (crate_sha256, lockfile_key, serial, version, gaps, document)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (crate_sha256, lockfile_key) DO UPDATE
                 SET version = $4, gaps = $5, document = $6, created_at = now(),
                     checked_at = now()
                 WHERE sboms.gaps > $5",
                &[
                    &sha256.as_bytes().as_slice(),
                    &key,
                    &sbom.serial,
                    &version,
                    &gaps,
                    &sbom.document,
                ],
            )
            .await?;

        Ok(())
    }

    /// Finished jobs without an SBOM, the newest first, then jobs whose
    /// SBOM has gaps and was not checked for a day.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn jobs_needing_sbom(&self, limit: i64) -> Result<Vec<JobId>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT j.id FROM jobs j JOIN job_fetches f ON f.job_id = j.id
                 LEFT JOIN sboms s ON s.crate_sha256 = j.cksum
                     AND s.lockfile_key = f.lockfile_key
                 WHERE j.state = 'Done'
                   AND (s.serial IS NULL
                        OR (s.gaps > 0 AND s.checked_at < now() - interval '1 day'))
                 ORDER BY s.serial IS NOT NULL, j.id DESC
                 LIMIT $1",
                &[&limit],
            )
            .await?;

        rows.iter().map(|r| Ok(JobId(r.try_get(0)?))).collect()
    }

    /// How often a job's verdict or review changed, and when last, in
    /// seconds since the epoch. A published finding counts as one more
    /// change, since the findings document then links its page.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn verdict_revision(&self, job: JobId) -> Result<Option<(i32, i64)>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT v.revision + (d.published_at IS NOT NULL)::integer,
                        extract(epoch FROM greatest(v.scored_at, v.reviewed_at, d.published_at))::bigint
                 FROM verdicts v LEFT JOIN disclosures d ON d.job_id = v.job_id
                 WHERE v.job_id = $1",
                &[&job.0],
            )
            .await?;

        row.map(|r| Ok((r.try_get(0)?, r.try_get(1)?))).transpose()
    }

    /// The kinds of VM runs a job had, `check` before `full`.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn run_kinds(&self, job: JobId) -> Result<Vec<String>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT run_kind FROM job_runs WHERE job_id = $1 ORDER BY run_kind",
                &[&job.0],
            )
            .await?;

        rows.iter().map(|r| Ok(r.try_get(0)?)).collect()
    }
}
