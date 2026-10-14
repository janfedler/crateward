//! Crate files, their fetches and static reports, and what the warm build
//! cache reads about them.

use serde_json::Value;

use super::{CrateFile, Store, StoreError, Unhashed, digest_column};
use crate::digest::Sha256Digest;
use crate::job::JobId;
use crate::name::CrateName;

impl Store {
    /// Records a validated crate file. Recording the same file twice is
    /// a no op.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_crate_file(&self, file: &CrateFile) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO crate_files (sha256, crate_name, version, blake3, compressed_bytes,
                                          unpacked_bytes, stored_bytes, report, sha512)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (sha256) DO NOTHING",
                &[
                    &file.sha256.as_bytes().as_slice(),
                    &file.name,
                    &file.version,
                    &file.blake3,
                    &file.compressed_bytes,
                    &file.unpacked_bytes,
                    &file.stored_bytes,
                    &file.report,
                    &file.sha512,
                ],
            )
            .await?;

        Ok(())
    }

    /// Records the SHA-512 of a crate file.
    ///
    /// # Errors
    ///
    /// Fails on database errors, including a hash that is not 128 lowercase
    /// hex digits.
    pub async fn record_sha512(
        &self,
        sha256: &Sha256Digest,
        sha512: &str,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "UPDATE crate_files SET sha512 = $2 WHERE sha256 = $1",
                &[&sha256.as_bytes().as_slice(), &sha512],
            )
            .await?;

        Ok(())
    }

    /// Crate files without SHA-512, the newest first, since they belong to
    /// the jobs people look at.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn unhashed_crate_files(&self, limit: i64) -> Result<Vec<Unhashed>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT sha256, crate_name, version FROM crate_files
                 WHERE sha512 IS NULL ORDER BY fetched_at DESC LIMIT $1",
                &[&limit],
            )
            .await?;

        rows.into_iter()
            .map(|r| {
                Ok(Unhashed {
                    sha256: digest_column(r.try_get(0)?)?,
                    name: r.try_get(1)?,
                    version: r.try_get(2)?,
                })
            })
            .collect()
    }

    /// A recorded crate file by its SHA-256.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn crate_file(&self, sha256: &Sha256Digest) -> Result<Option<CrateFile>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT crate_name, version, blake3, compressed_bytes, unpacked_bytes,
                        stored_bytes, report, sha512
                 FROM crate_files WHERE sha256 = $1",
                &[&sha256.as_bytes().as_slice()],
            )
            .await?;

        row.map(|r| {
            Ok(CrateFile {
                sha256: *sha256,
                sha512: r.try_get(7)?,
                name: r.try_get(0)?,
                version: r.try_get(1)?,
                blake3: r.try_get(2)?,
                compressed_bytes: r.try_get(3)?,
                unpacked_bytes: r.try_get(4)?,
                stored_bytes: r.try_get(5)?,
                report: r.try_get(6)?,
            })
        })
        .transpose()
    }

    /// Records the fetch stage's result for a job, replacing an earlier one
    /// (a retried fetch overwrites it).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_fetch(
        &self,
        job: JobId,
        lockfile: Option<&str>,
        resolution_error: Option<&str>,
        packages: &Value,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO job_fetches (job_id, lockfile, resolution_error, packages, lockfile_key)
                 VALUES ($1, $2, $3, $4, sha256(convert_to(coalesce($2, ''), 'UTF8')))
                 ON CONFLICT (job_id) DO UPDATE
                 SET lockfile = $2, resolution_error = $3, packages = $4, fetched_at = now(),
                     lockfile_key = EXCLUDED.lockfile_key",
                &[&job.0, &lockfile, &resolution_error, packages],
            )
            .await?;

        Ok(())
    }

    /// Replaces the popularity of the given crates (name, downloads,
    /// reverse dependencies) in batches.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn upsert_crate_stats(
        &self,
        stats: &[(String, i64, i64)],
    ) -> Result<u64, StoreError> {
        let mut written = 0;

        for chunk in stats.chunks(10_000) {
            let names: Vec<&str> = chunk.iter().map(|s| s.0.as_str()).collect();
            let canonical: Vec<String> = chunk
                .iter()
                .map(|s| s.0.to_ascii_lowercase().replace('-', "_"))
                .collect();

            let downloads: Vec<i64> = chunk.iter().map(|s| s.1).collect();
            let reverse: Vec<i64> = chunk.iter().map(|s| s.2).collect();
            written += self
                .client
                .execute(
                    "INSERT INTO crate_stats (canonical_name, crate_name, downloads, reverse_dependencies)
                     SELECT * FROM unnest($1::text[], $2::text[], $3::bigint[], $4::bigint[])
                     ON CONFLICT (canonical_name) DO UPDATE
                     SET crate_name = EXCLUDED.crate_name, downloads = EXCLUDED.downloads,
                         reverse_dependencies = EXCLUDED.reverse_dependencies, updated_at = now()",
                    &[&canonical, &names, &downloads, &reverse],
                )
                .await?;
        }

        Ok(written)
    }

    /// Reverse dependency count of a crate, if the dump knows it.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn reverse_dependencies(&self, name: &CrateName) -> Result<Option<i64>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT reverse_dependencies FROM crate_stats WHERE canonical_name = $1",
                &[&name.canonical()],
            )
            .await?
            .map(|r| r.get(0)))
    }

    /// The stored static report of a crate file: analyzer version and
    /// report.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn static_report(
        &self,
        sha256: &Sha256Digest,
    ) -> Result<Option<(i32, Value)>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT analyzer_version, report FROM static_reports WHERE sha256 = $1",
                &[&sha256.as_bytes().as_slice()],
            )
            .await?
            .map(|r| (r.get(0), r.get(1))))
    }

    /// Crate files whose static report an older analyzer wrote: those of
    /// scored jobs first, verdicts waiting for review before the others and
    /// the newest first, then dependencies, whose licences SBOMs list.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn outdated_static_reports(
        &self,
        analyzer_version: i32,
        limit: i64,
    ) -> Result<Vec<Sha256Digest>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT r.sha256, coalesce(max(v.job_id), 0) FROM static_reports r
                 LEFT JOIN jobs j ON j.cksum = r.sha256
                 LEFT JOIN verdicts v ON v.job_id = j.id
                 WHERE r.analyzer_version < $1
                 GROUP BY r.sha256
                 ORDER BY count(v.job_id) > 0 DESC, bool_or(v.review = 'pending') DESC,
                          max(v.job_id) DESC NULLS LAST
                 LIMIT $2",
                &[&analyzer_version, &limit],
            )
            .await?;

        rows.iter()
            .map(|r| {
                let bytes: Vec<u8> = r.get(0);
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| StoreError::Corrupt {
                    id: r.get(1),
                    reason: "checksum is not 32 bytes".into(),
                })?;

                Ok(Sha256Digest::from_bytes(bytes))
            })
            .collect()
    }

    /// Stores or replaces the static report of a crate file.
    ///
    /// # Errors
    ///
    /// Fails on database errors, including a crate file that is not recorded.
    pub async fn record_static_report(
        &self,
        sha256: &Sha256Digest,
        analyzer_version: i32,
        build_time_code: bool,
        max_severity: Option<&str>,
        report: &Value,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO static_reports (sha256, analyzer_version, build_time_code, max_severity, report)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (sha256) DO UPDATE
                 SET analyzer_version = $2, build_time_code = $3, max_severity = $4,
                     report = $5, analyzed_at = now()",
                &[&sha256.as_bytes().as_slice(), &analyzer_version, &build_time_code, &max_severity, report],
            )
            .await?;

        Ok(())
    }

    /// The locked packages the fetch stage recorded for a job, as stored.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn fetch_packages(&self, job: JobId) -> Result<Option<Value>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT packages FROM job_fetches WHERE job_id = $1",
                &[&job.0],
            )
            .await?
            .map(|r| r.get(0)))
    }

    /// Other versions of a crate that have a fetch record: job, version and
    /// locked packages.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn other_fetches(
        &self,
        name: &CrateName,
        except: JobId,
    ) -> Result<Vec<(JobId, String, Sha256Digest, Value)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT j.id, j.version, j.cksum, f.packages
                 FROM jobs j JOIN job_fetches f ON f.job_id = j.id
                 WHERE j.canonical_name = $1 AND j.id <> $2",
                &[&name.canonical(), &except.0],
            )
            .await?;

        rows.iter()
            .map(|r| {
                let id: i64 = r.try_get(0)?;
                let cksum: Vec<u8> = r.try_get(2)?;
                let cksum: [u8; 32] = cksum.try_into().map_err(|_| StoreError::Corrupt {
                    id,
                    reason: "checksum is not 32 bytes".into(),
                })?;

                Ok((
                    JobId(id),
                    r.try_get(1)?,
                    Sha256Digest::from_bytes(cksum),
                    r.try_get(3)?,
                ))
            })
            .collect()
    }

    /// The canonical names among `names` of crates with at least
    /// `min_reverse` reverse dependencies or `min_downloads` downloads.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn popular_among(
        &self,
        names: &[String],
        min_reverse: i64,
        min_downloads: i64,
    ) -> Result<Vec<String>, StoreError> {
        let canonical: Vec<String> = names
            .iter()
            .map(|n| n.to_ascii_lowercase().replace('-', "_"))
            .collect();

        let rows = self
            .client
            .query(
                "SELECT canonical_name FROM crate_stats
                 WHERE canonical_name = ANY($1)
                   AND (reverse_dependencies >= $2 OR downloads >= $3)",
                &[&canonical, &min_reverse, &min_downloads],
            )
            .await?;

        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    /// Recent fetch records that have a lockfile, newest first: job, crate
    /// name, version, lockfile and locked packages. The warm build replays
    /// them (ADR 0006).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn recent_fetches(
        &self,
        limit: i64,
    ) -> Result<Vec<(JobId, String, String, String, Value)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT j.id, j.crate_name, j.version, f.lockfile, f.packages
                 FROM job_fetches f JOIN jobs j ON j.id = f.job_id
                 WHERE f.lockfile IS NOT NULL AND f.packages IS NOT NULL
                 ORDER BY f.fetched_at DESC LIMIT $1",
                &[&limit],
            )
            .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    JobId(r.try_get(0)?),
                    r.try_get(1)?,
                    r.try_get(2)?,
                    r.try_get(3)?,
                    r.try_get(4)?,
                ))
            })
            .collect()
    }

    /// The BLAKE3 blob names of the given crate files (SHA-256) that are
    /// stored.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn crate_blobs(
        &self,
        sha256: &[Vec<u8>],
    ) -> Result<Vec<(Vec<u8>, String)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT sha256, blake3 FROM crate_files
                 WHERE sha256 = ANY($1) AND blake3 IS NOT NULL",
                &[&sha256],
            )
            .await?;

        rows.iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect()
    }

    /// Of the given crate files (SHA-256), those Crateward stored at least
    /// `min_age_secs` ago that have a static report and no report with a
    /// high severity finding, with the BLAKE3 name of their blob. This is the
    /// gate of the warm build cache (ADR 0006).
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn warm_eligible(
        &self,
        sha256: &[Vec<u8>],
        min_age_secs: f64,
    ) -> Result<Vec<(Vec<u8>, String)>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT cf.sha256, cf.blake3 FROM crate_files cf
                 WHERE cf.sha256 = ANY($1)
                   AND cf.fetched_at <= now() - make_interval(secs => $2)
                   AND EXISTS (SELECT 1 FROM static_reports s WHERE s.sha256 = cf.sha256)
                   AND NOT EXISTS (SELECT 1 FROM static_reports s
                                   WHERE s.sha256 = cf.sha256 AND s.max_severity = 'high')",
                &[&sha256, &min_age_secs],
            )
            .await?;

        rows.iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
            .collect()
    }

    /// Records the static analysis decision of a job.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_job_static(
        &self,
        job: JobId,
        triage: &Value,
        reasons: &Value,
        diff: Option<&Value>,
    ) -> Result<(), StoreError> {
        self.client
            .execute(
                "INSERT INTO job_static (job_id, triage, reasons, diff) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (job_id) DO UPDATE
                 SET triage = $2, reasons = $3, diff = $4, analyzed_at = now()",
                &[&job.0, triage, reasons, &diff],
            )
            .await?;

        Ok(())
    }

    /// The lockfile the fetch stage recorded for a job.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn fetch_lockfile(&self, job: JobId) -> Result<Option<String>, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT lockfile FROM job_fetches WHERE job_id = $1",
                &[&job.0],
            )
            .await?
            .and_then(|r| r.get(0)))
    }
}
