//! A job's CycloneDX documents (ADR 0012): the stored SBOM, and the
//! findings document that points into it. The findings document is built
//! on request, since a review changes it.

use crateward_core::cyclonedx::{self, VexInput};
use crateward_core::job::JobId;
use crateward_core::store::{Store, StoreError};
use serde_json::Value;

use crate::encode;
use crate::export::DOMAIN;

/// Crateward's version, named as the tool in the documents.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The media type of CycloneDX JSON.
pub const MEDIA_TYPE: &str = "application/vnd.cyclonedx+json";

/// A job's two documents.
#[derive(Debug, Clone, PartialEq)]
pub struct Documents {
    /// The crate's name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// The SBOM.
    pub sbom: Value,
    /// The findings document.
    pub vex: Value,
}

impl Documents {
    /// `name-version`, with only characters that are safe in a file name.
    fn stem(&self) -> String {
        format!("{}-{}", self.name, self.version)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
            .collect()
    }

    /// The SBOM's file name, `name-version.cdx.json`.
    #[must_use]
    pub fn sbom_file(&self) -> String {
        format!("{}.cdx.json", self.stem())
    }

    /// The findings document's file name, `name-version.vex.cdx.json`.
    #[must_use]
    pub fn vex_file(&self) -> String {
        format!("{}.vex.cdx.json", self.stem())
    }
}

/// The documents of job `id`. `None` if there is no such job, or it has
/// no SBOM or no verdict yet.
///
/// # Errors
///
/// Fails on database errors.
pub async fn documents(store: &Store, id: i64) -> Result<Option<Documents>, StoreError> {
    let job = JobId(id);
    let (Some(stored), Some(found), Some((verdict, review)), Some((revision, changed))) = (
        store.get(job).await?,
        store.job_sbom(job).await?,
        store.verdict(job).await?,
        store.verdict_revision(job).await?,
    ) else {
        return Ok(None);
    };

    let lockfile = store.fetch_lockfile(job).await?;
    let honeytokens = store.honeytoken_values(job).await?;
    let runs = store.run_kinds(job).await?;
    let finding_url = store
        .disclosure(job)
        .await?
        .and_then(|d| d.published_on.and(d.slug))
        .map(|slug| format!("https://{DOMAIN}/findings/{}/", encode(&slug)));

    let vex = cyclonedx::vex(&VexInput {
        job: id,
        name: &stored.name,
        version: &stored.version,
        sbom: (&found.serial, found.version),
        lockfile: lockfile.as_deref(),
        verdict: &verdict,
        review,
        revision,
        finding_url: finding_url.as_deref(),
        honeytokens: &honeytokens,
        coverage: verdict.coverage.label(),
        runs: &runs,
        timestamp: changed,
        tool_version: TOOL_VERSION,
    });

    Ok(Some(Documents {
        name: stored.name,
        version: stored.version,
        sbom: found.document,
        vex,
    }))
}
