//! Disclosure records (DISCLOSURE.md): a confirmed finding is reported,
//! the recipient acts, and only then is it published. A malicious crate
//! that crates.io removed before any report is recorded as such, resolved
//! by the removal. The database enforces the order. The public export
//! reads published rows only.

use super::{Store, StoreError};
use crate::job::JobId;

/// What kind of problem a finding is. Each has its own reporting path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureKind {
    /// Intentionally harmful code: reported to the crates.io team.
    Malicious,
    /// An unintended flaw: reported to the crate's owners first.
    Vulnerability,
}

impl DisclosureKind {
    /// Name stored in the database.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Vulnerability => "vulnerability",
        }
    }

    /// The kind of a stored name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Malicious, Self::Vulnerability]
            .into_iter()
            .find(|k| k.name() == name)
    }
}

/// Why a disclosure step was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisclosureRefusal {
    /// Only a verdict a human confirmed is reported.
    #[error("the verdict is not confirmed: review it first")]
    NotConfirmed,
    /// The step needs a report first.
    #[error("no report is recorded for this job")]
    NotReported,
    /// Publishing waits until the recipient acted.
    #[error("the report is not resolved yet and the embargo has not passed")]
    NotResolved,
    /// The slug must be lowercase letters, digits and dashes.
    #[error("the page name must be 1 to 64 lowercase letters, digits or dashes")]
    BadSlug,
    /// A finding about another crate uses the slug.
    #[error("another finding uses this page name")]
    SlugTaken,
}

/// A job's disclosure record. Dates are UTC days.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    /// The job.
    pub job: JobId,
    /// What the finding is.
    pub kind: DisclosureKind,
    /// Who received the report. `None` when crates.io removed the crate
    /// before a report.
    pub reported_to: Option<String>,
    /// When it was reported.
    pub reported_on: Option<String>,
    /// The recipient's ticket or advisory number.
    pub reference: Option<String>,
    /// When the recipient acted.
    pub resolved_on: Option<String>,
    /// When the finding was published.
    pub published_on: Option<String>,
    /// The page name under `findings/`.
    pub slug: Option<String>,
    /// Free text for the maintainer.
    pub note: Option<String>,
}

/// How a finding without a report reads, wherever its report would be.
pub const REMOVED_FIRST: &str = "not reported: crates.io removed the crate first";

impl Disclosure {
    /// The report in words: day and recipient, or [`REMOVED_FIRST`].
    #[must_use]
    pub fn reported(&self) -> String {
        match (&self.reported_on, &self.reported_to) {
            (Some(on), Some(to)) => format!("{on} to {to}"),
            _ => REMOVED_FIRST.to_owned(),
        }
    }
}

/// A published finding, for the public site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedFinding {
    /// Crate name.
    pub name: String,
    /// Version.
    pub version: String,
    /// What the finding is.
    pub kind: DisclosureKind,
    /// When it was reported. `None` when crates.io removed the crate first.
    pub reported_on: Option<String>,
    /// When it was published.
    pub published_on: String,
    /// The page name under `findings/`.
    pub slug: String,
}

fn valid_slug(slug: &str) -> bool {
    let mut bytes = slug.bytes();
    (1..=64).contains(&slug.len())
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

const DAY: &str = "'YYYY-MM-DD'";

impl Store {
    /// Records that a confirmed finding was reported.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_report(
        &self,
        job: JobId,
        kind: DisclosureKind,
        reported_to: &str,
        reference: Option<&str>,
        note: Option<&str>,
    ) -> Result<Result<(), DisclosureRefusal>, StoreError> {
        if !self.confirmed(job).await? {
            return Ok(Err(DisclosureRefusal::NotConfirmed));
        }

        self.client
            .execute(
                "INSERT INTO disclosures (job_id, kind, reported_to, reference, note)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (job_id) DO UPDATE SET kind = $2, reported_to = $3,
                     reported_at = COALESCE(disclosures.reported_at, now()),
                     reference = COALESCE($4, disclosures.reference),
                     note = COALESCE($5, disclosures.note)",
                &[&job.0, &kind.name(), &reported_to, &reference, &note],
            )
            .await?;

        Ok(Ok(()))
    }

    /// Records that crates.io removed a confirmed malicious crate before
    /// Crateward reported it. No report is needed then. The removal
    /// resolves the finding, which may be published.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn record_removal(
        &self,
        job: JobId,
        note: Option<&str>,
    ) -> Result<Result<(), DisclosureRefusal>, StoreError> {
        if !self.confirmed(job).await? {
            return Ok(Err(DisclosureRefusal::NotConfirmed));
        }

        self.client
            .execute(
                "INSERT INTO disclosures (job_id, kind, reported_to, reported_at, resolved_at, note)
                 VALUES ($1, 'malicious', NULL, NULL, now(), $2)
                 ON CONFLICT (job_id) DO UPDATE SET
                     resolved_at = COALESCE(disclosures.resolved_at, now()),
                     note = COALESCE($2, disclosures.note)",
                &[&job.0, &note],
            )
            .await?;

        Ok(Ok(()))
    }

    async fn confirmed(&self, job: JobId) -> Result<bool, StoreError> {
        Ok(self
            .client
            .query_opt(
                "SELECT 1 FROM verdicts WHERE job_id = $1 AND review = 'confirmed'",
                &[&job.0],
            )
            .await?
            .is_some())
    }

    /// Records that the recipient acted: crates.io removed the crate, or the
    /// owners released a fix.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn mark_resolved(
        &self,
        job: JobId,
        reference: Option<&str>,
    ) -> Result<Result<(), DisclosureRefusal>, StoreError> {
        let updated = self
            .client
            .execute(
                "UPDATE disclosures SET resolved_at = COALESCE(resolved_at, now()),
                        reference = COALESCE($2, reference)
                 WHERE job_id = $1",
                &[&job.0, &reference],
            )
            .await?;

        Ok(if updated == 1 {
            Ok(())
        } else {
            Err(DisclosureRefusal::NotReported)
        })
    }

    /// Marks a resolved finding as published under `findings/<slug>/`.
    /// Versions of one crate may share a page.
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn publish_finding(
        &self,
        job: JobId,
        slug: &str,
    ) -> Result<Result<(), DisclosureRefusal>, StoreError> {
        if !valid_slug(slug) {
            return Ok(Err(DisclosureRefusal::BadSlug));
        }

        let Some(row) = self
            .client
            .query_opt(
                "SELECT resolved_at IS NOT NULL FROM disclosures WHERE job_id = $1",
                &[&job.0],
            )
            .await?
        else {
            return Ok(Err(DisclosureRefusal::NotReported));
        };

        if !row.try_get::<_, bool>(0)? {
            return Ok(Err(DisclosureRefusal::NotResolved));
        }

        let taken = self
            .client
            .query_opt(
                "SELECT 1 FROM disclosures d
                 JOIN jobs o ON o.id = d.job_id
                 JOIN jobs j ON j.id = $2
                 WHERE d.slug = $1 AND o.canonical_name <> j.canonical_name",
                &[&slug, &job.0],
            )
            .await?
            .is_some();
        if taken {
            return Ok(Err(DisclosureRefusal::SlugTaken));
        }

        self.client
            .execute(
                "UPDATE disclosures SET slug = $2, published_at = COALESCE(published_at, now())
                 WHERE job_id = $1",
                &[&job.0, &slug],
            )
            .await?;

        Ok(Ok(()))
    }

    /// The disclosure record of a job.
    ///
    /// # Errors
    ///
    /// Fails on database errors or a corrupt row.
    pub async fn disclosure(&self, job: JobId) -> Result<Option<Disclosure>, StoreError> {
        let row = self
            .client
            .query_opt(
                &format!(
                    "SELECT kind, reported_to, to_char(reported_at AT TIME ZONE 'UTC', {DAY}),
                            reference, to_char(resolved_at AT TIME ZONE 'UTC', {DAY}),
                            to_char(published_at AT TIME ZONE 'UTC', {DAY}), slug, note
                     FROM disclosures WHERE job_id = $1"
                ),
                &[&job.0],
            )
            .await?;
        row.map(|r| {
            let kind: String = r.try_get(0)?;
            Ok(Disclosure {
                job,
                kind: DisclosureKind::parse(&kind).ok_or_else(|| StoreError::Corrupt {
                    id: job.0,
                    reason: format!("disclosure kind {kind}"),
                })?,
                reported_to: r.try_get(1)?,
                reported_on: r.try_get(2)?,
                reference: r.try_get(3)?,
                resolved_on: r.try_get(4)?,
                published_on: r.try_get(5)?,
                slug: r.try_get(6)?,
                note: r.try_get(7)?,
            })
        })
        .transpose()
    }

    /// The honeytoken values planted for a job, so an evidence pack can
    /// redact them (DISCLOSURE.md, "Rules").
    ///
    /// # Errors
    ///
    /// Fails on database errors.
    pub async fn honeytoken_values(&self, job: JobId) -> Result<Vec<String>, StoreError> {
        let rows = self
            .client
            .query(
                "SELECT value FROM job_honeytokens WHERE job_id = $1 ORDER BY kind",
                &[&job.0],
            )
            .await?;

        rows.iter().map(|r| Ok(r.try_get(0)?)).collect()
    }

    /// Every published finding, newest first.
    ///
    /// # Errors
    ///
    /// Fails on database errors or a corrupt row.
    pub async fn published_findings(&self) -> Result<Vec<PublishedFinding>, StoreError> {
        let rows = self
            .client
            .query(
                &format!(
                    "SELECT j.crate_name, j.version, d.kind,
                            to_char(d.reported_at AT TIME ZONE 'UTC', {DAY}),
                            to_char(d.published_at AT TIME ZONE 'UTC', {DAY}), d.slug, j.id
                     FROM disclosures d JOIN jobs j ON j.id = d.job_id
                     WHERE d.published_at IS NOT NULL
                     ORDER BY d.published_at DESC, j.id DESC"
                ),
                &[],
            )
            .await?;
        rows.iter()
            .map(|r| {
                let kind: String = r.try_get(2)?;
                let id: i64 = r.try_get(6)?;
                Ok(PublishedFinding {
                    name: r.try_get(0)?,
                    version: r.try_get(1)?,
                    kind: DisclosureKind::parse(&kind).ok_or_else(|| StoreError::Corrupt {
                        id,
                        reason: format!("disclosure kind {kind}"),
                    })?,
                    reported_on: r.try_get(3)?,
                    published_on: r.try_get(4)?,
                    slug: r.try_get(5)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_plain_page_names() {
        assert!(valid_slug("evil-crate-0-1-0"));
        assert!(valid_slug("2026-rustdecimal"));
        assert!(!valid_slug(""));
        assert!(!valid_slug("-lead"));
        assert!(!valid_slug("Upper"));
        assert!(!valid_slug("a/b"));
        assert!(!valid_slug("a.b"));
        assert!(!valid_slug(&"a".repeat(65)));
    }
}
