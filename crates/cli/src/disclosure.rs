//! The record of each step of a disclosure (DISCLOSURE.md).

use clap::Subcommand;
use crateward_core::job::JobId;
use crateward_core::store::{Disclosure, DisclosureKind, Store};

use crate::error::CliError;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// A confirmed finding was reported.
    Report {
        /// The job's number.
        job: i64,
        /// `malicious` (reported to the crates.io team) or `vulnerability`
        /// (reported to the owners).
        #[arg(long)]
        kind: String,
        /// Who received the report, for example `help@crates.io`.
        #[arg(long)]
        to: String,
        /// The recipient's ticket or advisory number.
        #[arg(long)]
        reference: Option<String>,
        /// A note for the record.
        #[arg(long)]
        note: Option<String>,
    },
    /// crates.io removed a confirmed malicious crate before it was
    /// reported: no report is needed, and the finding is resolved.
    Removed {
        /// The job's number.
        job: i64,
        /// A note for the record, for example when it was removed.
        #[arg(long)]
        note: Option<String>,
    },
    /// The recipient acted: the crate was removed or a fix released.
    Resolved {
        /// The job's number.
        job: i64,
        /// The recipient's ticket or advisory number.
        #[arg(long)]
        reference: Option<String>,
    },
    /// The finding page `findings/<slug>/` is written. List it publicly.
    Publish {
        /// The job's number.
        job: i64,
        /// Page name: lowercase letters, digits and dashes.
        #[arg(long)]
        slug: String,
    },
    /// Show a job's disclosure record.
    Show {
        /// The job's number.
        job: i64,
    },
}

/// Records the step, or shows the record.
pub async fn run(store: Store, command: Command) -> Result<(), CliError> {
    match command {
        Command::Report {
            job,
            kind,
            to,
            reference,
            note,
        } => {
            let kind = DisclosureKind::parse(&kind).ok_or(CliError::BadKind)?;
            let (reference, note) = (reference.as_deref(), note.as_deref());
            store
                .record_report(JobId(job), kind, &to, reference, note)
                .await??;
            out!("recorded the report of job {job} to {to}");
        }
        Command::Removed { job, note } => {
            store.record_removal(JobId(job), note.as_deref()).await??;
            out!("job {job} is resolved without a report and may be published");
        }
        Command::Resolved { job, reference } => {
            store
                .mark_resolved(JobId(job), reference.as_deref())
                .await??;
            out!("job {job} is resolved and may be published");
        }
        Command::Publish { job, slug } => {
            store.publish_finding(JobId(job), &slug).await??;
            out!("job {job} is listed as findings/{slug}/ at the next export");
        }
        Command::Show { job } => match store.disclosure(JobId(job)).await? {
            Some(record) => show(&record),
            None => out!("job {job} has no disclosure record"),
        },
    }

    Ok(())
}

fn show(record: &Disclosure) {
    out!("kind       {}", record.kind.name());
    out!("reported   {}", record.reported());
    out!("reference  {}", record.reference.as_deref().unwrap_or("-"));
    out!(
        "resolved   {}",
        record.resolved_on.as_deref().unwrap_or("-")
    );
    out!(
        "published  {}",
        record.published_on.as_deref().unwrap_or("-")
    );
    out!("page       {}", record.slug.as_deref().unwrap_or("-"));
    out!("note       {}", record.note.as_deref().unwrap_or("-"));
}
