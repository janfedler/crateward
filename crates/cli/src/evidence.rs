//! The evidence pack of a job, for a report (DISCLOSURE.md).

use std::path::Path;
use std::time::UNIX_EPOCH;

use crateward_core::job::JobId;
use crateward_core::paths::host;
use crateward_core::store::{Store, StoreError, StoredEvent, StoredJob};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::error::{CliError, io};

/// The last file of a pack: the digests of all the others.
const CHECKSUMS: &str = "SHA256SUMS";

/// Writes the pack of `job` into the new directory `dir` and lists its files.
pub async fn run(store: Store, data_dir: &Path, job: JobId, dir: &Path) -> Result<(), CliError> {
    let names = write_pack(&store, data_dir, job, dir).await?;
    out!("wrote {} files to {}", names.len(), dir.display());

    for name in names {
        out!("  {name}");
    }

    Ok(())
}

/// Replaces every honeytoken value in `text`. They are fake by
/// construction, but a reader should not have to know that.
#[must_use]
pub fn redact(text: &str, tokens: &[String]) -> String {
    tokens
        .iter()
        .filter(|t| !t.is_empty())
        .fold(text.to_owned(), |text, token| {
            text.replace(token.as_str(), "[honeytoken]")
        })
}

/// Writes the evidence pack of `job` into `dir`, which must not exist yet:
/// the job and its events, the verdict, the static results, the VM runs,
/// the resolution, the original `.crate` file, and `SHA256SUMS`.
async fn write_pack(
    store: &Store,
    data_dir: &Path,
    job: JobId,
    dir: &Path,
) -> Result<Vec<String>, CliError> {
    let stored = store.get(job).await?.ok_or(CliError::NoJob(job.0))?;
    std::fs::create_dir(dir).map_err(io(dir))?;
    let tokens = store.honeytoken_values(job).await?;
    let mut names = Vec::new();

    for (name, value) in documents(store, &stored).await? {
        let path = dir.join(name);
        let text = redact(&format!("{value:#}"), &tokens) + "\n";
        std::fs::write(&path, text).map_err(io(&path))?;
        names.push(name.to_owned());
    }

    names.extend(copy_original(data_dir, &stored, dir));
    write_checksums(dir, &names)?;
    names.push(CHECKSUMS.to_owned());

    Ok(names)
}

/// The JSON documents of the pack, by file name.
async fn documents(
    store: &Store,
    stored: &StoredJob,
) -> Result<Vec<(&'static str, Value)>, StoreError> {
    let job = stored.id;
    let events: Vec<Value> = store
        .events(job)
        .await?
        .into_iter()
        .map(event_json)
        .collect();

    let verdict = store.verdict(job).await?;
    let runs = store.job_runs(job).await?;

    Ok(vec![
        (
            "job.json",
            json!({
                "id": job.0,
                "name": stored.name,
                "version": stored.version,
                "sha256": stored.cksum.to_string(),
                "state": stored.job,
                "index_entry": stored.index_entry,
                "events": events,
            }),
        ),
        (
            "verdict.json",
            verdict.map_or(
                Value::Null,
                |(v, review)| json!({ "verdict": v, "review": review.name() }),
            ),
        ),
        ("static.json", static_document(store, stored).await?),
        (
            "runs.json",
            Value::Array(
                runs.into_iter()
                    .map(|(kind, report)| json!({ "kind": kind, "report": report }))
                    .collect(),
            ),
        ),
        (
            "resolution.json",
            json!({
                "packages": store.fetch_packages(job).await?,
                "lockfile": store.fetch_lockfile(job).await?,
            }),
        ),
    ])
}

fn event_json(event: StoredEvent) -> Value {
    let at = event
        .at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    json!({
        "at_unix": at,
        "from": event.from,
        "to": event.to,
        "event": event.event,
        "effect": event.effect,
    })
}

async fn static_document(store: &Store, stored: &StoredJob) -> Result<Value, StoreError> {
    let job_static = store.job_static(stored.id).await?;
    let report = store.static_report(&stored.cksum).await?;

    Ok(json!({
        "triage": job_static.as_ref().map(|s| &s.0),
        "reasons": job_static.as_ref().map(|s| &s.1),
        "diff": job_static.as_ref().and_then(|s| s.2.as_ref()),
        "report": report.map(|(version, report)| json!({ "analyzer_version": version, "report": report })),
    }))
}

/// Copies the original `.crate` file into the pack. A pack without it still
/// serves, so a missing file only warns.
fn copy_original(data_dir: &Path, stored: &StoredJob, dir: &Path) -> Option<String> {
    let original = data_dir
        .join(host::ORIGINALS)
        .join(format!("{}.crate", stored.cksum));

    let name = format!("{}-{}.crate", stored.name, stored.version);

    match std::fs::copy(&original, dir.join(&name)) {
        Ok(_) => Some(name),
        Err(error) => {
            eprintln!("the original crate file is missing ({error}), so the pack has none");
            None
        }
    }
}

/// Writes `SHA256SUMS` over the files `names`, in the format that
/// `sha256sum --check` reads.
fn write_checksums(dir: &Path, names: &[String]) -> Result<(), CliError> {
    let mut lines = Vec::new();
    for name in names {
        let path = dir.join(name);
        let digest = Sha256::digest(std::fs::read(&path).map_err(io(&path))?);
        lines.push(format!("{digest:x}  {name}"));
    }

    let path = dir.join(CHECKSUMS);

    std::fs::write(&path, lines.join("\n") + "\n").map_err(io(&path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honeytokens_are_redacted_everywhere() {
        let tokens = vec!["cioTOKEN123".to_owned(), String::new()];

        assert_eq!(
            redact(r#"{"a":"x cioTOKEN123 y","b":["cioTOKEN123"]}"#, &tokens),
            r#"{"a":"x [honeytoken] y","b":["[honeytoken]"]}"#
        );
        assert_eq!(redact("nothing", &tokens), "nothing");
    }
}
