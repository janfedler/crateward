//! The disclosure workflow on the command line (DISCLOSURE.md): the
//! evidence pack for a report, and the record of each step.

use std::path::Path;

use crateward_core::job::JobId;
use crateward_core::store::{DisclosureKind, DisclosureRefusal, Store};
use serde_json::{Value, json};

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

/// Writes the evidence pack of `job` into `out`, which must not exist yet:
/// the job and its events, the verdict, the static results, the VM runs,
/// the resolution, the original `.crate` file, and `SHA256SUMS`.
///
/// # Errors
///
/// Fails if the job does not exist, a query fails or a file cannot be
/// written.
pub async fn evidence_pack(
    store: &Store,
    data_dir: &Path,
    job: JobId,
    out: &Path,
) -> Result<Vec<String>, String> {
    let stored = store
        .get(job)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no job {}", job.0))?;
    std::fs::create_dir(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let tokens = store
        .honeytoken_values(job)
        .await
        .map_err(|e| e.to_string())?;
    let events: Vec<Value> = store
        .events(job)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|e| {
            let at = e
                .at
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default();
            json!({ "at_unix": at, "from": e.from, "to": e.to, "event": e.event, "effect": e.effect })
        })
        .collect();
    let verdict = store.verdict(job).await.map_err(|e| e.to_string())?;
    let job_static = store.job_static(job).await.map_err(|e| e.to_string())?;
    let static_report = store
        .static_report(&stored.cksum)
        .await
        .map_err(|e| e.to_string())?;
    let runs = store.job_runs(job).await.map_err(|e| e.to_string())?;
    let packages = store.fetch_packages(job).await.map_err(|e| e.to_string())?;
    let lockfile = store.fetch_lockfile(job).await.map_err(|e| e.to_string())?;
    let files: Vec<(String, Value)> = vec![
        (
            "job.json".into(),
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
            "verdict.json".into(),
            verdict.map_or(
                Value::Null,
                |(v, review)| json!({ "verdict": v, "review": review.name() }),
            ),
        ),
        (
            "static.json".into(),
            json!({
                "triage": job_static.as_ref().map(|s| &s.0),
                "reasons": job_static.as_ref().map(|s| &s.1),
                "diff": job_static.as_ref().and_then(|s| s.2.as_ref()),
                "report": static_report.map(|(version, report)| json!({ "analyzer_version": version, "report": report })),
            }),
        ),
        (
            "runs.json".into(),
            Value::Array(
                runs.into_iter()
                    .map(|(kind, report)| json!({ "kind": kind, "report": report }))
                    .collect(),
            ),
        ),
        (
            "resolution.json".into(),
            json!({ "packages": packages, "lockfile": lockfile }),
        ),
    ];
    let mut written = Vec::new();
    for (name, value) in files {
        let text = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?;
        let path = out.join(&name);
        std::fs::write(&path, redact(&text, &tokens) + "\n")
            .map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(name);
    }
    let original = data_dir
        .join("originals")
        .join(format!("{}.crate", stored.cksum));
    let crate_name = format!("{}-{}.crate", stored.name, stored.version);
    match std::fs::copy(&original, out.join(&crate_name)) {
        Ok(_) => written.push(crate_name),
        Err(error) => eprintln!("the original crate file is missing ({error}); the pack has none"),
    }
    let mut sums = String::new();
    for name in &written {
        let bytes = std::fs::read(out.join(name)).map_err(|e| format!("{name}: {e}"))?;
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(&bytes);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        sums.push_str(&format!("{hex}  {name}\n"));
    }
    std::fs::write(out.join("SHA256SUMS"), sums).map_err(|e| format!("SHA256SUMS: {e}"))?;
    written.push("SHA256SUMS".into());
    Ok(written)
}

/// The kind named on the command line.
///
/// # Errors
///
/// Fails on an unknown name.
pub fn kind(name: &str) -> Result<DisclosureKind, String> {
    DisclosureKind::parse(name).ok_or_else(|| "kind must be malicious or vulnerability".into())
}

/// Turns a refusal into the tool's error text.
///
/// # Errors
///
/// Returns the refusal as text.
pub fn refused(outcome: Result<(), DisclosureRefusal>) -> Result<(), String> {
    outcome.map_err(|refusal| refusal.to_string())
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
