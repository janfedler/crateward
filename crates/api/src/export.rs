//! The public site: a static export of aggregate statistics (ADR 0009).
//!
//! The server never serves the public. It renders a few static files and,
//! when `[export]` is configured, pushes them to the site repository with a
//! deploy key that can write to that repository only; GitHub Pages serves
//! them. The export contains counts only: no crate names, no evidence, no
//! undisclosed findings. Findings are added by hand after disclosure
//! (DISCLOSURE.md).

use std::path::{Path, PathBuf};
use std::time::Duration;

use askama::Template;
use crateward_core::config::ExportConfig;
use crateward_core::store::{PublicStats, Store, StoreError};

/// The site's domain, written to `CNAME` for GitHub Pages.
pub const DOMAIN: &str = "crateward.com";

#[derive(Template)]
#[template(path = "site.html")]
struct SitePage {
    versions: i64,
    finished: i64,
    coverage: Vec<(String, i64, String)>,
    levels: Vec<(String, i64)>,
    daily: Vec<(String, i64)>,
    canaries: String,
    generated: String,
}

/// What Crateward is and does; the user agent of every request to
/// crates.io points here.
#[derive(Template)]
#[template(path = "about.html")]
struct AboutPage;

fn coverage_label(kind: &str) -> String {
    match kind {
        "dynamic_linux" => "Built and traced in a microVM on Linux".into(),
        "static_only" => "Static analysis only".into(),
        "not_applicable_on_linux" => "No code for Linux (not applicable)".into(),
        other => other.replace('_', " "),
    }
}

/// The files of the site, by path.
///
/// # Errors
///
/// Fails if a template does not render.
pub fn render(
    stats: &PublicStats,
    canaries: &[(String, bool, i64)],
    generated: &str,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let total = stats.finished.max(1);
    let canary_text = if canaries.is_empty() {
        "No canary results yet.".to_owned()
    } else if canaries.iter().all(|(_, passed, _)| *passed) {
        "The latest canary runs (a known bad and a known good test crate) gave the expected results.".to_owned()
    } else {
        "A canary gave an unexpected result; analysis that depends on it is paused until it passes again.".to_owned()
    };
    let page = SitePage {
        versions: stats.versions,
        finished: stats.finished,
        coverage: stats
            .coverage
            .iter()
            .map(|(kind, n)| (coverage_label(kind), *n, format!("{}%", n * 100 / total)))
            .collect(),
        levels: stats.levels.clone(),
        daily: stats.daily.clone(),
        canaries: canary_text,
        generated: generated.to_owned(),
    };
    let json = serde_json::json!({
        "generated": generated,
        "versions": stats.versions,
        "finished": stats.finished,
        "coverage": stats.coverage.iter().map(|(k, n)| serde_json::json!({"kind": k, "count": n})).collect::<Vec<_>>(),
        "levels": stats.levels.iter().map(|(l, n)| serde_json::json!({"level": l, "count": n})).collect::<Vec<_>>(),
        "daily": stats.daily.iter().map(|(d, n)| serde_json::json!({"day": d, "finished": n})).collect::<Vec<_>>(),
        "canaries_pass": !canaries.is_empty() && canaries.iter().all(|(_, p, _)| *p),
    });
    Ok(vec![
        (
            "index.html".into(),
            page.render().map_err(|e| e.to_string())?.into_bytes(),
        ),
        (
            "about/index.html".into(),
            AboutPage.render().map_err(|e| e.to_string())?.into_bytes(),
        ),
        (
            "stats.json".into(),
            serde_json::to_vec_pretty(&json).map_err(|e| e.to_string())?,
        ),
        (
            "site.css".into(),
            include_bytes!("../static/site.css").to_vec(),
        ),
        ("CNAME".into(), format!("{DOMAIN}\n").into_bytes()),
        // Serve the files as they are, without Jekyll processing.
        (".nojekyll".into(), Vec::new()),
    ])
}

/// Writes the files into `dir`, replacing earlier ones.
///
/// # Errors
///
/// Fails if a file cannot be written.
pub fn write(dir: &Path, files: &[(String, Vec<u8>)]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for (name, data) in files {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)?;
    }
    Ok(())
}

async fn git(dir: &Path, key: &Path, args: &[&str]) -> Result<String, String> {
    let ssh = format!(
        "ssh -i {} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes",
        key.display()
    );
    let output = tokio::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .await
        .map_err(|e| format!("git {}: {e}", args.first().unwrap_or(&"")))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Pushes the files to the site repository: a fresh shallow clone, the
/// files replaced, one commit if anything changed.
///
/// # Errors
///
/// Fails if a git step fails.
pub async fn publish(
    config: &ExportConfig,
    work: &Path,
    files: &[(String, Vec<u8>)],
) -> Result<bool, String> {
    let checkout = work.join("checkout");
    let _ = std::fs::remove_dir_all(&checkout);
    std::fs::create_dir_all(work).map_err(|e| e.to_string())?;
    let target = checkout.to_string_lossy().into_owned();
    git(
        work,
        &config.deploy_key,
        &[
            "clone",
            "--depth",
            "1",
            "--branch",
            &config.branch,
            &config.repository,
            &target,
        ],
    )
    .await?;
    write(&checkout, files).map_err(|e| e.to_string())?;
    git(&checkout, &config.deploy_key, &["add", "--all"]).await?;
    let status = git(&checkout, &config.deploy_key, &["status", "--porcelain"]).await?;
    if status.trim().is_empty() {
        return Ok(false);
    }
    git(
        &checkout,
        &config.deploy_key,
        &[
            "-c",
            "user.name=Crateward",
            "-c",
            "user.email=security@crateward.com",
            "commit",
            "--quiet",
            "--message",
            "Update statistics",
        ],
    )
    .await?;
    git(
        &checkout,
        &config.deploy_key,
        &["push", "--quiet", "origin", &config.branch],
    )
    .await?;
    Ok(true)
}

/// Renders the site from the store.
///
/// # Errors
///
/// Fails on database or template errors.
pub async fn build(store: &Store) -> Result<Vec<(String, Vec<u8>)>, String> {
    let stats = store
        .public_stats()
        .await
        .map_err(|e: StoreError| e.to_string())?;
    let canaries = store.latest_canaries().await.map_err(|e| e.to_string())?;
    let now = store.now_epoch().await.map_err(|e| e.to_string())?;
    render(&stats, &canaries, &format_utc(now))
}

/// Seconds since the epoch as `YYYY-MM-DD HH:MM UTC`.
#[must_use]
pub fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        (rest % 3600) / 60
    )
}

/// Exports on a schedule until the process ends: writes the site below
/// `dir`, and pushes it when `config` is set.
pub async fn run(store: &Store, dir: PathBuf, config: Option<&ExportConfig>) {
    let interval = Duration::from_secs(config.map_or(24, |c| c.interval_hours) * 3600);
    loop {
        match build(store).await {
            Ok(files) => {
                if let Err(error) = write(&dir.join("site"), &files) {
                    tracing::warn!(%error, "cannot write the site");
                } else if let Some(config) = config {
                    match publish(config, &dir, &files).await {
                        Ok(changed) => tracing::info!(changed, "public site exported"),
                        Err(error) => tracing::warn!(%error, "public site not pushed"),
                    }
                } else {
                    tracing::info!(dir = %dir.display(), "public site written locally");
                }
            }
            Err(error) => tracing::warn!(%error, "cannot build the public site"),
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_formatted_in_utc() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(1_790_000_000), "2026-09-21 14:13 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
    }

    #[test]
    fn the_site_holds_counts_only() {
        let stats = PublicStats {
            versions: 10,
            finished: 8,
            coverage: vec![("dynamic_linux".into(), 2), ("static_only".into(), 6)],
            levels: vec![("none".into(), 7), ("high".into(), 1)],
            daily: vec![("2026-09-25".into(), 8)],
        };
        let files = render(&stats, &[("canary-exfil".into(), true, 0)], "now").unwrap();
        let index = String::from_utf8(files[0].1.clone()).unwrap();
        assert!(index.contains("Built and traced in a microVM on Linux"));
        assert!(index.contains("(25%)"));
        assert!(index.contains("expected results"));
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "index.html",
                "about/index.html",
                "stats.json",
                "site.css",
                "CNAME",
                ".nojekyll"
            ]
        );
        // The pages load nothing but their own stylesheet.
        assert!(!index.contains("<script"));
        let about = String::from_utf8(files[1].1.clone()).unwrap();
        assert!(!about.contains("<script"));
        // The user agent points at this page.
        assert!(
            about.contains("crateward/0.1 (+https://crateward.com/about; security@crateward.com)")
        );
    }
}
