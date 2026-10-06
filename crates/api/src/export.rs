//! The public site: a static export of aggregate statistics (ADR 0001).
//!
//! The server never serves the public. It renders a few static files and,
//! when `[export]` is configured, pushes them to the site repository with a
//! deploy key that can write to that repository only. GitHub Pages serves
//! them. The export contains counts, and the crate names of findings only
//! once the maintainer published them after disclosure (`crateward
//! disclosure publish`, DISCLOSURE.md). No evidence, no undisclosed
//! findings. The finding pages themselves are written by hand.

use std::path::{Path, PathBuf};
use std::time::Duration;

use askama::Template;
use crateward_core::config::ExportConfig;
use crateward_core::paths::host;
use crateward_core::store::{PublicStats, PublishedFinding, Store, StoreError};

/// The site's domain, written to `CNAME` for GitHub Pages.
pub const DOMAIN: &str = "crateward.com";

/// Why the site could not be built or pushed.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A template did not render.
    #[error(transparent)]
    Template(#[from] askama::Error),
    /// The statistics did not serialize.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The site's files could not be written.
    #[error("cannot write the site files: {0}")]
    Files(#[from] std::io::Error),
    /// A git step could not start.
    #[error("git {step}: {source}")]
    GitStart {
        /// The git subcommand.
        step: String,
        /// Why it could not start.
        source: std::io::Error,
    },
    /// A git step failed.
    #[error("git {step} failed: {stderr}")]
    GitFailed {
        /// The git subcommand.
        step: String,
        /// What git said.
        stderr: String,
    },
}

/// The site's stylesheet: the design system's tokens, then its own rules.
const SITE_CSS: &str = concat!(
    include_str!("../static/brand.css"),
    include_str!("../static/site.css")
);

#[derive(Template)]
#[template(path = "site.html")]
struct SitePage {
    versions: i64,
    finished: i64,
    coverage: Vec<(String, i64, String)>,
    levels: Vec<(String, i64)>,
    daily: Vec<(String, i64)>,
    canaries: String,
    findings: Vec<FindingLine>,
    generated: String,
}

/// One published finding on the public page.
struct FindingLine {
    name: String,
    version: String,
    kind: &'static str,
    reported_on: String,
    published_on: String,
    slug: String,
}

/// What Crateward is and does. The user agent of every request to
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
    findings: &[PublishedFinding],
    generated: &str,
) -> Result<Vec<(String, Vec<u8>)>, ExportError> {
    let total = stats.finished.max(1);
    let canary_text = if canaries.is_empty() {
        "No canary results yet.".to_owned()
    } else if canaries.iter().all(|(_, passed, _)| *passed) {
        "The latest canary runs (a known bad and a known good test crate) gave the expected results.".to_owned()
    } else {
        "A canary gave an unexpected result. Analysis that depends on it is paused until it passes again.".to_owned()
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
        findings: findings
            .iter()
            .map(|f| FindingLine {
                name: f.name.clone(),
                version: f.version.clone(),
                kind: f.kind.name(),
                reported_on: f
                    .reported_on
                    .clone()
                    .unwrap_or_else(|| "removed by crates.io first".to_owned()),
                published_on: f.published_on.clone(),
                slug: f.slug.clone(),
            })
            .collect(),
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
        "findings": findings.iter().map(|f| serde_json::json!({
            "crate": f.name,
            "version": f.version,
            "kind": f.kind.name(),
            "reported": f.reported_on,
            "published": f.published_on,
            "page": format!("findings/{}/", f.slug),
        })).collect::<Vec<_>>(),
    });

    let mut files: Vec<(String, Vec<u8>)> = vec![
        ("index.html".into(), page.render()?.into_bytes()),
        ("about/index.html".into(), AboutPage.render()?.into_bytes()),
        ("stats.json".into(), serde_json::to_vec_pretty(&json)?),
        ("site.css".into(), SITE_CSS.as_bytes().to_vec()),
    ];

    files.extend(
        crate::FONTS
            .iter()
            .map(|(name, bytes, _)| ((*name).to_owned(), bytes.to_vec())),
    );
    files.extend([
        (
            "OFL.txt".into(),
            include_bytes!("../static/OFL.txt").to_vec(),
        ),
        ("CNAME".into(), format!("{DOMAIN}\n").into_bytes()),
        // Serve the files as they are, without Jekyll processing.
        (".nojekyll".into(), Vec::new()),
    ]);

    Ok(files)
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

/// Runs one git command as Crateward, over SSH with the deploy key only.
async fn git(dir: &Path, key: &Path, args: &[&str]) -> Result<String, ExportError> {
    let step = args.first().copied().unwrap_or_default();
    let ssh = format!(
        "ssh -i {} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
         -o UserKnownHostsFile={}",
        key.display(),
        host::EXPORT_KNOWN_HOSTS
    );

    let output = tokio::process::Command::new("git")
        .args(["-c", "user.name=Crateward"])
        .args(["-c", "user.email=security@janfedler.de"])
        .args(args)
        .current_dir(dir)
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .await
        .map_err(|source| ExportError::GitStart {
            step: step.to_owned(),
            source,
        })?;
    if !output.status.success() {
        return Err(ExportError::GitFailed {
            step: step.to_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
) -> Result<bool, ExportError> {
    let checkout = work.join("checkout");
    let _ = std::fs::remove_dir_all(&checkout);
    std::fs::create_dir_all(work)?;
    let (key, branch) = (&config.deploy_key, &config.branch);
    let target = checkout.to_string_lossy();
    let clone = ["clone", "--depth", "1", "--branch", branch];
    git(
        work,
        key,
        &[&clone[..], &[&config.repository, &target]].concat(),
    )
    .await?;
    write(&checkout, files)?;
    git(&checkout, key, &["add", "--all"]).await?;

    if git(&checkout, key, &["status", "--porcelain"])
        .await?
        .trim()
        .is_empty()
    {
        return Ok(false);
    }

    git(
        &checkout,
        key,
        &["commit", "--quiet", "--message", "Update statistics"],
    )
    .await?;
    git(&checkout, key, &["push", "--quiet", "origin", branch]).await?;

    Ok(true)
}

/// Renders the site from the store.
///
/// # Errors
///
/// Fails on database or template errors.
pub async fn build(store: &Store) -> Result<Vec<(String, Vec<u8>)>, ExportError> {
    let stats = store.public_stats().await?;
    let canaries = store.latest_canaries().await?;
    let findings = store.published_findings().await?;
    let now = store.now_epoch().await?;

    render(&stats, &canaries, &findings, &format_utc(now))
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

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("crateward-export-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        dir
    }

    fn git_in(dir: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();

        assert!(output.status.success(), "git {args:?}: {output:?}");

        String::from_utf8(output.stdout).unwrap()
    }

    /// A bare repository with one commit on `main`, and a config that
    /// clones it over `file://`, so no SSH is involved.
    fn site_repository(root: &Path) -> ExportConfig {
        git_in(
            root,
            &[
                "init",
                "--quiet",
                "--bare",
                "--initial-branch=main",
                "site.git",
            ],
        );
        git_in(root, &["init", "--quiet", "--initial-branch=main", "seed"]);
        let seed = root.join("seed");
        std::fs::write(seed.join("README"), "seed\n").unwrap();
        git_in(&seed, &["add", "--all"]);
        git_in(
            &seed,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--quiet",
                "--message",
                "Seed",
            ],
        );
        let bare = root.join("site.git");
        git_in(&seed, &["push", "--quiet", &bare.to_string_lossy(), "main"]);

        ExportConfig {
            repository: format!("file://{}", bare.display()),
            branch: "main".into(),
            deploy_key: root.join("no-key"),
            interval_hours: 24,
        }
    }

    #[tokio::test]
    async fn the_site_is_pushed_as_crateward_and_only_when_it_changed() {
        let root = scratch("publish");
        let config = site_repository(&root);
        let work = root.join("work");
        let files = vec![("index.html".to_owned(), b"<p>hello</p>".to_vec())];

        assert!(publish(&config, &work, &files).await.unwrap());
        assert!(!publish(&config, &work, &files).await.unwrap());

        let bare = root.join("site.git");
        let last = git_in(&bare, &["log", "-1", "--format=%an <%ae>: %s", "main"]);

        assert_eq!(
            last.trim(),
            "Crateward <security@janfedler.de>: Update statistics"
        );
        assert_eq!(git_in(&bare, &["rev-list", "--count", "main"]).trim(), "2");

        let page = git_in(&bare, &["show", "main:index.html"]);
        assert_eq!(page, "<p>hello</p>");

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn a_repository_that_is_not_there_is_a_failed_clone() {
        let root = scratch("no-repository");
        let config = ExportConfig {
            repository: format!("file://{}", root.join("missing.git").display()),
            branch: "main".into(),
            deploy_key: root.join("no-key"),
            interval_hours: 24,
        };

        let error = publish(&config, &root.join("work"), &[]).await.unwrap_err();
        assert!(
            matches!(&error, ExportError::GitFailed { step, stderr }
                if step == "clone" && !stderr.is_empty()),
            "{error}"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn a_git_that_cannot_start_is_named_by_its_step() {
        let error = git(Path::new("/nonexistent/dir"), Path::new("key"), &["status"])
            .await
            .unwrap_err();

        assert!(
            matches!(&error, ExportError::GitStart { step, .. } if step == "status"),
            "{error}"
        );
        assert!(error.to_string().starts_with("git status: "), "{error}");
    }

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

        let files = render(&stats, &[("canary-exfil".into(), true, 0)], &[], "now").unwrap();
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
                "lobster-latin-400.woff2",
                "dm-sans-latin-wght.woff2",
                "jetbrains-mono-latin-wght.woff2",
                "OFL.txt",
                "CNAME",
                ".nojekyll"
            ]
        );

        // The pages load nothing but their own stylesheet.
        assert!(!index.contains("<script"));

        let about = String::from_utf8(files[1].1.clone()).unwrap();
        assert!(!about.contains("<script"));

        // The user agent points at this page, which names the contact.
        assert!(about.contains("security@janfedler.de"));
    }

    #[test]
    fn published_findings_are_listed_with_their_page() {
        use crateward_core::store::DisclosureKind;
        let stats = PublicStats {
            versions: 1,
            finished: 1,
            coverage: Vec::new(),
            levels: Vec::new(),
            daily: Vec::new(),
        };

        let finding = PublishedFinding {
            name: "evil<b>".into(),
            version: "0.1.0".into(),
            kind: DisclosureKind::Malicious,
            reported_on: Some("2026-09-20".into()),
            published_on: "2026-10-04".into(),
            slug: "evil-0-1-0".into(),
        };

        // crates.io removed this one before it was reported.
        let removed = PublishedFinding {
            name: "gone".into(),
            reported_on: None,
            slug: "gone-0-1-0".into(),
            ..finding.clone()
        };

        let files = render(&stats, &[], &[finding, removed], "now").unwrap();
        let index = String::from_utf8(files[0].1.clone()).unwrap();

        assert!(index.contains(r#"<a href="findings/evil-0-1-0/">details</a>"#));

        // Crate names are escaped like any other text.
        assert!(index.contains("evil&#60;b&#62;") || index.contains("evil&lt;b&gt;"));
        assert!(!index.contains("None yet."));

        let json: serde_json::Value = serde_json::from_slice(&files[2].1).unwrap();
        assert_eq!(json["findings"][0]["page"], "findings/evil-0-1-0/");
        assert!(index.contains("<td>removed by crates.io first</td>"));
        assert_eq!(json["findings"][1]["reported"], serde_json::Value::Null);
    }
}
