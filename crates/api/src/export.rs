//! The public site: a static export of aggregate statistics (ADR 0001), and
//! the job reports the maintainer chose to publish (ADR 0013).
//!
//! The server never serves the public. It renders a few static files and,
//! when `[export]` is configured, pushes them to the site repository with a
//! deploy key that can write to that repository only. GitHub Pages serves
//! them. The export contains counts, and the crate names of findings only
//! once the maintainer published them after disclosure (`crateward
//! disclosure publish`, DISCLOSURE.md). The finding pages themselves are
//! written by hand.
//!
//! `crateward archive --publish` adds chosen job reports under `reports/`,
//! with the archive's refusals (`crate::archive`). With `export.reports`,
//! every export refreshes them from the saved selection, so a report that
//! may no longer be published disappears. Every push replaces the branch
//! with a single commit, so a removed report leaves no history behind.

use std::path::{Path, PathBuf};
use std::time::Duration;

use askama::Template;
use crateward_core::config::ExportConfig;
use crateward_core::paths::{host, site};
use crateward_core::store::{PublicStats, PublishedFinding, Store, StoreError};
use crateward_core::text::Utc;

use crate::archive::{self, ArchiveError};
use crate::selection::Selection;

pub use crateward_core::paths::site::DOMAIN;

/// Why the site could not be built or pushed.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A template did not render.
    #[error(transparent)]
    Template(#[from] askama::Error),
    /// The statistics did not serialize, or the saved selection did not
    /// parse.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The job reports could not be written.
    #[error(transparent)]
    Archive(#[from] ArchiveError),
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
    reports: bool,
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

/// The files of the site, by path. `reports` says whether the site has job
/// reports to link to.
///
/// # Errors
///
/// Fails if a template does not render.
pub fn render(
    stats: &PublicStats,
    canaries: &[(String, bool, i64)],
    findings: &[PublishedFinding],
    reports: bool,
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
        reports,
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
        // The image that link previews of the site show.
        ("og.png".into(), include_bytes!("../static/og.png").to_vec()),
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

/// Clones the site repository's branch into `work/checkout`, replacing an
/// earlier checkout. Returns the checkout and the commit it is at.
async fn clone(config: &ExportConfig, work: &Path) -> Result<(PathBuf, String), ExportError> {
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

    let head = git(&checkout, key, &["rev-parse", "HEAD"]).await?;

    Ok((checkout, head.trim().to_owned()))
}

/// Replaces the branch with a single commit of the checkout's files, unless
/// it already is one with these files. The force push is leased on `head`,
/// so a commit pushed since the clone is not lost but fails the push.
async fn push(config: &ExportConfig, checkout: &Path, head: &str) -> Result<bool, ExportError> {
    let (key, branch) = (&config.deploy_key, &config.branch);
    git(checkout, key, &["add", "--all"]).await?;

    let tree = git(checkout, key, &["write-tree"]).await?;
    let tree = tree.trim();
    let current = git(checkout, key, &["rev-parse", "HEAD^{tree}"]).await?;

    // The raw commit names its parents even in a shallow clone.
    let raw = git(checkout, key, &["cat-file", "commit", "HEAD"]).await?;
    let alone = !raw.lines().any(|line| line.starts_with("parent "));

    if alone && current.trim() == tree {
        return Ok(false);
    }

    let commit = git(
        checkout,
        key,
        &["commit-tree", tree, "-m", "Update the site"],
    )
    .await?;

    let lease = format!("--force-with-lease=refs/heads/{branch}:{head}");
    let target = format!("{}:refs/heads/{branch}", commit.trim());
    git(
        checkout,
        key,
        &["push", "--quiet", &lease, "origin", &target],
    )
    .await?;

    Ok(true)
}

/// Pushes the site to the site repository, and replaces its job reports
/// with the jobs `reports` when given. Returns whether anything changed.
///
/// # Errors
///
/// Fails if a git step fails, a report may not be published, or the site
/// does not render.
pub async fn publish(
    store: &Store,
    config: &ExportConfig,
    work: &Path,
    reports: Option<&[i64]>,
) -> Result<bool, ExportError> {
    let (checkout, head) = clone(config, work).await?;
    let dir = checkout.join(site::REPORTS);

    if let Some(ids) = reports {
        match std::fs::remove_dir_all(&dir) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error.into());
            }
            _ => {}
        }

        archive::write(store, ids, &dir, None).await?;
    }

    let files = build(store, dir.join("index.html").is_file()).await?;
    write(&checkout, &files)?;

    push(config, &checkout, &head).await
}

/// The jobs of the saved report selection, or `None` without one.
///
/// # Errors
///
/// Fails if the selection cannot be read or parsed, or on database errors.
pub async fn saved_reports(store: &Store, path: &Path) -> Result<Option<Vec<i64>>, ExportError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    let selection: Selection = serde_json::from_slice(&bytes)?;
    let candidates = store.archive_candidates(None).await?;

    Ok(Some(selection.chosen(&candidates)))
}

/// Renders the site from the store.
///
/// # Errors
///
/// Fails on database or template errors.
pub async fn build(store: &Store, reports: bool) -> Result<Vec<(String, Vec<u8>)>, ExportError> {
    let stats = store.public_stats().await?;
    let canaries = store.latest_canaries().await?;
    let findings = store.published_findings().await?;
    let now = store.now_epoch().await?;

    render(&stats, &canaries, &findings, reports, &format_utc(now))
}

/// Seconds since the epoch as `YYYY-MM-DD HH:MM UTC`.
#[must_use]
pub fn format_utc(secs: i64) -> String {
    let t = Utc::from_epoch(secs);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        t.year, t.month, t.day, t.hour, t.minute
    )
}

/// Exports on a schedule until the process ends: pushes the site when
/// `config` is set, and writes it below `dir` otherwise.
pub async fn run(store: &Store, dir: PathBuf, config: Option<&ExportConfig>) {
    let interval = Duration::from_secs(config.map_or(24, |c| c.interval_hours) * 3600);

    loop {
        match export(store, &dir, config).await {
            Ok(Some(changed)) => tracing::info!(changed, "public site exported"),
            Ok(None) => tracing::info!(dir = %dir.display(), "public site written locally"),
            Err(error) => tracing::warn!(%error, "public site not exported"),
        }

        tokio::time::sleep(interval).await;
    }
}

/// One export. Returns whether the push changed the site, or `None` when
/// the site was only written locally.
async fn export(
    store: &Store,
    dir: &Path,
    config: Option<&ExportConfig>,
) -> Result<Option<bool>, ExportError> {
    let Some(config) = config else {
        write(&dir.join("site"), &build(store, false).await?)?;

        return Ok(None);
    };

    let reports = if config.reports {
        saved_reports(store, Path::new(host::REPORT_SELECTION)).await?
    } else {
        None
    };

    Ok(Some(publish(store, config, dir, reports.as_deref()).await?))
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
            reports: false,
        }
    }

    /// What `publish` does, without the database: clone, write `files`,
    /// push.
    async fn push_files(config: &ExportConfig, work: &Path, files: &[(String, Vec<u8>)]) -> bool {
        let (checkout, head) = clone(config, work).await.unwrap();
        write(&checkout, files).unwrap();

        push(config, &checkout, &head).await.unwrap()
    }

    #[tokio::test]
    async fn the_site_is_one_commit_by_crateward_pushed_only_when_it_changed() {
        let root = scratch("publish");
        let config = site_repository(&root);
        let work = root.join("work");
        let bare = root.join("site.git");
        let first = vec![("index.html".to_owned(), b"<p>hello</p>".to_vec())];

        assert!(push_files(&config, &work, &first).await);
        assert!(!push_files(&config, &work, &first).await);

        let second = vec![("index.html".to_owned(), b"<p>again</p>".to_vec())];

        assert!(push_files(&config, &work, &second).await);

        let last = git_in(&bare, &["log", "-1", "--format=%an <%ae>: %s", "main"]);

        assert_eq!(
            last.trim(),
            "Crateward <security@janfedler.de>: Update the site"
        );

        // The seed and the earlier pages are gone from the history, the
        // seed's files stay.
        assert_eq!(git_in(&bare, &["rev-list", "--count", "main"]).trim(), "1");
        assert_eq!(git_in(&bare, &["show", "main:index.html"]), "<p>again</p>");
        assert_eq!(git_in(&bare, &["show", "main:README"]), "seed\n");

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn a_commit_pushed_after_the_clone_fails_the_push_and_stays() {
        let root = scratch("lease");
        let config = site_repository(&root);
        let files = vec![("index.html".to_owned(), b"<p>hello</p>".to_vec())];
        let (checkout, head) = clone(&config, &root.join("work")).await.unwrap();
        write(&checkout, &files).unwrap();

        // The maintainer pushes a finding page meanwhile.
        let seed = root.join("seed");
        std::fs::write(seed.join("finding.html"), "by hand\n").unwrap();
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
                "Finding",
            ],
        );
        git_in(
            &seed,
            &[
                "push",
                "--quiet",
                &root.join("site.git").to_string_lossy(),
                "main",
            ],
        );

        let error = push(&config, &checkout, &head).await.unwrap_err();

        assert!(
            matches!(&error, ExportError::GitFailed { step, .. } if step == "push"),
            "{error}"
        );

        let bare = root.join("site.git");

        assert_eq!(git_in(&bare, &["show", "main:finding.html"]), "by hand\n");

        // The next export starts from it and keeps it.
        assert!(push_files(&config, &root.join("work"), &files).await);
        assert_eq!(git_in(&bare, &["show", "main:finding.html"]), "by hand\n");

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
            reports: false,
        };

        let error = clone(&config, &root.join("work")).await.unwrap_err();
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

        let files = render(
            &stats,
            &[("canary-exfil".into(), true, 0)],
            &[],
            false,
            "now",
        )
        .unwrap();

        let index = String::from_utf8(files[0].1.clone()).unwrap();

        assert!(index.contains("Built and traced in a microVM on Linux"));
        assert!(index.contains("(25%)"));
        assert!(index.contains("expected results"));
        assert!(!index.contains("reports/"), "no reports, no link");

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
                "og.png",
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

        let files = render(&stats, &[], &[finding, removed], false, "now").unwrap();
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

    /// The file `name` of a rendered site.
    fn file<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
        &files.iter().find(|(n, _)| n == name).unwrap().1
    }

    fn index(files: &[(String, Vec<u8>)]) -> String {
        String::from_utf8(file(files, "index.html").to_vec()).unwrap()
    }

    fn stats_json(files: &[(String, Vec<u8>)]) -> serde_json::Value {
        serde_json::from_slice(file(files, "stats.json")).unwrap()
    }

    #[test]
    fn the_canaries_are_summed_up_in_one_sentence() {
        let stats = PublicStats::default();
        let canary = |passed| ("canary-exfil".to_owned(), passed, 0);

        for (canaries, text, pass) in [
            (vec![], "No canary results yet.", false),
            (
                vec![canary(true), canary(true)],
                "gave the expected results",
                true,
            ),
            (
                vec![canary(true), canary(false)],
                "A canary gave an unexpected result.",
                false,
            ),
        ] {
            let files = render(&stats, &canaries, &[], false, "now").unwrap();

            assert!(index(&files).contains(text), "{text}");
            assert_eq!(stats_json(&files)["canaries_pass"], pass, "{text}");
        }
    }

    #[test]
    fn an_empty_store_renders_an_empty_site() {
        let files = render(&PublicStats::default(), &[], &[], false, "now").unwrap();
        let index = index(&files);

        assert!(index.contains("<tr><th>Versions seen</th><td>0</td></tr>"));
        assert!(index.contains("<tr><th>Versions with a verdict</th><td>0</td></tr>"));
        assert!(index.contains("<p>None yet.</p>"));

        assert_eq!(
            stats_json(&files),
            serde_json::json!({
                "generated": "now",
                "versions": 0,
                "finished": 0,
                "coverage": [],
                "levels": [],
                "daily": [],
                "canaries_pass": false,
                "findings": [],
            })
        );
    }

    #[test]
    fn counts_appear_on_the_page_and_in_the_json_in_their_order() {
        let stats = PublicStats {
            versions: 12,
            finished: 9,
            coverage: vec![
                ("static_only".into(), 6),
                ("dynamic_linux".into(), 2),
                ("not_applicable_on_linux".into(), 1),
            ],
            levels: vec![("none".into(), 7), ("low".into(), 1), ("high".into(), 1)],
            daily: vec![("2026-10-09".into(), 4), ("2026-10-08".into(), 5)],
        };

        let files = render(&stats, &[], &[], false, "2026-10-09 08:00 UTC").unwrap();
        let index = index(&files);

        for row in [
            "<tr><th>Versions seen</th><td>12</td></tr>",
            "<tr><th>Versions with a verdict</th><td>9</td></tr>",
            "<tr><th>Static analysis only</th><td>6 (66%)</td></tr>",
            "<tr><th>Built and traced in a microVM on Linux</th><td>2 (22%)</td></tr>",
            "<tr><th>No code for Linux (not applicable)</th><td>1 (11%)</td></tr>",
            "<tr><th>none</th><td>7</td></tr>",
            "<tr><th>high</th><td>1</td></tr>",
            "<span>Updated 2026-10-09 08:00 UTC</span>",
        ] {
            assert!(index.contains(row), "{row}");
        }

        let newer = index.find("<th>2026-10-09</th><td>4</td>").unwrap();
        let older = index.find("<th>2026-10-08</th><td>5</td>").unwrap();

        assert!(newer < older);

        let json = stats_json(&files);

        assert_eq!(json["versions"], 12);
        assert_eq!(json["finished"], 9);
        assert_eq!(
            json["coverage"][1],
            serde_json::json!({"kind": "dynamic_linux", "count": 2})
        );
        assert_eq!(
            json["levels"][2],
            serde_json::json!({"level": "high", "count": 1})
        );
        assert_eq!(
            json["daily"],
            serde_json::json!([
                {"day": "2026-10-09", "finished": 4},
                {"day": "2026-10-08", "finished": 5},
            ])
        );
    }

    #[test]
    fn an_unknown_coverage_kind_is_shown_in_words() {
        assert_eq!(coverage_label("unknown"), "unknown");
        assert_eq!(coverage_label("some_new_kind"), "some new kind");
    }

    #[test]
    fn the_page_loads_only_its_own_files() {
        let files = render(&PublicStats::default(), &[], &[], false, "now").unwrap();
        let index = index(&files);

        assert!(index.contains(
            "content=\"default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'\""
        ));
        assert!(index.contains(r#"<link rel="stylesheet" href="site.css">"#));

        for link in [
            r#"<a href="stats.json">"#,
            r#"<a href="about/">"#,
            r#"<a href="mailto:security@janfedler.de">"#,
        ] {
            assert!(index.contains(link), "{link}");
        }

        // Link previews need absolute URLs, and they name only the site.
        assert!(
            index.contains(r#"<meta property="og:image" content="https://crateward.com/og.png">"#)
        );
        let (head, body) = index.split_once("</head>").unwrap();
        let urls = head.split("https://").skip(1);
        assert!(urls.clone().count() > 0 && urls.clone().all(|u| u.starts_with("crateward.com/")));

        // Nothing else points elsewhere but the contact address.
        assert!(!body.contains("http://") && !body.contains("https://"));

        let css = String::from_utf8(file(&files, "site.css").to_vec()).unwrap();

        assert!(css.starts_with(include_str!("../static/brand.css")));
        assert!(css.ends_with(include_str!("../static/site.css")));
        assert_eq!(file(&files, "CNAME"), b"crateward.com\n");
        assert!(file(&files, ".nojekyll").is_empty());
    }

    #[test]
    fn writing_replaces_earlier_files_and_creates_directories() {
        let dir = scratch("write");
        let files = |text: &str| {
            vec![
                ("index.html".to_owned(), text.as_bytes().to_vec()),
                ("about/index.html".to_owned(), b"about".to_vec()),
            ]
        };

        write(&dir, &files("old")).unwrap();
        write(&dir, &files("new")).unwrap();

        assert_eq!(std::fs::read(dir.join("index.html")).unwrap(), b"new");
        assert_eq!(
            std::fs::read(dir.join("about/index.html")).unwrap(),
            b"about"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
