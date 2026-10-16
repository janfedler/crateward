//! `crateward archive`: choose jobs on a terminal screen, then write their
//! pages as a static archive (`crateward_api::archive`), or publish them on
//! the public site (`crateward_api::export`).

mod tui;

use std::io::IsTerminal as _;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crateward_api::archive::{self, SELECTION};
use crateward_api::export;
use crateward_api::selection::Selection;
use crateward_core::config::ExportConfig;
use crateward_core::paths::{host, site};
use crateward_core::store::Store;

use crate::error::{CliError, io};

/// Where the chosen reports go.
#[derive(Debug)]
pub enum Target {
    /// A directory, which keeps the selection next to the reports.
    Directory(PathBuf),
    /// The public site's `reports/`. The selection is saved where the daily
    /// export reads it.
    Site {
        /// The site repository.
        export: ExportConfig,
        /// The operator's email address, which the site shows.
        contact: String,
    },
}

impl Target {
    /// Where the selection is saved, and read as the screen's start.
    fn selection(&self) -> PathBuf {
        match self {
            Self::Directory(out) => out.join(SELECTION),
            Self::Site { .. } => PathBuf::from(host::REPORT_SELECTION),
        }
    }

    /// What the screen names as the destination.
    fn name(&self) -> PathBuf {
        match self {
            Self::Directory(out) => out.clone(),
            Self::Site { export, .. } => {
                PathBuf::from(format!("{} {}/", export.repository, site::REPORTS))
            }
        }
    }
}

/// The selection in `path`, or the default one if there is none.
fn load(path: &Path) -> Result<Selection, CliError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| CliError::Selection {
            path: path.to_path_buf(),
            source,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Selection::default()),
        Err(error) => Err(io(path)(error)),
    }
}

/// Writes the archive into a directory or publishes it on the site. The
/// jobs come from the saved selection `from`, or from the selection screen,
/// which starts from the target's saved selection.
pub async fn run(store: Store, target: &Target, from: Option<&Path>) -> Result<(), CliError> {
    let candidates = store.archive_candidates(None).await?;
    let saved_at = target.selection();

    let selection = match from {
        Some(path) => {
            if !path.exists() {
                return Err(io(path)(std::io::ErrorKind::NotFound.into()));
            }

            load(path)?
        }
        None => {
            if !std::io::stdout().is_terminal() {
                return Err(CliError::NoTerminal);
            }

            let mut app = tui::App::new(&candidates, load(&saved_at)?, &target.name());
            match tui::run(&mut app).map_err(CliError::Terminal)? {
                Some(selection) => selection,
                None => {
                    out!("nothing written");
                    return Ok(());
                }
            }
        }
    };

    let ids = selection.chosen(&candidates);
    let saved = serde_json::to_value(&selection).map_err(|source| CliError::Selection {
        path: saved_at.clone(),
        source,
    })?;

    match target {
        Target::Directory(out) => {
            out!("writing {} reports to {}", ids.len(), out.display());
            let written = archive::write(&store, &ids, out, Some(&saved)).await?;
            out!(
                "wrote {written} reports, open {}",
                out.join("index.html").display()
            );
        }
        Target::Site { export, contact } => {
            out!("publishing {} reports to {}", ids.len(), export.repository);
            let work = private_dir()?;
            let published = export::publish(&store, export, contact, &work, Some(&ids)).await;
            let _ = std::fs::remove_dir_all(&work);

            let changed = published?;
            save(&saved_at, &saved)?;
            out!(
                "{}, selection saved in {}",
                if changed {
                    "published"
                } else {
                    "the site is unchanged"
                },
                saved_at.display()
            );
        }
    }

    Ok(())
}

/// A new directory for the site's checkout that only this process uses.
/// `mkdir` fails on anything already there, a symbolic link included.
fn private_dir() -> Result<PathBuf, CliError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());

    let dir =
        std::env::temp_dir().join(format!("crateward-publish-{}-{nanos}", std::process::id()));

    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(io(&dir))?;

    Ok(dir)
}

/// Saves the selection readable for the dashboard's user, replacing the
/// file at once.
fn save(path: &Path, selection: &serde_json::Value) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(selection).map_err(|source| CliError::Selection {
        path: path.to_path_buf(),
        source,
    })? + "\n";

    let draft = path.with_extension("json.new");
    let mut file = std::fs::File::create(&draft).map_err(io(&draft))?;
    file.write_all(text.as_bytes()).map_err(io(&draft))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(io(&draft))?;

    std::fs::rename(&draft, path).map_err(io(path))
}
