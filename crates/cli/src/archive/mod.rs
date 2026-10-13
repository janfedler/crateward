//! `crateward archive`: choose jobs on a terminal screen, then write their
//! pages as a static archive (`crateward_api::archive`).

mod selection;
mod tui;

use std::io::IsTerminal as _;
use std::path::Path;

use crateward_api::archive::{self, SELECTION};
use crateward_core::store::Store;

use self::selection::Selection;
use crate::error::{CliError, io};

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

/// Writes the archive into `out`. The jobs come from the saved selection
/// `from`, or from the selection screen, which starts from the one an
/// earlier archive in `out` saved.
pub async fn run(store: Store, out: &Path, from: Option<&Path>) -> Result<(), CliError> {
    let candidates = store.archive_candidates(None).await?;

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

            let mut app = tui::App::new(&candidates, load(&out.join(SELECTION))?, out);
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
        path: out.join(SELECTION),
        source,
    })?;

    out!("writing {} reports to {}", ids.len(), out.display());
    let written = archive::write(&store, &ids, out, &saved).await?;
    out!(
        "wrote {written} reports, open {}",
        out.join("index.html").display()
    );

    Ok(())
}
