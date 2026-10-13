//! A job's CycloneDX SBOM and findings document as files (ADR 0012).

use std::path::Path;

use crateward_api::sbom::documents;
use crateward_core::store::Store;

use crate::error::{CliError, io};

/// Writes the two documents of job `id` into `dir`, which is created if
/// needed, and names them.
pub async fn run(store: Store, id: i64, dir: &Path) -> Result<(), CliError> {
    let Some(documents) = documents(&store, id).await? else {
        return Err(CliError::NoSbom(id));
    };

    std::fs::create_dir_all(dir).map_err(io(dir))?;

    for (file, value) in [
        (documents.sbom_file(), &documents.sbom),
        (documents.vex_file(), &documents.vex),
    ] {
        let path = dir.join(file);
        let json = serde_json::to_string_pretty(value).unwrap_or_default() + "\n";
        std::fs::write(&path, json).map_err(io(&path))?;
        out!("wrote {}", path.display());
    }

    Ok(())
}
