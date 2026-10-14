//! Checks that no Rust source is longer than [`MAX_LINES`], tests included,
//! since a reader scrolls through the whole file. A long unit test module
//! moves into a `tests.rs` next to its file, and long code splits into
//! modules (`CONTRIBUTING.md`).

use std::path::Path;

use crate::TaskError;
use crate::blank_lines::rust_files;

/// The longest a Rust source may be.
pub const MAX_LINES: usize = 1000;

/// The sources longer than [`MAX_LINES`], with their length.
fn too_long(root: &Path) -> Result<Vec<(String, usize)>, TaskError> {
    let mut long = Vec::new();

    for path in rust_files(root)? {
        let text = std::fs::read_to_string(&path).map_err(|e| TaskError::Io(path.clone(), e))?;
        let lines = text.lines().count();
        if lines > MAX_LINES {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            long.push((relative.display().to_string(), lines));
        }
    }

    Ok(long)
}

/// Fails on any Rust source longer than [`MAX_LINES`].
///
/// # Errors
///
/// Fails if a file cannot be read, or one is too long.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let long = too_long(root)?;

    for (path, lines) in &long {
        eprintln!("{path}: {lines} lines");
    }

    if !long.is_empty() {
        return Err(TaskError::Check(format!(
            "{} file(s) longer than {MAX_LINES} lines, see CONTRIBUTING.md",
            long.len()
        )));
    }

    eprintln!("xtask: every Rust source has at most {MAX_LINES} lines");

    Ok(())
}
