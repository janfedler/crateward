//! Keeps the state diagram in `docs/ARCHITECTURE.md` generated from code.
//!
//! The diagram is derived from `crateward_core::job::edges`, which explores
//! the real transition function. A hand drawn diagram would drift. This one
//! cannot, because CI and `cargo test` compare it with the code.

use std::path::Path;

use crateward_core::job::mermaid_diagram;

use crate::TaskError;

const BEGIN: &str =
    "<!-- BEGIN GENERATED: job state diagram, run `cargo xtask state-diagram --write` -->";
const END: &str = "<!-- END GENERATED: job state diagram -->";

/// The generated block including its markers.
fn block() -> String {
    format!("{BEGIN}\n```mermaid\n{}```\n{END}", mermaid_diagram())
}

/// Replaces the generated block in `text`, or returns `None` if the markers
/// are missing.
fn replace_block(text: &str) -> Option<String> {
    let start = text.find(BEGIN)?;
    let end = text.find(END)? + END.len();
    if end < start {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(text.get(..start)?);
    out.push_str(&block());
    out.push_str(text.get(end..)?);
    Some(out)
}

/// Checks the diagram, or rewrites it when `write` is set.
///
/// # Errors
///
/// Fails when the file cannot be read or written, the markers are missing,
/// or (in check mode) the diagram is out of date.
pub fn run(root: &Path, write: bool) -> Result<(), TaskError> {
    let path = root.join("docs").join("ARCHITECTURE.md");
    let text = std::fs::read_to_string(&path).map_err(|e| TaskError::Io(path.clone(), e))?;
    let updated = replace_block(&text).ok_or_else(|| {
        TaskError::Check(format!(
            "{} lacks the generated diagram markers",
            path.display()
        ))
    })?;
    if updated == text {
        eprintln!("xtask: state diagram is current");
        return Ok(());
    }
    if write {
        std::fs::write(&path, updated).map_err(|e| TaskError::Io(path.clone(), e))?;
        eprintln!("xtask: rewrote the state diagram in {}", path.display());
        Ok(())
    } else {
        Err(TaskError::Check(
            "the state diagram in docs/ARCHITECTURE.md is out of date: run `cargo xtask state-diagram --write`".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_diagram_is_current() {
        run(&crate::workspace_root(), false).unwrap();
    }

    #[test]
    fn replacement_is_idempotent() {
        let text = format!("intro\n{BEGIN}\nold\n{END}\noutro\n");
        let once = replace_block(&text).unwrap();
        assert_eq!(replace_block(&once).unwrap(), once);
        assert!(once.starts_with("intro\n") && once.ends_with("\noutro\n"));
    }
}
