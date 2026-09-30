//! What ends a command without success.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crateward_core::config::ConfigError;
use crateward_core::integrity::IntegrityError;
use crateward_core::store::{DisclosureRefusal, StoreError};

/// `EX_CONFIG` from `sysexits.h`.
const EXIT_CONFIG: u8 = 78;

/// A failed command. `main` prints it and ends with [`CliError::exit_code`].
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The configuration file cannot be used.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The async runtime did not start.
    #[error("cannot start the runtime: {0}")]
    Runtime(std::io::Error),
    /// The job store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The integrity manifest cannot be read or written.
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    /// The store refused a step of a disclosure.
    #[error(transparent)]
    Refused(#[from] DisclosureRefusal),
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The tool cannot tell where its own file is.
    #[error("cannot find the tool's own file: {0}")]
    ToolPath(std::io::Error),
    /// The tool's file has no parent directory.
    #[error("the tool has no directory")]
    NoToolDirectory,
    /// Some files do not match the integrity manifest.
    #[error("{0} files differ")]
    Differ(usize),
    /// `--kind` is neither of the two kinds.
    #[error("kind must be malicious or vulnerability")]
    BadKind,
    /// No stage has this name.
    #[error("unknown stage {0}")]
    UnknownStage(String),
    /// No job has this number.
    #[error("no job {0}")]
    NoJob(i64),
}

impl CliError {
    /// `EX_CONFIG` for a configuration that cannot be used, 1 otherwise.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Config(_) => ExitCode::from(EXIT_CONFIG),
            _ => ExitCode::FAILURE,
        }
    }
}

/// Names the file in an I/O error: `.map_err(io(&path))`.
pub fn io(path: &Path) -> impl FnOnce(std::io::Error) -> CliError + '_ {
    move |source| CliError::Io {
        path: path.to_path_buf(),
        source,
    }
}
