//! What a job left on its scratch disk, as the host read it.

use serde::{Deserialize, Serialize};

/// One file or directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Path as the guest saw it.
    pub path: String,
    /// `file`, `dir`, `symlink`, `fifo`, `socket`, `char`, `block`.
    pub kind: String,
    /// Size in bytes.
    pub size: u64,
    /// Permission bits, including set user ID, set group ID and sticky.
    pub mode: u16,
    /// Owner.
    pub uid: u32,
    /// For symbolic links: the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// What the scratch disk held after the run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScratchReport {
    /// Regular files.
    pub files: u64,
    /// Directories.
    pub directories: u64,
    /// Bytes in regular files.
    pub bytes: u64,
    /// The walk stopped at a limit.
    pub incomplete: bool,
    /// Entries outside the build areas and the planted files.
    pub outside_build: Vec<Entry>,
    /// Executables (by mode or ELF header) outside the target directory.
    pub executables_outside_target: Vec<Entry>,
    /// Files with set user ID or set group ID bits.
    pub setid: Vec<Entry>,
    /// Devices, FIFOs and sockets.
    pub special: Vec<Entry>,
    /// Symbolic links pointing outside the scratch disk.
    pub links_outside: Vec<Entry>,
    /// Planted honeytoken files that changed or disappeared.
    pub planted_changed: Vec<String>,
    /// `(token index, path)`: honeytokens found in file contents.
    pub tokens_found: Vec<(usize, String)>,
    /// Files with honeytokens that also hold the rest of the environment.
    /// `None` in reports of scanners that did not look for them.
    #[serde(default)]
    pub environment_dumps: Option<Vec<String>>,
    /// File names of compiled units in `target/debug/deps` (for example
    /// `libserde-0123456789abcdef.rmeta`). The hash in each name identifies
    /// the unit exactly (version, features, dependencies, profile), which
    /// measures what a shared build cache could reuse (ADR 0006).
    #[serde(default)]
    pub units: Vec<String>,
    /// Entries dropped from the lists above.
    pub omitted: u64,
    /// Why the image could not be read completely, if it could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
