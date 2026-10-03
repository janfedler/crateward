//! Helpers shared by the microVM tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crateward_core::paths::build;

/// The workspace root.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .unwrap()
}

/// The guest kernel from `cargo xtask guest-kernel`.
pub fn kernel() -> PathBuf {
    std::fs::read_dir(root().join(build::GUEST_OUT))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "bzImage"))
        .expect("run `cargo xtask guest-kernel` first")
}
