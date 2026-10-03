//! The host integrity manifest (ADR 0008).
//!
//! After every deploy the maintainer records the BLAKE3 digests of the
//! files the sandbox trusts: the Crateward binaries, Firecracker, the jail
//! launcher, the fake internet, the guest kernel and root filesystem, and
//! the toolchain's `cargo`. The supervisor checks them against the manifest
//! every `supervisor.integrity_interval_minutes`. A difference is a sign of a
//! host compromise. The format is that of `b3sum`, so `b3sum --check`
//! verifies a manifest by hand.
//!
//! An attacker with the service user's rights could rewrite the manifest
//! too. The check catches changes made without that care, and every change
//! made by a deploy is recorded on purpose.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::Config;

/// Failure to record or read a manifest.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// A file could not be read.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
    /// A manifest line is not `<64 hex digits>  <path>`.
    #[error("manifest line {line} is malformed")]
    Malformed {
        /// Line number, from 1.
        line: usize,
    },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> IntegrityError + '_ {
    move |source| IntegrityError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The files a manifest covers: the configured sandbox files and every
/// executable named `crateward*` next to `bin_dir`'s running binary.
///
/// # Errors
///
/// Fails if `bin_dir` cannot be listed.
pub fn covered(config: &Config, bin_dir: &Path) -> Result<Vec<PathBuf>, IntegrityError> {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = &config.sandbox;
    let mut files = vec![
        sandbox.firecracker_bin.clone(),
        sandbox.vmjail_bin.clone(),
        sandbox.fake_internet_bin.clone(),
        sandbox.kernel_image.clone(),
        sandbox.rootfs_image.clone(),
        config.fetcher.cargo_bin.clone(),
    ];
    for entry in std::fs::read_dir(bin_dir).map_err(io(bin_dir))? {
        let entry = entry.map_err(io(bin_dir))?;
        let path = entry.path();
        let name = entry.file_name();
        let Ok(meta) = entry.metadata() else { continue };
        if name.to_string_lossy().starts_with("crateward")
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            files.push(path);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// The BLAKE3 digest of a file, in hex.
///
/// # Errors
///
/// Fails if the file cannot be read.
pub fn digest(path: &Path) -> Result<String, IntegrityError> {
    let mut file = std::fs::File::open(path).map_err(io(path))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 1 << 16];
    loop {
        let n = file.read(&mut buffer).map_err(io(path))?;
        let Some(chunk) = buffer.get(..n).filter(|c| !c.is_empty()) else {
            break;
        };
        hasher.update(chunk);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Digests of `files`, in `b3sum` format.
///
/// # Errors
///
/// Fails if a file cannot be read.
pub fn record(files: &[PathBuf]) -> Result<String, IntegrityError> {
    let mut out = String::new();
    for path in files {
        out.push_str(&digest(path)?);
        out.push_str("  ");
        out.push_str(&path.to_string_lossy());
        out.push('\n');
    }
    Ok(out)
}

/// Parses a manifest.
///
/// # Errors
///
/// Fails on a malformed line.
pub fn parse(text: &str) -> Result<BTreeMap<PathBuf, String>, IntegrityError> {
    let mut out = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let malformed = IntegrityError::Malformed { line: index + 1 };
        let Some((hash, path)) = line.split_once("  ") else {
            return Err(malformed);
        };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) || path.is_empty() {
            return Err(malformed);
        }
        out.insert(PathBuf::from(path), hash.to_ascii_lowercase());
    }
    Ok(out)
}

/// A file that no longer matches the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// The file.
    pub path: PathBuf,
    /// What is wrong: a different digest, or why it cannot be read.
    pub reason: String,
}

/// Checks every file of a manifest.
#[must_use]
pub fn verify(manifest: &BTreeMap<PathBuf, String>) -> Vec<Mismatch> {
    let mut out = Vec::new();
    for (path, expected) in manifest {
        match digest(path) {
            Ok(actual) if actual == *expected => {}
            Ok(_) => out.push(Mismatch {
                path: path.clone(),
                reason: "digest differs".to_owned(),
            }),
            Err(error) => out.push(Mismatch {
                path: path.clone(),
                reason: error.to_string(),
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_manifest_verifies_until_a_file_changes() {
        let dir = std::env::temp_dir().join(format!(
            "cw-integrity-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"one").unwrap();
        std::fs::write(&b, b"two").unwrap();
        let text = record(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(
            text.lines().next().unwrap(),
            format!("{}  {}", blake3::hash(b"one").to_hex(), a.display())
        );
        let manifest = parse(&text).unwrap();
        assert!(verify(&manifest).is_empty());
        std::fs::write(&b, b"changed").unwrap();
        std::fs::remove_file(&a).unwrap();
        let mismatches = verify(&manifest);
        assert_eq!(mismatches.len(), 2);
        assert_eq!(mismatches[1].reason, "digest differs");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert!(parse("abc  /x\n").is_err());
        assert!(parse(&format!("{}  \n", "0".repeat(64))).is_err());
        assert!(parse(&format!("{} /x\n", "0".repeat(64))).is_err());
        assert!(parse("").unwrap().is_empty());
    }
}
