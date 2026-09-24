//! Helpers shared by the image building tasks.
//!
//! Every image Crateward produces is identified by its BLAKE3 digest. The
//! orchestrator verifies the digest before an image is used, so an image
//! that changed on disk, whether by corruption (the server has no ECC
//! memory) or by tampering, is never booted.

use std::io::Read;
use std::path::Path;

use crate::TaskError;

/// BLAKE3 digest of a file, hex encoded, read in chunks.
///
/// # Errors
///
/// Fails if the file cannot be read.
pub fn blake3_file(path: &Path) -> Result<String, TaskError> {
    let io = |e| TaskError::Io(path.to_path_buf(), e);
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).map_err(io)?;
        let Some(chunk) = buffer.get(..read) else {
            break;
        };
        if chunk.is_empty() {
            break;
        }
        hasher.update(chunk);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// SHA-256 digest of a file, hex encoded. Used where an external party
/// publishes SHA-256 checksums, such as Firecracker releases.
///
/// # Errors
///
/// Fails if the file cannot be read.
pub fn sha256_file(path: &Path) -> Result<String, TaskError> {
    use sha2::Digest as _;
    let io = |e| TaskError::Io(path.to_path_buf(), e);
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(io)?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
