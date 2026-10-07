//! Content addressed blob store for crate archives (ADR 0004).
//!
//! A blob is the unpacked tar of a crate, zstd compressed, stored at
//! `<root>/blobs/<ab>/<cd>/<blake3>.tar.zst` where the name is the BLAKE3
//! digest of the unpacked tar. Shared dependencies are therefore stored
//! once. Every read recomputes the digest: the server has no ECC memory and
//! ext4 does not checksum data (ADR 0003), so a blob that changed on disk
//! is detected instead of being analyzed.
//!
//! Writes go to a temporary file in the same directory and are renamed into
//! place, so a crash never leaves a partial blob under a valid name.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// zstd level: a good ratio for source code at modest CPU cost on four
/// cores.
const ZSTD_LEVEL: i32 = 9;

/// Why a blob operation failed.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// File I/O failed.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The blob does not match its name.
    #[error("blob {0} is corrupt: its content does not match its digest")]
    Corrupt(String),
    /// The name is not a BLAKE3 digest.
    #[error("{0:?} is not a blob name")]
    BadName(String),
}

/// A stored blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    /// BLAKE3 of the unpacked tar, hex encoded.
    pub blake3: String,
    /// Unpacked size.
    pub tar_bytes: u64,
    /// Compressed size on disk.
    pub stored_bytes: u64,
}

/// The blob store.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> BlobError + '_ {
    move |source| BlobError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl BlobStore {
    /// A store rooted at `root`, created if missing.
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be created.
    pub fn open(root: &Path) -> Result<Self, BlobError> {
        let blobs = root.join("blobs");
        std::fs::create_dir_all(&blobs).map_err(io(&blobs))?;

        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn path(&self, digest: &str) -> Result<PathBuf, BlobError> {
        let valid = digest.len() == 64
            && digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid {
            return Err(BlobError::BadName(digest.to_owned()));
        }

        let (a, b) = (
            digest.get(..2).unwrap_or_default(),
            digest.get(2..4).unwrap_or_default(),
        );

        Ok(self
            .root
            .join("blobs")
            .join(a)
            .join(b)
            .join(format!("{digest}.tar.zst")))
    }

    /// Stores an unpacked tar. Storing the same content twice is cheap: the
    /// existing blob is kept.
    ///
    /// # Errors
    ///
    /// Fails if writing fails.
    pub fn put(&self, tar: &[u8]) -> Result<Blob, BlobError> {
        let digest = blake3::hash(tar).to_hex().to_string();
        let path = self.path(&digest)?;
        let tar_bytes = u64::try_from(tar.len()).unwrap_or(u64::MAX);
        if let Ok(meta) = std::fs::metadata(&path) {
            return Ok(Blob {
                blake3: digest,
                tar_bytes,
                stored_bytes: meta.len(),
            });
        }

        let dir = path.parent().unwrap_or(&self.root);
        std::fs::create_dir_all(dir).map_err(io(dir))?;
        let temp = dir.join(format!(".{digest}.{}.tmp", std::process::id()));
        let compressed = zstd::bulk::compress(tar, ZSTD_LEVEL).map_err(io(&temp))?;
        let mut file = std::fs::File::create(&temp).map_err(io(&temp))?;
        file.write_all(&compressed).map_err(io(&temp))?;
        file.sync_all().map_err(io(&temp))?;
        std::fs::rename(&temp, &path).map_err(io(&path))?;

        Ok(Blob {
            blake3: digest,
            tar_bytes,
            stored_bytes: u64::try_from(compressed.len()).unwrap_or(u64::MAX),
        })
    }

    /// Reads a blob, verifying its digest. At most `max_bytes` are unpacked.
    ///
    /// # Errors
    ///
    /// [`BlobError::Corrupt`] if the content does not match the name.
    pub fn get(&self, digest: &str, max_bytes: u64) -> Result<Vec<u8>, BlobError> {
        let path = self.path(digest)?;
        let file = std::fs::File::open(&path).map_err(io(&path))?;
        let decoder = zstd::stream::read::Decoder::new(file).map_err(io(&path))?;
        let mut tar = Vec::new();
        decoder
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut tar)
            .map_err(|_| BlobError::Corrupt(digest.to_owned()))?;

        if u64::try_from(tar.len()).unwrap_or(u64::MAX) > max_bytes
            || blake3::hash(&tar).to_hex().as_str() != digest
        {
            return Err(BlobError::Corrupt(digest.to_owned()));
        }

        Ok(tar)
    }

    /// Whether a blob exists (without verifying it).
    #[must_use]
    pub fn contains(&self, digest: &str) -> bool {
        self.path(digest).is_ok_and(|p| p.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> BlobStore {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/blob-tests")
            .join(format!("{name}-{}", std::process::id()));

        let _ = std::fs::remove_dir_all(&dir);

        BlobStore::open(&dir).unwrap()
    }

    #[test]
    fn round_trip_and_deduplication() {
        let s = store("round");
        let data = b"tar bytes".repeat(1000);
        let first = s.put(&data).unwrap();
        let second = s.put(&data).unwrap();

        assert_eq!(first, second);
        assert!(first.stored_bytes < first.tar_bytes);
        assert_eq!(s.get(&first.blake3, 1 << 20).unwrap(), data);
    }

    #[test]
    fn corruption_and_bad_names_are_detected() {
        let s = store("corrupt");
        let blob = s.put(b"original content").unwrap();
        let path = s.path(&blob.blake3).unwrap();
        let tampered = zstd::bulk::compress(b"tampered content", 3).unwrap();
        std::fs::write(&path, tampered).unwrap();

        assert!(matches!(
            s.get(&blob.blake3, 1 << 20),
            Err(BlobError::Corrupt(_))
        ));
        assert!(matches!(
            s.get("../../etc/passwd", 10),
            Err(BlobError::BadName(_))
        ));
        assert!(matches!(s.get(&blob.blake3, 3), Err(BlobError::Corrupt(_))));
    }
}
