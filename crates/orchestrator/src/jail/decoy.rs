//! A decoy in every jail root (ADR 0008).
//!
//! Firecracker never looks at its jail root beyond the files it was told
//! about. A process that broke out of the VM and looks around does. Each
//! jail root therefore holds a file that looks like a credential, with its
//! access time set to the epoch. Under `relatime` (the default of ext4 and
//! tmpfs) the first read of a file whose access time is older than its
//! modification time updates the access time, so after the run the host can
//! tell whether anything read it. [`atime_works`] checks at startup that
//! the filesystem really behaves that way.

use std::fs::{File, FileTimes};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The decoy's name in the jail root.
pub const NAME: &str = "host-credentials";

/// The access time the decoy starts with, in seconds after the epoch.
const PLANTED_ATIME: i64 = 1;

fn plant_at(path: &Path) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(path)?;
    file.write_all(b"[default]\naws_access_key_id = AKIACRATEWARDDECOY00\n")?;
    file.set_times(
        FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .set_modified(SystemTime::now()),
    )
}

/// Plants the decoy in a fresh jail root. Readable by the slot's UID
/// through the root's ACL.
///
/// # Errors
///
/// Fails if the file cannot be written.
pub fn plant(root: &Path) -> std::io::Result<()> {
    plant_at(&root.join(NAME))
}

/// What the host finds of a jail root's decoy after the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoy {
    /// Planted and never read.
    Untouched,
    /// Read, changed or removed while the jail root stayed: only a process
    /// with the slot's rights reaches it.
    Touched,
    /// The whole jail root is gone. Only the host removes that, so it is a
    /// host fault, not a finding about the job.
    JailGone,
}

/// Inspects the decoy in `root`. Call it only after every process of the
/// slot is dead, so no read can follow unseen.
#[must_use]
pub fn inspect(root: &Path) -> Decoy {
    if !root.is_dir() {
        Decoy::JailGone
    } else if touched_at(&root.join(NAME)) {
        Decoy::Touched
    } else {
        Decoy::Untouched
    }
}

/// Checks that reading a planted decoy in `dir` changes its access time,
/// so a mount with `noatime` cannot switch the detection off unnoticed.
///
/// # Errors
///
/// Fails if the probe cannot be written or read.
pub fn atime_works(dir: &Path) -> std::io::Result<bool> {
    let probe: PathBuf = dir.join(format!(".decoy-probe-{}", std::process::id()));
    let _ = std::fs::remove_file(&probe);
    plant_at(&probe)?;
    let before = touched_at(&probe);
    let mut buffer = Vec::new();
    File::open(&probe)?.read_to_end(&mut buffer)?;
    let after = touched_at(&probe);
    std::fs::remove_file(&probe)?;
    Ok(!before && after)
}

fn touched_at(path: &Path) -> bool {
    std::fs::metadata(path).map_or(true, |m| m.atime() != PLANTED_ATIME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cw-decoy-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_read_is_seen_and_an_untouched_decoy_is_not() {
        let dir = tempdir();
        assert!(atime_works(&dir).unwrap());
        plant(&dir).unwrap();
        assert_eq!(inspect(&dir), Decoy::Untouched);
        // Metadata alone (what `ls -l` does) is not a read.
        let _ = std::fs::metadata(dir.join(NAME)).unwrap();
        assert_eq!(inspect(&dir), Decoy::Untouched);
        std::fs::read(dir.join(NAME)).unwrap();
        assert_eq!(inspect(&dir), Decoy::Touched);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_removed_decoy_is_touched_and_a_removed_jail_is_not() {
        let dir = tempdir();
        plant(&dir).unwrap();
        std::fs::remove_file(dir.join(NAME)).unwrap();
        assert_eq!(inspect(&dir), Decoy::Touched);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(inspect(&dir), Decoy::JailGone);
    }
}
