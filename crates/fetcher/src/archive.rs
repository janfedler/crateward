//! Validation of crate archives without extracting them (ADR 0014).
//!
//! A `.crate` file is a gzip compressed tar archive whose entries should all
//! live under `<name>-<version>/`. Crateward never materializes an archive
//! on the host filesystem: it streams the archive through this validator in
//! a sandbox and stores the tar as a blob. Everything unusual becomes a
//! finding rather than an error, because a hostile archive is evidence.
//!
//! Limits stop decompression bombs early: total unpacked bytes, bytes per
//! file, entry count, and the ratio of unpacked to compressed bytes.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::rc::Rc;

use serde::{Deserialize, Serialize};

/// Limits of one archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveLimits {
    /// Total unpacked bytes.
    pub max_unpacked_bytes: u64,
    /// Bytes of one file.
    pub max_file_bytes: u64,
    /// Entries of any kind.
    pub max_entries: u64,
    /// Unpacked bytes per compressed byte.
    pub max_ratio: u64,
    /// Bytes of one path.
    pub max_path_bytes: usize,
    /// Components of one path.
    pub max_depth: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_unpacked_bytes: 512 * 1024 * 1024,
            max_file_bytes: 256 * 1024 * 1024,
            max_entries: 50_000,
            max_ratio: 200,
            max_path_bytes: 512,
            max_depth: 32,
        }
    }
}

/// Something unusual about an archive. Every `path` is the entry's path as
/// written in the archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum ArchiveFinding {
    /// A path that is not valid UTF-8.
    NonUtf8Path,
    /// An absolute path.
    AbsolutePath {
        /// Entry path.
        path: String,
    },
    /// A path with a `..` component: traversal.
    ParentComponent {
        /// Entry path.
        path: String,
    },
    /// A path outside the expected `<name>-<version>/` prefix.
    OutsidePrefix {
        /// Entry path.
        path: String,
    },
    /// A path longer or deeper than the limits.
    OversizedPath {
        /// Entry path.
        path: String,
    },
    /// A symbolic link.
    Symlink {
        /// Entry path.
        path: String,
        /// Link target.
        target: String,
    },
    /// A hard link.
    Hardlink {
        /// Entry path.
        path: String,
        /// Link target.
        target: String,
    },
    /// A device, FIFO or other special file.
    SpecialFile {
        /// Entry path.
        path: String,
        /// The tar entry type.
        kind: String,
    },
    /// A file with the setuid, setgid or sticky bit.
    SpecialMode {
        /// Entry path.
        path: String,
        /// The mode bits.
        mode: u32,
    },
    /// The same path twice.
    Duplicate {
        /// Entry path.
        path: String,
    },
    /// Two paths that differ only in case, which collide on Windows and
    /// macOS file systems.
    CaseCollision {
        /// Entry path.
        path: String,
        /// The earlier path it collides with.
        other: String,
    },
}

/// The result of validating one archive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReport {
    /// Entries seen.
    pub entries: u64,
    /// Regular files seen.
    pub files: u64,
    /// Unpacked bytes of regular files.
    pub unpacked_bytes: u64,
    /// Compressed bytes read.
    pub compressed_bytes: u64,
    /// Unusual entries.
    pub findings: Vec<ArchiveFinding>,
    /// Why validation stopped early, if it did: a limit was exceeded or the
    /// archive is corrupt. Such an archive is never stored.
    pub aborted: Option<String>,
}

impl ArchiveReport {
    /// Whether the archive may be stored and used downstream.
    #[must_use]
    pub fn is_storable(&self) -> bool {
        self.aborted.is_none()
    }
}

/// Counts bytes read through it into a shared cell, so the count stays
/// readable while the decompressor owns the reader.
struct Counting<R> {
    inner: R,
    count: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(
            self.count
                .get()
                .saturating_add(u64::try_from(n).unwrap_or(u64::MAX)),
        );
        Ok(n)
    }
}

fn check_path(
    path: &str,
    prefix: &str,
    limits: &ArchiveLimits,
    findings: &mut Vec<ArchiveFinding>,
) {
    let owned = || path.to_owned();
    if path.starts_with('/') {
        findings.push(ArchiveFinding::AbsolutePath { path: owned() });
    }
    if path.split('/').any(|c| c == "..") {
        findings.push(ArchiveFinding::ParentComponent { path: owned() });
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed != prefix.trim_end_matches('/') && !path.starts_with(prefix) {
        findings.push(ArchiveFinding::OutsidePrefix { path: owned() });
    }
    if path.len() > limits.max_path_bytes || path.split('/').count() > limits.max_depth {
        findings.push(ArchiveFinding::OversizedPath { path: owned() });
    }
}

/// Validates a gzip compressed tar stream. `name` and `version` give the
/// expected top level directory.
#[must_use]
pub fn validate<R: Read>(
    compressed: R,
    name: &str,
    version: &str,
    limits: &ArchiveLimits,
) -> ArchiveReport {
    let prefix = format!("{name}-{version}/");
    let count = Rc::new(Cell::new(0));
    let counting = Counting {
        inner: compressed,
        count: Rc::clone(&count),
    };
    let mut report = ArchiveReport::default();
    let result = walk(counting, &count, &prefix, limits, &mut report);
    report.compressed_bytes = count.get();
    if let Err(reason) = result {
        report.aborted = Some(reason);
    }
    report
}

fn walk<R: Read>(
    counting: Counting<R>,
    count: &Cell<u64>,
    prefix: &str,
    limits: &ArchiveLimits,
    report: &mut ArchiveReport,
) -> Result<(), String> {
    let gz = flate2::read::GzDecoder::new(counting);
    let mut archive = tar::Archive::new(gz);
    let mut seen = HashSet::new();
    let mut lowercase: HashMap<String, String> = HashMap::new();
    let entries = archive
        .entries()
        .map_err(|e| format!("reading entries: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("corrupt archive: {e}"))?;
        report.entries += 1;
        if report.entries > limits.max_entries {
            return Err(format!("more than {} entries", limits.max_entries));
        }
        let raw_path = entry.path_bytes().into_owned();
        let Ok(path) = String::from_utf8(raw_path) else {
            report.findings.push(ArchiveFinding::NonUtf8Path);
            continue;
        };
        check_path(&path, prefix, limits, &mut report.findings);
        let kind = entry.header().entry_type();
        let mode = entry.header().mode().unwrap_or(0);
        if mode & 0o7000 != 0 {
            report.findings.push(ArchiveFinding::SpecialMode {
                path: path.clone(),
                mode,
            });
        }
        let link = || {
            entry
                .link_name_bytes()
                .map(|l| String::from_utf8_lossy(&l).into_owned())
                .unwrap_or_default()
        };
        match kind {
            tar::EntryType::Regular | tar::EntryType::Continuous => {}
            tar::EntryType::Directory => continue,
            tar::EntryType::Symlink => {
                report.findings.push(ArchiveFinding::Symlink {
                    path,
                    target: link(),
                });
                continue;
            }
            tar::EntryType::Link => {
                report.findings.push(ArchiveFinding::Hardlink {
                    path,
                    target: link(),
                });
                continue;
            }
            other => {
                report.findings.push(ArchiveFinding::SpecialFile {
                    path,
                    kind: format!("{other:?}"),
                });
                continue;
            }
        }
        if !seen.insert(path.clone()) {
            report
                .findings
                .push(ArchiveFinding::Duplicate { path: path.clone() });
        }
        if let Some(other) = lowercase.insert(path.to_lowercase(), path.clone())
            && other != path
        {
            report.findings.push(ArchiveFinding::CaseCollision {
                path: path.clone(),
                other,
            });
        }
        report.files += 1;
        // Count the real content, not the header's claim.
        let mut limited = (&mut entry).take(limits.max_file_bytes + 1);
        let size =
            io::copy(&mut limited, &mut io::sink()).map_err(|e| format!("corrupt archive: {e}"))?;
        if size > limits.max_file_bytes {
            return Err(format!("{path} exceeds {} bytes", limits.max_file_bytes));
        }
        report.unpacked_bytes += size;
        if report.unpacked_bytes > limits.max_unpacked_bytes {
            return Err(format!(
                "more than {} unpacked bytes",
                limits.max_unpacked_bytes
            ));
        }
        let compressed = count.get().max(1);
        // The ratio needs some volume to be meaningful: gzip reads ahead.
        if report.unpacked_bytes > 1024 * 1024
            && report.unpacked_bytes / compressed > limits.max_ratio
        {
            return Err(format!("compression ratio above {}", limits.max_ratio));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Builds a gzip compressed tar from raw headers, so tests can create
    /// entries a normal builder refuses to write.
    fn archive(entries: &[(&str, tar::EntryType, &[u8], &str, u32)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, kind, data, link, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(u64::try_from(data.len()).unwrap());
            header.set_mode(*mode);
            // Write the raw name, bypassing the builder's path checks.
            let name = path.as_bytes();
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            if !link.is_empty() {
                header.set_link_name(link).unwrap();
            }
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    const R: tar::EntryType = tar::EntryType::Regular;

    #[test]
    fn a_normal_crate_has_no_findings() {
        let bytes = archive(&[
            ("demo-1.0.0/Cargo.toml", R, b"[package]", "", 0o644),
            ("demo-1.0.0/src/lib.rs", R, b"pub fn f() {}", "", 0o644),
        ]);
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        assert!(report.is_storable(), "{report:?}");
        assert!(report.findings.is_empty(), "{report:?}");
        assert_eq!(report.files, 2);
    }

    #[test]
    fn hostile_entries_become_findings() {
        let bytes = archive(&[
            ("demo-1.0.0/../../etc/cron.d/x", R, b"x", "", 0o644),
            ("/etc/passwd", R, b"x", "", 0o644),
            ("other-dir/file", R, b"x", "", 0o644),
            (
                "demo-1.0.0/link",
                tar::EntryType::Symlink,
                b"",
                "/home",
                0o777,
            ),
            (
                "demo-1.0.0/hard",
                tar::EntryType::Link,
                b"",
                "/etc/shadow",
                0o644,
            ),
            ("demo-1.0.0/dev", tar::EntryType::Char, b"", "", 0o644),
            ("demo-1.0.0/suid", R, b"x", "", 0o4755),
            ("demo-1.0.0/a.rs", R, b"x", "", 0o644),
            ("demo-1.0.0/A.rs", R, b"x", "", 0o644),
        ]);
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        let kinds: Vec<_> = report
            .findings
            .iter()
            .map(|f| {
                serde_json::to_value(f).unwrap()["finding"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        for kind in [
            "parent_component",
            "absolute_path",
            "outside_prefix",
            "symlink",
            "hardlink",
            "special_file",
            "special_mode",
            "case_collision",
        ] {
            assert!(kinds.iter().any(|k| k == kind), "missing {kind}: {kinds:?}");
        }
        assert!(report.is_storable());
    }

    #[test]
    fn a_decompression_bomb_is_aborted() {
        let zeros = vec![0_u8; 8 * 1024 * 1024];
        let bytes = archive(&[("demo-1.0.0/zeros", R, &zeros, "", 0o644)]);
        let limits = ArchiveLimits {
            max_ratio: 50,
            ..ArchiveLimits::default()
        };
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &limits);
        assert!(!report.is_storable(), "{report:?}");
        let small = ArchiveLimits {
            max_file_bytes: 1024,
            ..ArchiveLimits::default()
        };
        assert!(!validate(bytes.as_slice(), "demo", "1.0.0", &small).is_storable());
    }

    #[test]
    fn garbage_is_aborted_not_panicking() {
        let report = validate(
            &b"not a gzip stream"[..],
            "demo",
            "1.0.0",
            &ArchiveLimits::default(),
        );
        assert!(!report.is_storable());
    }

    proptest! {
        #[test]
        fn validation_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        }
    }
}
