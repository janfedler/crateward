//! Validation of crate archives without extracting them (ADR 0004).
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
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(counting));
    let mut names = Names::default();
    let entries = archive
        .entries()
        .map_err(|e| format!("reading entries: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("corrupt archive: {e}"))?;
        report.entries += 1;
        if report.entries > limits.max_entries {
            return Err(format!("more than {} entries", limits.max_entries));
        }
        let Some(path) = inspect(&entry, prefix, limits, &mut report.findings) else {
            continue;
        };
        names.check(&path, &mut report.findings);
        report.files += 1;
        count_content(&mut entry, &path, count, limits, report)?;
    }
    Ok(())
}

/// Checks the header of one entry. Returns the path of a regular file, whose
/// content is still to be counted; any other entry is dealt with here.
fn inspect<R: Read>(
    entry: &tar::Entry<'_, R>,
    prefix: &str,
    limits: &ArchiveLimits,
    findings: &mut Vec<ArchiveFinding>,
) -> Option<String> {
    let Ok(path) = String::from_utf8(entry.path_bytes().into_owned()) else {
        findings.push(ArchiveFinding::NonUtf8Path);
        return None;
    };
    check_path(&path, prefix, limits, findings);
    let mode = entry.header().mode().unwrap_or(0);
    if mode & 0o7000 != 0 {
        findings.push(ArchiveFinding::SpecialMode {
            path: path.clone(),
            mode,
        });
    }
    let finding = match entry.header().entry_type() {
        tar::EntryType::Regular | tar::EntryType::Continuous => return Some(path),
        tar::EntryType::Directory => return None,
        tar::EntryType::Symlink => ArchiveFinding::Symlink {
            path,
            target: link_target(entry),
        },
        tar::EntryType::Link => ArchiveFinding::Hardlink {
            path,
            target: link_target(entry),
        },
        other => ArchiveFinding::SpecialFile {
            path,
            kind: entry_kind(other),
        },
    };
    findings.push(finding);
    None
}

/// The name of a special entry type, stable across `tar` versions.
fn entry_kind(kind: tar::EntryType) -> String {
    let name = match kind {
        tar::EntryType::Char => "Char",
        tar::EntryType::Block => "Block",
        tar::EntryType::Fifo => "Fifo",
        tar::EntryType::GNULongName => "GNULongName",
        tar::EntryType::GNULongLink => "GNULongLink",
        tar::EntryType::GNUSparse => "GNUSparse",
        tar::EntryType::XGlobalHeader => "XGlobalHeader",
        tar::EntryType::XHeader => "XHeader",
        other => return format!("type {:#04x}", other.as_byte()),
    };
    name.to_owned()
}

fn link_target<R: Read>(entry: &tar::Entry<'_, R>) -> String {
    entry
        .link_name_bytes()
        .map(|l| String::from_utf8_lossy(&l).into_owned())
        .unwrap_or_default()
}

/// The names of the regular files seen so far.
#[derive(Default)]
struct Names {
    exact: HashSet<String>,
    lowercase: HashMap<String, String>,
}

impl Names {
    /// Notes a name and reports a repeat, or a name that differs from an
    /// earlier one only in case.
    fn check(&mut self, path: &str, findings: &mut Vec<ArchiveFinding>) {
        if !self.exact.insert(path.to_owned()) {
            findings.push(ArchiveFinding::Duplicate {
                path: path.to_owned(),
            });
        }
        if let Some(other) = self.lowercase.insert(path.to_lowercase(), path.to_owned())
            && other != path
        {
            findings.push(ArchiveFinding::CaseCollision {
                path: path.to_owned(),
                other,
            });
        }
    }
}

/// Counts the real content of a file, not the header's claim, and holds it
/// to the limits.
fn count_content<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    path: &str,
    count: &Cell<u64>,
    limits: &ArchiveLimits,
    report: &mut ArchiveReport,
) -> Result<(), String> {
    let mut limited = entry.by_ref().take(limits.max_file_bytes + 1);
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
    if report.unpacked_bytes > 1024 * 1024 && report.unpacked_bytes / compressed > limits.max_ratio
    {
        return Err(format!("compression ratio above {}", limits.max_ratio));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Builds a gzip compressed tar from raw headers, so tests can create
    /// entries a normal builder refuses to write.
    fn archive<P: AsRef<[u8]>>(entries: &[(P, tar::EntryType, &[u8], &str, u32)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, kind, data, link, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(u64::try_from(data.len()).unwrap());
            header.set_mode(*mode);
            // Write the raw name, bypassing the builder's path checks.
            let name = path.as_ref();
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

    fn finding_path(path: &str) -> String {
        path.to_owned()
    }

    #[test]
    fn hostile_entries_become_findings_in_entry_order() {
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
        assert!(report.is_storable());
        assert_eq!(
            (report.entries, report.files, report.unpacked_bytes),
            (9, 6, 6)
        );
        assert_eq!(report.compressed_bytes, u64::try_from(bytes.len()).unwrap());
        assert_eq!(
            report.findings,
            vec![
                ArchiveFinding::ParentComponent {
                    path: finding_path("demo-1.0.0/../../etc/cron.d/x")
                },
                ArchiveFinding::AbsolutePath {
                    path: finding_path("/etc/passwd")
                },
                ArchiveFinding::OutsidePrefix {
                    path: finding_path("/etc/passwd")
                },
                ArchiveFinding::OutsidePrefix {
                    path: finding_path("other-dir/file")
                },
                ArchiveFinding::Symlink {
                    path: finding_path("demo-1.0.0/link"),
                    target: "/home".to_owned()
                },
                ArchiveFinding::Hardlink {
                    path: finding_path("demo-1.0.0/hard"),
                    target: "/etc/shadow".to_owned()
                },
                ArchiveFinding::SpecialFile {
                    path: finding_path("demo-1.0.0/dev"),
                    kind: "Char".to_owned()
                },
                ArchiveFinding::SpecialMode {
                    path: finding_path("demo-1.0.0/suid"),
                    mode: 0o4755
                },
                ArchiveFinding::CaseCollision {
                    path: finding_path("demo-1.0.0/A.rs"),
                    other: finding_path("demo-1.0.0/a.rs")
                },
            ]
        );
    }

    #[test]
    fn repeated_names_are_duplicates_and_case_collisions() {
        let bytes = archive(&[
            ("demo-1.0.0/same", R, b"1", "", 0o644),
            ("demo-1.0.0/same", R, b"22", "", 0o644),
            ("demo-1.0.0/a.rs", R, b"x", "", 0o644),
            ("demo-1.0.0/A.rs", R, b"x", "", 0o644),
            ("demo-1.0.0/a.rs", R, b"x", "", 0o644),
        ]);
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        assert_eq!(
            report.findings,
            vec![
                ArchiveFinding::Duplicate {
                    path: finding_path("demo-1.0.0/same")
                },
                ArchiveFinding::CaseCollision {
                    path: finding_path("demo-1.0.0/A.rs"),
                    other: finding_path("demo-1.0.0/a.rs")
                },
                ArchiveFinding::Duplicate {
                    path: finding_path("demo-1.0.0/a.rs")
                },
                ArchiveFinding::CaseCollision {
                    path: finding_path("demo-1.0.0/a.rs"),
                    other: finding_path("demo-1.0.0/A.rs")
                },
            ]
        );
        assert_eq!((report.entries, report.files), (5, 5));
        assert_eq!(report.unpacked_bytes, 6);
    }

    #[test]
    fn directories_are_checked_but_not_counted() {
        let dir = tar::EntryType::Directory;
        let bytes = archive(&[
            ("demo-1.0.0/", dir, b"", "", 0o755),
            ("demo-1.0.0/src/", dir, b"", "", 0o1777),
            ("elsewhere/", dir, b"", "", 0o755),
            ("demo-1.0.0/src/lib.rs", R, b"x", "", 0o644),
        ]);
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        assert_eq!(
            report.findings,
            vec![
                ArchiveFinding::SpecialMode {
                    path: finding_path("demo-1.0.0/src/"),
                    mode: 0o1777
                },
                ArchiveFinding::OutsidePrefix {
                    path: finding_path("elsewhere/")
                },
            ]
        );
        assert_eq!((report.entries, report.files), (4, 1));
    }

    #[test]
    fn special_files_are_named_by_their_type() {
        let bytes = archive(&[
            ("demo-1.0.0/pipe", tar::EntryType::Fifo, b"", "", 0o644),
            ("demo-1.0.0/disk", tar::EntryType::Block, b"", "", 0o644),
            ("demo-1.0.0/odd", tar::EntryType::new(b'A'), b"", "", 0o644),
            (
                "demo-1.0.0/contiguous",
                tar::EntryType::Continuous,
                b"x",
                "",
                0o644,
            ),
        ]);
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        assert_eq!(
            report.findings,
            vec![
                ArchiveFinding::SpecialFile {
                    path: finding_path("demo-1.0.0/pipe"),
                    kind: "Fifo".to_owned()
                },
                ArchiveFinding::SpecialFile {
                    path: finding_path("demo-1.0.0/disk"),
                    kind: "Block".to_owned()
                },
                ArchiveFinding::SpecialFile {
                    path: finding_path("demo-1.0.0/odd"),
                    kind: "type 0x41".to_owned()
                },
            ]
        );
        assert_eq!((report.entries, report.files), (4, 1));
    }

    #[test]
    fn a_path_that_is_not_utf8_is_a_finding_and_the_rest_goes_on() {
        let bytes = archive(&[
            (&b"demo-1.0.0/\xff\xfe"[..], R, b"x", "", 0o4755),
            (&b"demo-1.0.0/ok.rs"[..], R, b"yy", "", 0o644),
        ]);
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        assert_eq!(report.findings, vec![ArchiveFinding::NonUtf8Path]);
        assert_eq!(
            (report.entries, report.files, report.unpacked_bytes),
            (2, 1, 2)
        );
    }

    #[test]
    fn long_and_deep_paths_are_oversized() {
        let limits = ArchiveLimits {
            max_path_bytes: 24,
            max_depth: 3,
            ..ArchiveLimits::default()
        };
        let bytes = archive(&[
            ("demo-1.0.0/a/b", R, b"x", "", 0o644),
            ("demo-1.0.0/a/b/c", R, b"x", "", 0o644),
            ("demo-1.0.0/long-file-name.rs", R, b"x", "", 0o644),
        ]);
        let report = validate(bytes.as_slice(), "demo", "1.0.0", &limits);
        assert_eq!(
            report.findings,
            vec![
                ArchiveFinding::OversizedPath {
                    path: finding_path("demo-1.0.0/a/b/c")
                },
                ArchiveFinding::OversizedPath {
                    path: finding_path("demo-1.0.0/long-file-name.rs")
                },
            ]
        );
    }

    #[test]
    fn each_limit_aborts_with_its_own_reason_and_counts_so_far() {
        let small = |name: &str, len: usize| (name.to_owned(), vec![b'x'; len]);
        let build = |files: &[(String, Vec<u8>)]| {
            let entries: Vec<_> = files
                .iter()
                .map(|(name, data)| (name.as_str(), R, data.as_slice(), "", 0o644))
                .collect();
            archive(&entries)
        };
        let check = |bytes: &[u8], limits: ArchiveLimits| {
            let report = validate(bytes, "demo", "1.0.0", &limits);
            (
                report.aborted.clone(),
                (report.entries, report.files, report.unpacked_bytes),
            )
        };
        let three = build(&[
            small("demo-1.0.0/a", 5),
            small("demo-1.0.0/b", 6),
            small("demo-1.0.0/c", 7),
        ]);
        let few = ArchiveLimits {
            max_entries: 2,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            check(&three, few),
            (Some("more than 2 entries".to_owned()), (3, 2, 11))
        );
        let per_file = ArchiveLimits {
            max_file_bytes: 6,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            check(&three, per_file),
            (Some("demo-1.0.0/c exceeds 6 bytes".to_owned()), (3, 3, 11))
        );
        let total = ArchiveLimits {
            max_unpacked_bytes: 10,
            ..ArchiveLimits::default()
        };
        assert_eq!(
            check(&three, total),
            (Some("more than 10 unpacked bytes".to_owned()), (2, 2, 11))
        );
        let zeros = vec![0_u8; 8 * 1024 * 1024];
        let bomb = build(&[("demo-1.0.0/zeros".to_owned(), zeros)]);
        let ratio = ArchiveLimits {
            max_ratio: 50,
            ..ArchiveLimits::default()
        };
        let (aborted, counts) = check(&bomb, ratio);
        assert_eq!(aborted, Some("compression ratio above 50".to_owned()));
        assert_eq!(counts, (1, 1, 8 * 1024 * 1024));
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
        assert_eq!(
            report.aborted.as_deref(),
            Some("corrupt archive: invalid gzip header")
        );
    }

    proptest! {
        #[test]
        fn validation_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let _ = validate(bytes.as_slice(), "demo", "1.0.0", &ArchiveLimits::default());
        }
    }
}
