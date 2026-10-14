//! What a job left on its scratch disk.
//!
//! The scratch disk is the only writable disk a job has. Everything else in
//! the guest is a read only image or memory that ends with the VM. After
//! the run, the host reads the ext4 image. It was formatted empty, and the
//! agent created only the target directory and the honeytoken files, so
//! everything else on it is the job's doing.
//!
//! The image is hostile input: the guest wrote every byte and may have
//! crafted the filesystem itself. It is read with `ext4-view`, a read only
//! parser without unsafe code that is designed never to panic on invalid
//! data, in a sandboxed child (no network, no filesystem access, resource
//! limits) that gets the image as stdin and prints a JSON report. The walk
//! is bounded in entries, depth and bytes read.

use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd as _;
use std::path::Path;
use std::process::{ExitCode, Stdio};

use crateward_core::bytes::u32_le;
use crateward_core::child::{self, Child, ChildError};
use crateward_core::paths::guest::{self, WORK};
use crateward_core::sandbox::{self, FsAccess, Limits};
use ext4_view::{Ext4, Ext4Error, FileType, Metadata, PathBuf as ExtPath};
use serde::{Deserialize, Serialize};

use crate::payload::spawn_mkfs;
use crate::trace::render;
use crateward_core::report::scratch::{Entry, ScratchReport};

/// First argument of the sandboxed child.
pub const SCAN: &str = "sandbox-scratch";

/// First argument of the child that exports `/target` as a tar (the warm
/// build, ADR 0006).
pub const EXPORT: &str = "sandbox-scratch-export";

/// Bounds of an export.
const MAX_EXPORT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_EXPORT_ENTRIES: u64 = 1_000_000;

const MAX_ENTRIES: u64 = 200_000;
const MAX_DEPTH: usize = 64;
const MAX_LISTED: usize = 500;
const MAX_UNITS: usize = 5_000;
/// Bytes of file contents searched for honeytokens, per file and in total.
const MAX_FILE_SEARCH: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_SEARCH: u64 = 1024 * 1024 * 1024;
/// Largest report read back from the child.
const MAX_REPORT: u64 = 16 * 1024 * 1024;

/// The children in error messages.
const SCAN_NAME: &str = "scratch scanner";
const EXPORT_NAME: &str = "scratch export";

/// What the children that read the image may use.
const LIMITS: Limits = Limits {
    address_space: 2 << 30,
    cpu_seconds: 600,
    file_size: 0,
    open_files: 16,
};

/// The directory `mkfs.ext4` creates for recovered files, relative to the
/// scratch root.
const LOST_FOUND: &str = "/lost+found";

/// What the child needs besides the image.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSpec {
    /// Honeytoken values to look for in file contents.
    pub tokens: Vec<String>,
    /// Files the agent planted, as the guest sees them (under `/work`).
    /// They hold the tokens by design and are not searched.
    pub planted: Vec<String>,
    /// Directories the agent created, as the guest sees them.
    pub created: Vec<String>,
    /// Values of the job's ordinary environment variables. A file that
    /// holds a honeytoken and all of these holds a dump of the environment.
    #[serde(default)]
    pub environment: Vec<String>,
}

fn kind(file_type: FileType) -> &'static str {
    match file_type {
        FileType::Regular => "file",
        FileType::Directory => "dir",
        FileType::Symlink => "symlink",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
        FileType::CharacterDevice => "char",
        FileType::BlockDevice => "block",
    }
}

/// Whether `haystack` holds `value`. An empty value is never found.
fn contains(haystack: &[u8], value: &str) -> bool {
    !value.is_empty() && haystack.windows(value.len()).any(|w| w == value.as_bytes())
}

fn push<T>(list: &mut Vec<T>, omitted: &mut u64, item: T) {
    if list.len() < MAX_LISTED {
        list.push(item);
    } else {
        *omitted += 1;
    }
}

/// A guest path on the scratch disk, relative to the scratch root.
fn on_scratch(path: &'static str) -> &'static str {
    path.strip_prefix(WORK).unwrap_or(path)
}

/// Whether `path` is `dir` or below it.
fn within(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether a path is in a build area, where writes are part of a normal
/// `cargo check`. With a warm build cache, the job's own target writes land
/// in the overlay's upper directory.
fn in_build_area(relative: &str) -> bool {
    [
        on_scratch(guest::TARGET),
        on_scratch(guest::WARM),
        LOST_FOUND,
    ]
    .into_iter()
    .any(|area| within(relative, area))
}

/// Whether a path is cargo's own state in `CARGO_HOME`: lock files and the
/// cache database (with its journal files) by prefix, the rest by exact
/// path, so nothing else can hide below them.
fn is_cargo_state(relative: &str) -> bool {
    let Some(rest) = relative.strip_prefix(on_scratch(guest::CARGO_HOME)) else {
        return false;
    };

    rest.starts_with("/.package-cache")
        || rest.starts_with("/.global-cache")
        || matches!(rest, "/registry" | "/registry/CACHEDIR.TAG")
}

/// Whether a path is in a target directory, the job's own or the warm
/// cache's writable layer.
fn in_target(relative: &str) -> bool {
    [guest::TARGET, guest::WARM_UPPER]
        .into_iter()
        .any(|dir| within(relative, on_scratch(dir)))
}

/// The file name of a compiled unit, if the path is one.
fn unit_name(relative: &str) -> Option<&str> {
    let name = [guest::TARGET, guest::WARM_UPPER]
        .into_iter()
        .find_map(|dir| {
            relative
                .strip_prefix(on_scratch(dir))?
                .strip_prefix("/debug/deps/")
        })?;

    let unit = !name.contains('/') && [".rmeta", ".rlib", ".so"].iter().any(|e| name.ends_with(e));

    unit.then_some(name)
}

/// Whether a link points out of the scratch disk: to an absolute path
/// elsewhere or up with `..`.
fn leaves_scratch(target: &str) -> bool {
    (target.starts_with('/') && !target.starts_with(WORK)) || target.contains("..")
}

struct Scanner<'a> {
    fs: &'a Ext4,
    spec: &'a ScanSpec,
    report: ScratchReport,
    entries: u64,
    searched: u64,
}

impl Scanner<'_> {
    /// Reads the start of a file and searches it for honeytokens. Returns
    /// whether it starts with an ELF header.
    fn search(&mut self, path: &ExtPath, guest: &str) -> Result<bool, Ext4Error> {
        let mut file = self.fs.open(path.as_path())?;
        let spec = self.spec;
        let longest = spec
            .tokens
            .iter()
            .chain(&spec.environment)
            .map(String::len)
            .max()
            .unwrap_or(0);

        let mut window: Vec<u8> = Vec::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut read_total = 0_u64;
        let mut elf = false;
        let mut found = vec![false; spec.tokens.len()];
        let mut environment = vec![false; spec.environment.len()];

        while read_total < MAX_FILE_SEARCH && self.searched < MAX_TOTAL_SEARCH {
            let n = file.read_bytes(&mut buffer)?;
            if n == 0 {
                break;
            }

            let chunk = buffer.get(..n).unwrap_or_default();
            if read_total == 0 {
                elf = chunk.starts_with(b"\x7fELF");
            }

            read_total += n as u64;
            self.searched += n as u64;

            // Keep the tail of the previous chunk, so a value split across
            // two reads is still found.
            window.extend_from_slice(chunk);

            self.note_tokens(&window, &mut found, guest);

            for (seen, value) in environment.iter_mut().zip(&spec.environment) {
                *seen = *seen || contains(&window, value);
            }

            let keep = window.len().saturating_sub(longest);
            window.drain(..keep);
        }

        if read_total >= MAX_FILE_SEARCH || self.searched >= MAX_TOTAL_SEARCH {
            self.report.incomplete = true;
        }

        let dump = !environment.is_empty() && environment.iter().all(|&seen| seen);
        if dump
            && found.contains(&true)
            && let Some(dumps) = &mut self.report.environment_dumps
        {
            push(dumps, &mut self.report.omitted, guest.to_owned());
        }

        Ok(elf)
    }

    /// Reports each honeytoken in `window` that `found` does not have yet.
    fn note_tokens(&mut self, window: &[u8], found: &mut [bool], guest: &str) {
        for ((i, token), seen) in self.spec.tokens.iter().enumerate().zip(found) {
            if !*seen && contains(window, token) {
                *seen = true;
                let r = &mut self.report;
                push(&mut r.tokens_found, &mut r.omitted, (i, guest.to_owned()));
            }
        }
    }

    /// The entry as the report lists it. Reads the target of a symbolic link.
    fn describe(
        &self,
        child: &ExtPath,
        relative: &str,
        meta: &Metadata,
    ) -> Result<Entry, Ext4Error> {
        let file_type = meta.file_type();
        let target = if file_type == FileType::Symlink {
            Some(render(self.fs.read_link(child.as_path())?.as_ref()))
        } else {
            None
        };

        Ok(Entry {
            path: format!("{WORK}{relative}"),
            kind: kind(file_type).into(),
            size: meta.len(),
            mode: meta.mode(),
            uid: meta.uid(),
            target,
        })
    }

    fn visit(&mut self, path: &ExtPath, depth: usize) -> Result<(), Ext4Error> {
        if depth > MAX_DEPTH {
            self.report.incomplete = true;
            return Ok(());
        }

        for entry in self.fs.read_dir(path.as_path())? {
            let entry = entry?;
            if matches!(entry.file_name().as_ref(), b"." | b"..") {
                continue;
            }

            self.entries += 1;

            if self.entries > MAX_ENTRIES {
                self.report.incomplete = true;
                return Ok(());
            }

            let child = entry.path();
            let relative = render(child.as_ref());
            let meta = entry.metadata()?;
            let file_type = meta.file_type();
            let item = self.describe(&child, &relative, &meta)?;
            let planted = self.spec.planted.contains(&item.path);
            let created = self.spec.created.contains(&item.path);
            let stray =
                !(in_build_area(&relative) || is_cargo_state(&relative) || planted || created);

            let r = &mut self.report;
            if stray {
                push(&mut r.outside_build, &mut r.omitted, item.clone());
            }

            if item.mode & 0o6000 != 0 && file_type != FileType::Directory {
                push(&mut r.setid, &mut r.omitted, item.clone());
            }

            match file_type {
                FileType::Directory => {
                    r.directories += 1;

                    if relative != LOST_FOUND {
                        self.visit(&child, depth + 1)?;
                    }
                }
                FileType::Regular => self.regular(&child, &relative, item, planted)?,
                FileType::Symlink => {
                    if item.target.as_deref().is_some_and(leaves_scratch) {
                        push(&mut r.links_outside, &mut r.omitted, item);
                    }
                }

                // Overlayfs records a deleted lower file as a character
                // device (a whiteout), prepared in its work directory and
                // moved into the upper one.
                FileType::CharacterDevice if within(&relative, on_scratch(guest::WARM)) => {}
                _ => push(&mut r.special, &mut r.omitted, item),
            }
        }

        Ok(())
    }

    /// Counts a regular file: its unit, its size and, unless the agent
    /// planted it, its contents. Lists it if it is an executable outside the
    /// target directory.
    fn regular(
        &mut self,
        child: &ExtPath,
        relative: &str,
        item: Entry,
        planted: bool,
    ) -> Result<(), Ext4Error> {
        let r = &mut self.report;
        r.files += 1;

        if let Some(unit) = unit_name(relative) {
            if r.units.len() < MAX_UNITS {
                r.units.push(unit.to_owned());
            } else {
                r.omitted += 1;
            }
        }

        r.bytes = r.bytes.saturating_add(item.size);
        let elf = !planted && self.search(child, &item.path)?;
        let executable = item.mode & 0o111 != 0 || elf;
        if executable && !in_target(relative) {
            let r = &mut self.report;
            push(&mut r.executables_outside_target, &mut r.omitted, item);
        }

        Ok(())
    }
}

/// Scans a loaded filesystem. Errors end the walk and are reported. What
/// was found until then is kept.
#[must_use]
pub fn scan(fs: &Ext4, spec: &ScanSpec) -> ScratchReport {
    let mut scanner = Scanner {
        fs,
        spec,
        report: ScratchReport {
            environment_dumps: Some(Vec::new()),
            ..ScratchReport::default()
        },
        entries: 0,
        searched: 0,
    };

    if let Err(error) = scanner.visit(&ExtPath::new("/"), 0) {
        scanner.report.error = Some(error.to_string());
        scanner.report.incomplete = true;
    }

    for planted in &spec.planted {
        let relative = planted.strip_prefix(WORK).unwrap_or(planted);
        let intact = fs.read(relative).is_ok_and(|data| {
            spec.tokens
                .iter()
                .any(|t| !t.is_empty() && data.windows(t.len()).any(|w| w == t.as_bytes()))
        });

        if !intact {
            scanner.report.planted_changed.push(planted.clone());
        }
    }

    scanner.report
}

/// Scans the image at `image` in the sandboxed child. `exe` is the
/// orchestrator binary.
///
/// # Errors
///
/// Fails if the child cannot run or its report does not parse.
pub fn scan_in_sandbox(
    exe: &Path,
    image: &Path,
    spec: &ScanSpec,
) -> Result<ScratchReport, ChildError> {
    let input = File::open(image).map_err(ChildError::io(SCAN_NAME, "opening the image"))?;
    let spec =
        serde_json::to_string(spec).map_err(ChildError::io(SCAN_NAME, "encoding the spec"))?;

    let mut command = child::command(exe);
    command
        .arg(SCAN)
        .arg(spec)
        .stdin(input)
        .stdout(Stdio::piped());
    let report = Child::spawn(SCAN_NAME, command)?.output(MAX_REPORT)?;

    serde_json::from_slice(&report).map_err(|e| ChildError::answer(SCAN_NAME, e))
}

/// The crate a unit's file or directory in the target directory belongs to,
/// with `-` as `_`: `.fingerprint/<package>-<hash>`, `build/<package>-<hash>`,
/// `deps/lib<crate>-<hash>.<ext>` and `deps/<crate>-<hash>.d`.
#[must_use]
pub fn unit_owner(parent: &str, name: &str) -> Option<String> {
    let strip_hash = |stem: &str| {
        let (owner, hash) = stem.rsplit_once('-')?;
        (hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| owner.replace('-', "_"))
    };

    match parent.rsplit('/').next()? {
        ".fingerprint" | "build" => strip_hash(name),
        "deps" => {
            let stem = name.rsplit_once('.').map_or(name, |(stem, _)| stem);
            strip_hash(stem.strip_prefix("lib").unwrap_or(stem)).or_else(|| strip_hash(stem))
        }
        _ => None,
    }
}

/// Why the target directory could not be exported.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The filesystem could not be read.
    #[error(transparent)]
    Fs(#[from] Ext4Error),
    /// A file could not be read or the tar could not be written.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A path is not UTF-8.
    #[error("a path is not UTF-8")]
    Path,
    /// The directories nest deeper than the bound.
    #[error("the target directory is nested too deeply")]
    TooDeep,
    /// The target directory holds more entries than the bound.
    #[error("too many entries")]
    TooManyEntries,
    /// The files hold more bytes than the bound.
    #[error("the target directory is too large")]
    TooLarge,
    /// A file holds fewer bytes than its size says.
    #[error("{0} is shorter than its size")]
    Short(String),
}

/// The path of the tar entry for `path`: without the leading slash.
fn tar_name(path: &ExtPath) -> Result<String, ExportError> {
    let bytes = path.as_ref().get(1..).unwrap_or_default().to_vec();

    String::from_utf8(bytes).map_err(|_| ExportError::Path)
}

/// A tar header with Crateward's own fields: owners kept, no set ID bits,
/// time zero.
fn tar_header(kind: tar::EntryType, meta: &Metadata, size: u64) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(u32::from(meta.mode() & 0o777));
    header.set_uid(u64::from(meta.uid()));
    header.set_gid(u64::from(meta.gid()));
    header.set_mtime(0);

    header
}

/// Writes the directories and regular files below `/target` of `fs` as a
/// tar with Crateward's own headers: paths `target/…`, modes without set ID
/// bits, owners kept, time zero. Links, devices, FIFOs and sockets are left
/// out, and so are the units of the crates in `excluded` (names with `-`
/// or `_`). Returns entries and bytes written.
///
/// # Errors
///
/// Fails on a read or write error, or when the bounds are exceeded.
pub fn export<W: Write>(fs: &Ext4, out: W, excluded: &[String]) -> Result<(u64, u64), ExportError> {
    let excluded: HashSet<String> = excluded.iter().map(|n| n.replace('-', "_")).collect();
    let mut builder = tar::Builder::new(out);
    let mut stack = vec![(ExtPath::new(on_scratch(guest::TARGET)), 0_usize)];
    let (mut entries, mut bytes) = (0_u64, 0_u64);

    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(ExportError::TooDeep);
        }

        let name = tar_name(&dir)?;
        let mut header = tar_header(tar::EntryType::Directory, &fs.metadata(dir.as_path())?, 0);
        builder.append_data(&mut header, format!("{name}/"), io::empty())?;

        for entry in fs.read_dir(dir.as_path())? {
            let entry = entry?;
            if matches!(entry.file_name().as_ref(), b"." | b"..") {
                continue;
            }

            entries += 1;

            if entries > MAX_EXPORT_ENTRIES {
                return Err(ExportError::TooManyEntries);
            }

            let path = entry.path();
            let file_name = render(entry.file_name().as_ref());
            if unit_owner(&name, &file_name).is_some_and(|owner| excluded.contains(&owner)) {
                continue;
            }

            let meta = entry.metadata()?;
            match meta.file_type() {
                FileType::Directory => stack.push((path, depth + 1)),
                FileType::Regular => {
                    let name = tar_name(&path)?;
                    bytes = bytes.saturating_add(meta.len());

                    if bytes > MAX_EXPORT_BYTES {
                        return Err(ExportError::TooLarge);
                    }

                    let mut header = tar_header(tar::EntryType::Regular, &meta, meta.len());

                    // A reader that yields exactly the announced size.
                    let mut data = Vec::new();
                    let file = fs.open(path.as_path())?;
                    file.take(meta.len()).read_to_end(&mut data)?;

                    if data.len() as u64 != meta.len() {
                        return Err(ExportError::Short(name));
                    }

                    builder.append_data(&mut header, &name, data.as_slice())?;
                }
                _ => {}
            }
        }
    }

    builder.into_inner()?.flush()?;

    Ok((entries, bytes))
}

/// Packs `/target` of the scratch image at `image` into an EROFS image at
/// `out`, through two sandboxed children: the export reads the ext4 image,
/// `mkfs.erofs` writes the result.
///
/// # Errors
///
/// Fails if either child fails.
pub fn export_to_erofs(
    exe: &Path,
    image: &Path,
    out: &Path,
    excluded: &[String],
) -> Result<(), ChildError> {
    let input = File::open(image).map_err(ChildError::io(EXPORT_NAME, "opening the image"))?;
    let mut command = child::command(exe);
    command
        .arg(EXPORT)
        .args(excluded)
        .stdin(input)
        .stdout(Stdio::piped());
    let mut exporter = Child::spawn(EXPORT_NAME, command)?;
    let mut builder = spawn_mkfs(exe, out, exporter.stdout()?)?;
    exporter.finish(None)?;

    builder.finish(None)
}

/// Why the geometry a superblock claims is impossible.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum GeometryError {
    /// The superblock is shorter than the fields read from it.
    #[error("the superblock is truncated")]
    Truncated,
    /// The block size or the blocks per group make no sense.
    #[error("impossible block geometry")]
    Impossible,
    /// The superblock counts more than the image holds.
    #[error("the superblock claims {blocks} blocks in {groups} groups, more than the image holds")]
    TooLarge {
        /// The blocks the superblock counts.
        blocks: u64,
        /// The block groups that follow from it.
        groups: u64,
    },
}

/// Checks that the geometry a superblock claims fits in the image.
/// `ext4-view` reserves memory for every block group descriptor the
/// superblock counts before it reads one, so a crafted count asks for
/// gigabytes (found by the `scratch` fuzz target). A filesystem the guest
/// wrote to its disk cannot be larger than that disk, and its descriptors
/// must be on it.
///
/// # Errors
///
/// Returns why the geometry is impossible.
pub fn check_geometry(superblock: &[u8], image_len: u64) -> Result<(), GeometryError> {
    let u32_at = |offset: usize| u32_le(superblock, offset).ok_or(GeometryError::Truncated);

    let blocks = u64::from(u32_at(0x150)?) << 32 | u64::from(u32_at(0x4)?);
    let first_data_block = u64::from(u32_at(0x14)?);
    let log_block_size = u32_at(0x18)?;
    let blocks_per_group = u64::from(u32_at(0x20)?);
    let incompat = u32_at(0x60)?;
    let desc_size = u32_at(0xfc)? >> 16;

    if log_block_size > 6 || blocks_per_group == 0 {
        return Err(GeometryError::Impossible);
    }

    let block_size = 1024_u64 << log_block_size;
    let desc_size = if incompat & 0x80 == 0 {
        32
    } else {
        u64::from(desc_size).max(64)
    };

    let groups = blocks
        .saturating_sub(first_data_block)
        .div_ceil(blocks_per_group);
    if blocks.saturating_mul(block_size) > image_len || groups.saturating_mul(desc_size) > image_len
    {
        return Err(GeometryError::TooLarge { blocks, groups });
    }

    Ok(())
}

/// Why a scratch image could not be loaded.
#[derive(Debug, thiserror::Error)]
enum ImageError {
    #[error("reading the image: {0}")]
    Read(#[from] io::Error),
    #[error(transparent)]
    Geometry(#[from] GeometryError),
    #[error(transparent)]
    Ext4(#[from] Ext4Error),
}

/// Loads a scratch image after [`check_geometry`].
fn load(image: File) -> Result<Ext4, ImageError> {
    use std::os::unix::fs::FileExt as _;
    let mut superblock = [0_u8; 1024];
    image.read_exact_at(&mut superblock, 1024)?;
    check_geometry(&superblock, image.metadata()?.len())?;

    Ok(Ext4::load(Box::new(image))?)
}

/// Enters the sandbox for reading a scratch image from stdin, and returns
/// that image.
fn enter_sandbox() -> Result<File, Box<dyn Error>> {
    let image = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|e| format!("stdin: {e}"))?;

    sandbox::enter(LIMITS, &FsAccess::default())?;

    Ok(image)
}

/// Runs the export child if `args` names it: stdin is the image, stdout the
/// tar.
#[must_use]
pub fn dispatch_export(args: &[String]) -> Option<ExitCode> {
    (args.get(1).map(String::as_str) == Some(EXPORT))
        .then(|| child::exit(serve_export(args.get(2..).unwrap_or_default())))
}

fn serve_export(excluded: &[String]) -> Result<(), Box<dyn Error>> {
    let fs = load(enter_sandbox()?).map_err(|e| format!("not a readable ext4 image: {e}"))?;
    export(&fs, io::BufWriter::new(io::stdout().lock()), excluded)?;

    Ok(())
}

/// Runs the scanning child if `args` names it: stdin is the image, the
/// first argument the [`ScanSpec`] as JSON.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    (args.get(1).map(String::as_str) == Some(SCAN)).then(|| child::exit(serve_scan(args.get(2))))
}

fn serve_scan(spec: Option<&String>) -> Result<(), Box<dyn Error>> {
    let spec: ScanSpec = spec
        .and_then(|json| serde_json::from_str(json).ok())
        .ok_or("usage: sandbox-scratch <spec json> < image")?;

    let report = match load(enter_sandbox()?) {
        Ok(fs) => scan(&fs, &spec),
        Err(error) => ScratchReport {
            error: Some(format!("not a readable ext4 image: {error}")),
            incomplete: true,
            ..ScratchReport::default()
        },
    };

    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &report)?;
    stdout.flush()?;

    Ok(())
}

#[cfg(test)]
mod tests;
