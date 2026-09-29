//! What a job left on its scratch disk.
//!
//! The scratch disk is the only writable disk a job has; everything else in
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

use crateward_core::child::{self, Child, ChildError};
use crateward_core::sandbox::{self, FsAccess, Limits};
use ext4_view::{Ext4, FileType, PathBuf as ExtPath};
use serde::{Deserialize, Serialize};

use crate::payload::spawn_mkfs;

/// First argument of the sandboxed child.
pub const SCAN: &str = "sandbox-scratch";

/// First argument of the child that exports `/target` as a tar (the warm
/// build, ADR 0008).
pub const EXPORT: &str = "sandbox-scratch-export";

/// Bounds of an export.
const MAX_EXPORT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_EXPORT_ENTRIES: u64 = 1_000_000;

/// Where the guest mounts the scratch disk; paths are reported below it.
const MOUNT_POINT: &str = "/work";

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

/// Paths below which writes are part of a normal `cargo check`, relative to
/// the scratch root.
/// With a warm build cache, the job's own target writes land in the
/// overlay's upper directory below `/.warm/`.
const BUILD_AREAS: [&str; 3] = ["/target/", "/lost+found", "/.warm/"];

/// Cargo's own state in `CARGO_HOME`: lock files and the cache database
/// (with its journal files) by prefix, the rest by exact path, so nothing
/// else can hide below them.
const CARGO_STATE_PREFIXES: [&str; 2] =
    ["/home/.cargo/.package-cache", "/home/.cargo/.global-cache"];
const CARGO_STATE_PATHS: [&str; 2] = [
    "/home/.cargo/registry",
    "/home/.cargo/registry/CACHEDIR.TAG",
];

/// What the child needs besides the image.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSpec {
    /// Honeytoken values to look for in file contents.
    pub tokens: Vec<String>,
    /// Files the agent planted, as the guest sees them (under `/work`);
    /// they hold the tokens by design and are not searched.
    pub planted: Vec<String>,
    /// Directories the agent created, as the guest sees them.
    pub created: Vec<String>,
}

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
    /// File names of compiled units in `target/debug/deps` (for example
    /// `libserde-0123456789abcdef.rmeta`). The hash in each name identifies
    /// the unit exactly (version, features, dependencies, profile), which
    /// measures what a shared build cache could reuse (ADR 0008).
    #[serde(default)]
    pub units: Vec<String>,
    /// Entries dropped from the lists above.
    pub omitted: u64,
    /// Why the image could not be read completely, if it could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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

fn render(bytes: &[u8]) -> String {
    crate::trace::render(bytes)
}

fn push<T>(list: &mut Vec<T>, omitted: &mut u64, item: T) {
    if list.len() < MAX_LISTED {
        list.push(item);
    } else {
        *omitted += 1;
    }
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
    fn search(&mut self, path: &ExtPath, guest: &str) -> Result<bool, ext4_view::Ext4Error> {
        let mut file = self.fs.open(path.as_path())?;
        let longest = self.spec.tokens.iter().map(String::len).max().unwrap_or(0);
        let mut window: Vec<u8> = Vec::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        let mut read_total = 0_u64;
        let mut elf = false;
        let mut found = vec![false; self.spec.tokens.len()];
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
            // Keep the tail of the previous chunk, so a token split across
            // two reads is still found.
            window.extend_from_slice(chunk);
            for (i, token) in self.spec.tokens.iter().enumerate() {
                if !found.get(i).copied().unwrap_or(true)
                    && !token.is_empty()
                    && window.windows(token.len()).any(|w| w == token.as_bytes())
                {
                    if let Some(f) = found.get_mut(i) {
                        *f = true;
                    }
                    let r = &mut self.report;
                    push(&mut r.tokens_found, &mut r.omitted, (i, guest.to_owned()));
                }
            }
            let keep = window.len().saturating_sub(longest);
            window.drain(..keep);
        }
        if read_total >= MAX_FILE_SEARCH || self.searched >= MAX_TOTAL_SEARCH {
            self.report.incomplete = true;
        }
        Ok(elf)
    }

    fn visit(&mut self, path: &ExtPath, depth: usize) -> Result<(), ext4_view::Ext4Error> {
        if depth > MAX_DEPTH {
            self.report.incomplete = true;
            return Ok(());
        }
        for entry in self.fs.read_dir(path.as_path())? {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(name.as_ref(), b"." | b"..") {
                continue;
            }
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                self.report.incomplete = true;
                return Ok(());
            }
            let child = entry.path();
            let relative = render(child.as_ref());
            let guest = format!("{MOUNT_POINT}{relative}");
            let meta = entry.metadata()?;
            let file_type = meta.file_type();
            let target = if file_type == FileType::Symlink {
                Some(render(self.fs.read_link(child.as_path())?.as_ref()))
            } else {
                None
            };
            let item = Entry {
                path: guest.clone(),
                kind: kind(file_type).into(),
                size: meta.len(),
                mode: meta.mode(),
                uid: meta.uid(),
                target: target.clone(),
            };
            let in_build = BUILD_AREAS
                .iter()
                .any(|area| relative.starts_with(area) || format!("{relative}/") == *area)
                || relative == "/target"
                || relative == "/.warm";
            let cargo_state = CARGO_STATE_PREFIXES.iter().any(|p| relative.starts_with(p))
                || CARGO_STATE_PATHS.contains(&relative.as_str());
            let planted = self.spec.planted.contains(&guest);
            let created = self.spec.created.contains(&guest);
            let r = &mut self.report;
            if !(in_build || cargo_state || planted || created) {
                push(&mut r.outside_build, &mut r.omitted, item.clone());
            }
            if item.mode & 0o6000 != 0 && file_type != FileType::Directory {
                push(&mut r.setid, &mut r.omitted, item.clone());
            }
            match file_type {
                FileType::Directory => {
                    r.directories += 1;
                    if relative != "/lost+found" {
                        self.visit(&child, depth + 1)?;
                    }
                }
                FileType::Regular => {
                    r.files += 1;
                    if let Some(name) = relative
                        .strip_prefix("/target/debug/deps/")
                        .or_else(|| relative.strip_prefix("/.warm/upper/debug/deps/"))
                        && !name.contains('/')
                        && [".rmeta", ".rlib", ".so"].iter().any(|e| name.ends_with(e))
                    {
                        if r.units.len() < MAX_UNITS {
                            r.units.push(name.to_owned());
                        } else {
                            r.omitted += 1;
                        }
                    }
                    r.bytes = r.bytes.saturating_add(item.size);
                    let elf = if planted {
                        false
                    } else {
                        self.search(&child, &guest)?
                    };
                    let executable = item.mode & 0o111 != 0 || elf;
                    if executable
                        && !relative.starts_with("/target/")
                        && !relative.starts_with("/.warm/upper/")
                    {
                        let r = &mut self.report;
                        push(&mut r.executables_outside_target, &mut r.omitted, item);
                    }
                }
                FileType::Symlink => {
                    let outside = target.as_deref().is_some_and(|t| {
                        (t.starts_with('/') && !t.starts_with(MOUNT_POINT)) || t.contains("..")
                    });
                    if outside {
                        push(&mut r.links_outside, &mut r.omitted, item);
                    }
                }
                // Overlayfs records a deleted lower file as a character
                // device (a whiteout), prepared in its work directory and
                // moved into the upper one.
                FileType::CharacterDevice if relative.starts_with("/.warm/") => {}
                _ => push(&mut r.special, &mut r.omitted, item),
            }
        }
        Ok(())
    }
}

/// Scans a loaded filesystem. Errors end the walk and are reported; what
/// was found until then is kept.
#[must_use]
pub fn scan(fs: &Ext4, spec: &ScanSpec) -> ScratchReport {
    let mut scanner = Scanner {
        fs,
        spec,
        report: ScratchReport::default(),
        entries: 0,
        searched: 0,
    };
    if let Err(error) = scanner.visit(&ExtPath::new("/"), 0) {
        scanner.report.error = Some(error.to_string());
        scanner.report.incomplete = true;
    }
    for planted in &spec.planted {
        let relative = planted.strip_prefix(MOUNT_POINT).unwrap_or(planted);
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

/// Writes the directories and regular files below `/target` of `fs` as a
/// tar with Crateward's own headers: paths `target/…`, modes without set ID
/// bits, owners kept, time zero. Links, devices, FIFOs and sockets are left
/// out, and so are the units of the crates in `excluded` (names with `-`
/// or `_`). Returns entries and bytes written.
///
/// # Errors
///
/// Fails on a read or write error, or when the bounds are exceeded.
pub fn export<W: Write>(fs: &Ext4, out: W, excluded: &[String]) -> Result<(u64, u64), String> {
    let excluded: HashSet<String> = excluded.iter().map(|n| n.replace('-', "_")).collect();
    let mut builder = tar::Builder::new(out);
    let mut stack = vec![(ExtPath::new("/target"), 0_usize)];
    let (mut entries, mut bytes) = (0_u64, 0_u64);
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err("the target directory is nested too deeply".into());
        }
        let meta = fs.metadata(dir.as_path()).map_err(|e| e.to_string())?;
        let name = String::from_utf8(dir.as_ref().get(1..).unwrap_or_default().to_vec())
            .map_err(|_| "a path is not UTF-8".to_owned())?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_size(0);
        header.set_mode(u32::from(meta.mode() & 0o777));
        header.set_uid(u64::from(meta.uid()));
        header.set_gid(u64::from(meta.gid()));
        header.set_mtime(0);
        builder
            .append_data(&mut header, format!("{name}/"), io::empty())
            .map_err(|e| e.to_string())?;
        for entry in fs.read_dir(dir.as_path()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if matches!(entry.file_name().as_ref(), b"." | b"..") {
                continue;
            }
            entries += 1;
            if entries > MAX_EXPORT_ENTRIES {
                return Err("too many entries".into());
            }
            let path = entry.path();
            let file_name = render(entry.file_name().as_ref());
            if unit_owner(&name, &file_name).is_some_and(|owner| excluded.contains(&owner)) {
                continue;
            }
            let meta = entry.metadata().map_err(|e| e.to_string())?;
            match meta.file_type() {
                FileType::Directory => stack.push((path, depth + 1)),
                FileType::Regular => {
                    let name =
                        String::from_utf8(path.as_ref().get(1..).unwrap_or_default().to_vec())
                            .map_err(|_| "a path is not UTF-8".to_owned())?;
                    bytes = bytes.saturating_add(meta.len());
                    if bytes > MAX_EXPORT_BYTES {
                        return Err("the target directory is too large".into());
                    }
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(meta.len());
                    header.set_mode(u32::from(meta.mode() & 0o777));
                    header.set_uid(u64::from(meta.uid()));
                    header.set_gid(u64::from(meta.gid()));
                    header.set_mtime(0);
                    let file = fs.open(path.as_path()).map_err(|e| e.to_string())?;
                    // A reader that yields exactly the announced size.
                    let mut data = Vec::new();
                    file.take(meta.len())
                        .read_to_end(&mut data)
                        .map_err(|e| e.to_string())?;
                    if data.len() as u64 != meta.len() {
                        return Err(format!("{name} is shorter than its size"));
                    }
                    builder
                        .append_data(&mut header, &name, data.as_slice())
                        .map_err(|e| e.to_string())?;
                }
                _ => {}
            }
        }
    }
    builder
        .into_inner()
        .and_then(|mut w| w.flush())
        .map_err(|e| e.to_string())?;
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
pub fn check_geometry(superblock: &[u8], image_len: u64) -> Result<(), String> {
    let u32_at = |offset: usize| {
        superblock
            .get(offset..offset + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or("the superblock is truncated")
    };
    let blocks = u64::from(u32_at(0x150)?) << 32 | u64::from(u32_at(0x4)?);
    let first_data_block = u64::from(u32_at(0x14)?);
    let log_block_size = u32_at(0x18)?;
    let blocks_per_group = u64::from(u32_at(0x20)?);
    let incompat = u32_at(0x60)?;
    let desc_size = u32_at(0xfc)? >> 16;
    if log_block_size > 6 || blocks_per_group == 0 {
        return Err("impossible block geometry".into());
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
        return Err(format!(
            "the superblock claims {blocks} blocks in {groups} groups, more than the image holds"
        ));
    }
    Ok(())
}

/// Loads a scratch image after [`check_geometry`].
fn load(image: File) -> Result<Ext4, String> {
    use std::os::unix::fs::FileExt as _;
    let len = image.metadata().map_err(|e| e.to_string())?.len();
    let mut superblock = [0_u8; 1024];
    image
        .read_exact_at(&mut superblock, 1024)
        .map_err(|e| format!("reading the superblock: {e}"))?;
    check_geometry(&superblock, len)?;
    Ext4::load(Box::new(image)).map_err(|e| e.to_string())
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
mod tests {
    use std::process::Command;

    use super::*;

    /// Builds an ext4 image from a directory with `mkfs.ext4 -d`, as the
    /// orchestrator formats scratch disks with the same tool.
    fn image(files: &[(&str, &[u8], u32)]) -> Option<Vec<u8>> {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "cw-scratch-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let root = dir.join("root");
        std::fs::create_dir_all(root.join("target/debug")).ok()?;
        std::fs::create_dir_all(root.join("home/.cargo")).ok()?;
        for (path, data, mode) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent()?).ok()?;
            std::fs::write(&full, data).ok()?;
            std::fs::set_permissions(&full, std::fs::Permissions::from_mode(*mode)).ok()?;
        }
        let out = dir.join("scratch.img");
        let status = Command::new("/usr/sbin/mkfs.ext4")
            .args(["-q", "-F", "-d"])
            .arg(&root)
            .arg(&out)
            .arg("8M")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        let data = status.success().then(|| std::fs::read(&out).ok()).flatten();
        let _ = std::fs::remove_dir_all(&dir);
        data
    }

    fn spec() -> ScanSpec {
        ScanSpec {
            tokens: vec!["cioSECRETTOKEN0123".into()],
            planted: vec!["/work/home/.cargo/credentials.toml".into()],
            created: vec![
                "/work/home".into(),
                "/work/home/.cargo".into(),
                "/work/target".into(),
            ],
        }
    }

    #[test]
    fn finds_what_a_job_left_outside_the_build() {
        let Some(data) = image(&[
            (
                "/home/.cargo/credentials.toml",
                b"token = \"cioSECRETTOKEN0123\"",
                0o600,
            ),
            ("/target/debug/libx.rlib", b"normal output", 0o644),
            ("/target/debug/deps/libx-0123abcd.rmeta", b"metadata", 0o644),
            ("/target/debug/deps/x-0123abcd.d", b"dep info", 0o644),
            ("/target/debug/build-script-build", b"\x7fELF...", 0o755),
            (
                "/target/debug/out/stolen.txt",
                b"xx cioSECRETTOKEN0123 xx",
                0o644,
            ),
            (
                "/home/.config/autostart/evil.desktop",
                b"[Desktop Entry]",
                0o644,
            ),
            ("/home/.local/bin/dropper", b"\x7fELF payload", 0o644),
            ("/home/.cargo/.global-cache", b"sqlite", 0o644),
        ]) else {
            eprintln!("skipping: mkfs.ext4 is not available");
            return;
        };
        let fs = Ext4::load(Box::new(data)).unwrap();
        let report = scan(&fs, &spec());
        assert!(report.error.is_none(), "{:?}", report.error);
        let paths: Vec<&str> = report
            .outside_build
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert!(paths.contains(&"/work/home/.config/autostart/evil.desktop"));
        assert!(paths.contains(&"/work/home/.local/bin/dropper"));
        assert!(!paths.iter().any(|p| p.starts_with("/work/target")));
        assert!(!paths.contains(&"/work/home/.cargo/.global-cache"));
        assert!(!paths.contains(&"/work/home/.cargo/credentials.toml"));
        assert_eq!(
            report
                .executables_outside_target
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["/work/home/.local/bin/dropper"]
        );
        assert_eq!(
            report.tokens_found,
            [(0, "/work/target/debug/out/stolen.txt".to_owned())]
        );
        assert!(report.planted_changed.is_empty());
        assert!(report.files >= 7);
        assert_eq!(report.units, ["libx-0123abcd.rmeta"]);
    }

    #[test]
    fn exports_the_target_directory_only() {
        let Some(data) = image(&[
            ("/target/debug/deps/libx-0123.rmeta", b"metadata", 0o4755),
            ("/target/debug/.fingerprint/x-0123/lib-x", b"fp", 0o644),
            (
                "/target/debug/.fingerprint/stub-crate-0123456789abcdef/lib",
                b"fp",
                0o644,
            ),
            (
                "/target/debug/deps/libstub_crate-0123456789abcdef.rmeta",
                b"m",
                0o644,
            ),
            (
                "/target/debug/deps/stub_crate-0123456789abcdef.d",
                b"d",
                0o644,
            ),
            ("/home/.cargo/credentials.toml", b"secret", 0o600),
        ]) else {
            return;
        };
        let fs = Ext4::load(Box::new(data)).unwrap();
        let mut tar = Vec::new();
        export(&fs, &mut tar, &["stub-crate".into()]).unwrap();
        let mut archive = tar::Archive::new(tar.as_slice());
        let mut seen = Vec::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            if path.ends_with(".rmeta") {
                // Set ID bits never survive.
                assert_eq!(entry.header().mode().unwrap(), 0o755);
            }
            seen.push(path);
        }
        assert!(seen.contains(&"target/debug/deps/libx-0123.rmeta".to_owned()));
        assert!(seen.contains(&"target/debug/.fingerprint/x-0123/lib-x".to_owned()));
        assert!(seen.iter().all(|p| p.starts_with("target/")));
        assert!(seen.iter().all(|p| !p.contains("stub")), "{seen:?}");
    }

    #[test]
    fn unit_owners_follow_cargo_names() {
        let h = "0123456789abcdef";
        assert_eq!(
            unit_owner("target/debug/.fingerprint", &format!("serde-json-{h}")).as_deref(),
            Some("serde_json")
        );
        assert_eq!(
            unit_owner("target/debug/deps", &format!("libserde_json-{h}.rmeta")).as_deref(),
            Some("serde_json")
        );
        assert_eq!(
            unit_owner("target/debug/deps", &format!("serde_json-{h}.d")).as_deref(),
            Some("serde_json")
        );
        assert_eq!(
            unit_owner("target/debug/deps", &format!("liblibc-{h}.rmeta")).as_deref(),
            Some("libc")
        );
        assert_eq!(
            unit_owner("target/debug/build", &format!("ring-{h}")).as_deref(),
            Some("ring")
        );
        assert_eq!(unit_owner("target/debug", "deps"), None);
        assert_eq!(unit_owner("target/debug/deps", "short-123.rmeta"), None);
    }

    #[test]
    fn a_superblock_larger_than_its_image_is_rejected() {
        // The shape of the fuzz finding: a huge block count and one block
        // per group, which asked `ext4-view` for 8 GiB.
        let mut sb = vec![0_u8; 1024];
        sb[0x4..0x8].copy_from_slice(&u32::MAX.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&1_u32.to_le_bytes());
        assert!(check_geometry(&sb, 1 << 20).is_err());
        sb[0x4..0x8].copy_from_slice(&1024_u32.to_le_bytes());
        assert!(check_geometry(&sb, 1 << 20).is_ok());
        sb[0x150..0x154].copy_from_slice(&1_u32.to_le_bytes());
        assert!(check_geometry(&sb, 1 << 20).is_err());
        assert!(check_geometry(&sb[..100], 1 << 20).is_err());
        let Some(data) = image(&[("/target/debug/x", b"x", 0o644)]) else {
            return;
        };
        assert!(check_geometry(&data[1024..2048], data.len() as u64).is_ok());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        let mut data = vec![0_u8; 4 * 1024 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i.wrapping_mul(2_654_435_761) >> 13) as u8;
        }
        assert!(Ext4::load(Box::new(data)).is_err());
    }

    #[test]
    fn a_missing_planted_file_is_reported() {
        let Some(data) = image(&[("/target/debug/x", b"x", 0o644)]) else {
            return;
        };
        let fs = Ext4::load(Box::new(data)).unwrap();
        let report = scan(&fs, &spec());
        assert_eq!(
            report.planted_changed,
            ["/work/home/.cargo/credentials.toml"]
        );
    }
}
