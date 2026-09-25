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

use std::io::{Read, Write};
use std::os::fd::AsFd as _;
use std::path::Path;
use std::process::{Command, Stdio};

use crateward_core::sandbox::{self, FsAccess, Limits};
use ext4_view::{Ext4, FileType, PathBuf as ExtPath};
use serde::{Deserialize, Serialize};

/// First argument of the sandboxed child.
pub const SCAN: &str = "sandbox-scratch";

/// Where the guest mounts the scratch disk; paths are reported below it.
const MOUNT_POINT: &str = "/work";

const MAX_ENTRIES: u64 = 200_000;
const MAX_DEPTH: usize = 64;
const MAX_LISTED: usize = 500;
/// Bytes of file contents searched for honeytokens, per file and in total.
const MAX_FILE_SEARCH: u64 = 16 * 1024 * 1024;
const MAX_TOTAL_SEARCH: u64 = 1024 * 1024 * 1024;
/// Largest report read back from the child.
const MAX_REPORT: u64 = 16 * 1024 * 1024;

/// Paths below which writes are part of a normal `cargo check`, relative to
/// the scratch root.
const BUILD_AREAS: [&str; 2] = ["/target/", "/lost+found"];

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
                || relative == "/target";
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
                    r.bytes = r.bytes.saturating_add(item.size);
                    let elf = if planted {
                        false
                    } else {
                        self.search(&child, &guest)?
                    };
                    let executable = item.mode & 0o111 != 0 || elf;
                    if executable && !relative.starts_with("/target/") {
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
pub fn scan_in_sandbox(exe: &Path, image: &Path, spec: &ScanSpec) -> Result<ScratchReport, String> {
    let input = std::fs::File::open(image).map_err(|e| format!("{}: {e}", image.display()))?;
    let spec = serde_json::to_string(spec).map_err(|e| e.to_string())?;
    let mut child = Command::new(exe)
        .arg(SCAN)
        .arg(spec)
        .env_clear()
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("starting the scanner: {e}"))?;
    let mut stderr = child.stderr.take().ok_or("no stderr")?;
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stderr).take(64 * 1024).read_to_string(&mut text);
        text
    });
    let mut out = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        stdout
            .take(MAX_REPORT)
            .read_to_end(&mut out)
            .map_err(|e| format!("reading the report: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("waiting: {e}"))?;
    let errors = errors.join().unwrap_or_default();
    if !status.success() {
        return Err(format!("scanner {status}: {}", errors.trim()));
    }
    serde_json::from_slice(&out).map_err(|e| format!("scanner report: {e}"))
}

/// Runs the scanning child if `args` names it: stdin is the image, the
/// first argument the [`ScanSpec`] as JSON.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<std::process::ExitCode> {
    if args.get(1).map(String::as_str) != Some(SCAN) {
        return None;
    }
    let fail = |message: &str| {
        eprintln!("crateward sandbox: {message}");
        std::process::ExitCode::FAILURE
    };
    let Some(spec) = args
        .get(2)
        .and_then(|s| serde_json::from_str::<ScanSpec>(s).ok())
    else {
        return Some(fail("usage: sandbox-scratch <spec json> < image"));
    };
    let image = match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(fd) => std::fs::File::from(fd),
        Err(error) => return Some(fail(&format!("stdin: {error}"))),
    };
    let entered = sandbox::isolate_network()
        .and_then(|()| {
            sandbox::limit(Limits {
                address_space: 2 << 30,
                cpu_seconds: 300,
                file_size: 0,
                open_files: 16,
            })
        })
        .and_then(|()| sandbox::restrict_fs(&FsAccess::default()));
    if let Err(error) = entered {
        return Some(fail(&error.to_string()));
    }
    let report = match Ext4::load(Box::new(image)) {
        Ok(fs) => scan(&fs, &spec),
        Err(error) => ScratchReport {
            error: Some(format!("not a readable ext4 image: {error}")),
            incomplete: true,
            ..ScratchReport::default()
        },
    };
    let mut stdout = std::io::stdout().lock();
    let written = serde_json::to_writer(&mut stdout, &report)
        .map_err(|e| e.to_string())
        .and_then(|()| stdout.flush().map_err(|e| e.to_string()));
    match written {
        Ok(()) => Some(std::process::ExitCode::SUCCESS),
        Err(error) => Some(fail(&error.to_string())),
    }
}

#[cfg(test)]
mod tests {
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
