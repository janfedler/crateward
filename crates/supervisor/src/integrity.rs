//! Host escape detection (ADR 0008): the integrity manifest, decoy files
//! watched with inotify, and processes running as a slot UID that the jail
//! did not start. Each check returns findings. The supervisor quarantines
//! the pipeline and raises a sandbox escape alert on any.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crateward_core::integrity;
use rustix::fs::inotify;

use crate::checks::{self, HostProcess};

/// What a decoy holds. It looks like a credential and works nowhere.
const DECOY: &[u8] = b"[default]\naws_access_key_id = AKIACRATEWARDDECOY01\n\
aws_secret_access_key = crateward/decoy/any+use+of+this+is+an+alert\n";

/// State kept between rounds.
pub struct Integrity {
    manifest: PathBuf,
    interval: Duration,
    next_manifest_check: Instant,
    warned_no_manifest: bool,
    inotify: OwnedFd,
    watches: HashMap<i32, PathBuf>,
    stray_before: HashSet<i32>,
}

impl Integrity {
    /// Sets up the inotify instance.
    ///
    /// # Errors
    ///
    /// Fails if inotify is unavailable.
    pub fn new(data_dir: &Path, interval: Duration) -> std::io::Result<Self> {
        let inotify =
            inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC)?;
        Ok(Self {
            manifest: data_dir.join(integrity::MANIFEST),
            interval,
            next_manifest_check: Instant::now(),
            warned_no_manifest: false,
            inotify,
            watches: HashMap::new(),
            stray_before: HashSet::new(),
        })
    }

    /// Files that differ from the manifest, when a check is due.
    pub fn manifest(&mut self) -> Vec<String> {
        if Instant::now() < self.next_manifest_check {
            return Vec::new();
        }
        self.next_manifest_check = Instant::now() + self.interval;
        let text = match std::fs::read_to_string(&self.manifest) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !self.warned_no_manifest {
                    tracing::warn!(
                        path = %self.manifest.display(),
                        "no integrity manifest: run `crateward integrity record`"
                    );
                    self.warned_no_manifest = true;
                }
                return Vec::new();
            }
            Err(error) => return vec![format!("{}: {error}", self.manifest.display())],
        };
        match integrity::parse(&text) {
            Ok(manifest) => integrity::verify(&manifest)
                .into_iter()
                .map(|m| format!("{}: {}", m.path.display(), m.reason))
                .collect(),
            Err(error) => vec![format!("{}: {error}", self.manifest.display())],
        }
    }

    /// Plants and watches missing decoys, then reports every event on one.
    pub fn decoys(&mut self, decoys: &[PathBuf]) -> Vec<String> {
        let mut findings = Vec::new();
        let mut buffer = [MaybeUninit::<u8>::uninit(); 4096];
        let mut reader = inotify::Reader::new(&self.inotify, &mut buffer);
        let mut gone = Vec::new();
        loop {
            match reader.next() {
                Ok(event) => {
                    let path = self
                        .watches
                        .get(&event.wd())
                        .map_or_else(|| "a decoy".to_owned(), |p| p.display().to_string());
                    findings.push(format!("{path}: {:?}", event.events()));
                    if event.events().contains(inotify::ReadFlags::IGNORED) {
                        gone.push(event.wd());
                    }
                }
                Err(rustix::io::Errno::AGAIN) => break,
                Err(error) => {
                    findings.push(format!("reading decoy events: {error}"));
                    break;
                }
            }
        }
        for wd in gone {
            self.watches.remove(&wd);
        }
        let watched: HashSet<PathBuf> = self.watches.values().cloned().collect();
        for decoy in decoys.iter().filter(|d| !watched.contains(*d)) {
            if let Err(error) = self.plant(decoy) {
                tracing::warn!(path = %decoy.display(), %error, "cannot plant the decoy");
            }
        }
        findings
    }

    fn plant(&mut self, path: &Path) -> std::io::Result<()> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(path)?;
            file.write_all(DECOY)?;
        }
        let flags = inotify::WatchFlags::ACCESS
            | inotify::WatchFlags::OPEN
            | inotify::WatchFlags::MODIFY
            | inotify::WatchFlags::ATTRIB
            | inotify::WatchFlags::DELETE_SELF
            | inotify::WatchFlags::MOVE_SELF;
        let wd = inotify::add_watch(&self.inotify, path, flags)?;
        self.watches.insert(wd, path.to_path_buf());
        tracing::info!(path = %path.display(), "decoy watched");
        Ok(())
    }

    /// Processes that run as a slot UID without being what the jail starts,
    /// found in this scan and the one before.
    pub fn processes(&mut self, slot_uids: std::ops::RangeInclusive<u32>) -> Vec<String> {
        let processes = host_processes();
        let stray: HashSet<i32> = checks::stray_processes(&processes, slot_uids)
            .into_iter()
            .collect();
        let findings = processes
            .iter()
            .filter(|p| stray.contains(&p.pid) && self.stray_before.contains(&p.pid))
            .map(|p| {
                let [real, ..] = p.uids;
                format!(
                    "process {} ({}) runs as UID {real} below {}",
                    p.pid, p.name, p.ppid
                )
            })
            .collect();
        self.stray_before = stray;
        findings
    }
}

/// Every process the supervisor can see, from `/proc`.
fn host_processes() -> Vec<HostProcess> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        tracing::warn!("cannot list /proc");
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| {
            // A process can end between the listing and the read.
            let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
            checks::parse_status(pid, &text)
        })
        .collect()
}
