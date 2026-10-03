//! cgroup v2 limits for VM slots, inside the orchestrator's own delegated
//! subtree.
//!
//! systemd delegates a cgroup subtree to a unit with `Delegate=yes`. The
//! unit's user may then create child cgroups and set their limits without
//! privileges. The orchestrator uses it like this:
//!
//! ```text
//! <own cgroup>/                cgroup.subtree_control = +cpu +memory +pids
//! <own cgroup>/supervisor/     the orchestrator's own processes
//! <own cgroup>/slot-<n>/       one per running VM: cpu.max, memory.max,
//!                              memory.swap.max, pids.max
//! ```
//!
//! cgroup v2 forbids processes in a cgroup whose controllers are enabled
//! for its children, hence the `supervisor` leaf. A slot is ended with
//! `cgroup.kill`, which kills every process in it at once, including any
//! the launcher might have left behind.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where cgroup v2 is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Name prefix of slot cgroups.
pub const SLOT_PREFIX: &str = "slot-";

/// Why a cgroup operation failed.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    /// A cgroup file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The orchestrator's cgroup is not delegated to it.
    #[error("cgroup {0} is not delegated to this user: run under systemd with Delegate=yes")]
    NotDelegated(PathBuf),
    /// A controller the slots need is not available.
    #[error("controller {0} is not available in the delegated cgroup")]
    MissingController(&'static str),
    /// Processes did not leave a killed cgroup in time.
    #[error("cgroup {0} still has processes after cgroup.kill")]
    StillPopulated(PathBuf),
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> CgroupError + '_ {
    move |source| CgroupError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn write(path: &Path, value: &str) -> Result<(), CgroupError> {
    std::fs::write(path, value).map_err(io(path))
}

fn read(path: &Path) -> Result<String, CgroupError> {
    std::fs::read_to_string(path).map_err(io(path))
}

/// Limits of one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotLimits {
    /// CPU time, in whole CPUs.
    pub cpus: u32,
    /// Memory for Firecracker including guest memory, in MiB.
    pub memory_mib: u64,
    /// Processes and threads.
    pub pids: u32,
}

/// The orchestrator's delegated cgroup.
#[derive(Debug, Clone)]
pub struct CgroupTree {
    root: PathBuf,
}

impl CgroupTree {
    /// The cgroup the current process runs in, prepared for slots: own
    /// processes moved into a `supervisor` leaf, controllers enabled for
    /// children.
    ///
    /// # Errors
    ///
    /// Fails if the cgroup is not delegated or lacks a controller.
    pub fn own() -> Result<Self, CgroupError> {
        let self_cgroup = read(Path::new("/proc/self/cgroup"))?;
        let relative = self_cgroup
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap_or("/")
            .trim_start_matches('/');
        let mut root = Path::new(CGROUP_ROOT).join(relative);
        // A restarted orchestrator may already sit in its supervisor leaf.
        if root.file_name().is_some_and(|name| name == "supervisor")
            && let Some(parent) = root.parent()
        {
            root = parent.to_path_buf();
        }
        let tree = Self { root };
        tree.prepare()?;
        Ok(tree)
    }

    /// A tree rooted at an explicit cgroup directory. For tests.
    ///
    /// # Errors
    ///
    /// Fails like [`CgroupTree::own`].
    pub fn at(root: &Path) -> Result<Self, CgroupError> {
        let tree = Self {
            root: root.to_path_buf(),
        };
        tree.prepare()?;
        Ok(tree)
    }

    fn prepare(&self) -> Result<(), CgroupError> {
        let subtree = self.root.join("cgroup.subtree_control");
        let writable = std::fs::OpenOptions::new()
            .write(true)
            .open(&subtree)
            .is_ok();
        if !writable {
            return Err(CgroupError::NotDelegated(self.root.clone()));
        }
        let available = read(&self.root.join("cgroup.controllers"))?;
        for controller in ["cpu", "memory", "pids"] {
            if !available.split_whitespace().any(|c| c == controller) {
                return Err(CgroupError::MissingController(controller));
            }
        }
        let supervisor = self.root.join("supervisor");
        std::fs::create_dir_all(&supervisor).map_err(io(&supervisor))?;
        for pid in read(&self.root.join("cgroup.procs"))?.lines() {
            // A process may exit between listing and moving it.
            let _ = std::fs::write(supervisor.join("cgroup.procs"), pid);
        }
        write(&subtree, "+cpu +memory +pids")
    }

    fn slot_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{SLOT_PREFIX}{name}"))
    }

    /// Creates a slot cgroup with limits. An existing one of the same name is
    /// killed and replaced.
    ///
    /// # Errors
    ///
    /// Fails if the cgroup cannot be created or a limit not written.
    pub fn create_slot(&self, name: &str, limits: SlotLimits) -> Result<SlotCgroup, CgroupError> {
        let path = self.slot_path(name);
        if path.exists() {
            SlotCgroup { path: path.clone() }.remove()?;
        }
        std::fs::create_dir(&path).map_err(io(&path))?;
        let slot = SlotCgroup { path };
        let period: u64 = 100_000;
        slot.set(
            "cpu.max",
            &format!("{} {period}", u64::from(limits.cpus) * period),
        )?;
        slot.set("memory.max", &(limits.memory_mib * 1024 * 1024).to_string())?;
        // Guest memory must never be written to disk (Firecracker production
        // host guide). The host has no swap, and this makes sure of it.
        if slot.path.join("memory.swap.max").exists() {
            slot.set("memory.swap.max", "0")?;
        }
        slot.set("pids.max", &limits.pids.to_string())?;
        Ok(slot)
    }

    /// Kills and removes every slot cgroup. Used at startup, when no slot can
    /// legitimately exist yet.
    ///
    /// # Errors
    ///
    /// Fails if a leftover cgroup cannot be removed.
    pub fn remove_all_slots(&self) -> Result<Vec<String>, CgroupError> {
        let mut removed = Vec::new();
        let entries = std::fs::read_dir(&self.root).map_err(io(&self.root))?;
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(SLOT_PREFIX) && entry.path().is_dir() {
                SlotCgroup { path: entry.path() }.remove()?;
                removed.push(name);
            }
        }
        Ok(removed)
    }

    /// Names of existing slot cgroups.
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be listed.
    pub fn slots(&self) -> Result<Vec<String>, CgroupError> {
        let entries = std::fs::read_dir(&self.root).map_err(io(&self.root))?;
        Ok(entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(SLOT_PREFIX))
            .collect())
    }
}

/// One slot's cgroup.
#[derive(Debug)]
pub struct SlotCgroup {
    path: PathBuf,
}

impl SlotCgroup {
    /// The cgroup directory, which the jail launcher joins.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn set(&self, file: &str, value: &str) -> Result<(), CgroupError> {
        write(&self.path.join(file), value)
    }

    /// Whether any process is still in the cgroup.
    ///
    /// # Errors
    ///
    /// Fails if `cgroup.events` cannot be read.
    pub fn populated(&self) -> Result<bool, CgroupError> {
        let events = read(&self.path.join("cgroup.events"))?;
        Ok(events.lines().any(|line| line == "populated 1"))
    }

    /// A counter from `memory.events` or `pids.events`, for reporting why a
    /// VM died.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read.
    pub fn event(&self, file: &str, key: &str) -> Result<u64, CgroupError> {
        let text = read(&self.path.join(file))?;
        Ok(text
            .lines()
            .find_map(|line| line.strip_prefix(key)?.trim().parse().ok())
            .unwrap_or(0))
    }

    /// Kills every process in the cgroup.
    ///
    /// # Errors
    ///
    /// Fails if `cgroup.kill` cannot be written.
    pub fn kill(&self) -> Result<(), CgroupError> {
        self.set("cgroup.kill", "1")
    }

    /// Kills every process and waits until the cgroup is empty, so nothing
    /// of the slot runs any more when this returns.
    ///
    /// # Errors
    ///
    /// Fails if processes remain after a second.
    pub fn kill_and_wait(&self) -> Result<(), CgroupError> {
        self.kill()?;
        for _ in 0..200 {
            if !self.populated()? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(CgroupError::StillPopulated(self.path.clone()))
    }

    /// Kills every process, waits for the cgroup to empty, and removes it.
    ///
    /// # Errors
    ///
    /// Fails if processes remain after a second or the directory cannot be
    /// removed.
    pub fn remove(self) -> Result<(), CgroupError> {
        if !self.path.exists() {
            return Ok(());
        }
        self.kill_and_wait()?;
        std::fs::remove_dir(&self.path).map_err(io(&self.path))
    }
}
