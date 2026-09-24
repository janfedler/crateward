//! Duties of PID 1: mount the pseudo filesystems and shut the VM down.
//!
//! The root filesystem is a read only EROFS image. `/dev` is mounted by the
//! kernel (`CONFIG_DEVTMPFS_MOUNT`); everything else writable is tmpfs, so
//! nothing a job writes outlives the VM.

use rustix::mount::{MountFlags, mount};

use crate::AgentError;

/// A filesystem to mount at startup.
struct Mount {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    flags: MountFlags,
    data: Option<&'static std::ffi::CStr>,
}

fn mounts() -> [Mount; 4] {
    let hardened = MountFlags::NOSUID | MountFlags::NODEV;
    [
        Mount {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            flags: hardened | MountFlags::NOEXEC,
            data: None,
        },
        Mount {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            flags: hardened | MountFlags::NOEXEC,
            data: None,
        },
        Mount {
            source: "tmpfs",
            target: "/tmp",
            fstype: "tmpfs",
            flags: hardened,
            data: Some(c"mode=1777"),
        },
        Mount {
            source: "tmpfs",
            target: "/run",
            fstype: "tmpfs",
            flags: hardened | MountFlags::NOEXEC,
            data: Some(c"mode=755"),
        },
    ]
}

/// Whether this process is PID 1.
#[must_use]
pub fn is_pid1() -> bool {
    rustix::process::getpid().is_init()
}

/// Mounts `/proc`, `/sys`, `/tmp` and `/run`. A target that is already
/// mounted is left alone.
///
/// # Errors
///
/// Fails if a mount fails for any reason other than already being mounted.
pub fn mount_filesystems() -> Result<(), AgentError> {
    for m in mounts() {
        match mount(m.source, m.target, m.fstype, m.flags, m.data) {
            Ok(()) | Err(rustix::io::Errno::BUSY) => {}
            Err(errno) => {
                return Err(AgentError::Io {
                    context: m.target,
                    source: errno.into(),
                });
            }
        }
    }
    Ok(())
}

/// Syncs and restarts the VM. With `reboot=k` on the kernel command line,
/// Firecracker exits when the guest restarts, which ends the VM.
pub fn shut_down() -> ! {
    rustix::fs::sync();
    let _ = rustix::system::reboot(rustix::system::RebootCommand::Restart);
    // Only reached if reboot failed; returning from PID 1 panics the kernel,
    // and `panic=1` on the command line turns that into a restart as well.
    loop {
        std::thread::park();
    }
}
