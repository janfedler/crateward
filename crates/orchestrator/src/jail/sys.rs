//! The one system call the jail needs that `rustix` does not wrap safely.
//!
//! `unshare(2)` is `unsafe` in `rustix` only because of `CLONE_FILES`: after
//! unsharing the file descriptor table, file descriptors created by other
//! threads may not exist in the calling thread. This module never passes
//! that flag, and the jail launcher is single threaded, so no other thread
//! exists to observe a difference. The flags are an enum here so that no
//! caller can request anything else.

#![allow(unsafe_code)]

use rustix::thread::UnshareFlags;

/// The namespace sets the jail creates, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespaces {
    /// A new user namespace, created first and alone so the host can write
    /// its ID maps before anything else happens.
    User,
    /// New mount, network, IPC and UTS namespaces, owned by the new user
    /// namespace.
    Isolation,
}

impl Namespaces {
    fn flags(self) -> UnshareFlags {
        match self {
            Self::User => UnshareFlags::NEWUSER,
            Self::Isolation => {
                UnshareFlags::NEWNS
                    | UnshareFlags::NEWNET
                    | UnshareFlags::NEWIPC
                    | UnshareFlags::NEWUTS
            }
        }
    }
}

/// Moves the calling process into new namespaces.
///
/// # Errors
///
/// Returns the `errno` of `unshare(2)`.
pub fn unshare(namespaces: Namespaces) -> std::io::Result<()> {
    let flags = namespaces.flags();
    debug_assert!(!flags.contains(UnshareFlags::FILES));
    // SAFETY: `flags` never contains `UnshareFlags::FILES` (see `flags`),
    // which is the only reason `unshare_unsafe` is unsafe. The launcher that
    // calls this is single threaded.
    unsafe { rustix::thread::unshare_unsafe(flags) }.map_err(std::io::Error::from)
}
