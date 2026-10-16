//! Rootless jail for Firecracker (ADR 0002).
//!
//! Firecracker's own jailer needs root. Crateward gets the same isolation
//! from unprivileged user namespaces instead, so no process on the host runs
//! as root for the sandbox. A small, single threaded launcher
//! (`crateward-vmjail`) sets up one jail and then becomes Firecracker:
//!
//! 1. It joins the slot's cgroup, so every limit applies from the start.
//! 2. It creates a user namespace. The orchestrator writes the ID maps with
//!    the setuid helpers `newuidmap` and `newgidmap`: inside UID 0 is the
//!    orchestrator's own user (for setup only), inside UID 1 is the slot's
//!    own subordinate UID, which no other slot shares.
//! 3. It creates a PID namespace and starts itself again in it, as PID 1.
//!    This second stage does the steps below and becomes Firecracker, which
//!    therefore sees no process outside the jail. The first stage switches
//!    to inside UID 1 as well and only waits. It is the orchestrator's
//!    handle on the jail: when it dies, the parent death signal kills
//!    Firecracker, and with it every process in the namespace.
//! 4. It creates mount, network, IPC and UTS namespaces, bind mounts exactly
//!    the files the VM needs into the slot's root directory, creates the
//!    slot's tap device, checks that no descriptor but stdin, stdout and
//!    stderr survives `exec`, and `pivot_root`s into that directory. No
//!    `/proc` and no other host path exists inside.
//! 5. It sets resource limits, switches to inside UID 1 (which clears every
//!    capability), sets `no_new_privs`, and executes Firecracker, whose own
//!    seccomp filter then applies.
//!
//! The launcher keeps the orchestrator's supplementary groups because it
//! never calls `setgroups`. That is how Firecracker can still open
//! `/dev/kvm`. The orchestrator's service user must therefore have no
//! supplementary group except `kvm`.
//!
//! All namespaces and the tap device belong to the Firecracker process and
//! disappear with it, so they cannot leak.

pub mod acl;
pub mod decoy;
pub mod host;
pub mod launcher;

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// UID and GID inside the jail's user namespace that map to the
/// orchestrator's own user. Used only while setting up.
pub const INSIDE_SETUP_ID: u32 = 0;

/// UID and GID inside the jail's user namespace that map to the slot's
/// subordinate ID. Firecracker runs as this.
pub const INSIDE_VM_ID: u32 = 1;

/// Firecracker's path inside the jail.
pub const FIRECRACKER_IN_JAIL: &str = "/firecracker";

/// The fake internet's path inside the jail.
pub const FAKE_INTERNET_IN_JAIL: &str = "/fake-internet";

/// Largest specification the launcher reads.
pub const MAX_SPEC_BYTES: u64 = 64 * 1024;

/// One file bind mounted into the jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindMount {
    /// File on the host.
    pub source: PathBuf,
    /// File name in the jail root. A single path component.
    pub target: String,
    /// Whether Firecracker may write it.
    pub writable: bool,
}

/// The fake internet of a jail (see `crateward-fake-internet`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sinks {
    /// The `crateward-fake-internet` binary on the host.
    pub binary: PathBuf,
    /// Its event log on the host, opened before the jail closes.
    pub events: PathBuf,
    /// The TLS authority (certificate and private key, PEM) on the host.
    /// The launcher reads it and passes it on stdin, so no path in the jail
    /// ever holds the key.
    pub authority: Option<PathBuf>,
}

/// Everything the launcher needs to build one jail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JailSpec {
    /// Firecracker `--id`, and the jail's hostname.
    pub id: String,
    /// The slot's root directory on the host. Owned by the orchestrator,
    /// with an ACL entry that lets the slot's subordinate UID write it.
    pub root: PathBuf,
    /// Firecracker binary on the host.
    pub firecracker: PathBuf,
    /// Files to expose in the jail root.
    pub mounts: Vec<BindMount>,
    /// Device nodes to expose under `/dev` in the jail.
    pub devices: Vec<PathBuf>,
    /// Name of a tap device to create in the jail's network namespace.
    pub tap: Option<String>,
    /// The fake internet to start behind the tap device.
    pub sinks: Option<Sinks>,
    /// cgroup directory to join before anything else.
    pub cgroup: Option<PathBuf>,
    /// Firecracker's log on the host (stdout and stderr).
    pub log: PathBuf,
    /// `RLIMIT_NOFILE` for Firecracker.
    pub max_open_files: u64,
    /// `RLIMIT_FSIZE` for Firecracker, in bytes.
    pub max_file_size: u64,
}

/// Why a specification is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid jail specification: {0}")]
pub struct SpecError(pub String);

fn is_simple_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `path` names a device node under `/dev`: absolute, and every
/// component after `/dev` a simple name, so `..` cannot leave `/dev` on the
/// host or the jail root.
fn is_device_path(path: &Path) -> bool {
    let mut components = path.components();
    let under_dev = components.next() == Some(Component::RootDir)
        && components.next() == Some(Component::Normal("dev".as_ref()));

    let names: Vec<_> = components.collect();

    under_dev
        && !names.is_empty()
        && names.iter().all(|c| match c {
            Component::Normal(name) => name.to_str().is_some_and(is_simple_name),
            _ => false,
        })
}

impl JailSpec {
    /// Checks the rules the launcher relies on: absolute host paths, simple
    /// names inside the jail, device nodes only under `/dev`, and no mount
    /// that would shadow Firecracker or `/dev`.
    ///
    /// # Errors
    ///
    /// Returns the first broken rule.
    pub fn validate(&self) -> Result<(), SpecError> {
        let fail = |message: String| Err(SpecError(message));
        if !is_simple_name(&self.id) || self.id.contains('.') {
            return fail(format!("id {:?} is not a simple name", self.id));
        }

        for path in [&self.root, &self.firecracker, &self.log] {
            if !path.is_absolute() {
                return fail(format!("{} is not absolute", path.display()));
            }
        }

        if let Some(sinks) = &self.sinks {
            if self.tap.is_none() {
                return fail("the fake internet needs a tap device".into());
            }

            for path in [&sinks.binary, &sinks.events]
                .into_iter()
                .chain(sinks.authority.as_ref())
            {
                if !path.is_absolute() {
                    return fail(format!("{} is not absolute", path.display()));
                }
            }
        }

        for mount in &self.mounts {
            if !mount.source.is_absolute() {
                return fail(format!("{} is not absolute", mount.source.display()));
            }

            if !is_simple_name(&mount.target)
                || matches!(mount.target.as_str(), "dev" | "firecracker")
            {
                return fail(format!("mount target {:?} is not allowed", mount.target));
            }

            if mount.target == FAKE_INTERNET_IN_JAIL.trim_start_matches('/') {
                return fail(format!("mount target {:?} is reserved", mount.target));
            }
        }

        for device in &self.devices {
            if !is_device_path(device) {
                return fail(format!("device {} is not allowed", device.display()));
            }
        }

        if let Some(tap) = &self.tap
            && (!is_simple_name(tap) || tap.len() > 15)
        {
            return fail(format!("tap name {tap:?} is not allowed"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> JailSpec {
        JailSpec {
            id: "slot-0".into(),
            root: "/run/cw/slots/0/root".into(),
            firecracker: "/opt/fc/firecracker".into(),
            mounts: vec![BindMount {
                source: "/images/rootfs.erofs".into(),
                target: "rootfs.erofs".into(),
                writable: false,
            }],
            devices: vec!["/dev/kvm".into(), "/dev/net/tun".into()],
            tap: Some("tap0".into()),
            sinks: None,
            cgroup: None,
            log: "/run/cw/slots/0/firecracker.log".into(),
            max_open_files: 2048,
            max_file_size: 1 << 30,
        }
    }

    #[test]
    fn a_normal_spec_is_valid() {
        spec().validate().unwrap();
    }

    #[test]
    fn traversal_and_shadowing_are_rejected() {
        for target in ["..", "a/b", "dev", "firecracker", ""] {
            let mut s = spec();
            s.mounts[0].target = target.into();

            assert!(s.validate().is_err(), "{target:?}");
        }

        for device in [
            "/etc/shadow",
            "/dev",
            "dev/kvm",
            "/dev/../etc/shadow",
            "/dev/net/../../etc/shadow",
            "/dev/../../../home/user/.ssh/id_ed25519",
        ] {
            let mut s = spec();
            s.devices = vec![device.into()];

            assert!(s.validate().is_err(), "{device:?}");
        }

        let mut s = spec();
        s.mounts[0].source = "relative/path".into();

        assert!(s.validate().is_err());

        let mut s = spec();
        s.tap = Some("a-name-longer-than-15".into());

        assert!(s.validate().is_err());
    }
}
