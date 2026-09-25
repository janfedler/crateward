//! Prepares a job's workspace: mounts, directories, files.
//!
//! The host is trusted, but a wrong path could still damage the guest image
//! the snapshot runs on, so every path is checked: absolute, no `..`, no
//! NUL, and devices limited to the job's virtio block drives.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use crateward_core::protocol::{FileSpec, MountSpec, PathSpec, Workspace};
use rustix::mount::{MountFlags, mount};

/// Checks that a path is absolute and plain.
fn plain(path: &str) -> Result<&Path, String> {
    let p = Path::new(path);
    let ok = p.is_absolute()
        && !path.contains('\0')
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    if ok {
        Ok(p)
    } else {
        Err(format!("refusing path {path:?}"))
    }
}

fn check_mount(m: &MountSpec) -> Result<MountFlags, String> {
    let letter = m.device.strip_prefix("/dev/vd").unwrap_or_default();
    if !(letter.len() == 1 && letter.bytes().all(|b| (b'b'..=b'z').contains(&b))) {
        return Err(format!("refusing device {:?}", m.device));
    }
    plain(&m.target)?;
    let base = MountFlags::NOSUID | MountFlags::NODEV;
    match (m.fstype.as_str(), m.read_only) {
        // Crate sources are never executed from where they are mounted.
        ("erofs", _) => Ok(base | MountFlags::RDONLY | MountFlags::NOEXEC),
        ("ext4", true) => Ok(base | MountFlags::RDONLY),
        ("ext4", false) => Ok(base),
        (other, _) => Err(format!("refusing file system {other:?}")),
    }
}

fn chown(path: &Path, owner: u32) -> Result<(), String> {
    std::os::unix::fs::chown(path, Some(owner), Some(owner))
        .map_err(|e| format!("chown {}: {e}", path.display()))
}

fn make_dir(spec: &PathSpec) -> Result<(), String> {
    let path = plain(&spec.path)?;
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {}
        Err(e) => return Err(format!("mkdir {}: {e}", path.display())),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(spec.mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    chown(path, spec.owner)
}

fn write_file(spec: &FileSpec) -> Result<(), String> {
    let path = plain(&spec.path.path)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(spec.path.mode)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(&spec.contents)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    chown(path, spec.path.owner)
}

/// Checks every entry before changing anything.
///
/// # Errors
///
/// Names the first entry that is refused.
pub fn validate(workspace: &Workspace) -> Result<(), String> {
    for m in &workspace.mounts {
        check_mount(m)?;
    }
    for d in &workspace.directories {
        plain(&d.path)?;
    }
    for f in &workspace.files {
        plain(&f.path.path)?;
    }
    Ok(())
}

/// Applies the workspace: mounts, then directories, then files.
///
/// # Errors
///
/// Names the step that failed. The VM is discarded after the job either
/// way, so a partial workspace is never reused.
pub fn prepare(workspace: &Workspace) -> Result<(), String> {
    validate(workspace)?;
    for m in &workspace.mounts {
        let flags = check_mount(m)?;
        mount(
            m.device.as_str(),
            m.target.as_str(),
            m.fstype.as_str(),
            flags,
            None,
        )
        .map_err(|e| format!("mount {} on {}: {e}", m.device, m.target))?;
    }
    for d in &workspace.directories {
        make_dir(d)?;
    }
    for f in &workspace.files {
        write_file(f)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount_spec(device: &str, target: &str, fstype: &str) -> MountSpec {
        MountSpec {
            device: device.into(),
            target: target.into(),
            fstype: fstype.into(),
            read_only: false,
        }
    }

    #[test]
    fn only_plain_paths_and_job_drives_pass() {
        assert!(plain("/work/home").is_ok());
        assert!(plain("work").is_err());
        assert!(plain("/work/../etc").is_err());
        assert!(plain("/work/./x").is_ok());
        assert!(check_mount(&mount_spec("/dev/vdb", "/cw", "erofs")).is_ok());
        assert!(check_mount(&mount_spec("/dev/vda", "/cw", "erofs")).is_err());
        assert!(check_mount(&mount_spec("/dev/sda", "/cw", "ext4")).is_err());
        assert!(check_mount(&mount_spec("/dev/vdc", "/work", "vfat")).is_err());
    }

    #[test]
    fn directories_and_files_are_created_with_their_modes() {
        let dir = std::env::temp_dir().join(format!("cw-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let me = rustix::process::getuid().as_raw();
        let base = dir.to_string_lossy().into_owned();
        let ws = Workspace {
            mounts: Vec::new(),
            directories: vec![PathSpec {
                path: format!("{base}/home"),
                owner: me,
                mode: 0o700,
            }],
            files: vec![FileSpec {
                path: PathSpec {
                    path: format!("{base}/home/token"),
                    owner: me,
                    mode: 0o600,
                },
                contents: b"secret".to_vec(),
            }],
        };
        prepare(&ws).unwrap();
        let meta = std::fs::metadata(dir.join("home/token")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(dir.join("home/token")).unwrap(), b"secret");
        // Files are never overwritten.
        assert!(prepare(&ws).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
