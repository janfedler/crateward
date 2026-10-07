//! Prepares a job's workspace: mounts, directories, files.
//!
//! The host is trusted, but a wrong path could still damage the guest image
//! the snapshot runs on, so every path is checked: absolute, no `..`, no
//! NUL, and devices limited to the job's virtio block drives. An overlay
//! may only stack directories of mounts listed before it: its lower layer
//! on a read only image, its upper and work directories on a writable one.

use std::ffi::{CString, NulError};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crateward_core::protocol::{FileSpec, MountSpec, PathSpec, Workspace};
use rustix::io::Errno;
use rustix::mount::{MountFlags, mount};

/// Why a workspace is refused or could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    /// A path that is not absolute and plain.
    #[error("refusing path {0:?}")]
    Path(String),
    /// A device that is not one of the job's drives.
    #[error("refusing device {0:?}")]
    Device(String),
    /// A file system that is not allowed with the settings of its mount.
    #[error("refusing file system {0:?} with these settings")]
    FileSystem(String),
    /// Options on a mount that is not an overlay.
    #[error("only overlays take options")]
    Options,
    /// An overlay with a device or flags that are not the fixed ones.
    #[error("refusing overlay settings")]
    OverlaySettings,
    /// An overlay without options.
    #[error("an overlay needs options")]
    NoOverlayOptions,
    /// An overlay option that is no `key=value` pair or has an unknown key.
    #[error("refusing overlay option {0:?}")]
    OverlayOption(String),
    /// An overlay path that would stack more than one layer.
    #[error("refusing overlay path {0:?}")]
    OverlayPath(String),
    /// An overlay option given twice.
    #[error("duplicate overlay option {0:?}")]
    DuplicateOverlayOption(String),
    /// An overlay without all of `lowerdir`, `upperdir` and `workdir`.
    #[error("an overlay needs lowerdir, upperdir and workdir")]
    IncompleteOverlay,
    /// An overlay directory that is not on the right earlier mount.
    #[error("an overlay must stack directories of earlier mounts")]
    OverlayLayers,
    /// An overlay that is not mounted on the writable disk.
    #[error("an overlay must be mounted on the writable disk")]
    OverlayTarget,
    /// Overlay options that hold a NUL byte.
    #[error("overlay options: {0}")]
    Nul(#[from] NulError),
    /// A file system call failed.
    #[error("{action} {}: {source}", .path.display())]
    Io {
        /// What was being done.
        action: &'static str,
        /// What it was done to.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// A mount call failed.
    #[error("mount {device} on {target}: {source}")]
    Mount {
        /// The device.
        device: String,
        /// The mount point.
        target: String,
        /// The underlying error.
        source: Errno,
    },
}

/// For `map_err`: `action` failed on `path`.
fn failed(
    action: &'static str,
    path: impl AsRef<Path>,
) -> impl FnOnce(io::Error) -> WorkspaceError {
    let path = path.as_ref().to_owned();

    move |source| WorkspaceError::Io {
        action,
        path,
        source,
    }
}

/// For `map_err`: mounting `m` failed.
fn mount_failed(m: &MountSpec) -> impl FnOnce(Errno) -> WorkspaceError {
    let (device, target) = (m.device.clone(), m.target.clone());

    move |source| WorkspaceError::Mount {
        device,
        target,
        source,
    }
}

/// Checks that a path is absolute and plain.
fn plain(path: &str) -> Result<&Path, WorkspaceError> {
    let p = Path::new(path);
    let ok = p.is_absolute()
        && !path.contains('\0')
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));

    if ok {
        Ok(p)
    } else {
        Err(WorkspaceError::Path(path.into()))
    }
}

/// The directories of an overlay: lower, upper, work.
struct Overlay<'a> {
    lower: &'a str,
    upper: &'a str,
    work: &'a str,
}

fn overlay_options(options: Option<&str>) -> Result<Overlay<'_>, WorkspaceError> {
    let options = options.ok_or(WorkspaceError::NoOverlayOptions)?;
    let (mut lower, mut upper, mut work) = (None, None, None);

    for option in options.split(',') {
        let (key, value) = option
            .split_once('=')
            .ok_or_else(|| WorkspaceError::OverlayOption(option.into()))?;

        let slot = match key {
            "lowerdir" => &mut lower,
            "upperdir" => &mut upper,
            "workdir" => &mut work,
            other => return Err(WorkspaceError::OverlayOption(other.into())),
        };

        // One lower layer only: `:` would stack several.
        if value.contains(':') {
            return Err(WorkspaceError::OverlayPath(value.into()));
        }

        plain(value)?;

        if slot.replace(value).is_some() {
            return Err(WorkspaceError::DuplicateOverlayOption(key.into()));
        }
    }

    match (lower, upper, work) {
        (Some(lower), Some(upper), Some(work)) => Ok(Overlay { lower, upper, work }),
        _ => Err(WorkspaceError::IncompleteOverlay),
    }
}

/// Whether `path` lies strictly below `mount`.
fn below(path: &str, mount: &str) -> bool {
    path.strip_prefix(mount)
        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
}

fn check_mount(m: &MountSpec, earlier: &[MountSpec]) -> Result<MountFlags, WorkspaceError> {
    plain(&m.target)?;
    let base = MountFlags::NOSUID | MountFlags::NODEV;

    if m.fstype == "overlay" {
        if m.device != "overlay" || m.read_only || m.executable {
            return Err(WorkspaceError::OverlaySettings);
        }

        let o = overlay_options(m.options.as_deref())?;
        let on = |path: &str, fstype: &str, writable: bool| {
            earlier
                .iter()
                .any(|e| e.fstype == fstype && e.read_only != writable && below(path, &e.target))
        };

        if !on(o.lower, "erofs", false) || !on(o.upper, "ext4", true) || !on(o.work, "ext4", true) {
            return Err(WorkspaceError::OverlayLayers);
        }

        if !on(&m.target, "ext4", true) {
            return Err(WorkspaceError::OverlayTarget);
        }

        return Ok(base);
    }

    let letter = m.device.strip_prefix("/dev/vd").unwrap_or_default();
    if !(letter.len() == 1 && letter.bytes().all(|b| (b'b'..=b'z').contains(&b))) {
        return Err(WorkspaceError::Device(m.device.clone()));
    }

    if m.options.is_some() {
        return Err(WorkspaceError::Options);
    }

    match (m.fstype.as_str(), m.read_only, m.executable) {
        // Crate sources are never executed from where they are mounted.
        ("erofs", _, false) => Ok(base | MountFlags::RDONLY | MountFlags::NOEXEC),
        // The warm build cache holds compiled build scripts and proc macros.
        ("erofs", _, true) => Ok(base | MountFlags::RDONLY),
        ("ext4", true, false) => Ok(base | MountFlags::RDONLY),
        ("ext4", false, false) => Ok(base),
        (other, _, _) => Err(WorkspaceError::FileSystem(other.into())),
    }
}

fn chown(path: &Path, owner: u32) -> Result<(), WorkspaceError> {
    std::os::unix::fs::chown(path, Some(owner), Some(owner)).map_err(failed("chown", path))
}

fn make_dir(spec: &PathSpec) -> Result<(), WorkspaceError> {
    let path = plain(&spec.path)?;
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
        Err(e) => return Err(failed("mkdir", path)(e)),
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(spec.mode))
        .map_err(failed("chmod", path))?;

    chown(path, spec.owner)
}

fn write_file(spec: &FileSpec) -> Result<(), WorkspaceError> {
    let path = plain(&spec.path.path)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(spec.path.mode)
        .open(path)
        .map_err(failed("create", path))?;

    file.write_all(&spec.contents)
        .map_err(failed("write", path))?;

    chown(path, spec.path.owner)
}

/// Checks every entry before changing anything.
///
/// # Errors
///
/// Names the first entry that is refused.
pub fn validate(workspace: &Workspace) -> Result<(), WorkspaceError> {
    for (i, m) in workspace.mounts.iter().enumerate() {
        check_mount(m, workspace.mounts.get(..i).unwrap_or_default())?;
    }

    for d in &workspace.directories {
        plain(&d.path)?;
    }

    for f in &workspace.files {
        plain(&f.path.path)?;
    }

    Ok(())
}

/// Mounts an overlay that `check_mount` has approved.
fn mount_overlay(m: &MountSpec, flags: MountFlags) -> Result<(), WorkspaceError> {
    let o = overlay_options(m.options.as_deref())?;
    for dir in [o.upper, o.work, m.target.as_str()] {
        std::fs::create_dir_all(dir).map_err(failed("mkdir", dir))?;
    }

    // The merged root takes its owner and mode from the upper directory, so
    // it gets those of the lower one.
    let lower = std::fs::metadata(o.lower).map_err(failed("stat", o.lower))?;
    std::os::unix::fs::chown(o.upper, Some(lower.uid()), Some(lower.gid()))
        .map_err(failed("chown", o.upper))?;
    std::fs::set_permissions(
        o.upper,
        std::fs::Permissions::from_mode(lower.mode() & 0o7777),
    )
    .map_err(failed("chmod", o.upper))?;
    let data = CString::new(m.options.as_deref().unwrap_or_default())?;
    mount(
        "overlay",
        m.target.as_str(),
        "overlay",
        flags,
        Some(data.as_c_str()),
    )
    .map_err(mount_failed(m))
}

/// Mounts a drive of the job.
fn mount_drive(
    m: &MountSpec,
    earlier: &[MountSpec],
    flags: MountFlags,
) -> Result<(), WorkspaceError> {
    // A mount point on the writable disk is created, for example for the
    // warm image. Elsewhere it must exist in the image.
    if earlier
        .iter()
        .any(|e| e.fstype == "ext4" && !e.read_only && below(&m.target, &e.target))
    {
        std::fs::create_dir_all(&m.target).map_err(failed("mkdir", &m.target))?;
    }

    mount(
        m.device.as_str(),
        m.target.as_str(),
        m.fstype.as_str(),
        flags,
        None,
    )
    .map_err(mount_failed(m))
}

/// Applies the workspace: mounts, then directories, then files.
///
/// # Errors
///
/// Names the step that failed. The VM is discarded after the job either
/// way, so a partial workspace is never reused.
pub fn prepare(workspace: &Workspace) -> Result<(), WorkspaceError> {
    validate(workspace)?;

    for (i, m) in workspace.mounts.iter().enumerate() {
        let earlier = workspace.mounts.get(..i).unwrap_or_default();
        let flags = check_mount(m, earlier)?;
        if m.fstype == "overlay" {
            mount_overlay(m, flags)?;
        } else {
            mount_drive(m, earlier, flags)?;
        }
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
            read_only: fstype == "erofs",
            executable: false,
            options: None,
        }
    }

    fn overlay(options: &str) -> MountSpec {
        MountSpec {
            device: "overlay".into(),
            target: "/work/target".into(),
            fstype: "overlay".into(),
            read_only: false,
            executable: false,
            options: Some(options.into()),
        }
    }

    #[test]
    fn overlays_only_stack_earlier_mounts() {
        let earlier = [
            mount_spec("/dev/vdc", "/work", "ext4"),
            mount_spec("/dev/vdd", "/warm", "erofs"),
        ];

        let good = "lowerdir=/warm/target,upperdir=/work/.warm/upper,workdir=/work/.warm/work";
        assert!(check_mount(&overlay(good), &earlier).is_ok());

        let refused = |options: &str| check_mount(&overlay(options), &earlier).unwrap_err();
        let layers = |e| matches!(e, WorkspaceError::OverlayLayers);

        assert!(layers(refused(
            "lowerdir=/etc,upperdir=/work/u,workdir=/work/w"
        )));
        assert!(layers(refused(
            "lowerdir=/warm/target,upperdir=/tmp/u,workdir=/work/w"
        )));
        assert!(matches!(
            refused("lowerdir=/warm/target:/etc,upperdir=/work/u,workdir=/work/w"),
            WorkspaceError::OverlayPath(path) if path == "/warm/target:/etc"
        ));
        assert!(matches!(
            refused("lowerdir=/warm/target,upperdir=/work/u"),
            WorkspaceError::IncompleteOverlay
        ));
        assert!(matches!(
            refused("lowerdir=/warm/target,upperdir=/work/u,workdir=/work/w,redirect_dir=on"),
            WorkspaceError::OverlayOption(key) if key == "redirect_dir"
        ));
        assert!(matches!(
            refused("lowerdir=/warm/../etc,upperdir=/work/u,workdir=/work/w"),
            WorkspaceError::Path(_)
        ));
        assert!(matches!(
            refused("lowerdir=/warm/target,lowerdir=/warm/x,upperdir=/work/u,workdir=/work/w"),
            WorkspaceError::DuplicateOverlayOption(key) if key == "lowerdir"
        ));

        // Order matters: nothing mounted yet.
        assert!(layers(check_mount(&overlay(good), &[]).unwrap_err()));
    }

    #[test]
    fn overlays_have_fixed_settings_and_a_writable_target() {
        let earlier = [
            mount_spec("/dev/vdc", "/work", "ext4"),
            mount_spec("/dev/vdd", "/warm", "erofs"),
        ];

        let good = "lowerdir=/warm/target,upperdir=/work/.warm/upper,workdir=/work/.warm/work";
        let mut executable = overlay(good);
        executable.executable = true;

        assert!(matches!(
            check_mount(&executable, &earlier),
            Err(WorkspaceError::OverlaySettings)
        ));

        let mut bare = overlay(good);
        bare.options = None;

        assert!(matches!(
            check_mount(&bare, &earlier),
            Err(WorkspaceError::NoOverlayOptions)
        ));

        let mut read_only_target = overlay(good);
        read_only_target.target = "/warm/target/merged".into();

        assert!(matches!(
            check_mount(&read_only_target, &earlier),
            Err(WorkspaceError::OverlayTarget)
        ));
    }

    fn check_mount_alone(m: &MountSpec) -> Result<MountFlags, WorkspaceError> {
        check_mount(m, &[])
    }

    #[test]
    fn only_plain_paths_and_job_drives_pass() {
        assert!(plain("/work/home").is_ok());
        assert!(matches!(plain("work"), Err(WorkspaceError::Path(_))));
        assert!(matches!(
            plain("/work/../etc"),
            Err(WorkspaceError::Path(_))
        ));
        assert!(matches!(plain("/work/\0x"), Err(WorkspaceError::Path(_))));
        assert!(plain("/work/./x").is_ok());
        assert!(check_mount_alone(&mount_spec("/dev/vdb", "/cw", "erofs")).is_ok());
        assert!(matches!(
            check_mount_alone(&mount_spec("/dev/vda", "/cw", "erofs")),
            Err(WorkspaceError::Device(device)) if device == "/dev/vda"
        ));
        assert!(matches!(
            check_mount_alone(&mount_spec("/dev/sda", "/cw", "ext4")),
            Err(WorkspaceError::Device(_))
        ));
        assert!(matches!(
            check_mount_alone(&mount_spec("/dev/vdc", "/work", "vfat")),
            Err(WorkspaceError::FileSystem(fs)) if fs == "vfat"
        ));
    }

    #[test]
    fn drive_mounts_take_no_options_and_ext4_is_never_executable() {
        let mut with_options = mount_spec("/dev/vdb", "/cw", "erofs");
        with_options.options = Some("ro".into());

        assert!(matches!(
            check_mount_alone(&with_options),
            Err(WorkspaceError::Options)
        ));

        let mut executable = mount_spec("/dev/vdd", "/warm", "erofs");
        executable.executable = true;

        assert!(check_mount_alone(&executable).is_ok());

        let mut ext4 = mount_spec("/dev/vdc", "/work", "ext4");
        ext4.executable = true;

        assert!(matches!(
            check_mount_alone(&ext4),
            Err(WorkspaceError::FileSystem(fs)) if fs == "ext4"
        ));
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
        assert!(matches!(
            prepare(&ws),
            Err(WorkspaceError::Io {
                action: "create",
                ..
            })
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
