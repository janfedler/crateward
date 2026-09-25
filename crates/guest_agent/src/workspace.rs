//! Prepares a job's workspace: mounts, directories, files.
//!
//! The host is trusted, but a wrong path could still damage the guest image
//! the snapshot runs on, so every path is checked: absolute, no `..`, no
//! NUL, and devices limited to the job's virtio block drives. An overlay
//! may only stack directories of mounts listed before it: its lower layer
//! on a read only image, its upper and work directories on a writable one.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

/// The directories of an overlay: lower, upper, work.
struct Overlay<'a> {
    lower: &'a str,
    upper: &'a str,
    work: &'a str,
}

fn overlay_options(options: Option<&str>) -> Result<Overlay<'_>, String> {
    let options = options.ok_or("an overlay needs options")?;
    let (mut lower, mut upper, mut work) = (None, None, None);
    for option in options.split(',') {
        let (key, value) = option
            .split_once('=')
            .ok_or_else(|| format!("refusing overlay option {option:?}"))?;
        // One lower layer only: `:` would stack several.
        if value.contains(':') {
            return Err(format!("refusing overlay path {value:?}"));
        }
        plain(value)?;
        let slot = match key {
            "lowerdir" => &mut lower,
            "upperdir" => &mut upper,
            "workdir" => &mut work,
            other => return Err(format!("refusing overlay option {other:?}")),
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate overlay option {key:?}"));
        }
    }
    match (lower, upper, work) {
        (Some(lower), Some(upper), Some(work)) => Ok(Overlay { lower, upper, work }),
        _ => Err("an overlay needs lowerdir, upperdir and workdir".into()),
    }
}

/// Whether `path` lies strictly below `mount`.
fn below(path: &str, mount: &str) -> bool {
    path.strip_prefix(mount)
        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
}

fn check_mount(m: &MountSpec, earlier: &[MountSpec]) -> Result<MountFlags, String> {
    plain(&m.target)?;
    let base = MountFlags::NOSUID | MountFlags::NODEV;
    if m.fstype == "overlay" {
        if m.device != "overlay" || m.read_only || m.executable {
            return Err("refusing overlay settings".into());
        }
        let o = overlay_options(m.options.as_deref())?;
        let on = |path: &str, fstype: &str, writable: bool| {
            earlier
                .iter()
                .any(|e| e.fstype == fstype && e.read_only != writable && below(path, &e.target))
        };
        if !on(o.lower, "erofs", false) || !on(o.upper, "ext4", true) || !on(o.work, "ext4", true) {
            return Err("an overlay must stack directories of earlier mounts".into());
        }
        if !on(&m.target, "ext4", true) {
            return Err("an overlay must be mounted on the writable disk".into());
        }
        return Ok(base);
    }
    let letter = m.device.strip_prefix("/dev/vd").unwrap_or_default();
    if !(letter.len() == 1 && letter.bytes().all(|b| (b'b'..=b'z').contains(&b))) {
        return Err(format!("refusing device {:?}", m.device));
    }
    if m.options.is_some() {
        return Err("only overlays take options".into());
    }
    match (m.fstype.as_str(), m.read_only, m.executable) {
        // Crate sources are never executed from where they are mounted.
        ("erofs", _, false) => Ok(base | MountFlags::RDONLY | MountFlags::NOEXEC),
        // The warm build cache holds compiled build scripts and proc macros.
        ("erofs", _, true) => Ok(base | MountFlags::RDONLY),
        ("ext4", true, false) => Ok(base | MountFlags::RDONLY),
        ("ext4", false, false) => Ok(base),
        (other, _, _) => Err(format!(
            "refusing file system {other:?} with these settings"
        )),
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

/// Applies the workspace: mounts, then directories, then files.
///
/// # Errors
///
/// Names the step that failed. The VM is discarded after the job either
/// way, so a partial workspace is never reused.
pub fn prepare(workspace: &Workspace) -> Result<(), String> {
    validate(workspace)?;
    for (i, m) in workspace.mounts.iter().enumerate() {
        let flags = check_mount(m, workspace.mounts.get(..i).unwrap_or_default())?;
        if m.fstype == "overlay" {
            let o = overlay_options(m.options.as_deref())?;
            for dir in [o.upper, o.work, m.target.as_str()] {
                std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
            }
            // The merged root takes its owner and mode from the upper
            // directory, so it gets those of the lower one.
            let lower = std::fs::metadata(o.lower).map_err(|e| format!("stat {}: {e}", o.lower))?;
            std::os::unix::fs::chown(o.upper, Some(lower.uid()), Some(lower.gid()))
                .map_err(|e| format!("chown {}: {e}", o.upper))?;
            std::fs::set_permissions(
                o.upper,
                std::fs::Permissions::from_mode(lower.mode() & 0o7777),
            )
            .map_err(|e| format!("chmod {}: {e}", o.upper))?;
            let data = std::ffi::CString::new(m.options.as_deref().unwrap_or_default())
                .map_err(|e| e.to_string())?;
            mount(
                "overlay",
                m.target.as_str(),
                "overlay",
                flags,
                Some(data.as_c_str()),
            )
            .map_err(|e| format!("overlay on {}: {e}", m.target))?;
            continue;
        }
        // A mount point on the writable disk is created, for example for
        // the warm image; elsewhere it must exist in the image.
        let earlier = workspace.mounts.get(..i).unwrap_or_default();
        if earlier
            .iter()
            .any(|e| e.fstype == "ext4" && !e.read_only && below(&m.target, &e.target))
        {
            std::fs::create_dir_all(&m.target).map_err(|e| format!("mkdir {}: {e}", m.target))?;
        }
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
        for bad in [
            "lowerdir=/warm/target:/etc,upperdir=/work/u,workdir=/work/w",
            "lowerdir=/etc,upperdir=/work/u,workdir=/work/w",
            "lowerdir=/warm/target,upperdir=/tmp/u,workdir=/work/w",
            "lowerdir=/warm/target,upperdir=/work/u",
            "lowerdir=/warm/target,upperdir=/work/u,workdir=/work/w,redirect_dir=on",
            "lowerdir=/warm/../etc,upperdir=/work/u,workdir=/work/w",
            "lowerdir=/warm/target,lowerdir=/warm/x,upperdir=/work/u,workdir=/work/w",
        ] {
            assert!(check_mount(&overlay(bad), &earlier).is_err(), "{bad}");
        }
        // Order matters: nothing mounted yet.
        assert!(check_mount(&overlay(good), &[]).is_err());
        let mut executable = mount_spec("/dev/vdd", "/warm", "erofs");
        executable.executable = true;
        assert!(check_mount(&executable, &[]).is_ok());
        let mut ext4_exec = mount_spec("/dev/vdc", "/work", "ext4");
        ext4_exec.executable = true;
        assert!(check_mount(&ext4_exec, &[]).is_err());
    }

    fn check_mount_alone(m: &MountSpec) -> Result<MountFlags, String> {
        check_mount(m, &[])
    }

    #[test]
    fn only_plain_paths_and_job_drives_pass() {
        assert!(plain("/work/home").is_ok());
        assert!(plain("work").is_err());
        assert!(plain("/work/../etc").is_err());
        assert!(plain("/work/./x").is_ok());
        assert!(check_mount_alone(&mount_spec("/dev/vdb", "/cw", "erofs")).is_ok());
        assert!(check_mount_alone(&mount_spec("/dev/vda", "/cw", "erofs")).is_err());
        assert!(check_mount_alone(&mount_spec("/dev/sda", "/cw", "ext4")).is_err());
        assert!(check_mount_alone(&mount_spec("/dev/vdc", "/work", "vfat")).is_err());
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
