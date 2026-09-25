//! Builds the guest root filesystem image.
//!
//! Two layers, so that a change to the guest agent does not mean downloading
//! Debian again:
//!
//! 1. A Debian base tarball from `mmdebstrap` in unshare mode, which needs no
//!    root: it maps the build into the caller's subordinate user IDs. The
//!    archive comes from snapshot.debian.org at the time pinned in
//!    `guest/rootfs/rootfs.toml`, so the package set is fixed. The tarball is
//!    cached under a name derived from the BLAKE3 digest of its inputs.
//! 2. The Rust toolchain pinned in `guest/rootfs/rust.toml` under
//!    `/usr/local`, downloaded once and verified by SHA-256.
//! 3. The guest agent, appended to a copy of the base tarball with root
//!    ownership.
//!
//! The result is packed with `mkfs.erofs` into a compressed, read only
//! image with a fixed timestamp on every file.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{GUEST_TARGET, TaskError, run_in};

/// Where the agent lives in the guest, and the kernel's `init=`.
pub const AGENT_PATH_IN_GUEST: &str = "usr/sbin/crateward-agent";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    debian: Debian,
    image: Image,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Debian {
    suite: String,
    snapshot: String,
    variant: String,
    packages: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    source_date_epoch: u64,
    compression: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Toolchain {
    version: String,
    component: Vec<Component>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    dir: String,
    url: String,
    sha256: String,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> TaskError + '_ {
    move |e| TaskError::Io(path.to_path_buf(), e)
}

/// Builds `target/guest/out/rootfs.erofs`.
///
/// # Errors
///
/// Fails if a build step fails.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let inputs = root.join("guest").join("rootfs");
    let manifest_path = inputs.join("rootfs.toml");
    let manifest_text = std::fs::read_to_string(&manifest_path).map_err(io(&manifest_path))?;
    let manifest: Manifest = toml::from_str(&manifest_text)
        .map_err(|e| TaskError::Check(format!("guest/rootfs/rootfs.toml: {e}")))?;
    let hook = inputs.join("customize.sh");
    let hook_text = std::fs::read_to_string(&hook).map_err(io(&hook))?;

    let work = root.join("target").join("guest").join("rootfs");
    let out_dir = root.join("target").join("guest").join("out");
    for dir in [&work, &out_dir] {
        std::fs::create_dir_all(dir).map_err(io(dir))?;
    }
    let epoch = manifest.image.source_date_epoch.to_string();

    // Layer 1: the Debian base, cached by the digest of its inputs.
    let mut hasher = blake3::Hasher::new();
    hasher.update(manifest_text.as_bytes());
    hasher.update(hook_text.as_bytes());
    let key = hasher.finalize().to_hex();
    let base = work.join(format!("base-{}.tar", key.get(..16).unwrap_or_default()));
    if base.exists() {
        eprintln!("xtask: reusing {}", base.display());
    } else {
        build_base(&manifest.debian, &hook_text, &base, &epoch)?;
        // Bases for older inputs are never used again and are large.
        for entry in std::fs::read_dir(&work).map_err(io(&work))?.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path != base && name.starts_with("base-") && name.ends_with(".tar") {
                std::fs::remove_file(&path).map_err(io(&path))?;
            }
        }
    }

    // Layer 2: the Rust toolchain.
    let toolchain = stage_toolchain(root, &inputs.join("rust.toml"), &work)?;

    // Layer 3: the guest agent.
    crate::guest_agent()?;
    let agent = root
        .join("target")
        .join(GUEST_TARGET)
        .join("release")
        .join("crateward_guest_agent");
    let staging = work.join("agent-layer");
    let staged_agent = staging.join(AGENT_PATH_IN_GUEST);
    if let Some(parent) = staged_agent.parent() {
        std::fs::create_dir_all(parent).map_err(io(parent))?;
    }
    std::fs::copy(&agent, &staged_agent).map_err(io(&agent))?;
    let tarball = work.join("rootfs.tar");
    std::fs::copy(&base, &tarball).map_err(io(&base))?;
    let tar = tarball.to_string_lossy().into_owned();
    let staging_dir = staging.to_string_lossy().into_owned();
    // The toolchain keeps its own file modes.
    run_in(
        root,
        "tar",
        &[
            "--append",
            "--file",
            &tar,
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            &format!("--mtime=@{epoch}"),
            "-C",
            &toolchain.to_string_lossy(),
            "usr",
        ],
        &[],
    )?;
    run_in(
        root,
        "tar",
        &[
            "--append",
            "--file",
            &tar,
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--mode=0755",
            &format!("--mtime=@{epoch}"),
            "-C",
            &staging_dir,
            AGENT_PATH_IN_GUEST,
        ],
        &[],
    )?;

    let image = out_dir.join("rootfs.erofs");
    if image.exists() {
        std::fs::remove_file(&image).map_err(io(&image))?;
    }
    run_in(
        root,
        "mkfs.erofs",
        &[
            "--tar=f",
            &format!("-z{}", manifest.image.compression),
            &format!("-T{epoch}"),
            "--quiet",
            &image.to_string_lossy(),
            &tar,
        ],
        &[],
    )?;
    let digest = crate::images::blake3_file(&image)?;
    eprintln!("xtask: wrote {} (blake3 {digest})", image.display());
    Ok(())
}

/// Runs mmdebstrap. The customize hook is passed as inline shell code:
/// inside the user namespace the build runs as a subordinate user ID that
/// cannot read the caller's home directory, so a path would not work.
fn build_base(debian: &Debian, hook: &str, base: &Path, epoch: &str) -> Result<(), TaskError> {
    let snapshot = |archive: &str| {
        format!(
            "https://snapshot.debian.org/archive/{archive}/{}/",
            debian.snapshot
        )
    };
    let main = format!("deb {} {} main", snapshot("debian"), debian.suite);
    let security = format!(
        "deb {} {}-security main",
        snapshot("debian-security"),
        debian.suite
    );
    let variant = format!("--variant={}", debian.variant);
    let include = format!("--include={}", debian.packages.join(","));
    let customize = format!("--customize-hook={hook}");
    let partial = base.with_extension("partial.tar");
    let partial_path = partial.to_string_lossy().into_owned();
    let mut args = vec![
        "--mode=unshare",
        variant.as_str(),
        "--format=tar",
        // Snapshots of the archive are old by design; their Release files
        // are still verified against the Debian keyring.
        "--aptopt=Acquire::Check-Valid-Until \"false\"",
        customize.as_str(),
    ];
    if !debian.packages.is_empty() {
        args.push(include.as_str());
    }
    args.extend([
        debian.suite.as_str(),
        partial_path.as_str(),
        main.as_str(),
        security.as_str(),
    ]);
    let dir = base.parent().unwrap_or(base);
    run_in(dir, "mmdebstrap", &args, &[("SOURCE_DATE_EPOCH", epoch)])?;
    std::fs::rename(&partial, base).map_err(io(&partial))?;
    Ok(())
}

/// Downloads and verifies the pinned toolchain components and unpacks them
/// into `<work>/toolchain/usr/local`. Returns the staging root.
fn stage_toolchain(root: &Path, pin_path: &Path, work: &Path) -> Result<PathBuf, TaskError> {
    let text = std::fs::read_to_string(pin_path).map_err(io(pin_path))?;
    let pin: Toolchain = toml::from_str(&text)
        .map_err(|e| TaskError::Check(format!("guest/rootfs/rust.toml: {e}")))?;
    let downloads = root.join("target").join("guest").join("downloads");
    std::fs::create_dir_all(&downloads).map_err(io(&downloads))?;
    let staging = work.join("toolchain");
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(io(&staging))?;
    }
    let prefix = staging.join("usr").join("local");
    std::fs::create_dir_all(&prefix).map_err(io(&prefix))?;
    for component in &pin.component {
        let name = component
            .url
            .rsplit('/')
            .next()
            .filter(|n| n.ends_with(".tar.xz"))
            .ok_or_else(|| TaskError::Check(format!("unexpected URL {}", component.url)))?;
        let archive = downloads.join(name);
        let archive_str = archive.to_string_lossy().into_owned();
        if !archive.exists() {
            run_in(
                &downloads,
                "curl",
                &[
                    "-sSfL",
                    "--proto",
                    "=https",
                    "-o",
                    &archive_str,
                    &component.url,
                ],
                &[],
            )?;
        }
        let digest = crate::images::sha256_file(&archive)?;
        if digest != component.sha256 {
            std::fs::remove_file(&archive).map_err(io(&archive))?;
            return Err(TaskError::Check(format!(
                "{name} has SHA-256 {digest}, pinned {}; deleted it",
                component.sha256
            )));
        }
        // <name>-<version>-<target>/<dir>/{bin,lib,...} lands in /usr/local.
        let top = name.trim_end_matches(".tar.xz");
        run_in(
            root,
            "tar",
            &[
                "-xJf",
                &archive_str,
                "-C",
                &prefix.to_string_lossy(),
                "--strip-components=2",
                "--exclude=manifest.in",
                &format!("{top}/{}", component.dir),
            ],
            &[],
        )?;
    }
    eprintln!("xtask: staged Rust {} for the guest", pin.version);
    Ok(staging)
}
