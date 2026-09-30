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
//! 3. The fake internet's TLS authority, added to the system trust bundle.
//!    It is created once per installation under `target/guest/ca` (mode
//!    0600) and reused, because the orchestrator needs its private key.
//! 4. The guest agent and its eBPF programs, appended to a copy of the base
//!    tarball with root ownership.
//!
//! The result is packed with `mkfs.erofs` into a compressed, read only
//! image with a fixed timestamp on every file.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{GUEST_TARGET, TaskError, run_in};

/// Where the agent lives in the guest, and the kernel's `init=`.
pub const AGENT_PATH_IN_GUEST: &str = "usr/sbin/crateward-agent";

/// Where the agent loads the eBPF programs from
/// (`crateward_guest_agent::trace::OBJECT_PATH`).
const EBPF_PATH_IN_GUEST: &str = "usr/lib/crateward/guest-ebpf.o";

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

    let base = base_layer(&manifest.debian, &manifest_text, &hook_text, &work, &epoch)?;
    let toolchain = stage_toolchain(root, &inputs.join("rust.toml"), &work)?;
    let trust = stage_trust(root, &base, &work)?;
    let agent = stage_agent(root, &work)?;

    let tarball = work.join("rootfs.tar");
    std::fs::copy(&base, &tarball).map_err(io(&base))?;
    let layers = [
        // The toolchain keeps its own file modes.
        Layer::new(&toolchain, None, &["usr"]),
        // A later entry replaces an earlier one with the same path.
        Layer::new(&trust, Some("0644"), &[TRUST_BUNDLE, TRUST_ANCHOR]),
        Layer::new(&agent, Some("0755"), &[AGENT_PATH_IN_GUEST]),
        Layer::new(&agent, Some("0644"), &[EBPF_PATH_IN_GUEST]),
    ];
    for layer in &layers {
        append(root, &tarball, &epoch, layer)?;
    }
    let image = out_dir.join("rootfs.erofs");
    pack_image(root, &tarball, &image, &manifest.image.compression, &epoch)
}

/// The name of the cached base tarball. It holds a digest of the inputs, so
/// a change to either one builds a new base.
fn base_name(manifest_text: &str, hook_text: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(manifest_text.as_bytes());
    hasher.update(hook_text.as_bytes());
    let key = hasher.finalize().to_hex();
    format!("base-{}.tar", key.get(..16).unwrap_or_default())
}

/// Layer 1: the Debian base, cached by the digest of its inputs.
fn base_layer(
    debian: &Debian,
    manifest_text: &str,
    hook_text: &str,
    work: &Path,
    epoch: &str,
) -> Result<PathBuf, TaskError> {
    let base = work.join(base_name(manifest_text, hook_text));
    if base.exists() {
        eprintln!("xtask: reusing {}", base.display());
        return Ok(base);
    }
    build_base(debian, hook_text, &base, epoch)?;
    remove_old_bases(work, &base)?;
    Ok(base)
}

/// Bases for older inputs are never used again and are large.
fn remove_old_bases(work: &Path, keep: &Path) -> Result<(), TaskError> {
    for entry in std::fs::read_dir(work).map_err(io(work))?.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path != keep && name.starts_with("base-") && name.ends_with(".tar") {
            std::fs::remove_file(&path).map_err(io(&path))?;
        }
    }
    Ok(())
}

/// Layer 4: builds the guest agent and its eBPF programs and stages both
/// under `<work>/agent-layer`. Returns the staging root.
fn stage_agent(root: &Path, work: &Path) -> Result<PathBuf, TaskError> {
    crate::guest_agent()?;
    let agent = root
        .join("target")
        .join(GUEST_TARGET)
        .join("release")
        .join("crateward_guest_agent");
    let staging = work.join("agent-layer");
    stage_file(&agent, &staging.join(AGENT_PATH_IN_GUEST))?;
    crate::guest_ebpf::run(root)?;
    let ebpf = crate::guest_ebpf::object_path(root);
    stage_file(&ebpf, &staging.join(EBPF_PATH_IN_GUEST))?;
    Ok(staging)
}

/// Copies `source` to `target` and creates the parent directories.
fn stage_file(source: &Path, target: &Path) -> Result<(), TaskError> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(io(parent))?;
    }
    std::fs::copy(source, target).map_err(io(source))?;
    Ok(())
}

/// Files of a staging directory that are appended to the image tarball.
struct Layer<'a> {
    dir: &'a Path,
    /// The mode of every entry; `None` keeps the modes in the directory.
    mode: Option<&'a str>,
    paths: &'a [&'a str],
}

impl<'a> Layer<'a> {
    fn new(dir: &'a Path, mode: Option<&'a str>, paths: &'a [&'a str]) -> Self {
        Self { dir, mode, paths }
    }
}

/// The `tar` arguments that append `layer` to the tarball with root
/// ownership and a fixed timestamp.
fn append_args(tarball: &str, epoch: &str, layer: &Layer<'_>) -> Vec<String> {
    let mut args = vec![
        "--append".to_owned(),
        "--file".to_owned(),
        tarball.to_owned(),
        "--owner=0".to_owned(),
        "--group=0".to_owned(),
        "--numeric-owner".to_owned(),
    ];
    if let Some(mode) = layer.mode {
        args.push(format!("--mode={mode}"));
    }
    args.push(format!("--mtime=@{epoch}"));
    args.push("-C".to_owned());
    args.push(layer.dir.to_string_lossy().into_owned());
    args.extend(layer.paths.iter().map(|path| (*path).to_owned()));
    args
}

fn append(root: &Path, tarball: &Path, epoch: &str, layer: &Layer<'_>) -> Result<(), TaskError> {
    let args = append_args(&tarball.to_string_lossy(), epoch, layer);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_in(root, "tar", &args, &[])
}

/// Packs the tarball into the compressed, read only image. An old image is
/// removed first.
fn pack_image(
    root: &Path,
    tarball: &Path,
    image: &Path,
    compression: &str,
    epoch: &str,
) -> Result<(), TaskError> {
    if image.exists() {
        std::fs::remove_file(image).map_err(io(image))?;
    }
    run_in(
        root,
        "mkfs.erofs",
        &[
            "--tar=f",
            &format!("-z{compression}"),
            &format!("-T{epoch}"),
            "--quiet",
            &image.to_string_lossy(),
            &tarball.to_string_lossy(),
        ],
        &[],
    )?;
    let digest = crate::images::blake3_file(image)?;
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
    remove_dir(&staging)?;
    let prefix = staging.join("usr").join("local");
    std::fs::create_dir_all(&prefix).map_err(io(&prefix))?;
    for component in &pin.component {
        let archive = component.fetch(&downloads)?;
        component.unpack(root, &archive, &prefix)?;
    }
    eprintln!("xtask: staged Rust {} for the guest", pin.version);
    Ok(staging)
}

/// Removes `dir` and everything in it, if it exists.
fn remove_dir(dir: &Path) -> Result<(), TaskError> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(io(dir))?;
    }
    Ok(())
}

impl Component {
    /// The file name of the archive, taken from the URL.
    fn archive_name(&self) -> Result<&str, TaskError> {
        self.url
            .rsplit('/')
            .next()
            .filter(|name| name.ends_with(".tar.xz"))
            .ok_or_else(|| TaskError::Check(format!("unexpected URL {}", self.url)))
    }

    /// Downloads the archive unless `downloads` has it and checks the pinned
    /// SHA-256. An archive with another digest is deleted.
    fn fetch(&self, downloads: &Path) -> Result<PathBuf, TaskError> {
        let name = self.archive_name()?;
        let archive = downloads.join(name);
        if !archive.exists() {
            let target = archive.to_string_lossy();
            let args = ["-sSfL", "--proto", "=https", "-o", &target, &self.url];
            run_in(downloads, "curl", &args, &[])?;
        }
        let digest = crate::images::sha256_file(&archive)?;
        if digest != self.sha256 {
            std::fs::remove_file(&archive).map_err(io(&archive))?;
            return Err(TaskError::Check(format!(
                "{name} has SHA-256 {digest}, pinned {}; deleted it",
                self.sha256
            )));
        }
        Ok(archive)
    }

    /// Unpacks the archive into `prefix`:
    /// `<name>-<version>-<target>/<dir>/{bin,lib,...}` lands in `/usr/local`.
    fn unpack(&self, root: &Path, archive: &Path, prefix: &Path) -> Result<(), TaskError> {
        let top = self.archive_name()?.trim_end_matches(".tar.xz");
        let args = [
            "-xJf",
            &archive.to_string_lossy(),
            "-C",
            &prefix.to_string_lossy(),
            "--strip-components=2",
            "--exclude=manifest.in",
            &format!("{top}/{}", self.dir),
        ];
        run_in(root, "tar", &args, &[])
    }
}

/// The system trust bundle that OpenSSL, curl and Python read.
const TRUST_BUNDLE: &str = "etc/ssl/certs/ca-certificates.crt";
/// Where `update-ca-certificates` expects local anchors.
const TRUST_ANCHOR: &str = "usr/local/share/ca-certificates/crateward-fake-internet.crt";

/// Creates the authority if needed and stages the trust bundle with its
/// certificate appended. Returns the staging root.
fn stage_trust(root: &Path, base: &Path, work: &Path) -> Result<PathBuf, TaskError> {
    let cert = authority_certificate(root)?;
    let mut bundle = base_bundle(base)?;
    if !bundle.ends_with('\n') {
        bundle.push('\n');
    }
    bundle.push_str(&cert);

    let staging = work.join("trust");
    remove_dir(&staging)?;
    for (name, text) in [
        (TRUST_BUNDLE, bundle.as_str()),
        (TRUST_ANCHOR, cert.as_str()),
    ] {
        let path = staging.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io(parent))?;
        }
        std::fs::write(&path, text).map_err(io(&path))?;
    }
    Ok(staging)
}

/// The certificate of the fake internet's authority. The authority is
/// created once per installation and reused, because the orchestrator needs
/// its private key.
fn authority_certificate(root: &Path) -> Result<String, TaskError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let ca_dir = root.join("target").join("guest").join("ca");
    std::fs::create_dir_all(&ca_dir).map_err(io(&ca_dir))?;
    let authority = ca_dir.join("authority.pem");
    if !authority.exists() {
        let (cert, key) = crateward_fake_internet::tls::generate_ca()
            .map_err(|e| TaskError::Check(format!("generating the TLS authority: {e}")))?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&authority)
            .and_then(|mut f| f.write_all(format!("{cert}{key}").as_bytes()))
            .map_err(io(&authority))?;
        eprintln!("xtask: created the TLS authority {}", authority.display());
    }
    let pem = std::fs::read_to_string(&authority).map_err(io(&authority))?;
    let (cert, _) = crateward_fake_internet::tls::split_pem(&pem).ok_or_else(|| {
        TaskError::Check(format!(
            "{} is not a certificate and a key",
            authority.display()
        ))
    })?;
    Ok(cert)
}

/// The trust bundle inside the base tarball.
fn base_bundle(base: &Path) -> Result<String, TaskError> {
    use std::io::Read;
    let file = std::fs::File::open(base).map_err(io(base))?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries().map_err(io(base))? {
        let mut entry = entry.map_err(io(base))?;
        let path = entry
            .path()
            .map_err(io(base))?
            .to_string_lossy()
            .into_owned();
        if path.trim_start_matches("./") == TRUST_BUNDLE {
            let mut text = String::new();
            entry.read_to_string(&mut text).map_err(io(base))?;
            return Ok(text);
        }
    }
    Err(TaskError::Check(format!(
        "the base has no {TRUST_BUNDLE}; is ca-certificates installed?"
    )))
}

/// Moves the Debian snapshot pin of the root filesystem to today (UTC), the
/// first step of the image refresh (ADR 0024). The build, the canary and
/// the commit that follow stay deliberate steps.
///
/// # Errors
///
/// Fails if the pin file cannot be read, has no snapshot line, or the date
/// cannot be read.
pub fn bump_snapshot(root: &Path) -> Result<(), TaskError> {
    let path = root.join("guest").join("rootfs").join("rootfs.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| TaskError::Io(path.clone(), e))?;
    let out = std::process::Command::new("date")
        .args(["--utc", "+%Y%m%dT000000Z"])
        .output()
        .map_err(|e| TaskError::Command(format!("date: {e}")))?;
    let today = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let (updated, old) = with_snapshot(&text, &today)
        .ok_or_else(|| TaskError::Check(format!("{}: no snapshot line", path.display())))?;
    std::fs::write(&path, updated).map_err(|e| TaskError::Io(path.clone(), e))?;
    eprintln!("xtask: Debian snapshot {old} -> {today}");
    eprintln!("xtask: next: cargo xtask rootfs, cargo xtask canary, commit, cargo xtask release");
    Ok(())
}

/// `text` with its `snapshot = "..."` line set to `snapshot`, and the old
/// value.
fn with_snapshot(text: &str, snapshot: &str) -> Option<(String, String)> {
    let mut old = None;
    let lines: Vec<String> = text
        .lines()
        .map(|line| match line.strip_prefix("snapshot = \"") {
            Some(rest) if old.is_none() => {
                old = rest.strip_suffix('"').map(str::to_owned);
                format!("snapshot = \"{snapshot}\"")
            }
            _ => line.to_owned(),
        })
        .collect();
    Some((lines.join("\n") + "\n", old?))
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn only_the_snapshot_line_changes() {
        let text = "# c\n[debian]\nsuite = \"trixie\"\nsnapshot = \"20260924T000000Z\"\nvariant = \"minbase\"\n";
        let (updated, old) = with_snapshot(text, "20261001T000000Z").unwrap();
        assert_eq!(old, "20260924T000000Z");
        assert_eq!(updated, text.replace("20260924", "20261001"));
        assert!(with_snapshot("[debian]\n", "x").is_none());
    }
}

#[cfg(test)]
mod stage_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cw-rootfs-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn succeeds(program: &str, args: &[&str]) {
        let status = Command::new(program).args(args).status().unwrap();
        assert!(status.success(), "{program} {args:?}");
    }

    fn base_with_bundle(dir: &Path, bundle: Option<&str>) -> PathBuf {
        let tree = dir.join("tree");
        write(&tree.join("etc/hostname"), "guest\n");
        if let Some(bundle) = bundle {
            write(&tree.join(TRUST_BUNDLE), bundle);
        }
        let base = dir.join("base.tar");
        succeeds(
            "tar",
            &[
                "-cf",
                &base.to_string_lossy(),
                "-C",
                &tree.to_string_lossy(),
                ".",
            ],
        );
        base
    }

    #[test]
    fn the_base_is_named_after_a_digest_of_its_inputs() {
        assert_eq!(base_name("manifest", "hook"), "base-ddd266004f4c7485.tar");
        assert_ne!(
            base_name("manifest", "hook2"),
            base_name("manifest", "hook")
        );
        assert_ne!(
            base_name("manifest2", "hook"),
            base_name("manifest", "hook")
        );
    }

    #[test]
    fn bases_of_older_inputs_are_removed() {
        let dir = scratch("bases");
        for name in [
            "base-aaaa.tar",
            "base-bbbb.tar",
            "base-bbbb.partial.tar",
            "rootfs.tar",
            "base.txt",
        ] {
            write(&dir.join(name), "x");
        }
        std::fs::create_dir(dir.join("base-dir.tar.d")).unwrap();
        remove_old_bases(&dir, &dir.join("base-bbbb.tar")).unwrap();
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            ["base-bbbb.tar", "base-dir.tar.d", "base.txt", "rootfs.tar"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reused_base_is_not_built_again() {
        let dir = scratch("reuse");
        let debian = Debian {
            suite: "trixie".into(),
            snapshot: "20260101T000000Z".into(),
            variant: "minbase".into(),
            packages: Vec::new(),
        };
        let cached = dir.join(base_name("manifest", "hook"));
        write(&cached, "cached");
        let base = base_layer(&debian, "manifest", "hook", &dir, "1").unwrap();
        assert_eq!(base, cached);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_layers_are_appended_with_root_ownership_and_a_fixed_time() {
        let args = |layer: &Layer<'_>| append_args("/w/rootfs.tar", "1700000000", layer);
        let expected = |mode: &[&str], dir: &str, paths: &[&str]| -> Vec<String> {
            let mut all = vec![
                "--append",
                "--file",
                "/w/rootfs.tar",
                "--owner=0",
                "--group=0",
                "--numeric-owner",
            ];
            all.extend(mode);
            all.extend(["--mtime=@1700000000", "-C", dir]);
            all.extend(paths);
            all.into_iter().map(str::to_owned).collect()
        };
        let toolchain = Layer::new(Path::new("/w/toolchain"), None, &["usr"]);
        assert_eq!(args(&toolchain), expected(&[], "/w/toolchain", &["usr"]));
        let trust = Layer::new(
            Path::new("/w/trust"),
            Some("0644"),
            &[TRUST_BUNDLE, TRUST_ANCHOR],
        );
        let paths = [TRUST_BUNDLE, TRUST_ANCHOR];
        assert_eq!(args(&trust), expected(&["--mode=0644"], "/w/trust", &paths));
        let agent = Layer::new(
            Path::new("/w/agent-layer"),
            Some("0755"),
            &[AGENT_PATH_IN_GUEST],
        );
        let paths = ["usr/sbin/crateward-agent"];
        assert_eq!(
            args(&agent),
            expected(&["--mode=0755"], "/w/agent-layer", &paths)
        );
        let ebpf = Layer::new(
            Path::new("/w/agent-layer"),
            Some("0644"),
            &[EBPF_PATH_IN_GUEST],
        );
        let paths = ["usr/lib/crateward/guest-ebpf.o"];
        assert_eq!(
            args(&ebpf),
            expected(&["--mode=0644"], "/w/agent-layer", &paths)
        );
    }

    #[test]
    fn appended_files_are_owned_by_root_with_the_given_mode_and_time() {
        let dir = scratch("append");
        let base = base_with_bundle(&dir, Some("B"));
        let staging = dir.join("stage");
        write(&staging.join("usr/sbin/agent"), "binary");
        write(&staging.join("usr/lib/object.o"), "object");
        let tarball = dir.join("out.tar");
        std::fs::copy(&base, &tarball).unwrap();
        let agent = Layer::new(&staging, Some("0755"), &["usr/sbin/agent"]);
        append(&dir, &tarball, "1700000000", &agent).unwrap();
        let object = Layer::new(&staging, Some("0644"), &["usr/lib/object.o"]);
        append(&dir, &tarball, "1700000000", &object).unwrap();
        let mut archive = tar::Archive::new(std::fs::File::open(&tarball).unwrap());
        let found: Vec<_> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                let name = e.path().unwrap().to_string_lossy().into_owned();
                (
                    name,
                    h.uid().unwrap(),
                    h.gid().unwrap(),
                    h.mode().unwrap(),
                    h.mtime().unwrap(),
                )
            })
            .filter(|(name, ..)| name.starts_with("usr/"))
            .collect();
        assert_eq!(
            found,
            [
                ("usr/sbin/agent".to_owned(), 0, 0, 0o755, 1_700_000_000),
                ("usr/lib/object.o".to_owned(), 0, 0, 0o644, 1_700_000_000),
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_staged_file_gets_its_parent_directories() {
        let dir = scratch("stage-file");
        let source = dir.join("agent");
        write(&source, "binary");
        stage_file(&source, &dir.join("layer/usr/sbin/agent")).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("layer/usr/sbin/agent")).unwrap(),
            "binary"
        );
        let error = stage_file(&dir.join("missing"), &dir.join("layer/x")).unwrap_err();
        assert!(error.to_string().contains("missing"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_trust_layer_appends_the_authority_to_the_bundle() {
        let dir = scratch("trust");
        let base = base_with_bundle(&dir, Some("BASE BUNDLE"));
        let work = dir.join("work");
        let staging = stage_trust(&dir, &base, &work).unwrap();
        let authority = dir.join("target/guest/ca/authority.pem");
        let pem = std::fs::read_to_string(&authority).unwrap();
        let (cert, _key) = crateward_fake_internet::tls::split_pem(&pem).unwrap();
        assert_eq!(staging, work.join("trust"));
        assert_eq!(
            std::fs::read_to_string(staging.join(TRUST_BUNDLE)).unwrap(),
            format!("BASE BUNDLE\n{cert}")
        );
        assert_eq!(
            std::fs::read_to_string(staging.join(TRUST_ANCHOR)).unwrap(),
            cert
        );
        let mode = std::fs::metadata(&authority).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        stage_trust(&dir, &base, &work).unwrap();
        assert_eq!(std::fs::read_to_string(&authority).unwrap(), pem);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_bundle_with_a_final_newline_keeps_it_once() {
        let dir = scratch("newline");
        let base = base_with_bundle(&dir, Some("BASE BUNDLE\n"));
        let staging = stage_trust(&dir, &base, &dir.join("work")).unwrap();
        let bundle = std::fs::read_to_string(staging.join(TRUST_BUNDLE)).unwrap();
        assert!(bundle.starts_with("BASE BUNDLE\n-----BEGIN CERTIFICATE-----"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_base_without_the_bundle_is_refused() {
        let dir = scratch("nobundle");
        let base = base_with_bundle(&dir, None);
        let error = stage_trust(&dir, &base, &dir.join("work")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("the base has no etc/ssl/certs/ca-certificates.crt"),
            "{error}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_authority_that_is_not_pem_is_refused() {
        let dir = scratch("badca");
        let base = base_with_bundle(&dir, Some("B"));
        write(&dir.join("target/guest/ca/authority.pem"), "junk");
        let error = stage_trust(&dir, &base, &dir.join("work")).unwrap_err();
        assert!(
            error.to_string().contains("is not a certificate and a key"),
            "{error}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A pinned component whose archive is already in the download cache, so
    /// nothing is fetched.
    fn cached_component(dir: &Path, sha256: Option<&str>) -> PathBuf {
        let tree = dir.join("src");
        write(&tree.join("rust-1.0-x86_64/comp/bin/rustc"), "compiler");
        write(&tree.join("rust-1.0-x86_64/comp/manifest.in"), "listing");
        let archive = dir.join("target/guest/downloads/rust-1.0-x86_64.tar.xz");
        std::fs::create_dir_all(archive.parent().unwrap()).unwrap();
        succeeds(
            "tar",
            &[
                "-cJf",
                &archive.to_string_lossy(),
                "-C",
                &tree.to_string_lossy(),
                "rust-1.0-x86_64",
            ],
        );
        let digest = crate::images::sha256_file(&archive).unwrap();
        let pin = dir.join("rust.toml");
        write(
            &pin,
            &format!(
                "version = \"1.0\"\n[[component]]\ndir = \"comp\"\nurl = \"https://example.invalid/rust-1.0-x86_64.tar.xz\"\nsha256 = \"{}\"\n",
                sha256.unwrap_or(&digest)
            ),
        );
        pin
    }

    #[test]
    fn a_cached_component_is_verified_and_unpacked_into_usr_local() {
        let dir = scratch("toolchain");
        let pin = cached_component(&dir, None);
        let staging = stage_toolchain(&dir, &pin, &dir.join("work")).unwrap();
        assert_eq!(staging, dir.join("work/toolchain"));
        let prefix = staging.join("usr/local");
        assert_eq!(
            std::fs::read_to_string(prefix.join("bin/rustc")).unwrap(),
            "compiler"
        );
        assert!(!prefix.join("manifest.in").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn staging_the_toolchain_again_starts_from_an_empty_directory() {
        let dir = scratch("restage");
        let pin = cached_component(&dir, None);
        let stale = dir.join("work/toolchain/usr/local/stale");
        write(&stale, "old");
        stage_toolchain(&dir, &pin, &dir.join("work")).unwrap();
        assert!(!stale.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_wrong_digest_deletes_the_archive() {
        let dir = scratch("digest");
        let pin = cached_component(&dir, Some(&"0".repeat(64)));
        let error = stage_toolchain(&dir, &pin, &dir.join("work")).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("rust-1.0-x86_64.tar.xz has SHA-256 "),
            "{message}"
        );
        assert!(
            message.contains(&format!("pinned {}; deleted it", "0".repeat(64))),
            "{message}"
        );
        assert!(
            !dir.join("target/guest/downloads/rust-1.0-x86_64.tar.xz")
                .exists()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_url_that_is_not_an_xz_archive_is_refused() {
        let dir = scratch("url");
        let pin = dir.join("rust.toml");
        write(
            &pin,
            "version = \"1.0\"\n[[component]]\ndir = \"c\"\nurl = \"https://example.invalid/rust.zip\"\nsha256 = \"0\"\n",
        );
        let error = stage_toolchain(&dir, &pin, &dir.join("work")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unexpected URL https://example.invalid/rust.zip"),
            "{error}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
