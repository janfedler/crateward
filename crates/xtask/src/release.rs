//! Builds the release bundle that `install.sh` installs.
//!
//! The bundle holds the service binaries (`bin/`), the sandbox binaries
//! (`sandbox/`), the guest images with the fake internet's authority
//! (`guest/`), the playbooks and units (`deploy/`), the example
//! configuration (`config/`), `install.sh`, a CycloneDX software bill of
//! materials, the vendored sources of every dependency, and `SHA256SUMS`
//! over all of it. The bundle directory is packed into a tarball next to
//! it. Signing the sums file needs the maintainer's key, so this task stops
//! before that and prints the commands; `cargo xtask pack` packs the
//! bundle again once the signature is in it.
//!
//! The guest kernel, the root filesystem and Firecracker take long to build
//! or download; the task expects them from `cargo xtask guest-kernel`,
//! `cargo xtask rootfs` and `cargo xtask firecracker` and says which is
//! missing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::{GUEST_TARGET, TaskError, musl_cc, run};

/// Service binaries, from the host build.
const SERVICES: &[&str] = &[
    "crateward",
    "crateward_feed",
    "crateward_fetcher",
    "crateward_static_analysis",
    "crateward_orchestrator",
    "crateward_analyzer",
    "crateward_api",
    "crateward_supervisor",
];

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> TaskError + '_ {
    move |e| TaskError::Io(path.to_path_buf(), e)
}

fn output(root: &Path, program: &str, args: &[&str]) -> Result<String, TaskError> {
    let out = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| TaskError::Command(format!("cannot start {program}: {e}")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(TaskError::Command(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn copy(from: &Path, to: &Path, mode: u32) -> Result<(), TaskError> {
    use std::os::unix::fs::PermissionsExt as _;
    if !from.is_file() {
        return Err(TaskError::Check(format!("{} is missing", from.display())));
    }
    std::fs::copy(from, to).map_err(io(to))?;
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode)).map_err(io(to))
}

/// The one file in `dir` whose name starts with `prefix` and ends with
/// `suffix`, for the versioned kernel image.
fn only(dir: &Path, prefix: &str, suffix: &str) -> Result<PathBuf, TaskError> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(io(dir))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
        })
        .collect();
    match (found.pop(), found.is_empty()) {
        (Some(path), true) => Ok(path),
        (None, _) => Err(TaskError::Check(format!(
            "no {prefix}*{suffix} in {}; run `cargo xtask guest-kernel`",
            dir.display()
        ))),
        (Some(_), false) => Err(TaskError::Check(format!(
            "several {prefix}*{suffix} in {}; remove the stale ones",
            dir.display()
        ))),
    }
}

/// Builds the bundle and returns its directory.
///
/// # Errors
///
/// Fails if a build fails, a guest artifact is missing, or the fake
/// internet is not static.
pub fn run_release(root: &Path) -> Result<(), TaskError> {
    let commit = output(root, "git", &["rev-parse", "--short=12", "HEAD"])?;
    let dirty = !output(root, "git", &["status", "--porcelain"])?.is_empty();
    let version = env!("CARGO_PKG_VERSION");
    let name = format!(
        "crateward-{version}-{commit}{}",
        if dirty { "-dirty" } else { "" }
    );
    if dirty {
        eprintln!("xtask: the working tree has changes; the bundle is marked dirty");
    }

    run(
        "cargo",
        &["build", "--release", "--locked", "--workspace"],
        &[],
    )?;
    run(
        "cargo",
        &[
            "build",
            "--release",
            "--locked",
            "--target",
            GUEST_TARGET,
            "--package",
            "crateward_fake_internet",
        ],
        &[("CC_x86_64_unknown_linux_musl", musl_cc())],
    )?;

    let target = root.join("target");
    let out = target.join("release-bundle").join(&name);
    if out.exists() {
        std::fs::remove_dir_all(&out).map_err(io(&out))?;
    }
    for dir in ["bin", "sandbox", "guest"] {
        std::fs::create_dir_all(out.join(dir)).map_err(io(&out))?;
    }
    let release = target.join("release");
    for binary in SERVICES {
        copy(&release.join(binary), &out.join("bin").join(binary), 0o755)?;
    }
    copy(
        &release.join("crateward-vmjail"),
        &out.join("sandbox/crateward-vmjail"),
        0o755,
    )?;
    let fake = target
        .join(GUEST_TARGET)
        .join("release")
        .join("crateward_fake_internet");
    let bytes = std::fs::read(&fake).map_err(io(&fake))?;
    if crateward_core::elf::is_static(&bytes) != Ok(true) {
        return Err(TaskError::Check(format!(
            "{} is not static",
            fake.display()
        )));
    }
    copy(&fake, &out.join("sandbox/crateward_fake_internet"), 0o755)?;
    let firecracker = target.join("guest/bin/firecracker");
    if !firecracker.is_file() {
        return Err(TaskError::Check(
            "no Firecracker; run `cargo xtask firecracker`".into(),
        ));
    }
    copy(&firecracker, &out.join("sandbox/firecracker"), 0o755)?;
    let guest = target.join("guest/out");
    copy(
        &only(&guest, "kernel-", ".bzImage")?,
        &out.join("guest/kernel.bzImage"),
        0o644,
    )?;
    let rootfs = guest.join("rootfs.erofs");
    if !rootfs.is_file() {
        return Err(TaskError::Check(
            "no root filesystem; run `cargo xtask rootfs`".into(),
        ));
    }
    copy(&rootfs, &out.join("guest/rootfs.erofs"), 0o644)?;
    // The image trusts exactly this authority, so both come from one build.
    copy(
        &target.join("guest/ca/authority.pem"),
        &out.join("guest/authority.pem"),
        0o600,
    )?;

    let deploy = root.join("deploy");
    for dir in ["ansible", "systemd", "nftables"] {
        copy_tree(&deploy.join(dir), &out.join("deploy").join(dir))?;
    }
    copy(&deploy.join("README.md"), &out.join("deploy/README.md"), 0o644)?;
    copy(&deploy.join("install.sh"), &out.join("install.sh"), 0o755)?;
    std::fs::create_dir_all(out.join("config")).map_err(io(&out))?;
    copy(
        &root.join("config/crateward.example.toml"),
        &out.join("config/crateward.example.toml"),
        0o644,
    )?;

    let sbom = sbom(root, version)?;
    let sbom_path = out.join("sbom.cdx.json");
    std::fs::write(&sbom_path, sbom).map_err(io(&sbom_path))?;

    crate::vendor()?;
    copy(
        &target.join("crateward-vendor.tar.gz"),
        &out.join("crateward-vendor.tar.gz"),
        0o644,
    )?;

    let sums = sums(&out)?;
    let sums_path = out.join("SHA256SUMS");
    std::fs::write(&sums_path, sums).map_err(io(&sums_path))?;
    let archive = pack(&out)?;
    eprintln!("xtask: wrote {}", out.display());
    eprintln!("xtask: wrote {}", archive.display());
    eprintln!(
        "xtask: to sign it, run `ssh-keygen -Y sign -f <release key> -n file {}`, \
         then `cargo xtask pack {}`",
        sums_path.display(),
        out.display()
    );
    Ok(())
}

/// Copies the files below `from` to `to`, readable by everyone.
fn copy_tree(from: &Path, to: &Path) -> Result<(), TaskError> {
    std::fs::create_dir_all(to).map_err(io(to))?;
    for entry in std::fs::read_dir(from).map_err(io(from))? {
        let path = entry.map_err(io(from))?.path();
        let Some(name) = path.file_name() else {
            continue;
        };
        if path.is_dir() {
            copy_tree(&path, &to.join(name))?;
        } else {
            copy(&path, &to.join(name), 0o644)?;
        }
    }
    Ok(())
}

/// Packs a bundle directory into `<directory>.tar.gz` next to it, with
/// sorted names, fixed owner and timestamps, so the same bundle gives the
/// same archive. A `SHA256SUMS.sig` in the directory is packed with it.
///
/// # Errors
///
/// Fails if the directory has no `SHA256SUMS` or `tar` fails.
pub fn pack(bundle: &Path) -> Result<PathBuf, TaskError> {
    let bundle = &bundle.canonicalize().map_err(io(bundle))?;
    if !bundle.join("SHA256SUMS").is_file() {
        return Err(TaskError::Check(format!(
            "{} is not a release bundle: no SHA256SUMS",
            bundle.display()
        )));
    }
    let (Some(parent), Some(name)) = (bundle.parent(), bundle.file_name()) else {
        return Err(TaskError::Check(format!("{} has no name", bundle.display())));
    };
    let name = name.to_string_lossy().into_owned();
    let archive = parent.join(format!("{name}.tar.gz"));
    let archive_arg = archive.to_string_lossy().into_owned();
    let parent_arg = parent.to_string_lossy().into_owned();
    run(
        "tar",
        &[
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            // Root unpacks it as is; nothing in it is writable by others.
            "--mode=go-w",
            "-C",
            &parent_arg,
            "--use-compress-program=gzip -n",
            "-cf",
            &archive_arg,
            &name,
        ],
        &[],
    )?;
    Ok(archive)
}

/// `sha256sum` lines for every file below `dir`, sorted by path.
fn sums(dir: &Path) -> Result<String, TaskError> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, String>) -> Result<(), TaskError> {
        for entry in std::fs::read_dir(dir).map_err(io(dir))? {
            let path = entry.map_err(io(dir))?.path();
            if path.is_dir() {
                walk(&path, base, out)?;
            } else {
                let relative = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                out.insert(relative, crate::images::sha256_file(&path)?);
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    walk(dir, dir, &mut files)?;
    Ok(files
        .iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect())
}

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    version: String,
    source: Option<String>,
    license: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Lock {
    package: Vec<LockPackage>,
}

#[derive(Debug, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Pin {
    version: String,
    url: String,
    sha256: String,
}

/// A CycloneDX 1.6 bill of materials: every crates.io package of the
/// lockfile with its license and checksum, and the pinned third party
/// parts of the sandbox.
fn sbom(root: &Path, version: &str) -> Result<String, TaskError> {
    let metadata = output(
        root,
        "cargo",
        &[
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-gnu",
        ],
    )?;
    let metadata: Metadata = serde_json::from_str(&metadata)
        .map_err(|e| TaskError::Check(format!("cargo metadata: {e}")))?;
    let lock_path = root.join("Cargo.lock");
    let lock: Lock = toml::from_str(&std::fs::read_to_string(&lock_path).map_err(io(&lock_path))?)
        .map_err(|e| TaskError::Check(format!("Cargo.lock: {e}")))?;
    let checksums: BTreeMap<(String, String), String> = lock
        .package
        .into_iter()
        .filter_map(|p| Some(((p.name, p.version), p.checksum?)))
        .collect();
    let mut components: Vec<serde_json::Value> = metadata
        .packages
        .iter()
        .filter(|p| {
            p.source
                .as_deref()
                .is_some_and(|s| s.starts_with("registry+"))
        })
        .map(|p| {
            let mut component = serde_json::Map::new();
            component.insert("type".into(), "library".into());
            component.insert("name".into(), p.name.clone().into());
            component.insert("version".into(), p.version.clone().into());
            component.insert(
                "purl".into(),
                format!("pkg:cargo/{}@{}", p.name, p.version).into(),
            );
            if let Some(license) = &p.license {
                component.insert(
                    "licenses".into(),
                    serde_json::json!([{ "expression": license }]),
                );
            }
            if let Some(sum) = checksums.get(&(p.name.clone(), p.version.clone())) {
                component.insert(
                    "hashes".into(),
                    serde_json::json!([{ "alg": "SHA-256", "content": sum }]),
                );
            }
            serde_json::Value::Object(component)
        })
        .collect();
    components.sort_by_key(|c| c["purl"].as_str().map(str::to_owned));
    let pin = |path: &str| -> Result<Pin, TaskError> {
        let file = root.join(path);
        toml::from_str(&std::fs::read_to_string(&file).map_err(io(&file))?)
            .map_err(|e| TaskError::Check(format!("{path}: {e}")))
    };
    let firecracker = pin("guest/firecracker.toml")?;
    components.push(serde_json::json!({
        "type": "application",
        "name": "firecracker",
        "version": firecracker.version,
        "hashes": [{ "alg": "SHA-256", "content": firecracker.sha256 }],
        "externalReferences": [{ "type": "distribution", "url": firecracker.url }],
    }));
    let kernel: toml::Table = toml::from_str(
        &std::fs::read_to_string(root.join("guest/kernel/kernel.toml"))
            .map_err(io(&root.join("guest/kernel/kernel.toml")))?,
    )
    .map_err(|e| TaskError::Check(format!("guest/kernel/kernel.toml: {e}")))?;
    let source = kernel.get("source").and_then(toml::Value::as_table);
    components.push(serde_json::json!({
        "type": "operating-system",
        "name": "linux",
        "version": source.and_then(|s| s.get("version")).and_then(toml::Value::as_str).unwrap_or_default(),
        "externalReferences": [{
            "type": "vcs",
            "url": format!(
                "{}@{}",
                source.and_then(|s| s.get("repository")).and_then(toml::Value::as_str).unwrap_or_default(),
                source.and_then(|s| s.get("commit")).and_then(toml::Value::as_str).unwrap_or_default()
            ),
        }],
    }));
    let rootfs: toml::Table = toml::from_str(
        &std::fs::read_to_string(root.join("guest/rootfs/rootfs.toml"))
            .map_err(io(&root.join("guest/rootfs/rootfs.toml")))?,
    )
    .map_err(|e| TaskError::Check(format!("guest/rootfs/rootfs.toml: {e}")))?;
    let debian = rootfs.get("debian").and_then(toml::Value::as_table);
    let text = |t: Option<&toml::Table>, key: &str| {
        t.and_then(|t| t.get(key))
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    components.push(serde_json::json!({
        "type": "operating-system",
        "name": "debian",
        "version": text(debian, "suite"),
        "externalReferences": [{
            "type": "distribution",
            "url": format!("https://snapshot.debian.org/archive/debian/{}/", text(debian, "snapshot")),
        }],
    }));
    let rust: toml::Table = toml::from_str(
        &std::fs::read_to_string(root.join("guest/rootfs/rust.toml"))
            .map_err(io(&root.join("guest/rootfs/rust.toml")))?,
    )
    .map_err(|e| TaskError::Check(format!("guest/rootfs/rust.toml: {e}")))?;
    for part in rust
        .get("component")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
    {
        components.push(serde_json::json!({
            "type": "application",
            "name": format!("rust-{}", text(Some(part), "dir")),
            "version": rust.get("version").and_then(toml::Value::as_str).unwrap_or_default(),
            "hashes": [{ "alg": "SHA-256", "content": text(Some(part), "sha256") }],
            "externalReferences": [{ "type": "distribution", "url": text(Some(part), "url") }],
        }));
    }
    let bom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": { "type": "application", "name": "crateward", "version": version },
        },
        "components": components,
    });
    serde_json::to_string_pretty(&bom).map_err(|e| TaskError::Check(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bill_of_materials_lists_locked_packages_with_checksums() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bom: serde_json::Value = serde_json::from_str(&sbom(&root, "0.0.0").unwrap()).unwrap();
        let components = bom["components"].as_array().unwrap();
        let serde = components.iter().find(|c| c["name"] == "serde").unwrap();
        assert!(
            serde["purl"]
                .as_str()
                .unwrap()
                .starts_with("pkg:cargo/serde@")
        );
        assert_eq!(serde["hashes"][0]["content"].as_str().unwrap().len(), 64);
        assert!(serde["licenses"][0]["expression"].is_string());
        assert!(components.iter().any(|c| c["name"] == "firecracker"));
        let linux = components.iter().find(|c| c["name"] == "linux").unwrap();
        assert!(!linux["version"].as_str().unwrap().is_empty());
        assert!(components.iter().any(|c| c["name"] == "debian"));
        assert!(components.iter().any(|c| c["name"] == "rust-cargo"));
        // Workspace members are the product, not components.
        assert!(!components.iter().any(|c| c["name"] == "crateward_core"));
    }
}
