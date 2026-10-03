//! Builds the release bundle that `install.sh` installs.
//!
//! The bundle holds the service binaries (`bin/`), the sandbox binaries
//! (`sandbox/`), the guest images with the fake internet's authority
//! (`guest/`), the playbooks and units (`deploy/`), the example
//! configuration (`config/`), `install.sh`, the license texts, a CycloneDX
//! software bill of materials, the vendored sources of every dependency,
//! and `SHA256SUMS` over all of it. The bundle directory is packed into a
//! tarball next to it. Signing the sums file needs the maintainer's key, so this task stops
//! before that and prints the commands. `cargo xtask pack` packs the
//! bundle again once the signature is in it.
//!
//! The guest kernel, the root filesystem and Firecracker take long to build
//! or download. The task expects them from `cargo xtask guest-kernel`,
//! `cargo xtask rootfs` and `cargo xtask firecracker` and says which is
//! missing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crateward_core::paths::{build, bundle, repo};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{TaskError, copy, io, musl_cc, output, read_toml, run};

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
    let version = env!("CARGO_PKG_VERSION");
    let name = bundle_name(root, version)?;
    build_binaries()?;

    let out = root.join(build::RELEASE_BUNDLES).join(&name);
    create_bundle_dir(&out)?;
    stage_binaries(root, &out)?;
    stage_guest(root, &out)?;
    stage_deploy(root, &out)?;

    let sbom_path = out.join(bundle::SBOM);
    std::fs::write(&sbom_path, sbom(root, version)?).map_err(io(&sbom_path))?;
    crate::vendor()?;
    copy(
        &root.join(build::VENDOR_ARCHIVE),
        &out.join(bundle::VENDOR_ARCHIVE),
        0o644,
    )?;

    let sums_path = out.join(bundle::SUMS);
    std::fs::write(&sums_path, sums(&out)?).map_err(io(&sums_path))?;
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

/// `crateward-<version>-<commit>`, with `-dirty` if the working tree has
/// changes.
fn bundle_name(root: &Path, version: &str) -> Result<String, TaskError> {
    let commit = output(root, "git", &["rev-parse", "--short=12", "HEAD"])?;
    let dirty = !output(root, "git", &["status", "--porcelain"])?.is_empty();
    if dirty {
        eprintln!("xtask: the working tree has changes, so the bundle is marked dirty");
    }

    Ok(format!(
        "crateward-{version}-{commit}{}",
        if dirty { "-dirty" } else { "" }
    ))
}

/// Builds the host binaries, and the fake internet as a static binary for
/// the sandbox.
fn build_binaries() -> Result<(), TaskError> {
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
            build::GUEST_TARGET,
            "--package",
            "crateward_fake_internet",
        ],
        &[("CC_x86_64_unknown_linux_musl", musl_cc())],
    )
}

/// An empty directory for the bundle, with the ones that hold binaries and
/// guest images.
fn create_bundle_dir(out: &Path) -> Result<(), TaskError> {
    if out.exists() {
        std::fs::remove_dir_all(out).map_err(io(out))?;
    }

    for dir in [bundle::BIN, bundle::SANDBOX, bundle::GUEST] {
        std::fs::create_dir_all(out.join(dir)).map_err(io(out))?;
    }

    Ok(())
}

/// The service binaries, and the sandbox binaries: the launcher, the fake
/// internet and Firecracker.
fn stage_binaries(root: &Path, out: &Path) -> Result<(), TaskError> {
    let release = root.join(build::RELEASE);
    for binary in SERVICES {
        copy(
            &release.join(binary),
            &out.join(bundle::BIN).join(binary),
            0o755,
        )?;
    }

    let sandbox = out.join(bundle::SANDBOX);
    copy(
        &release.join("crateward-vmjail"),
        &sandbox.join("crateward-vmjail"),
        0o755,
    )?;
    stage_fake_internet(root, out)?;

    let firecracker = root.join(build::FIRECRACKER);
    if !firecracker.is_file() {
        return Err(TaskError::Check(
            "no Firecracker: run `cargo xtask firecracker`".into(),
        ));
    }

    copy(&firecracker, &sandbox.join("firecracker"), 0o755)
}

/// The fake internet runs on the bare guest, so it must not need a loader.
fn stage_fake_internet(root: &Path, out: &Path) -> Result<(), TaskError> {
    let fake = root.join(build::FAKE_INTERNET);
    let bytes = std::fs::read(&fake).map_err(io(&fake))?;
    if crateward_core::elf::is_static(&bytes) != Ok(true) {
        return Err(TaskError::Check(format!(
            "{} is not static",
            fake.display()
        )));
    }

    copy(
        &fake,
        &out.join(bundle::SANDBOX).join("crateward_fake_internet"),
        0o755,
    )
}

/// The guest kernel, the root filesystem and the authority it trusts.
fn stage_guest(root: &Path, out: &Path) -> Result<(), TaskError> {
    copy(
        &only(&root.join(build::GUEST_OUT), "kernel-", ".bzImage")?,
        &out.join(bundle::KERNEL),
        0o644,
    )?;

    let rootfs = root.join(build::ROOTFS_IMAGE);
    if !rootfs.is_file() {
        return Err(TaskError::Check(
            "no root filesystem: run `cargo xtask rootfs`".into(),
        ));
    }

    copy(&rootfs, &out.join(bundle::ROOTFS), 0o644)?;

    // The image trusts exactly this authority, so both come from one build.
    copy(
        &root.join(build::AUTHORITY),
        &out.join(bundle::AUTHORITY),
        0o600,
    )
}

/// The playbooks, the units, `install.sh`, the example configuration and
/// the license texts.
fn stage_deploy(root: &Path, out: &Path) -> Result<(), TaskError> {
    for (from, to) in [
        ("LICENSE-MIT", "LICENSE-MIT"),
        ("LICENSE-APACHE", "LICENSE-APACHE"),
        (repo::GUEST_EBPF_LICENSE, "LICENSE-GPL-2.0"),
        (repo::DEPLOY_README, repo::DEPLOY_README),
        (repo::CONFIG_EXAMPLE, bundle::CONFIG_EXAMPLE),
    ] {
        copy(&root.join(from), &out.join(to), 0o644)?;
    }

    for dir in ["ansible", "systemd", "nftables"] {
        let from = root.join(repo::DEPLOY).join(dir);
        copy_tree(&from, &out.join(bundle::DEPLOY).join(dir))?;
    }

    copy(
        &root.join(repo::INSTALL_SCRIPT),
        &out.join(bundle::INSTALL_SCRIPT),
        0o755,
    )
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
pub fn pack(dir: &Path) -> Result<PathBuf, TaskError> {
    let dir = &dir.canonicalize().map_err(io(dir))?;
    if !dir.join(bundle::SUMS).is_file() {
        return Err(TaskError::Check(format!(
            "{} is not a release bundle: no SHA256SUMS",
            dir.display()
        )));
    }

    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        return Err(TaskError::Check(format!("{} has no name", dir.display())));
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
            // Root unpacks it as is. Nothing in it is writable by others.
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
        .flat_map(|(path, digest)| [digest.as_str(), "  ", path.as_str(), "\n"])
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
    let mut components = package_components(root)?;
    components.push(firecracker_component(root)?);
    components.push(linux_component(root)?);
    components.push(debian_component(root)?);
    components.extend(rust_components(root)?);
    let bom = json!({
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

/// The string at `key` in `table`, or an empty string.
fn text(table: Option<&toml::Table>, key: &str) -> String {
    let value = table.and_then(|t| t.get(key));
    value
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The packages from crates.io, sorted by package URL. Workspace members
/// are the product, not components.
fn package_components(root: &Path) -> Result<Vec<Value>, TaskError> {
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
    let lock: Lock = read_toml(root, "Cargo.lock")?;
    let checksums: BTreeMap<(String, String), String> = lock
        .package
        .into_iter()
        .filter_map(|p| Some(((p.name, p.version), p.checksum?)))
        .collect();
    let mut components: Vec<Value> = metadata
        .packages
        .iter()
        .filter(|p| {
            p.source
                .as_deref()
                .is_some_and(|s| s.starts_with("registry+"))
        })
        .map(|p| package_component(p, checksums.get(&(p.name.clone(), p.version.clone()))))
        .collect();
    components.sort_by_key(|c| c["purl"].as_str().map(str::to_owned));

    Ok(components)
}

fn package_component(package: &Package, checksum: Option<&String>) -> Value {
    let (name, version) = (&package.name, &package.version);
    let mut fields = serde_json::Map::new();
    fields.insert("type".into(), json!("library"));
    fields.insert("name".into(), json!(name));
    fields.insert("version".into(), json!(version));
    fields.insert("purl".into(), json!(format!("pkg:cargo/{name}@{version}")));

    if let Some(license) = &package.license {
        fields.insert("licenses".into(), json!([{ "expression": license }]));
    }

    if let Some(sum) = checksum {
        fields.insert(
            "hashes".into(),
            json!([{ "alg": "SHA-256", "content": sum }]),
        );
    }

    Value::Object(fields)
}

fn firecracker_component(root: &Path) -> Result<Value, TaskError> {
    let pin: Pin = read_toml(root, repo::FIRECRACKER_PIN)?;

    Ok(json!({
        "type": "application",
        "name": "firecracker",
        "version": pin.version,
        "hashes": [{ "alg": "SHA-256", "content": pin.sha256 }],
        "externalReferences": [{ "type": "distribution", "url": pin.url }],
    }))
}

fn linux_component(root: &Path) -> Result<Value, TaskError> {
    let kernel: toml::Table = read_toml(root, repo::KERNEL_PIN)?;
    let source = kernel.get("source").and_then(toml::Value::as_table);

    Ok(json!({
        "type": "operating-system",
        "name": "linux",
        "version": text(source, "version"),
        "externalReferences": [{
            "type": "vcs",
            "url": format!("{}@{}", text(source, "repository"), text(source, "commit")),
        }],
    }))
}

fn debian_component(root: &Path) -> Result<Value, TaskError> {
    let rootfs: toml::Table = read_toml(root, repo::ROOTFS_PIN)?;
    let debian = rootfs.get("debian").and_then(toml::Value::as_table);
    let snapshot = text(debian, "snapshot");

    Ok(json!({
        "type": "operating-system",
        "name": "debian",
        "version": text(debian, "suite"),
        "externalReferences": [{
            "type": "distribution",
            "url": format!("https://snapshot.debian.org/archive/debian/{snapshot}/"),
        }],
    }))
}

fn rust_components(root: &Path) -> Result<Vec<Value>, TaskError> {
    let rust: toml::Table = read_toml(root, repo::RUST_PIN)?;
    let version = text(Some(&rust), "version");
    let parts = rust.get("component").and_then(toml::Value::as_array);

    Ok(parts
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .map(|part| {
            json!({
                "type": "application",
                "name": format!("rust-{}", text(Some(part), "dir")),
                "version": version,
                "hashes": [{ "alg": "SHA-256", "content": text(Some(part), "sha256") }],
                "externalReferences": [{ "type": "distribution", "url": text(Some(part), "url") }],
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::testing::{scratch, write};

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// An ELF header, with a `PT_INTERP` program header if `loader` is set.
    fn elf(loader: bool) -> Vec<u8> {
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;

        if loader {
            bytes[0x20] = 64;
            bytes[0x36] = 56;
            bytes[0x38] = 1;
            bytes.extend([3, 0, 0, 0]);
            bytes.resize(64 + 56, 0);
        }

        bytes
    }

    /// The build outputs that a bundle is made from, under `dir` as the
    /// workspace root.
    fn fake_build(dir: &Path) {
        for binary in SERVICES.iter().chain(&["crateward-vmjail"]) {
            write(&dir.join(build::RELEASE).join(binary), "binary");
        }

        write(&dir.join(build::FAKE_INTERNET), elf(false));
        write(&dir.join(build::FIRECRACKER), "firecracker");
        write(
            &dir.join(build::GUEST_OUT).join("kernel-6.1.bzImage"),
            "kernel",
        );
        write(&dir.join(build::ROOTFS_IMAGE), "rootfs");
        write(&dir.join(build::AUTHORITY), "authority");
    }

    #[test]
    fn the_binaries_are_staged_and_executable() {
        let dir = scratch("binaries");
        fake_build(&dir);
        let out = dir.join("bundle");
        create_bundle_dir(&out).unwrap();
        stage_binaries(&dir, &out).unwrap();

        for binary in SERVICES {
            assert_eq!(mode(&out.join("bin").join(binary)), 0o755, "{binary}");
        }

        for file in ["crateward-vmjail", "crateward_fake_internet", "firecracker"] {
            assert_eq!(mode(&out.join("sandbox").join(file)), 0o755, "{file}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_binary_is_named() {
        let dir = scratch("missing");
        fake_build(&dir);
        std::fs::remove_file(dir.join(build::RELEASE).join("crateward_feed")).unwrap();
        let out = dir.join("bundle");
        create_bundle_dir(&out).unwrap();
        let error = stage_binaries(&dir, &out).unwrap_err();

        assert!(
            error.to_string().contains("crateward_feed is missing"),
            "{error}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_fake_internet_that_needs_a_loader_is_refused() {
        let dir = scratch("loader");
        fake_build(&dir);
        write(&dir.join(build::FAKE_INTERNET), elf(true));
        let out = dir.join("bundle");
        create_bundle_dir(&out).unwrap();
        let error = stage_binaries(&dir, &out).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("crateward_fake_internet is not static"),
            "{error}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_firecracker_names_its_task() {
        let dir = scratch("firecracker");
        fake_build(&dir);
        std::fs::remove_file(dir.join(build::FIRECRACKER)).unwrap();
        let out = dir.join("bundle");
        create_bundle_dir(&out).unwrap();
        let error = stage_binaries(&dir, &out).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no Firecracker: run `cargo xtask firecracker`")
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_guest_files_are_staged_with_their_modes() {
        let dir = scratch("guest");
        fake_build(&dir);
        let out = dir.join("bundle");
        create_bundle_dir(&out).unwrap();
        stage_guest(&dir, &out).unwrap();

        assert_eq!(mode(&out.join(bundle::KERNEL)), 0o644);
        assert_eq!(mode(&out.join(bundle::ROOTFS)), 0o644);
        assert_eq!(mode(&out.join(bundle::AUTHORITY)), 0o600);
        assert_eq!(
            std::fs::read_to_string(out.join(bundle::KERNEL)).unwrap(),
            "kernel"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_root_filesystem_names_its_task() {
        let dir = scratch("rootfs");
        fake_build(&dir);
        std::fs::remove_file(dir.join(build::ROOTFS_IMAGE)).unwrap();
        let out = dir.join("bundle");
        create_bundle_dir(&out).unwrap();
        let error = stage_guest(&dir, &out).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no root filesystem: run `cargo xtask rootfs`")
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn exactly_one_kernel_image_is_accepted() {
        let dir = scratch("kernel");
        let error = only(&dir, "kernel-", ".bzImage").unwrap_err().to_string();

        assert!(error.contains("no kernel-*.bzImage in"), "{error}");
        assert!(error.contains("run `cargo xtask guest-kernel`"), "{error}");

        write(&dir.join("kernel-a.bzImage"), "a");
        write(&dir.join("kernel-a.config"), "config");

        assert_eq!(
            only(&dir, "kernel-", ".bzImage").unwrap(),
            dir.join("kernel-a.bzImage")
        );

        write(&dir.join("kernel-b.bzImage"), "b");
        let error = only(&dir, "kernel-", ".bzImage").unwrap_err().to_string();

        assert!(error.contains("several kernel-*.bzImage in"), "{error}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_deploy_files_are_staged() {
        let dir = scratch("deploy");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        stage_deploy(&root, &dir).unwrap();

        assert_eq!(mode(&dir.join(bundle::INSTALL_SCRIPT)), 0o755);
        assert_eq!(mode(&dir.join(repo::DEPLOY_README)), 0o644);
        assert_eq!(mode(&dir.join(bundle::CONFIG_EXAMPLE)), 0o644);
        assert!(dir.join(repo::FIREWALL).is_file());
        assert!(dir.join(repo::ANSIBLE).is_dir());
        assert!(dir.join(repo::UNITS).is_dir());

        for license in ["LICENSE-MIT", "LICENSE-APACHE", "LICENSE-GPL-2.0"] {
            assert_eq!(mode(&dir.join(license)), 0o644, "{license}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_bundle_directory_starts_empty() {
        let dir = scratch("bundle");
        write(&dir.join("old.txt"), "old");
        create_bundle_dir(&dir).unwrap();

        assert!(!dir.join("old.txt").exists());

        for sub in ["bin", "sandbox", "guest"] {
            assert!(dir.join(sub).is_dir(), "{sub}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_bill_of_materials_lists_locked_packages_with_checksums() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let bom: Value = serde_json::from_str(&sbom(&root, "0.0.0").unwrap()).unwrap();
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
