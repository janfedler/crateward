//! Builds the guest kernel from a pinned source and configuration.
//!
//! Inputs live in `guest/kernel/`: `kernel.toml` pins the source commit and
//! version, `firecracker-6.18-x86_64.config` is Firecracker's validated guest
//! configuration, vendored unchanged, and `crateward.config` holds our
//! changes. The build runs as an unprivileged user in `target/guest/kernel`.
//!
//! Kconfig silently drops options whose dependencies are unmet, so after
//! merging the fragment this task checks that every option of the fragment
//! survived. Build metadata (timestamp, user, host) is fixed so that two
//! builds of the same inputs produce the same image.

use std::path::Path;
use std::process::Command;

use crateward_core::paths::{build, repo};
use serde::Deserialize;

use crate::{TaskError, io, read_toml, run_in};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    source: Source,
    config: ConfigFiles,
    build: Build,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    repository: String,
    branch: String,
    commit: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFiles {
    base: String,
    fragment: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Build {
    timestamp: String,
    user: String,
    host: String,
}

/// One requirement from the fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Requirement {
    /// `CONFIG_X=value`
    Set(String, String),
    /// `# CONFIG_X is not set`
    Unset(String),
}

/// Parses the requirements of a configuration fragment.
fn requirements(fragment: &str) -> Vec<Requirement> {
    fragment
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("# CONFIG_") {
                let name = rest.strip_suffix(" is not set")?;
                return Some(Requirement::Unset(format!("CONFIG_{name}")));
            }
            let (name, value) = line.split_once('=')?;
            name.starts_with("CONFIG_")
                .then(|| Requirement::Set(name.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Returns the requirements that the final configuration does not meet.
fn unmet(requirements: &[Requirement], config: &str) -> Vec<String> {
    let value_of = |name: &str| {
        config.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == name).then_some(value)
        })
    };
    requirements
        .iter()
        .filter_map(|requirement| match requirement {
            Requirement::Set(name, wanted) => match value_of(name) {
                Some(value) if value == wanted => None,
                Some(value) => Some(format!("{name} is {value}, wanted {wanted}")),
                None => Some(format!("{name} is not set, wanted {wanted}")),
            },
            Requirement::Unset(name) => value_of(name)
                .filter(|value| *value != "n")
                .map(|value| format!("{name} is {value}, wanted it unset")),
        })
        .collect()
}

fn read(path: &Path) -> Result<String, TaskError> {
    std::fs::read_to_string(path).map_err(io(path))
}

fn output(program: &str, args: &[&str], dir: &Path) -> Result<String, TaskError> {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| TaskError::Command(format!("cannot start {program}: {e}")))?;
    if !out.status.success() {
        return Err(TaskError::Command(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Fetches exactly the pinned commit into `src`, reusing an existing clone.
fn fetch(source: &Source, src: &Path) -> Result<(), TaskError> {
    if !src.join(".git").exists() {
        std::fs::create_dir_all(src).map_err(|e| TaskError::Io(src.to_path_buf(), e))?;
        run_in(src, "git", &["init", "--quiet"], &[])?;
    }
    let head = output("git", &["rev-parse", "HEAD"], src).unwrap_or_default();
    if head != source.commit {
        eprintln!(
            "xtask: fetching {} at {} ({})",
            source.repository, source.commit, source.branch
        );
        run_in(
            src,
            "git",
            &["fetch", "--depth", "1", &source.repository, &source.commit],
            &[],
        )?;
        run_in(
            src,
            "git",
            &["checkout", "--quiet", "--force", "--detach", "FETCH_HEAD"],
            &[],
        )?;
    }
    let head = output("git", &["rev-parse", "HEAD"], src)?;
    if head != source.commit {
        return Err(TaskError::Check(format!(
            "kernel source is at {head}, expected {}",
            source.commit
        )));
    }
    let version = output("make", &["-s", "kernelversion"], src)?;
    if version != source.version {
        return Err(TaskError::Check(format!(
            "kernel source reports version {version}, kernel.toml expects {}",
            source.version
        )));
    }
    Ok(())
}

/// Builds the guest kernel and copies it to `target/guest/out`.
///
/// # Errors
///
/// Fails if a command fails, the source does not match the pin, or the
/// final configuration lost an option of the fragment.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let manifest: Manifest = read_toml(root, repo::KERNEL_PIN)?;

    let src = root.join(build::KERNEL_WORK).join("src");
    let build = root.join(build::KERNEL_WORK).join("build");
    let out_dir = root.join(build::GUEST_OUT);
    for dir in [&build, &out_dir] {
        std::fs::create_dir_all(dir).map_err(io(dir))?;
    }

    fetch(&manifest.source, &src)?;
    configure(
        &manifest.config,
        &root.join(repo::KERNEL_INPUTS),
        &src,
        &build,
    )?;
    compile(&manifest.build, &src, &build)?;
    publish(&build, &out_dir, &manifest.source.version)
}

/// The `make` argument that names the build directory.
fn make_dir(build: &Path) -> String {
    format!("O={}", build.to_string_lossy())
}

/// Merges the fragment into the base configuration and checks that every
/// option of the fragment survived.
fn configure(
    files: &ConfigFiles,
    inputs: &Path,
    src: &Path,
    build: &Path,
) -> Result<(), TaskError> {
    let base = inputs.join(&files.base);
    let fragment = inputs.join(&files.fragment);
    let path = |p: &Path| p.to_string_lossy().into_owned();
    run_in(
        src,
        "scripts/kconfig/merge_config.sh",
        &["-m", "-O", &path(build), &path(&base), &path(&fragment)],
        &[],
    )?;
    run_in(src, "make", &[&make_dir(build), "olddefconfig"], &[])?;
    check_fragment(
        &files.fragment,
        &read(&fragment)?,
        &read(&build.join(".config"))?,
    )
}

fn check_fragment(name: &str, fragment: &str, config: &str) -> Result<(), TaskError> {
    let missing = unmet(&requirements(fragment), config);
    if missing.is_empty() {
        return Ok(());
    }
    Err(TaskError::Check(format!(
        "the kernel configuration lost options of {name}:\n  {}",
        missing.join("\n  ")
    )))
}

/// Builds the image with the fixed build metadata that makes it reproducible.
fn compile(build: &Build, src: &Path, dir: &Path) -> Result<(), TaskError> {
    let jobs = format!(
        "-j{}",
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    );
    run_in(
        src,
        "make",
        &[&make_dir(dir), &jobs, "bzImage"],
        &[
            ("KBUILD_BUILD_TIMESTAMP", build.timestamp.as_str()),
            ("KBUILD_BUILD_USER", build.user.as_str()),
            ("KBUILD_BUILD_HOST", build.host.as_str()),
        ],
    )
}

/// Copies the image and the final configuration to `out_dir`.
fn publish(build: &Path, out_dir: &Path, version: &str) -> Result<(), TaskError> {
    let name = format!("kernel-{version}");
    let image = out_dir.join(format!("{name}.bzImage"));
    copy(&build.join("arch/x86/boot/bzImage"), &image)?;
    copy(
        &build.join(".config"),
        &out_dir.join(format!("{name}.config")),
    )?;
    let digest = crate::images::blake3_file(&image)?;
    eprintln!("xtask: wrote {} (blake3 {digest})", image.display());
    Ok(())
}

fn copy(from: &Path, to: &Path) -> Result<(), TaskError> {
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| TaskError::Io(from.to_path_buf(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_set_and_unset_requirements() {
        let fragment = "# comment\nCONFIG_A=y\n# CONFIG_B is not set\nCONFIG_C=\"x\"\n";
        assert_eq!(
            requirements(fragment),
            vec![
                Requirement::Set("CONFIG_A".into(), "y".into()),
                Requirement::Unset("CONFIG_B".into()),
                Requirement::Set("CONFIG_C".into(), "\"x\"".into()),
            ]
        );
    }

    #[test]
    fn reports_dropped_and_changed_options() {
        let reqs = requirements("CONFIG_A=y\nCONFIG_B=y\n# CONFIG_C is not set\nCONFIG_D=y\n");
        let config = "CONFIG_A=y\nCONFIG_B=m\nCONFIG_C=y\n";
        assert_eq!(
            unmet(&reqs, config),
            vec![
                "CONFIG_B is m, wanted y".to_owned(),
                "CONFIG_C is y, wanted it unset".to_owned(),
                "CONFIG_D is not set, wanted y".to_owned(),
            ]
        );
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cw-kernel-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_fragment_that_survived_passes() {
        let config = "CONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\n";
        assert!(
            check_fragment(
                "f.config",
                "CONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\n",
                config
            )
            .is_ok()
        );
    }

    #[test]
    fn a_lost_option_names_the_fragment_and_each_option() {
        let error = check_fragment(
            "crateward.config",
            "CONFIG_A=y\nCONFIG_B=y\nCONFIG_D=y\n",
            "CONFIG_A=y\nCONFIG_B=m\n",
        )
        .unwrap_err();
        assert!(matches!(error, TaskError::Check(_)));
        assert_eq!(
            error.to_string(),
            "the kernel configuration lost options of crateward.config:\n  CONFIG_B is m, wanted y\n  CONFIG_D is not set, wanted y"
        );
    }

    #[test]
    fn the_image_and_the_configuration_are_published_under_the_version() {
        let dir = scratch("publish");
        let (build, out) = (dir.join("build"), dir.join("out"));
        std::fs::create_dir_all(build.join("arch/x86/boot")).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(build.join("arch/x86/boot/bzImage"), "image").unwrap();
        std::fs::write(build.join(".config"), "CONFIG_A=y\n").unwrap();
        publish(&build, &out, "6.18.51").unwrap();
        assert_eq!(
            std::fs::read_to_string(out.join("kernel-6.18.51.bzImage")).unwrap(),
            "image"
        );
        assert_eq!(
            std::fs::read_to_string(out.join("kernel-6.18.51.config")).unwrap(),
            "CONFIG_A=y\n"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_image_names_its_path() {
        let dir = scratch("no-image");
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let Err(TaskError::Io(path, _)) = publish(&dir.join("build"), &out, "1") else {
            panic!("the missing image was not reported");
        };
        assert_eq!(path, dir.join("build/arch/x86/boot/bzImage"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_real_manifest_parses_and_names_files_that_exist() {
        let root = crate::workspace_root();
        let inputs = root.join(repo::KERNEL_INPUTS);
        let manifest: Manifest = read_toml(&root, repo::KERNEL_PIN).unwrap();
        assert_eq!(manifest.source.commit.len(), 40);
        assert!(inputs.join(&manifest.config.base).is_file());
        assert!(inputs.join(&manifest.config.fragment).is_file());
    }

    #[test]
    fn the_real_fragment_parses() {
        let text = std::fs::read_to_string(
            crate::workspace_root()
                .join(repo::KERNEL_INPUTS)
                .join("crateward.config"),
        )
        .unwrap();
        let reqs = requirements(&text);
        assert!(reqs.contains(&Requirement::Unset("CONFIG_MODULES".into())));
        assert!(reqs.contains(&Requirement::Set("CONFIG_BPF_LSM".into(), "y".into())));
    }
}
