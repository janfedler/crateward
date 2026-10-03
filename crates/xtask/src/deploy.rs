//! Checks of `deploy/`: the playbooks parse, the units verify, and the
//! firewall loads (`cargo xtask deploy-check`, run in CI). Unit tests
//! that keep the playbook consistent with the rest of the repository.

use std::path::Path;
use std::process::Command;

use crate::TaskError;

/// Firewall variables with placeholder IDs, for the dry run.
const SAMPLE_VARS: &str = "define SSH_PORT = 22
define SLOT_UIDS = 200000-200003
define FEED_UID = 991
define FETCHER_UID = 992
define STATIC_UID = 993
define ORCHESTRATOR_UID = 994
define ANALYZER_UID = 995
define API_UID = 996
define SUPERVISOR_UID = 997
define BUILDER_UID = 998
";

/// Where the firewall includes its variables on the server.
const VARS_PATH: &str = "/etc/crateward/nftables-vars.nft";

fn check(command: &mut Command, what: &str) -> Result<String, TaskError> {
    let out = command
        .output()
        .map_err(|e| TaskError::Command(format!("cannot start {what}: {e}")))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(TaskError::Check(format!("{what} failed:\n{}", text.trim())))
    }
}

/// Runs every check of `deploy/`.
///
/// # Errors
///
/// Fails if a tool is missing or a check finds a problem.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let deploy = root.join("deploy");
    check_playbooks(&deploy.join("ansible"))?;
    check_install_script(&deploy.join("install.sh"))?;
    check_units(&deploy.join("systemd"))?;
    check_firewall(root, &deploy.join("nftables").join("crateward.nft"))
}

fn check_playbooks(ansible: &Path) -> Result<(), TaskError> {
    for playbook in ["site.yml", "rollback.yml", "uninstall.yml"] {
        let args = [
            "-i",
            "inventory.example.yml",
            playbook,
            "-e",
            "@vars.example.yml",
        ];
        check(
            Command::new("ansible-playbook")
                .current_dir(ansible)
                .args(args)
                .arg("--syntax-check"),
            &format!("ansible-playbook --syntax-check {playbook}"),
        )?;
        eprintln!("xtask: {playbook} parses");
    }
    Ok(())
}

/// shellcheck is on the CI runners. A development machine may lack it.
fn check_install_script(script: &Path) -> Result<(), TaskError> {
    match Command::new("shellcheck").arg(script).output() {
        Ok(out) if out.status.success() => eprintln!("xtask: install.sh passes shellcheck"),
        Ok(out) => {
            return Err(TaskError::Check(format!(
                "shellcheck install.sh:\n{}",
                String::from_utf8_lossy(&out.stdout).trim()
            )));
        }
        Err(_) if std::env::var_os("CI").is_some() => {
            return Err(TaskError::Command("shellcheck is missing".into()));
        }
        Err(_) => eprintln!("xtask: no shellcheck here, CI runs it on install.sh"),
    }
    Ok(())
}

fn check_units(units: &Path) -> Result<(), TaskError> {
    let mut names: Vec<String> = std::fs::read_dir(units)
        .map_err(|e| TaskError::Io(units.to_path_buf(), e))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in &names {
        verify_unit(units, name)?;
    }
    eprintln!("xtask: {} units verify", names.len());
    Ok(())
}

fn verify_unit(units: &Path, name: &str) -> Result<(), TaskError> {
    let out = Command::new("systemd-analyze")
        .current_dir(units)
        .args(["verify", "--man=no", &format!("./{name}")])
        .output()
        .map_err(|e| TaskError::Command(format!("cannot start systemd-analyze: {e}")))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let problems = unit_problems(&stderr);
    if problems.is_empty() {
        return Ok(());
    }
    Err(TaskError::Check(format!(
        "{name}:\n{}",
        problems.join("\n")
    )))
}

/// The binaries exist only on the server. Every other complaint counts.
fn unit_problems(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|l| !l.contains("is not executable: No such file or directory"))
        .filter(|l| !l.trim().is_empty())
        .collect()
}

fn check_firewall(root: &Path, rules_path: &Path) -> Result<(), TaskError> {
    let dir = root.join("target").join("deploy-check");
    std::fs::create_dir_all(&dir).map_err(|e| TaskError::Io(dir.clone(), e))?;
    let vars = dir.join("nftables-vars.nft");
    std::fs::write(&vars, SAMPLE_VARS).map_err(|e| TaskError::Io(vars.clone(), e))?;
    let rules = std::fs::read_to_string(rules_path)
        .map_err(|e| TaskError::Io(rules_path.to_path_buf(), e))?
        .replace(VARS_PATH, &vars.to_string_lossy());
    let test = dir.join("crateward.nft");
    std::fs::write(&test, rules).map_err(|e| TaskError::Io(test.clone(), e))?;
    // In a new user and network namespace, so no privilege is needed and
    // the host's firewall is untouched.
    let test = test.to_string_lossy().into_owned();
    check(
        Command::new("unshare").args([
            "--user",
            "--map-root-user",
            "--net",
            "/usr/sbin/nft",
            "-c",
            "-f",
            &test,
        ]),
        "nft -c on the firewall",
    )?;
    eprintln!("xtask: the firewall loads");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn read(relative: &str) -> String {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        std::fs::read_to_string(root.join(relative)).unwrap()
    }

    /// The playbook installs the host cargo from the same pinned release as
    /// the guest image.
    #[test]
    fn the_playbook_pins_the_guest_cargo() {
        let pins: toml::Table = toml::from_str(&read("guest/rootfs/rust.toml")).unwrap();
        let cargo = pins["component"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["dir"].as_str() == Some("cargo"))
            .unwrap();
        let playbook = read("deploy/ansible/site.yml");
        let url = cargo["url"].as_str().unwrap();
        let sha256 = cargo["sha256"].as_str().unwrap();
        assert!(playbook.contains(&format!("cargo_url: {url}\n")), "{url}");
        assert!(
            playbook.contains(&format!("cargo_sha256: {sha256}\n")),
            "{sha256}"
        );
        let version = pins["version"].as_str().unwrap();
        assert!(playbook.contains(&format!("cargo-{version}-x86_64-unknown-linux-gnu")));
    }

    /// Every unit the playbooks install and remove exists, and every unit
    /// in `deploy/systemd` is installed and removed.
    #[test]
    fn the_playbooks_cover_every_unit() {
        let playbook = read("deploy/ansible/components.yml");
        for user in ["site.yml", "uninstall.yml"] {
            assert!(read(&format!("deploy/ansible/{user}")).contains("    - components.yml\n"));
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/systemd");
        for entry in std::fs::read_dir(root).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            let stem = name.rsplit_once('.').unwrap().0;
            assert!(playbook.contains(&format!("  - {stem}\n")), "{name}");
        }
    }

    #[test]
    fn a_missing_binary_is_no_problem_but_anything_else_is() {
        let stderr = [
            "x.service: Command /opt/crateward/bin/x is not executable: No such file or directory",
            "",
            "x.service: Unknown key 'Foo' in section [Service]",
            "   ",
            "x.service: Failed to create unit",
        ]
        .join("\n");
        assert_eq!(
            unit_problems(&stderr),
            [
                "x.service: Unknown key 'Foo' in section [Service]",
                "x.service: Failed to create unit",
            ]
        );
        assert!(unit_problems("").is_empty());
    }

    #[test]
    fn a_missing_unit_directory_names_the_path() {
        let path = Path::new("/nonexistent/units");
        let Err(TaskError::Io(named, _)) = check_units(path) else {
            panic!("the missing directory was not reported");
        };
        assert_eq!(named, path);
    }

    /// The dry run swaps the variables file for a sample. That only works
    /// while the rules include the path it replaces.
    #[test]
    fn the_firewall_includes_the_variables_file() {
        assert!(read("deploy/nftables/crateward.nft").contains(VARS_PATH));
    }
}
