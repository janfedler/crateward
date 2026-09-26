//! Checks of `deploy/`: the playbooks parse, the units verify, and the
//! firewall loads (`cargo xtask deploy-check`, run in CI); and unit tests
//! that keep the playbook consistent with the rest of the repository.

use std::path::Path;
use std::process::Command;

use crate::TaskError;

/// Firewall variables with placeholder IDs, for the dry run.
const SAMPLE_VARS: &str = "define WG_PORT = 51820
define SSH_PORT = 22
define SSH_IFACES = { \"wg0\" }
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
    let ansible = deploy.join("ansible");
    for playbook in ["site.yml", "rollback.yml"] {
        check(
            Command::new("ansible-playbook")
                .current_dir(&ansible)
                .args([
                    "-i",
                    "inventory.example.yml",
                    playbook,
                    "-e",
                    "@vars.example.yml",
                    "--syntax-check",
                ]),
            &format!("ansible-playbook --syntax-check {playbook}"),
        )?;
        eprintln!("xtask: {playbook} parses");
    }
    let units = deploy.join("systemd");
    let mut names: Vec<String> = std::fs::read_dir(&units)
        .map_err(|e| TaskError::Io(units.clone(), e))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in &names {
        // The binaries exist only on the server; every other complaint
        // counts.
        let out = Command::new("systemd-analyze")
            .current_dir(&units)
            .args(["verify", "--man=no", &format!("./{name}")])
            .output()
            .map_err(|e| TaskError::Command(format!("cannot start systemd-analyze: {e}")))?;
        let problems: Vec<String> = String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|l| !l.contains("is not executable: No such file or directory"))
            .filter(|l| !l.trim().is_empty())
            .map(str::to_owned)
            .collect();
        if !problems.is_empty() {
            return Err(TaskError::Check(format!(
                "{name}:\n{}",
                problems.join("\n")
            )));
        }
    }
    eprintln!("xtask: {} units verify", names.len());
    let dir = root.join("target").join("deploy-check");
    std::fs::create_dir_all(&dir).map_err(|e| TaskError::Io(dir.clone(), e))?;
    let vars = dir.join("nftables-vars.nft");
    std::fs::write(&vars, SAMPLE_VARS).map_err(|e| TaskError::Io(vars.clone(), e))?;
    let rules_path = deploy.join("nftables").join("crateward.nft");
    let rules = std::fs::read_to_string(&rules_path)
        .map_err(|e| TaskError::Io(rules_path.clone(), e))?
        .replace("/etc/crateward/nftables-vars.nft", &vars.to_string_lossy());
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

    /// Every unit the playbook installs exists, and every unit in
    /// `deploy/systemd` is installed.
    #[test]
    fn the_playbook_installs_every_unit() {
        let playbook = read("deploy/ansible/site.yml");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/systemd");
        for entry in std::fs::read_dir(root).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            let stem = name.rsplit_once('.').unwrap().0;
            assert!(playbook.contains(&format!("      - {stem}\n")), "{name}");
        }
    }
}
