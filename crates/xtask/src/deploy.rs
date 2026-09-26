//! Checks that keep `deploy/` consistent with the rest of the repository.

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
