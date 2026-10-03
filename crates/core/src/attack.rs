//! MITRE ATT&CK techniques that evidence is consistent with.
//!
//! A shared vocabulary for reviewers and for reports to crates.io, RustSec
//! or OSV. The tags label evidence. They never add points. Most signals
//! are harmless in most builds (a build script that runs a shell), so a
//! tag reads "consistent with", and only a confirmed verdict claims
//! [`SUPPLY_CHAIN`] for the crate itself.
//!
//! Every ID and name was checked against the ATT&CK website for
//! [`VERSION`]. When a release renames or moves a technique (v19 moved
//! T1562.001 to T1685), update the table and the version together.

/// The ATT&CK Enterprise release the table follows.
pub const VERSION: &str = "v19";

/// A technique, a subtechnique or a tactic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Technique {
    /// `T1552.001`, or `TA0003` for a tactic.
    pub id: &'static str,
    /// The full name, as ATT&CK writes it.
    pub name: &'static str,
}

impl Technique {
    /// Its page on attack.mitre.org.
    #[must_use]
    pub fn url(self) -> String {
        if self.id.starts_with("TA") {
            return format!("https://attack.mitre.org/tactics/{}/", self.id);
        }

        format!(
            "https://attack.mitre.org/techniques/{}/",
            self.id.replace('.', "/")
        )
    }
}

const fn t(id: &'static str, name: &'static str) -> Technique {
    Technique { id, name }
}

/// What every malicious crate is: the way in.
pub const SUPPLY_CHAIN: Technique = t(
    "T1195.001",
    "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
);

const INGRESS: Technique = t("T1105", "Ingress Tool Transfer");
const INTERPRETER: Technique = t("T1059", "Command and Scripting Interpreter");
const UNIX_SHELL: Technique = t("T1059.004", "Command and Scripting Interpreter: Unix Shell");
const PYTHON: Technique = t("T1059.006", "Command and Scripting Interpreter: Python");
const UNSECURED: Technique = t("T1552", "Unsecured Credentials");
const CREDENTIAL_FILES: Technique = t("T1552.001", "Unsecured Credentials: Credentials In Files");
const PRIVATE_KEYS: Technique = t("T1552.004", "Unsecured Credentials: Private Keys");
const PROC_MEMORY: Technique = t("T1003.007", "OS Credential Dumping: Proc Filesystem");
const BROWSERS: Technique = t(
    "T1555.003",
    "Credentials from Password Stores: Credentials from Web Browsers",
);
const LOCAL_DATA: Technique = t("T1005", "Data from Local System");
const SYSTEM_DISCOVERY: Technique = t("T1082", "System Information Discovery");
const SANDBOX_CHECKS: Technique = t("T1497.001", "Virtualization/Sandbox Evasion: System Checks");
const OBFUSCATED: Technique = t("T1027", "Obfuscated Files or Information");
const EMBEDDED: Technique = t(
    "T1027.009",
    "Obfuscated Files or Information: Embedded Payloads",
);
const ENCODED: Technique = t(
    "T1027.013",
    "Obfuscated Files or Information: Encrypted/Encoded File",
);
const DECODE: Technique = t("T1140", "Deobfuscate/Decode Files or Information");
const C2_EXFILTRATION: Technique = t("T1041", "Exfiltration Over C2 Channel");
const WEB_EXFILTRATION: Technique = t("T1567", "Exfiltration Over Web Service");
const DNS: Technique = t("T1071.004", "Application Layer Protocol: DNS");
const RAW_PROTOCOL: Technique = t("T1095", "Non-Application Layer Protocol");
const ELEVATION: Technique = t("T1548", "Abuse Elevation Control Mechanism");
const SETID: Technique = t(
    "T1548.001",
    "Abuse Elevation Control Mechanism: Setuid and Setgid",
);
const SUDO: Technique = t(
    "T1548.003",
    "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
);
const PERMISSIONS: Technique = t(
    "T1222.002",
    "File and Directory Permissions Modification: Linux and Mac Permissions",
);
const DISABLE_TOOLS: Technique = t("T1685", "Disable or Modify Tools");
const PERSISTENCE: Technique = t("TA0003", "Persistence");
const SHELL_CONFIG: Technique = t(
    "T1546.004",
    "Event Triggered Execution: Unix Shell Configuration Modification",
);
const XDG_AUTOSTART: Technique = t(
    "T1547.013",
    "Boot or Logon Autostart Execution: XDG Autostart Entries",
);
const SYSTEMD: Technique = t(
    "T1543.002",
    "Create or Modify System Process: Systemd Service",
);
const CRON: Technique = t("T1053.003", "Scheduled Task/Job: Cron");
const AUTHORIZED_KEYS: Technique = t("T1098.004", "Account Manipulation: SSH Authorized Keys");
/// A compiler or linker name outside the guest image's system directories.
pub const MASQUERADING: Technique = t(
    "T1036.005",
    "Masquerading: Match Legitimate Resource Name or Location",
);

/// The program name at the end of a path.
fn program(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Persistence by the path written. The tactic when the path names none.
fn persistence(path: &str) -> Technique {
    if [".bashrc", ".profile", ".zshrc", ".bash_profile"]
        .iter()
        .any(|p| path.contains(p))
    {
        SHELL_CONFIG
    } else if path.contains("/autostart/") {
        XDG_AUTOSTART
    } else if path.contains("/systemd/") {
        SYSTEMD
    } else if path.contains("/cron") {
        CRON
    } else if path.contains("/.ssh/authorized_keys") {
        AUTHORIZED_KEYS
    } else {
        PERSISTENCE
    }
}

/// How a honeytoken left: the destination is `scheme://host` or `ip:port`
/// for TCP, a bare name for DNS (which never holds a colon), or `udp`.
fn exfiltration(via: &str) -> Vec<Technique> {
    if via == "udp" {
        vec![RAW_PROTOCOL]
    } else if via.contains(':') {
        vec![C2_EXFILTRATION]
    } else {
        vec![DNS, C2_EXFILTRATION]
    }
}

fn execution(signal: &str, exe: &str) -> Vec<Technique> {
    let name = program(exe);

    match signal {
        "exec_downloader" => vec![INGRESS],
        "exec_shell" => vec![UNIX_SHELL],
        "exec_interpreter" if name.starts_with("python") => vec![PYTHON],
        "exec_interpreter" => vec![INTERPRETER],
        "exec_encoder" => vec![DECODE],
        "exec_network-tool" => vec![RAW_PROTOCOL],
        "exec_privilege" if name == "sudo" || name == "su" => vec![SUDO],
        "exec_privilege" if name == "chmod" || name == "chown" => vec![PERMISSIONS],
        "exec_privilege" => vec![ELEVATION],
        _ => Vec::new(),
    }
}

fn yara(rule: &str) -> Vec<Technique> {
    match rule {
        "bidi_control_characters" | "invisible_characters" => vec![OBFUSCATED],
        "embedded_pe_executable" | "embedded_elf_executable" | "embedded_macho_executable" => {
            vec![EMBEDDED]
        }
        "base64_encoded_executable" => vec![EMBEDDED, ENCODED],
        "reverse_shell" => vec![UNIX_SHELL],
        // The rule matches any of several paths, so only the tactic is sure.
        "persistence_locations" => vec![PERSISTENCE],
        "wallet_and_browser_theft" => vec![BROWSERS, LOCAL_DATA],
        "sandbox_evasion" => vec![SANDBOX_CHECKS],
        _ => Vec::new(),
    }
}

fn finding(kind: &str) -> Vec<Technique> {
    match kind {
        "downloader_pattern" => vec![INGRESS],
        "shell_command" => vec![UNIX_SHELL],
        "credential_access" => vec![CREDENTIAL_FILES],
        "secret_environment_variable" => vec![UNSECURED],
        "environment_enumeration" => vec![SYSTEM_DISCOVERY],
        "exfiltration_endpoint" => vec![WEB_EXFILTRATION],
        "obfuscated_data" => vec![OBFUSCATED],
        "included_binary" => vec![EMBEDDED],
        _ => match kind.strip_prefix("yara:") {
            Some(rule) => yara(rule),
            None => Vec::new(),
        },
    }
}

/// The techniques a piece of evidence is consistent with, by its signal
/// and location (a path, program or destination). Empty when none fits:
/// most signals, such as a URL in the code, are no technique on their own.
#[must_use]
pub fn techniques(signal: &str, location: Option<&str>) -> Vec<Technique> {
    let location = location.unwrap_or_default();

    if let Some(kind) = signal.strip_prefix("static:") {
        return finding(kind);
    }

    if signal.starts_with("exec_") {
        return execution(signal, location);
    }

    match signal {
        "read_cargo_credentials" | "read_git_credentials" | "read_aws" | "read_secrets" => {
            vec![CREDENTIAL_FILES]
        }
        "read_ssh" => vec![PRIVATE_KEYS],
        "read_other_process" => vec![PROC_MEMORY],
        "honeytoken_copied" => vec![CREDENTIAL_FILES],
        "honeytoken_left_vm" => exfiltration(location),
        "write_persistence" | "disk_persistence" => vec![persistence(location)],
        "became_root" => vec![ELEVATION],
        "disk_setid" => vec![SETID],
        "tamper_attempt" => vec![DISABLE_TOOLS],
        "network_raw" => vec![RAW_PROTOCOL],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(signal: &str, location: Option<&str>) -> Vec<&'static str> {
        techniques(signal, location).iter().map(|t| t.id).collect()
    }

    #[test]
    fn signals_map_to_techniques() {
        assert_eq!(
            ids("static:downloader_pattern", Some("build.rs:4")),
            ["T1105"]
        );
        assert_eq!(
            ids("static:yara:base64_encoded_executable", None),
            ["T1027.009", "T1027.013"]
        );
        assert_eq!(ids("static:url_literal", None), Vec::<&str>::new());
        assert_eq!(
            ids("exec_interpreter", Some("/usr/bin/python3")),
            ["T1059.006"]
        );
        assert_eq!(ids("exec_interpreter", Some("/usr/bin/perl")), ["T1059"]);
        assert_eq!(ids("exec_privilege", Some("/usr/bin/chmod")), ["T1222.002"]);
        assert_eq!(
            ids("read_ssh", Some("/home/b/.ssh/id_ed25519")),
            ["T1552.004"]
        );
        assert_eq!(ids("tamper_attempt", Some("pid 4")), ["T1685"]);
        assert_eq!(
            ids("network_lookup", Some("example.com")),
            Vec::<&str>::new()
        );
    }

    #[test]
    fn locations_choose_the_technique() {
        assert_eq!(
            ids("write_persistence", Some("/home/b/.bashrc")),
            ["T1546.004"]
        );
        assert_eq!(
            ids(
                "disk_persistence",
                Some("/home/b/.config/autostart/x.desktop")
            ),
            ["T1547.013"]
        );
        assert_eq!(
            ids(
                "write_persistence",
                Some("/home/b/.config/systemd/user/x.service")
            ),
            ["T1543.002"]
        );
        assert_eq!(
            ids("write_persistence", Some("/etc/cron.d/x")),
            ["T1053.003"]
        );
        assert_eq!(
            ids("write_persistence", Some("/home/b/.ssh/authorized_keys")),
            ["T1098.004"]
        );
        assert_eq!(
            ids("write_persistence", Some("/home/b/.gitconfig")),
            ["TA0003"]
        );
        assert_eq!(
            ids("honeytoken_left_vm", Some("tls://evil.example:443")),
            ["T1041"]
        );
        assert_eq!(
            ids("honeytoken_left_vm", Some("a1b2.evil.example")),
            ["T1071.004", "T1041"]
        );
        assert_eq!(
            ids("honeytoken_left_vm", Some("203.0.113.9:443")),
            ["T1041"]
        );
        assert_eq!(ids("honeytoken_left_vm", Some("udp")), ["T1095"]);
    }

    #[test]
    fn links_point_at_the_technique_or_tactic() {
        assert_eq!(
            SUPPLY_CHAIN.url(),
            "https://attack.mitre.org/techniques/T1195/001/"
        );
        assert_eq!(INGRESS.url(), "https://attack.mitre.org/techniques/T1105/");
        assert_eq!(
            PERSISTENCE.url(),
            "https://attack.mitre.org/tactics/TA0003/"
        );
    }
}
