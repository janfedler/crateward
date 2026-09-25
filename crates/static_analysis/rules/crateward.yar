// Crateward's YARA-X rules for crate contents.
//
// They cover what the syn based analysis cannot see or does not see in
// every file: bytes outside Rust syntax, binaries and data files shipped in
// the crate, and strings in any file type. Every rule declares a severity
// (info, low, medium or high) and a description. Rules with
// `source_only = true` apply to source files only (by extension), because
// the bytes they look for are common in images, archives and test data.
//
// A shipped executable is medium: test fixtures are common. When build
// time code includes or runs it, other findings raise the alarm.

rule bidi_control_characters {
    meta:
        severity = "high"
        description = "Unicode bidirectional control characters, used to make source code read differently than it compiles (Trojan Source, CVE-2021-42574)"
        source_only = true
    strings:
        $embed = { E2 80 (AA | AB | AC | AD | AE) }
        $isolate = { E2 81 (A6 | A7 | A8 | A9) }
    condition:
        any of them
}

rule invisible_characters {
    meta:
        severity = "medium"
        description = "Zero width or invisible characters, which can hide identifiers or payloads"
        source_only = true
    strings:
        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }
        $zwj = { E2 80 8D }
        $wj = { E2 81 A0 }
    condition:
        any of them
}

rule embedded_pe_executable {
    meta:
        severity = "medium"
        description = "A Windows executable shipped inside the crate"
    condition:
        filesize > 64 and uint16(0) == 0x5A4D and uint32(0x3C) < filesize - 4
        and uint32(uint32(0x3C)) == 0x00004550
}

rule embedded_elf_executable {
    meta:
        severity = "medium"
        description = "An ELF executable or library shipped inside the crate"
    condition:
        uint32(0) == 0x464C457F
}

rule embedded_macho_executable {
    meta:
        severity = "medium"
        description = "A Mach-O executable shipped inside the crate"
    condition:
        uint32(0) == 0xFEEDFACF or uint32(0) == 0xCFFAEDFE or uint32(0) == 0xBEBAFECA
}

rule base64_encoded_executable {
    meta:
        severity = "high"
        description = "A base64 encoded Windows or ELF executable header"
    strings:
        $pe = "TVqQAAMAAAAEAAAA"
        $elf = "f0VMRgIBAQ"
    condition:
        any of them
}

rule reverse_shell {
    meta:
        severity = "high"
        description = "Reverse shell idioms"
    strings:
        $tcp = "/dev/tcp/"
        $nc = /nc(at)? (-[a-z]+ )*-e \/bin\/(ba)?sh/
        $bash = /bash -i >& ?\//
    condition:
        any of them
}

rule persistence_locations {
    meta:
        severity = "medium"
        description = "Paths and keys used to persist on a developer machine"
    strings:
        $run = "CurrentVersion\\Run" nocase
        $agents = "Library/LaunchAgents"
        $cron = "/etc/cron"
        $crontab = "crontab -"
        $bashrc = ".bashrc"
        $zshrc = ".zshrc"
        $systemd = ".config/systemd/user"
    condition:
        any of them
}

rule wallet_and_browser_theft {
    meta:
        severity = "high"
        description = "Names of cryptocurrency wallets or browser credential stores"
    strings:
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn"
        $exodus = "Exodus/exodus.wallet"
        $electrum = "Electrum/wallets"
        $login = "Login Data"
        $state = "Local State"
    condition:
        any of ($metamask, $exodus, $electrum) or ($login and $state)
}

rule sandbox_evasion {
    meta:
        severity = "medium"
        description = "Checks for virtual machines, sandboxes or debuggers"
    strings:
        $vbox = "VBoxService"
        $vmware = "vmtoolsd"
        $qemu = "QEMU Virtual CPU"
        $firecracker = "Firecracker" nocase
        $cgroup = "/proc/self/cgroup"
        $tracer = "TracerPid"
        $hypervisor = "/sys/hypervisor"
    condition:
        any of them
}
