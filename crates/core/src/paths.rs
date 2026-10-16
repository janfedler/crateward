//! Every fixed path of Crateward, defined once.
//!
//! The services, the guest agent, the image builds and the tests import
//! these constants instead of spelling paths out, so two places cannot
//! disagree about where a file lives. Each section says what its paths are
//! relative to.

/// The public site.
pub mod site {
    /// The site's domain, written to `CNAME` for GitHub Pages and named as
    /// the creator of SBOMs.
    pub const DOMAIN: &str = "crateward.com";
}

/// The installed server.
pub mod host {
    /// The configuration file every service reads by default.
    pub const CONFIG: &str = "/etc/crateward/crateward.toml";

    /// The firewall's variables, written by Ansible.
    pub const NFTABLES_VARS: &str = "/etc/crateward/nftables-vars.nft";

    /// GitHub's host key for the site export, written by Ansible. `ssh`
    /// takes the home directory from the user database, not from `HOME`,
    /// so the export names this file.
    pub const EXPORT_KNOWN_HOSTS: &str = "/var/lib/crateward/api/.ssh/known_hosts";

    /// The content addressed blob store, in `instance.data_dir`.
    pub const BLOBS: &str = "cas";

    /// The original `.crate` files, in `instance.data_dir`.
    pub const ORIGINALS: &str = "originals";

    /// The integrity manifest, in `instance.data_dir` (ADR 0008).
    pub const INTEGRITY_MANIFEST: &str = "integrity.b3";

    /// The fetcher's work directories, in `instance.run_dir`.
    pub const FETCH_WORK: &str = "fetch";

    /// The orchestrator's snapshots and placeholders, in `instance.run_dir`.
    pub const ORCHESTRATOR_WORK: &str = "orchestrator";

    /// The public site export, in `instance.run_dir`.
    pub const EXPORT_WORK: &str = "export";

    /// `ip` from Debian's `iproute2`.
    pub const IP: &str = "/usr/sbin/ip";

    /// `nft` from Debian's `nftables`.
    pub const NFT: &str = "/usr/sbin/nft";

    /// `mkfs.erofs` from Debian's `erofs-utils`.
    pub const MKFS_EROFS: &str = "/usr/bin/mkfs.erofs";

    /// `mkfs.ext4` from Debian's `e2fsprogs`.
    pub const MKFS_EXT4: &str = "/usr/sbin/mkfs.ext4";

    /// The KVM device every microVM needs.
    pub const KVM: &str = "/dev/kvm";

    /// The TUN device for a microVM's tap interface.
    pub const TUN: &str = "/dev/net/tun";

    /// The cgroup v2 hierarchy.
    pub const CGROUPS: &str = "/sys/fs/cgroup";

    /// The calling process's own cgroup.
    pub const OWN_CGROUP: &str = "/proc/self/cgroup";
}

/// Inside a microVM. The root filesystem build, the orchestrator and the
/// guest agent all rely on these.
pub mod guest {
    /// The guest agent. It runs as PID 1 (`init=`).
    pub const AGENT: &str = "/usr/sbin/crateward-agent";

    /// The eBPF programs the agent loads at boot (ADR 0007).
    pub const EBPF_OBJECT: &str = "/usr/lib/crateward/guest-ebpf.o";

    /// The unprivileged user that jobs run as. `guest/rootfs/customize.sh`
    /// creates it with these IDs.
    pub const BUILDER_USER: &str = "builder";

    /// User ID of [`BUILDER_USER`].
    pub const BUILDER_UID: u32 = 1000;

    /// Group ID of [`BUILDER_USER`].
    pub const BUILDER_GID: u32 = 1000;

    /// The read only payload drive (ADR 0004).
    pub const PAYLOAD_DEVICE: &str = "/dev/vdb";

    /// Where the payload is mounted.
    pub const PAYLOAD: &str = "/cw";

    /// The probe directory in the payload, the job's working directory.
    pub const PROBE: &str = "/cw/probe";

    /// The locked crates in the payload, which replace crates.io.
    pub const VENDOR: &str = "/cw/vendor";

    /// The shell that runs payload scripts.
    pub const SHELL: &str = "/bin/sh";

    /// The kernel's own BTF, which the agent checks the eBPF programs
    /// against.
    pub const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

    /// The writable scratch disk.
    pub const SCRATCH_DEVICE: &str = "/dev/vdc";

    /// Where the scratch disk is mounted.
    pub const WORK: &str = "/work";

    /// The builder's home directory, on the scratch disk.
    pub const HOME: &str = "/work/home";

    /// Cargo's home directory.
    pub const CARGO_HOME: &str = "/work/home/.cargo";

    /// The target directory, as cargo sees it.
    pub const TARGET: &str = "/work/target";

    /// The read only warm build cache drive (ADR 0006).
    pub const WARM_DEVICE: &str = "/dev/vdd";

    /// The warm build cache's directories, on the scratch disk.
    pub const WARM: &str = "/work/.warm";

    /// Where the warm image is mounted.
    pub const WARM_IMAGE: &str = "/work/.warm/image";

    /// The overlay's writable layer above the warm image.
    pub const WARM_UPPER: &str = "/work/.warm/upper";

    /// The overlay's work directory.
    pub const WARM_WORK: &str = "/work/.warm/work";
}

/// Inputs in the repository, relative to the workspace root.
pub mod repo {
    /// The example configuration, which documents every key.
    pub const CONFIG_EXAMPLE: &str = "config/crateward.example.toml";

    /// The architecture document with the generated state diagram.
    pub const ARCHITECTURE: &str = "docs/ARCHITECTURE.md";

    /// The deployment files.
    pub const DEPLOY: &str = "deploy";

    /// The Ansible playbooks.
    pub const ANSIBLE: &str = "deploy/ansible";

    /// The deployment guide.
    pub const DEPLOY_README: &str = "deploy/README.md";

    /// The installer of a release bundle.
    pub const INSTALL_SCRIPT: &str = "deploy/install.sh";

    /// The systemd units.
    pub const UNITS: &str = "deploy/systemd";

    /// The host firewall.
    pub const FIREWALL: &str = "deploy/nftables/crateward.nft";

    /// The pinned Firecracker release.
    pub const FIRECRACKER_PIN: &str = "guest/firecracker.toml";

    /// The pinned `bpf-linker` release.
    pub const BPF_LINKER_PIN: &str = "guest/bpf-linker.toml";

    /// The guest kernel's pins and configuration.
    pub const KERNEL_INPUTS: &str = "guest/kernel";

    /// The guest kernel's source pin.
    pub const KERNEL_PIN: &str = "guest/kernel/kernel.toml";

    /// The root filesystem's Debian pin.
    pub const ROOTFS_PIN: &str = "guest/rootfs/rootfs.toml";

    /// The root filesystem's mmdebstrap customize hook.
    pub const ROOTFS_HOOK: &str = "guest/rootfs/customize.sh";

    /// The guest's pinned Rust toolchain.
    pub const RUST_PIN: &str = "guest/rootfs/rust.toml";

    /// The eBPF package, with its own workspace (ADR 0007).
    pub const GUEST_EBPF: &str = "crates/guest_ebpf";

    /// The eBPF package's manifest.
    pub const GUEST_EBPF_MANIFEST: &str = "crates/guest_ebpf/Cargo.toml";

    /// The eBPF package's license text (GPL-2.0-only, ADR 0010).
    pub const GUEST_EBPF_LICENSE: &str = "crates/guest_ebpf/LICENSE";

    /// The fuzz package, with its own workspace.
    pub const FUZZ: &str = "fuzz";

    /// The fuzz targets, one file each.
    pub const FUZZ_TARGETS: &str = "fuzz/fuzz_targets";

    /// The seed corpus, one directory per target.
    pub const FUZZ_CORPUS: &str = "fuzz/corpus";

    /// The AFL++ state, one output directory per target.
    pub const FUZZ_AFL: &str = "fuzz/afl";

    /// The targets built by `cargo afl build --release`.
    pub const FUZZ_AFL_BINARIES: &str = "fuzz/target/release";
}

/// The build machine: outputs relative to the workspace root, which the
/// `xtask` tasks write and the release bundle and the microVM tests read,
/// and the tools the tasks use.
pub mod build {
    /// `musl-gcc` from Debian's `musl-tools`, used for the guest target when
    /// installed.
    pub const MUSL_GCC: &str = "/usr/bin/musl-gcc";

    /// The target triple of everything that runs on the bare guest.
    pub const GUEST_TARGET: &str = "x86_64-unknown-linux-musl";

    /// The host binaries of a release build.
    pub const RELEASE: &str = "target/release";

    /// The static guest agent.
    pub const GUEST_AGENT: &str = "target/x86_64-unknown-linux-musl/release/crateward-guest-agent";

    /// The static fake internet.
    pub const FAKE_INTERNET: &str =
        "target/x86_64-unknown-linux-musl/release/crateward-fake-internet";

    /// The finished guest kernel (`kernel-<version>.bzImage`), root
    /// filesystem and eBPF object.
    pub const GUEST_OUT: &str = "target/guest/out";

    /// The root filesystem image.
    pub const ROOTFS_IMAGE: &str = "target/guest/out/rootfs.erofs";

    /// The compiled eBPF programs.
    pub const EBPF_OBJECT: &str = "target/guest/out/guest-ebpf.o";

    /// Pinned third party binaries.
    pub const GUEST_BIN: &str = "target/guest/bin";

    /// Firecracker, from `cargo xtask firecracker`.
    pub const FIRECRACKER: &str = "target/guest/bin/firecracker";

    /// The fake internet's TLS authority, certificate and private key.
    pub const AUTHORITY: &str = "target/guest/ca/authority.pem";

    /// Downloaded archives, such as the guest's Rust toolchain.
    pub const DOWNLOADS: &str = "target/guest/downloads";

    /// Work directory of the root filesystem build.
    pub const ROOTFS_WORK: &str = "target/guest/rootfs";

    /// Work directory of the guest kernel build.
    pub const KERNEL_WORK: &str = "target/guest/kernel";

    /// Target directory of the eBPF build.
    pub const EBPF_WORK: &str = "target/guest/ebpf";

    /// Release bundles, one directory each.
    pub const RELEASE_BUNDLES: &str = "target/release-bundle";

    /// The vendored dependencies of a release.
    pub const VENDOR_DIR: &str = "target/release-vendor";

    /// The vendored dependencies, packed.
    pub const VENDOR_ARCHIVE: &str = "target/crateward-vendor.tar.gz";

    /// Scratch files of `cargo xtask deploy-check`.
    pub const DEPLOY_CHECK: &str = "target/deploy-check";

    /// Pinned check tools, such as the CycloneDX validators.
    pub const CHECK_TOOLS: &str = "target/check-tools";

    /// The sample SBOM and findings document of `cargo xtask cyclonedx`.
    pub const CYCLONEDX_SAMPLES: &str = "target/cyclonedx";

    /// The line coverage summary of `cargo xtask coverage`.
    pub const COVERAGE_SUMMARY: &str = "target/llvm-cov/summary.json";

    /// The coverage report per line, from `cargo xtask coverage`.
    pub const COVERAGE_HTML: &str = "target/llvm-cov/html";
}

/// Inside a release bundle, relative to its directory. `cargo xtask
/// release` writes this layout, `install.sh` and the playbooks read it.
pub mod bundle {
    /// The service binaries.
    pub const BIN: &str = "bin";

    /// The sandbox binaries: the jail launcher, the fake internet and
    /// Firecracker.
    pub const SANDBOX: &str = "sandbox";

    /// The guest images and the authority the root filesystem trusts.
    pub const GUEST: &str = "guest";

    /// The guest kernel.
    pub const KERNEL: &str = "guest/kernel.bzImage";

    /// The root filesystem image.
    pub const ROOTFS: &str = "guest/rootfs.erofs";

    /// The fake internet's TLS authority.
    pub const AUTHORITY: &str = "guest/authority.pem";

    /// The example configuration.
    pub const CONFIG_EXAMPLE: &str = "config/crateward.example.toml";

    /// The playbooks, units and firewall.
    pub const DEPLOY: &str = "deploy";

    /// The installer.
    pub const INSTALL_SCRIPT: &str = "install.sh";

    /// The vendored dependencies.
    pub const VENDOR_ARCHIVE: &str = "crateward-vendor.tar.gz";

    /// The software bill of materials.
    pub const SBOM: &str = "sbom.cdx.json";

    /// SHA-256 of every file, the input of the signature.
    pub const SUMS: &str = "SHA256SUMS";
}

#[cfg(test)]
mod tests {
    use super::{build, guest};

    #[test]
    fn guest_paths_lie_in_their_directories() {
        for path in [guest::PROBE, guest::VENDOR] {
            assert!(path.starts_with(guest::PAYLOAD), "{path}");
        }

        for path in [guest::HOME, guest::CARGO_HOME, guest::TARGET, guest::WARM] {
            assert!(path.starts_with(guest::WORK), "{path}");
        }

        for path in [guest::WARM_IMAGE, guest::WARM_UPPER, guest::WARM_WORK] {
            assert!(path.starts_with(guest::WARM), "{path}");
        }
    }

    #[test]
    fn guest_binaries_are_built_for_the_guest_target() {
        let dir = format!("target/{}/release/", build::GUEST_TARGET);

        assert!(build::GUEST_AGENT.starts_with(&dir));
        assert!(build::FAKE_INTERNET.starts_with(&dir));
    }

    #[test]
    fn guest_outputs_lie_in_their_directories() {
        for path in [build::ROOTFS_IMAGE, build::EBPF_OBJECT] {
            assert!(path.starts_with(build::GUEST_OUT), "{path}");
        }

        assert!(build::FIRECRACKER.starts_with(build::GUEST_BIN));
    }
}
