//! The guest's fixed paths and identities.
//!
//! The root filesystem build (`cargo xtask rootfs`), the orchestrator and
//! the guest agent must agree on where things live inside a microVM. They
//! all take the paths from here, so the image, the host and the agent
//! cannot drift apart. [`artifacts`] does the same for the build outputs
//! on the host.

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

/// Where the warm image is mounted.
pub const WARM_IMAGE: &str = "/work/.warm/image";

/// The overlay's writable layer above the warm image.
pub const WARM_UPPER: &str = "/work/.warm/upper";

/// The overlay's work directory.
pub const WARM_WORK: &str = "/work/.warm/work";

/// Build outputs on the host, relative to the workspace root. The `xtask`
/// tasks write them, the release bundle and the microVM tests read them.
pub mod artifacts {
    /// The guest kernel (`kernel-<version>.bzImage`), the root filesystem
    /// image and the eBPF object.
    pub const OUT: &str = "target/guest/out";

    /// Pinned third party binaries: Firecracker and `bpf-linker`.
    pub const BIN: &str = "target/guest/bin";

    /// Downloaded archives, such as the guest's Rust toolchain.
    pub const DOWNLOADS: &str = "target/guest/downloads";

    /// The fake internet's TLS authority, certificate and private key.
    pub const AUTHORITY: &str = "target/guest/ca/authority.pem";

    /// File name of the root filesystem image in [`OUT`].
    pub const ROOTFS: &str = "rootfs.erofs";

    /// File name of the eBPF object in [`OUT`].
    pub const EBPF: &str = "guest-ebpf.o";

    /// File name of Firecracker in [`BIN`].
    pub const FIRECRACKER: &str = "firecracker";
}
