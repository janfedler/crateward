//! One Firecracker process and the VM inside it.
//!
//! Every VM gets its own directory on the host. Dropping or destroying a
//! [`Vm`] kills Firecracker and removes the directory, so a VM cannot
//! outlive its owner without startup reconciliation noticing the directory.
//!
//! A VM runs either jailed (production, see [`crate::jail`]) or directly as
//! the calling user (development only). In the jail, Firecracker sees fixed
//! paths such as `/kernel` and `/rootfs.erofs`. Snapshots record those
//! paths, which is what lets one snapshot restore into any slot: every
//! jail offers the same paths, backed by different host files.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use crateward_core::paths::host;
use crateward_core::protocol::{AGENT_PORT, Limits};
use tokio::process::{Child, Command};
use tokio::time::Instant;

use super::agent::{AgentConnection, AgentError};
use super::api::{
    Api, ApiError, BootSource, Drive, DriveUpdate, InstanceAction, MachineConfig, MemoryBackend,
    NetworkInterface, RateLimiter, Serial, SnapshotCreate, SnapshotLoad, TokenBucket, VmState,
    Vsock, VsockOverride,
};
use crate::jail::host::{IdMap, JailError};
use crate::jail::{BindMount, JailSpec, Sinks};

/// Guest context ID. Every VM uses the same one: Firecracker's vsock is
/// private to each VM process, so there is no global CID namespace.
pub const GUEST_CID: u32 = 3;

/// How long Firecracker may take to create its API socket.
const API_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// Names Firecracker sees inside a jail.
const KERNEL: &str = "kernel";
const ROOTFS: &str = "rootfs.erofs";
const STATE: &str = "vm.state";
const MEMORY: &str = "vm.mem";
const NEW_STATE: &str = "snapshot.state";
const NEW_MEMORY: &str = "snapshot.mem";
const VSOCK: &str = "vsock.sock";
const PAYLOAD: &str = "payload.img";
const SCRATCH: &str = "scratch.img";
const WARM: &str = "warm.img";

/// Tap device of every slot. Each jail has its own network namespace, so
/// the name is the same everywhere, as the snapshot requires.
pub const TAP: &str = "tap0";

/// Guest side addresses. Every slot uses the same ones in its own network
/// namespace. The fake internet answers at [`HOST_ADDRESS`].
pub const GUEST_ADDRESS: &str = "10.0.2.2";
/// Host side address of the tap device, the guest's gateway and resolver.
pub const HOST_ADDRESS: &str = "10.0.2.1";
/// The guest's host name. Without one the kernel names the guest after its
/// address, and the C library then appends the domain part (`0.2.2`) to
/// names it fails to resolve, so every lookup shows up twice.
pub const GUEST_HOSTNAME: &str = "build";
/// Prefix length of the link between guest and host.
pub const PREFIX_LEN: u8 = 30;
const GUEST_MAC: &str = "06:00:0a:00:02:02";

/// Limits of the job drives. Both live in host memory. The limits keep one
/// guest from monopolizing memory bandwidth and the host's I/O threads.
/// Compiling reads and writes far less than this.
const DRIVE_LIMIT: RateLimiter = RateLimiter {
    bandwidth: TokenBucket {
        size: 256 << 20,
        refill_time: 1_000,
    },
    ops: TokenBucket {
        size: 50_000,
        refill_time: 1_000,
    },
};

/// Limits of the network interface. Everything the guest sends goes to the
/// fake internet, which only needs to see that something was sent.
const NETWORK_LIMIT: RateLimiter = RateLimiter {
    bandwidth: TokenBucket {
        size: 4 << 20,
        refill_time: 1_000,
    },
    ops: TokenBucket {
        size: 2_000,
        refill_time: 1_000,
    },
};
const API: &str = "api.sock";

/// Why a VM operation failed.
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// File or process I/O failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The Firecracker API rejected a request.
    #[error("firecracker api: {0}")]
    Api(#[from] ApiError),
    /// The guest agent could not be reached or misbehaved.
    #[error("guest agent: {0}")]
    Agent(#[from] AgentError),
    /// The jail could not be built.
    #[error("jail: {0}")]
    Jail(#[from] JailError),
    /// Firecracker did not create its API socket in time or exited early.
    #[error("firecracker did not start: {0}")]
    Start(String),
}

fn io_error(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> VmError {
    let context = context.into();

    move |source| VmError::Io { context, source }
}

/// Settings of a jailed VM.
#[derive(Debug, Clone)]
pub struct JailConfig {
    /// The `crateward-vmjail` binary.
    pub launcher: PathBuf,
    /// The slot's subordinate UID.
    pub vm_uid: u32,
    /// The slot's subordinate GID.
    pub vm_gid: u32,
    /// Tap device to create in the jail's network namespace.
    pub tap: Option<String>,
    /// The fake internet behind the tap device.
    pub sinks: Option<Sinks>,
    /// cgroup the jail joins.
    pub cgroup: Option<PathBuf>,
    /// `RLIMIT_FSIZE` for Firecracker. Must fit the guest memory when the
    /// VM will be snapshotted.
    pub max_file_size: u64,
}

/// How Firecracker is started.
#[derive(Debug, Clone)]
pub enum Isolation {
    /// Directly as the calling user. For development only.
    Direct,
    /// In a rootless jail.
    Jail(JailConfig),
}

/// Where and how one VM runs.
#[derive(Debug, Clone)]
pub struct Launch {
    /// The Firecracker binary.
    pub firecracker: PathBuf,
    /// The VM's directory on the host. Created, and removed on destroy.
    pub dir: PathBuf,
    /// Firecracker `--id`.
    pub id: String,
    /// Isolation mode.
    pub isolation: Isolation,
}

/// The per job drives: the read only payload (`/dev/vdb` in the guest),
/// the writable scratch disk (`/dev/vdc`) and the read only warm build
/// cache (`/dev/vdd`, ADR 0006).
#[derive(Debug, Clone)]
pub struct JobDrives {
    /// EROFS image with the job's sources.
    pub payload: PathBuf,
    /// ext4 image the job may write.
    pub scratch: PathBuf,
    /// EROFS image with the warm target directory, or an empty placeholder
    /// file when there is none.
    pub warm: PathBuf,
}

/// Resources of a VM that is booted from scratch.
#[derive(Debug, Clone)]
pub struct BootSpec {
    /// Kernel image.
    pub kernel: PathBuf,
    /// Root filesystem image, attached read only.
    pub rootfs: PathBuf,
    /// Kernel command line.
    pub boot_args: String,
    /// vCPUs.
    pub vcpus: u8,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Placeholder drives, so that a snapshot of this VM can take job
    /// drives after restore.
    pub drives: Option<JobDrives>,
    /// Attach a network interface on [`TAP`].
    pub network: bool,
}

impl BootSpec {
    /// The kernel command line for the Crateward guest: serial console,
    /// restart on panic, exit on reboot (`reboot=k` makes Firecracker exit
    /// when the guest restarts), no PCI probing (Firecracker uses MMIO
    /// devices unless PCI is enabled), and the agent as PID 1 on a read only
    /// EROFS root.
    #[must_use]
    pub fn default_boot_args(agent_path: &str) -> String {
        format!(
            "console=ttyS0 reboot=k panic=1 pci=off quiet root=/dev/vda rootfstype=erofs ro init={agent_path}"
        )
    }

    /// Kernel IP autoconfiguration for the guest side of the tap link.
    #[must_use]
    pub fn network_boot_args() -> String {
        format!("ip={GUEST_ADDRESS}::{HOST_ADDRESS}:255.255.255.252:{GUEST_HOSTNAME}:eth0:off")
    }
}

/// Files of a full snapshot on the host.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Device and vCPU state.
    pub state: PathBuf,
    /// Guest memory.
    pub memory: PathBuf,
    /// The root filesystem the snapshot was taken with. Restores attach it
    /// at the same path inside the jail.
    pub rootfs: PathBuf,
}

/// A running Firecracker process.
#[derive(Debug)]
pub struct Vm {
    child: Child,
    api: Api,
    dir: PathBuf,
    /// The jail root on the host, if jailed.
    root: Option<PathBuf>,
    vsock_host: PathBuf,
}

/// A host file and the name Firecracker sees it under in a jail.
struct Exposed {
    host: PathBuf,
    name: &'static str,
    writable: bool,
}

impl Exposed {
    fn read_only(host: &Path, name: &'static str) -> Self {
        Self {
            host: host.to_path_buf(),
            name,
            writable: false,
        }
    }

    fn drives(drives: &JobDrives) -> [Self; 3] {
        [
            Self::read_only(&drives.payload, PAYLOAD),
            Self::read_only(&drives.warm, WARM),
            Self {
                host: drives.scratch.clone(),
                name: SCRATCH,
                writable: true,
            },
        ]
    }
}

impl Launch {
    fn jail_root(&self) -> PathBuf {
        self.dir.join("root")
    }

    /// The path Firecracker uses for a host file exposed under `name`.
    fn fc_path(&self, host: &Path, name: &str) -> PathBuf {
        match self.isolation {
            Isolation::Direct => host.to_path_buf(),
            Isolation::Jail(_) => PathBuf::from(format!("/{name}")),
        }
    }

    /// The path Firecracker uses for a file it creates itself.
    fn fc_created(&self, name: &str) -> PathBuf {
        match self.isolation {
            Isolation::Direct => self.dir.join(name),
            Isolation::Jail(_) => PathBuf::from(format!("/{name}")),
        }
    }

    /// Host path of a file Firecracker creates itself.
    fn host_created(&self, name: &str) -> PathBuf {
        match self.isolation {
            Isolation::Direct => self.dir.join(name),
            Isolation::Jail(_) => self.jail_root().join(name),
        }
    }

    /// Starts Firecracker as a child of this process.
    fn spawn_direct(&self, log: &Path) -> Result<Child, VmError> {
        let log = std::fs::File::create(log).map_err(io_error("creating the log"))?;
        let log_err = log.try_clone().map_err(io_error("duplicating the log"))?;

        Command::new(&self.firecracker)
            .arg("--api-sock")
            .arg(self.host_created(API))
            .arg("--id")
            .arg(&self.id)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log_err)
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(io_error(format!("starting {}", self.firecracker.display())))
    }

    /// What the launcher builds the jail from.
    fn jail_spec(&self, jail: &JailConfig, files: &[Exposed], log: PathBuf) -> JailSpec {
        let mut devices = vec![PathBuf::from(host::KVM)];
        if jail.tap.is_some() {
            devices.push(PathBuf::from(host::TUN));
        }

        JailSpec {
            id: self.id.clone(),
            root: self.jail_root(),
            firecracker: self.firecracker.clone(),
            mounts: files
                .iter()
                .map(|file| BindMount {
                    source: file.host.clone(),
                    target: file.name.to_owned(),
                    writable: file.writable,
                })
                .collect(),
            devices,
            tap: jail.tap.clone(),
            sinks: jail.sinks.clone(),
            cgroup: jail.cgroup.clone(),
            log,
            max_open_files: 2048,
            max_file_size: jail.max_file_size,
        }
    }

    /// Starts Firecracker in a jail built by the launcher.
    async fn spawn_jailed(
        &self,
        jail: &JailConfig,
        files: &[Exposed],
        log: PathBuf,
    ) -> Result<Child, VmError> {
        crate::jail::host::prepare_root(&self.jail_root(), jail.vm_uid)?;
        let spec = self.jail_spec(jail, files, log);
        let ids = IdMap::for_slot(jail.vm_uid, jail.vm_gid);

        Ok(crate::jail::host::spawn(&jail.launcher, &spec, ids).await?)
    }
}

impl Vm {
    /// Starts Firecracker and waits for its API socket.
    async fn spawn(launch: &Launch, files: &[Exposed]) -> Result<Self, VmError> {
        tokio::fs::create_dir_all(&launch.dir)
            .await
            .map_err(io_error(format!("creating {}", launch.dir.display())))?;
        let log = launch.dir.join("firecracker.log");
        let (child, root) = match &launch.isolation {
            Isolation::Direct => (launch.spawn_direct(&log)?, None),
            Isolation::Jail(jail) => {
                let child = launch.spawn_jailed(jail, files, log).await?;
                (child, Some(launch.jail_root()))
            }
        };

        let socket = launch.host_created(API);
        let mut vm = Self {
            child,
            api: Api::new(&socket),
            dir: launch.dir.clone(),
            root,
            vsock_host: launch.host_created(VSOCK),
        };

        vm.wait_for_socket(&socket).await?;

        Ok(vm)
    }

    async fn wait_for_socket(&mut self, socket: &Path) -> Result<(), VmError> {
        let deadline = Instant::now() + API_SOCKET_TIMEOUT;

        while !socket.exists() {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(io_error("polling firecracker"))?
            {
                return Err(VmError::Start(format!("exited with {status}")));
            }

            if Instant::now() >= deadline {
                return Err(VmError::Start("no API socket".into()));
            }

            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        Ok(())
    }

    /// Boots a VM from a kernel and root filesystem.
    ///
    /// # Errors
    ///
    /// Fails if Firecracker does not start or rejects the configuration.
    pub async fn boot(launch: &Launch, spec: &BootSpec) -> Result<Self, VmError> {
        let mut files = vec![
            Exposed::read_only(&spec.kernel, KERNEL),
            Exposed::read_only(&spec.rootfs, ROOTFS),
        ];

        if let Some(drives) = &spec.drives {
            files.extend(Exposed::drives(drives));
        }

        let vm = Self::spawn(launch, &files).await?;
        vm.configure(launch, spec).await?;
        let start = InstanceAction {
            action_type: "InstanceStart",
        };

        vm.api.put("/actions", &start).await?;

        Ok(vm)
    }

    /// Sends everything Firecracker needs before the VM starts.
    async fn configure(&self, launch: &Launch, spec: &BootSpec) -> Result<(), VmError> {
        let api = &self.api;

        // The serial console carries guest controlled text into our log.
        // Excess output is dropped: 64 KiB burst, then 4 KiB per second.
        let serial = Serial {
            rate_limiter: TokenBucket {
                size: 64 * 1024,
                refill_time: 16_000,
            },
        };

        api.put("/serial", &serial).await?;
        let boot_source = BootSource {
            kernel_image_path: launch.fc_path(&spec.kernel, KERNEL),
            boot_args: spec.boot_args.clone(),
        };

        api.put("/boot-source", &boot_source).await?;
        let machine = MachineConfig {
            vcpu_count: spec.vcpus,
            mem_size_mib: spec.memory_mib,
            smt: false,
        };

        api.put("/machine-config", &machine).await?;
        let rootfs = Drive {
            drive_id: "rootfs".into(),
            path_on_host: launch.fc_path(&spec.rootfs, ROOTFS),
            is_root_device: true,
            is_read_only: true,
            rate_limiter: None,
        };

        api.put("/drives/rootfs", &rootfs).await?;

        if let Some(drives) = &spec.drives {
            self.put_job_drives(launch, drives).await?;
        }

        if spec.network {
            let interface = NetworkInterface {
                iface_id: "eth0".into(),
                host_dev_name: TAP.into(),
                guest_mac: GUEST_MAC.into(),
                rx_rate_limiter: NETWORK_LIMIT,
                tx_rate_limiter: NETWORK_LIMIT,
            };

            api.put("/network-interfaces/eth0", &interface).await?;
        }

        let vsock = Vsock {
            guest_cid: GUEST_CID,
            uds_path: launch.fc_created(VSOCK),
        };

        api.put("/vsock", &vsock).await?;

        Ok(())
    }

    /// Attaches the job drives. A restore points them at the job's files.
    async fn put_job_drives(&self, launch: &Launch, drives: &JobDrives) -> Result<(), VmError> {
        for (id, host, name, read_only) in [
            ("payload", &drives.payload, PAYLOAD, true),
            ("scratch", &drives.scratch, SCRATCH, false),
            ("warm", &drives.warm, WARM, true),
        ] {
            let drive = Drive {
                drive_id: id.into(),
                path_on_host: launch.fc_path(host, name),
                is_root_device: false,
                is_read_only: read_only,
                rate_limiter: Some(DRIVE_LIMIT),
            };

            self.api.put(&format!("/drives/{id}"), &drive).await?;
        }

        Ok(())
    }

    /// Restores a VM from a full snapshot and resumes it. The VM gets its
    /// own vsock socket through `vsock_override`. With `drives`, the
    /// snapshot's placeholder drives are pointed at the job's files and the
    /// guest is told their sizes (`PATCH /drives`), before the agent is
    /// asked to mount them.
    ///
    /// # Errors
    ///
    /// Fails if Firecracker does not start or rejects the snapshot.
    pub async fn restore(
        launch: &Launch,
        snapshot: &Snapshot,
        drives: Option<&JobDrives>,
    ) -> Result<Self, VmError> {
        let mut files = vec![
            Exposed::read_only(&snapshot.rootfs, ROOTFS),
            Exposed::read_only(&snapshot.state, STATE),
            Exposed::read_only(&snapshot.memory, MEMORY),
        ];

        if let Some(drives) = drives {
            files.extend(Exposed::drives(drives));
        }

        let vm = Self::spawn(launch, &files).await?;
        vm.api
            .put(
                "/snapshot/load",
                &SnapshotLoad {
                    snapshot_path: launch.fc_path(&snapshot.state, STATE),
                    mem_backend: MemoryBackend {
                        backend_type: "File",
                        backend_path: launch.fc_path(&snapshot.memory, MEMORY),
                    },
                    resume_vm: true,
                    vsock_override: VsockOverride {
                        uds_path: launch.fc_created(VSOCK),
                    },
                },
            )
            .await?;

        if let Some(drives) = drives {
            for (id, host, name) in [
                ("payload", &drives.payload, PAYLOAD),
                ("scratch", &drives.scratch, SCRATCH),
                ("warm", &drives.warm, WARM),
            ] {
                vm.api
                    .patch(
                        &format!("/drives/{id}"),
                        &DriveUpdate {
                            drive_id: id.into(),
                            path_on_host: launch.fc_path(host, name),
                        },
                    )
                    .await?;
            }
        }

        Ok(vm)
    }

    /// Connects to the guest agent, waiting until `deadline` for it to
    /// listen.
    ///
    /// # Errors
    ///
    /// Fails if the agent is not reachable before the deadline.
    pub async fn agent(&self, deadline: Instant) -> Result<AgentConnection, VmError> {
        Ok(AgentConnection::connect_until(
            &self.vsock_host,
            AGENT_PORT,
            Limits::default(),
            deadline,
        )
        .await?)
    }

    /// Pauses the VM and writes a full snapshot into `out` on the host.
    /// `launch` must be the one the VM was started with, and `rootfs` the
    /// root filesystem it runs on.
    ///
    /// # Errors
    ///
    /// Fails if pausing, snapshotting or copying fails.
    pub async fn snapshot(
        &self,
        launch: &Launch,
        rootfs: &Path,
        out: &Path,
    ) -> Result<Snapshot, VmError> {
        tokio::fs::create_dir_all(out)
            .await
            .map_err(io_error(format!("creating {}", out.display())))?;
        self.api.patch("/vm", &VmState { state: "Paused" }).await?;
        self.api
            .put(
                "/snapshot/create",
                &SnapshotCreate {
                    snapshot_type: "Full",
                    snapshot_path: launch.fc_created(NEW_STATE),
                    mem_file_path: launch.fc_created(NEW_MEMORY),
                },
            )
            .await?;
        let snapshot = Snapshot {
            state: out.join(STATE),
            memory: out.join(MEMORY),
            rootfs: rootfs.to_path_buf(),
        };

        // Copy rather than move: in a jail the files belong to the slot's
        // user, and the copies must belong to the orchestrator so that no
        // slot can ever write a snapshot another VM restores from.
        for (from, to) in [(NEW_STATE, &snapshot.state), (NEW_MEMORY, &snapshot.memory)] {
            let from = launch.host_created(from);
            tokio::fs::copy(&from, to)
                .await
                .map_err(io_error(format!("copying {}", from.display())))?;
            tokio::fs::remove_file(&from)
                .await
                .map_err(io_error(format!("removing {}", from.display())))?;
        }

        Ok(snapshot)
    }

    /// Waits up to `limit` for Firecracker to exit on its own, for example
    /// after the guest shut down.
    ///
    /// # Errors
    ///
    /// Fails if waiting fails.
    pub async fn wait_exit(
        &mut self,
        limit: Duration,
    ) -> Result<Option<std::process::ExitStatus>, VmError> {
        match tokio::time::timeout(limit, self.child.wait()).await {
            Ok(status) => Ok(Some(status.map_err(io_error("waiting for firecracker"))?)),
            Err(_) => Ok(None),
        }
    }

    /// The VM's directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The jail root on the host, if the VM is jailed.
    #[must_use]
    pub fn jail_root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// Process ID of the Firecracker process, while it runs.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Kills Firecracker (if still running) and removes the VM directory.
    ///
    /// # Errors
    ///
    /// Fails if the process cannot be reaped or the directory not removed.
    pub async fn destroy(mut self) -> Result<(), VmError> {
        self.kill().await?;

        self.remove().await
    }

    /// Kills Firecracker, if it still runs, and reaps it.
    ///
    /// # Errors
    ///
    /// Fails if the process cannot be polled or reaped.
    pub async fn kill(&mut self) -> Result<(), VmError> {
        if self
            .child
            .try_wait()
            .map_err(io_error("polling firecracker"))?
            .is_none()
        {
            // Ignore the error of a process that exits between the check and the kill.
            let _ = self.child.start_kill();
            self.child
                .wait()
                .await
                .map_err(io_error("reaping firecracker"))?;
        }

        Ok(())
    }

    /// Removes the VM directory. Call after [`Vm::kill`].
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be removed.
    pub async fn remove(self) -> Result<(), VmError> {
        tokio::fs::remove_dir_all(&self.dir)
            .await
            .map_err(io_error(format!("removing {}", self.dir.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guest_gets_a_host_name_without_a_domain() {
        assert_eq!(
            BootSpec::network_boot_args(),
            "ip=10.0.2.2::10.0.2.1:255.255.255.252:build:eth0:off"
        );
        assert!(!GUEST_HOSTNAME.contains('.'));
    }
}
