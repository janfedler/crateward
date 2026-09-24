//! One Firecracker process and the VM inside it.
//!
//! Every VM gets its own directory holding the API socket, the vsock socket
//! and the log. Dropping or killing a [`Vm`] kills its whole process group
//! and removes the directory, so a VM cannot outlive its owner without the
//! startup reconciliation noticing its directory.
//!
//! This layer starts Firecracker directly as the calling user. Isolation
//! (namespaces, cgroup limits, a distinct user per slot) wraps it in a later
//! step of M1; the API sequence here stays the same.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use crateward_core::protocol::{AGENT_PORT, Limits};
use tokio::process::{Child, Command};
use tokio::time::Instant;

use super::agent::{AgentConnection, AgentError};
use super::api::{
    Api, ApiError, BootSource, Drive, InstanceAction, MachineConfig, MemoryBackend, Serial,
    SnapshotCreate, SnapshotLoad, TokenBucket, VmState, Vsock, VsockOverride,
};

/// Guest context ID. Every VM uses the same one: Firecracker's vsock is
/// private to each VM process, so there is no global CID namespace.
pub const GUEST_CID: u32 = 3;

/// How long Firecracker may take to create its API socket.
const API_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Firecracker did not create its API socket in time or exited early.
    #[error("firecracker did not start: {0}")]
    Start(String),
}

fn io_error(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> VmError {
    let context = context.into();
    move |source| VmError::Io { context, source }
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
}

/// Files of a full snapshot.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Device and vCPU state.
    pub state: PathBuf,
    /// Guest memory.
    pub memory: PathBuf,
}

/// A running Firecracker process.
#[derive(Debug)]
pub struct Vm {
    child: Child,
    api: Api,
    dir: PathBuf,
    vsock_uds: PathBuf,
}

/// Paths inside a VM directory.
fn api_socket(dir: &Path) -> PathBuf {
    dir.join("api.sock")
}

fn vsock_socket(dir: &Path) -> PathBuf {
    dir.join("vsock.sock")
}

impl Vm {
    /// Starts Firecracker in `dir` and waits for its API socket.
    async fn spawn(firecracker: &Path, dir: &Path, id: &str) -> Result<Self, VmError> {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(io_error(format!("creating {}", dir.display())))?;
        let log_path = dir.join("firecracker.log");
        let log = std::fs::File::create(&log_path).map_err(io_error("creating the log"))?;
        let log_err = log.try_clone().map_err(io_error("duplicating the log"))?;
        let socket = api_socket(dir);
        let child = Command::new(firecracker)
            .arg("--api-sock")
            .arg(&socket)
            .arg("--id")
            .arg(id)
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(log_err)
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .map_err(io_error(format!("starting {}", firecracker.display())))?;
        let mut vm = Self {
            child,
            api: Api::new(&socket),
            dir: dir.to_path_buf(),
            vsock_uds: vsock_socket(dir),
        };
        let deadline = Instant::now() + API_SOCKET_TIMEOUT;
        while !socket.exists() {
            if let Some(status) = vm
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
        Ok(vm)
    }

    /// Boots a VM from a kernel and root filesystem.
    ///
    /// # Errors
    ///
    /// Fails if Firecracker does not start or rejects the configuration.
    pub async fn boot(
        firecracker: &Path,
        dir: &Path,
        id: &str,
        spec: &BootSpec,
    ) -> Result<Self, VmError> {
        let vm = Self::spawn(firecracker, dir, id).await?;
        // The serial console carries guest controlled text into our log.
        // Excess output is dropped: 64 KiB burst, then 4 KiB per second.
        vm.api
            .put(
                "/serial",
                &Serial {
                    rate_limiter: TokenBucket {
                        size: 64 * 1024,
                        refill_time: 16_000,
                    },
                },
            )
            .await?;
        vm.api
            .put(
                "/boot-source",
                &BootSource {
                    kernel_image_path: spec.kernel.clone(),
                    boot_args: spec.boot_args.clone(),
                },
            )
            .await?;
        vm.api
            .put(
                "/machine-config",
                &MachineConfig {
                    vcpu_count: spec.vcpus,
                    mem_size_mib: spec.memory_mib,
                    smt: false,
                },
            )
            .await?;
        vm.api
            .put(
                "/drives/rootfs",
                &Drive {
                    drive_id: "rootfs".into(),
                    path_on_host: spec.rootfs.clone(),
                    is_root_device: true,
                    is_read_only: true,
                },
            )
            .await?;
        vm.api
            .put(
                "/vsock",
                &Vsock {
                    guest_cid: GUEST_CID,
                    uds_path: vm.vsock_uds.clone(),
                },
            )
            .await?;
        vm.api
            .put(
                "/actions",
                &InstanceAction {
                    action_type: "InstanceStart",
                },
            )
            .await?;
        Ok(vm)
    }

    /// Restores a VM from a full snapshot and resumes it. The VM gets its
    /// own vsock socket through `vsock_override`.
    ///
    /// # Errors
    ///
    /// Fails if Firecracker does not start or rejects the snapshot.
    pub async fn restore(
        firecracker: &Path,
        dir: &Path,
        id: &str,
        snapshot: &Snapshot,
    ) -> Result<Self, VmError> {
        let vm = Self::spawn(firecracker, dir, id).await?;
        vm.api
            .put(
                "/snapshot/load",
                &SnapshotLoad {
                    snapshot_path: snapshot.state.clone(),
                    mem_backend: MemoryBackend {
                        backend_type: "File",
                        backend_path: snapshot.memory.clone(),
                    },
                    resume_vm: true,
                    vsock_override: VsockOverride {
                        uds_path: vm.vsock_uds.clone(),
                    },
                },
            )
            .await?;
        Ok(vm)
    }

    /// Connects to the guest agent, waiting until `deadline` for it to
    /// listen.
    ///
    /// # Errors
    ///
    /// Fails if the agent is not reachable before the deadline.
    pub async fn agent(&self, deadline: Instant) -> Result<AgentConnection, VmError> {
        Ok(
            AgentConnection::connect_until(
                &self.vsock_uds,
                AGENT_PORT,
                Limits::default(),
                deadline,
            )
            .await?,
        )
    }

    /// Pauses the VM and writes a full snapshot into `out`.
    ///
    /// # Errors
    ///
    /// Fails if pausing or snapshotting fails.
    pub async fn snapshot(&self, out: &Path) -> Result<Snapshot, VmError> {
        tokio::fs::create_dir_all(out)
            .await
            .map_err(io_error(format!("creating {}", out.display())))?;
        let snapshot = Snapshot {
            state: out.join("vm.state"),
            memory: out.join("vm.mem"),
        };
        self.api.patch("/vm", &VmState { state: "Paused" }).await?;
        self.api
            .put(
                "/snapshot/create",
                &SnapshotCreate {
                    snapshot_type: "Full",
                    snapshot_path: snapshot.state.clone(),
                    mem_file_path: snapshot.memory.clone(),
                },
            )
            .await?;
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
        tokio::fs::remove_dir_all(&self.dir)
            .await
            .map_err(io_error(format!("removing {}", self.dir.display())))
    }
}
