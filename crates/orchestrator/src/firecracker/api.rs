//! Typed client for the subset of the Firecracker API that Crateward uses.
//!
//! Requests and responses follow `src/firecracker/swagger/firecracker.yaml`
//! of Firecracker v1.17.0. Each request uses its own HTTP/1.1 connection
//! over the API socket: the API is used a handful of times per VM, and a
//! fresh connection keeps the client free of state.
//!
//! Firecracker is our own process, but it runs next to a hostile guest, so
//! response bodies are still read with a size limit.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{ACCEPT, CONTENT_TYPE, HOST};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

/// Largest response body read from Firecracker.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Why an API call failed.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The API socket could not be reached.
    #[error("cannot connect to {path}: {source}")]
    Connect {
        /// The socket.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// HTTP failed.
    #[error("http: {0}")]
    Http(#[from] hyper::Error),
    /// The request could not be built or the response not read.
    #[error("{0}")]
    Transport(String),
    /// Firecracker answered with an error.
    #[error("{method} {path} failed with {status}: {message}")]
    Rejected {
        /// Request method.
        method: Method,
        /// Request path.
        path: String,
        /// Response status.
        status: u16,
        /// Firecracker's `fault_message`.
        message: String,
    },
}

/// `PUT /boot-source`
#[derive(Debug, Clone, Serialize)]
pub struct BootSource {
    /// Kernel image (ELF `vmlinux` or `bzImage`).
    pub kernel_image_path: PathBuf,
    /// Kernel command line.
    pub boot_args: String,
}

/// `PUT /machine-config`
#[derive(Debug, Clone, Serialize)]
pub struct MachineConfig {
    /// Number of vCPUs.
    pub vcpu_count: u8,
    /// Guest memory in MiB.
    pub mem_size_mib: u32,
    /// Simultaneous multithreading inside the guest. Always off.
    pub smt: bool,
}

/// `PUT /drives/{drive_id}`
#[derive(Debug, Clone, Serialize)]
pub struct Drive {
    /// Drive identifier.
    pub drive_id: String,
    /// Backing file.
    pub path_on_host: PathBuf,
    /// Whether the guest boots from this drive.
    pub is_root_device: bool,
    /// Whether the guest may only read it.
    pub is_read_only: bool,
    /// I/O limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
}

/// `PATCH /drives/{drive_id}`: points a drive at another backing file and
/// tells the guest about the new size.
#[derive(Debug, Clone, Serialize)]
pub struct DriveUpdate {
    /// Drive identifier.
    pub drive_id: String,
    /// New backing file.
    pub path_on_host: PathBuf,
}

/// `PUT /network-interfaces/{iface_id}`
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    /// Interface identifier.
    pub iface_id: String,
    /// Tap device on the host (in the jail's network namespace).
    pub host_dev_name: String,
    /// MAC address the guest sees.
    pub guest_mac: String,
    /// Limits on what the guest receives.
    pub rx_rate_limiter: RateLimiter,
    /// Limits on what the guest sends.
    pub tx_rate_limiter: RateLimiter,
}

/// `PUT /vsock`
#[derive(Debug, Clone, Serialize)]
pub struct Vsock {
    /// Guest context identifier (at least 3).
    pub guest_cid: u32,
    /// Host side Unix socket.
    pub uds_path: PathBuf,
}

/// Token bucket of a rate limiter.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct TokenBucket {
    /// Bucket capacity.
    pub size: u64,
    /// Milliseconds to refill the whole bucket.
    pub refill_time: u64,
}

/// Independent byte and operation limits of a device.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RateLimiter {
    /// Bytes per refill time.
    pub bandwidth: TokenBucket,
    /// Operations (requests or packets) per refill time.
    pub ops: TokenBucket,
}

/// `PUT /serial`
#[derive(Debug, Clone, Serialize)]
pub struct Serial {
    /// Limits console output bytes. Excess output is dropped.
    pub rate_limiter: TokenBucket,
}

/// `PUT /actions`
#[derive(Debug, Clone, Serialize)]
pub struct InstanceAction {
    /// Action name, for example `InstanceStart`.
    pub action_type: &'static str,
}

/// `PATCH /vm`
#[derive(Debug, Clone, Serialize)]
pub struct VmState {
    /// `Paused` or `Resumed`.
    pub state: &'static str,
}

/// `PUT /snapshot/create`
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotCreate {
    /// Always `Full`. Diff snapshots are a developer preview.
    pub snapshot_type: &'static str,
    /// Device and vCPU state file.
    pub snapshot_path: PathBuf,
    /// Guest memory file.
    pub mem_file_path: PathBuf,
}

/// Memory backend of `PUT /snapshot/load`.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryBackend {
    /// Always `File`: the memory file is mapped privately, so restored VMs
    /// share its page cache and write to private copies.
    pub backend_type: &'static str,
    /// The memory file.
    pub backend_path: PathBuf,
}

/// Vsock override of `PUT /snapshot/load`.
#[derive(Debug, Clone, Serialize)]
pub struct VsockOverride {
    /// Socket path for the restored VM.
    pub uds_path: PathBuf,
}

/// `PUT /snapshot/load`
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotLoad {
    /// Device and vCPU state file.
    pub snapshot_path: PathBuf,
    /// Guest memory.
    pub mem_backend: MemoryBackend,
    /// Resume right after loading.
    pub resume_vm: bool,
    /// Gives each restored VM its own vsock socket.
    pub vsock_override: VsockOverride,
}

#[derive(Debug, Deserialize)]
struct Fault {
    fault_message: String,
}

/// A client bound to one Firecracker API socket.
#[derive(Debug, Clone)]
pub struct Api {
    socket: PathBuf,
}

impl Api {
    /// A client for the given socket.
    #[must_use]
    pub fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_path_buf(),
        }
    }

    /// Sends `PUT path` with a JSON body.
    ///
    /// # Errors
    ///
    /// Fails if the request fails or Firecracker rejects it.
    pub async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<(), ApiError> {
        self.call(Method::PUT, path, body).await
    }

    /// Sends `PATCH path` with a JSON body.
    ///
    /// # Errors
    ///
    /// Fails if the request fails or Firecracker rejects it.
    pub async fn patch<T: Serialize>(&self, path: &str, body: &T) -> Result<(), ApiError> {
        self.call(Method::PATCH, path, body).await
    }

    async fn call<T: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &T,
    ) -> Result<(), ApiError> {
        let json = serde_json::to_vec(body).map_err(|e| ApiError::Transport(e.to_string()))?;
        let stream =
            UnixStream::connect(&self.socket)
                .await
                .map_err(|source| ApiError::Connect {
                    path: self.socket.clone(),
                    source,
                })?;

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;

        let driver = tokio::spawn(connection);
        let request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header(HOST, "localhost")
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(json)))
            .map_err(|e| ApiError::Transport(e.to_string()))?;

        let response = sender.send_request(request).await;
        let result = match response {
            Ok(response) => {
                let status = response.status();
                let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
                    .collect()
                    .await
                    .map_err(|e| ApiError::Transport(format!("reading the response: {e}")))?
                    .to_bytes();
                if status.is_success() {
                    Ok(())
                } else {
                    let message = serde_json::from_slice::<Fault>(&body)
                        .map(|f| f.fault_message)
                        .unwrap_or_else(|_| String::from_utf8_lossy(&body).into_owned());

                    Err(ApiError::Rejected {
                        method,
                        path: path.to_owned(),
                        status: status.as_u16(),
                        message,
                    })
                }
            }
            Err(error) => Err(ApiError::Http(error)),
        };

        driver.abort();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_serialize_to_the_documented_field_names() {
        let load = SnapshotLoad {
            snapshot_path: "/s/state".into(),
            mem_backend: MemoryBackend {
                backend_type: "File",
                backend_path: "/s/mem".into(),
            },
            resume_vm: true,
            vsock_override: VsockOverride {
                uds_path: "/v.sock".into(),
            },
        };

        let json = serde_json::to_value(&load).unwrap();
        assert_eq!(json["mem_backend"]["backend_type"], "File");
        assert_eq!(json["vsock_override"]["uds_path"], "/v.sock");

        let machine = serde_json::to_value(MachineConfig {
            vcpu_count: 1,
            mem_size_mib: 512,
            smt: false,
        })
        .unwrap();

        assert_eq!(machine["mem_size_mib"], 512);
    }
}
