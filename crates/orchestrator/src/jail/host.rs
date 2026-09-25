//! The orchestrator side of the jail: starts `crateward-vmjail`, writes the
//! ID maps, and hands back the process that becomes Firecracker.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdout, Command};

use super::{INSIDE_SETUP_ID, INSIDE_VM_ID, JailSpec, SpecError};

/// How long the launcher may take to build the jail.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The host identities one jail maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMap {
    /// The orchestrator's own UID and GID (inside ID 0, setup only).
    pub setup_uid: u32,
    /// The orchestrator's own GID.
    pub setup_gid: u32,
    /// The slot's subordinate UID (inside ID 1, Firecracker).
    pub vm_uid: u32,
    /// The slot's subordinate GID.
    pub vm_gid: u32,
}

impl IdMap {
    /// The map for the current user and a slot's subordinate IDs.
    #[must_use]
    pub fn for_slot(vm_uid: u32, vm_gid: u32) -> Self {
        Self {
            setup_uid: rustix::process::geteuid().as_raw(),
            setup_gid: rustix::process::getegid().as_raw(),
            vm_uid,
            vm_gid,
        }
    }
}

/// Why a jail could not be started.
#[derive(Debug, thiserror::Error)]
pub enum JailError {
    /// The specification was rejected before starting anything.
    #[error(transparent)]
    Spec(#[from] SpecError),
    /// Starting or talking to the launcher failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// `newuidmap` or `newgidmap` refused the mapping.
    #[error("{tool} failed: {stderr}")]
    IdMap {
        /// The helper.
        tool: &'static str,
        /// Its error output.
        stderr: String,
    },
    /// The launcher reported a failure.
    #[error("launcher: {0}")]
    Launcher(String),
    /// The launcher did not finish in time.
    #[error("the launcher did not finish within {0:?}")]
    Timeout(Duration),
}

fn io(context: &'static str) -> impl FnOnce(std::io::Error) -> JailError {
    move |source| JailError::Io { context, source }
}

async fn expect_line(out: &mut BufReader<ChildStdout>, wanted: &str) -> Result<(), JailError> {
    let mut line = String::new();
    out.read_line(&mut line)
        .await
        .map_err(io("reading from the launcher"))?;
    let line = line.trim_end();
    if line == wanted {
        Ok(())
    } else if let Some(reason) = line.strip_prefix("error: ") {
        Err(JailError::Launcher(reason.to_owned()))
    } else if line.is_empty() {
        Err(JailError::Launcher("exited without an answer".into()))
    } else {
        Err(JailError::Launcher(format!("unexpected answer {line:?}")))
    }
}

async fn write_map(tool: &'static str, pid: u32, setup: u32, vm: u32) -> Result<(), JailError> {
    let output = Command::new(tool)
        .arg(pid.to_string())
        .args([INSIDE_SETUP_ID.to_string(), setup.to_string(), "1".into()])
        .args([INSIDE_VM_ID.to_string(), vm.to_string(), "1".into()])
        .output()
        .await
        .map_err(io("running an ID map helper"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(JailError::IdMap {
            tool,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// Starts a jailed Firecracker. When this returns, the process has executed
/// Firecracker inside the jail; its API socket appears in the jail root.
///
/// # Errors
///
/// Fails if the specification is invalid, the ID maps are refused, or any
/// step of the launcher fails. The launcher process is killed on failure.
pub async fn spawn(launcher: &Path, spec: &JailSpec, ids: IdMap) -> Result<Child, JailError> {
    spec.validate()?;
    let mut child = Command::new(launcher)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .map_err(io("starting the jail launcher"))?;
    let handshake = async {
        let pid = child
            .id()
            .ok_or_else(|| JailError::Launcher("exited immediately".into()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| JailError::Launcher("no stdin".into()))?;
        let mut stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| JailError::Launcher("no stdout".into()))?,
        );
        let mut json = serde_json::to_vec(spec).map_err(|e| JailError::Launcher(e.to_string()))?;
        json.push(b'\n');
        stdin
            .write_all(&json)
            .await
            .map_err(io("sending the specification"))?;
        expect_line(&mut stdout, "unshared").await?;
        write_map("newuidmap", pid, ids.setup_uid, ids.vm_uid).await?;
        write_map("newgidmap", pid, ids.setup_gid, ids.vm_gid).await?;
        stdin
            .write_all(b"mapped\n")
            .await
            .map_err(io("confirming the ID maps"))?;
        expect_line(&mut stdout, "exec").await
    };
    match tokio::time::timeout(LAUNCH_TIMEOUT, handshake).await {
        Ok(Ok(())) => Ok(child),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            Err(error)
        }
        Err(_) => {
            let _ = child.kill().await;
            Err(JailError::Timeout(LAUNCH_TIMEOUT))
        }
    }
}

/// Prepares a slot's root directory: empty, owned by the orchestrator, and
/// accessible to the slot's subordinate UID through an ACL entry only,
/// with a [decoy](super::decoy) in it.
///
/// # Errors
///
/// Fails if the directory cannot be created or the ACL not set.
pub fn prepare_root(root: &Path, vm_uid: u32) -> Result<(), JailError> {
    use std::os::unix::fs::PermissionsExt;
    if root.exists() {
        std::fs::remove_dir_all(root).map_err(io("clearing the jail root"))?;
    }
    std::fs::create_dir_all(root).map_err(io("creating the jail root"))?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
        .map_err(io("restricting the jail root"))?;
    super::acl::grant_user(root, vm_uid).map_err(io("setting the jail root ACL"))?;
    super::decoy::plant(root).map_err(io("planting the jail decoy"))
}

/// Host path of a file Firecracker sees at `name` in the jail root.
#[must_use]
pub fn host_path(root: &Path, name: &str) -> PathBuf {
    root.join(name.trim_start_matches('/'))
}
