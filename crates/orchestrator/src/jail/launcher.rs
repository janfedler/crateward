//! The launcher side of the jail: runs in `crateward-vmjail`, single
//! threaded, and ends by executing Firecracker.
//!
//! Control protocol with the orchestrator, one line each over stdin and
//! stdout: the orchestrator sends the [`JailSpec`] as JSON. The launcher
//! answers `unshared` once it is in its new user namespace. The orchestrator
//! writes the ID maps and answers `mapped`. The launcher answers `exec` right
//! before it replaces itself with Firecracker, or `error: <reason>` if a
//! step fails. From then on Firecracker's stdout and stderr go to the log.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::fs::{Gid, Uid};
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::process::{Resource, Rlimit};

use super::{FAKE_INTERNET_IN_JAIL, FIRECRACKER_IN_JAIL, INSIDE_VM_ID, JailSpec, MAX_SPEC_BYTES};
use crate::firecracker::vm::{HOST_ADDRESS, PREFIX_LEN};
use crateward_core::paths::host::{IP, NFT};
use crateward_core::sandbox::{Namespaces, unshare};

/// Redirects everything the guest sends to the fake internet's ports
/// (`crateward_fake_internet::server::SlotConfig::default`). The namespace
/// has no other interface and no route, so nothing leaves it anyway. The
/// redirect makes every attempt visible.
fn ruleset(tap: &str) -> String {
    format!(
        "table ip crateward {{\n\
         \tchain prerouting {{\n\
         \t\ttype nat hook prerouting priority dstnat; policy accept;\n\
         \t\tiifname \"{tap}\" udp dport 53 redirect to :5353\n\
         \t\tiifname \"{tap}\" tcp dport 0-65535 redirect to :8080\n\
         \t\tiifname \"{tap}\" udp dport 0-65535 redirect to :5354\n\
         \t}}\n\
         }}\n"
    )
}

fn run_nft(rules: &str) -> Result<(), LaunchError> {
    let mut child = Command::new(NFT)
        .args(["-f", "-"])
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(step("running nft"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(rules.as_bytes())
            .map_err(step("writing the nft rules"))?;
    }

    let status = child.wait().map_err(step("running nft"))?;

    if status.success() {
        Ok(())
    } else {
        Err(LaunchError {
            step: "running nft",
            detail: format!("nft failed with {status}"),
        })
    }
}

/// A failed step, with enough context to act on.
#[derive(Debug, thiserror::Error)]
#[error("{step}: {detail}")]
pub struct LaunchError {
    step: &'static str,
    detail: String,
}

fn step<E: std::fmt::Display>(step: &'static str) -> impl FnOnce(E) -> LaunchError {
    move |e| LaunchError {
        step,
        detail: e.to_string(),
    }
}

fn read_line<R: BufRead>(input: &mut R, limit: usize) -> Result<String, LaunchError> {
    let mut line = String::new();
    let mut limited = input
        .by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX));

    limited
        .read_line(&mut line)
        .map_err(step("reading from the orchestrator"))?;

    if !line.ends_with('\n') {
        return Err(LaunchError {
            step: "reading from the orchestrator",
            detail: "line missing or too long".into(),
        });
    }

    line.pop();

    Ok(line)
}

fn say(line: &str) -> Result<(), LaunchError> {
    let mut out = std::io::stdout().lock();

    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(step("writing to the orchestrator"))
}

/// Creates an empty file or directory as a bind mount point.
fn mount_point(target: &Path, directory: bool) -> Result<(), LaunchError> {
    if directory {
        std::fs::create_dir_all(target).map_err(step("creating a mount point"))
    } else {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(target)
            .map(drop)
            .map_err(step("creating a mount point"))
    }
}

/// Bind mounts `source` onto `target`, then tightens the flags. Adding
/// restrictions on a bind mount is always allowed inside a user namespace.
fn bind(source: &Path, target: &Path, flags: MountFlags) -> Result<(), LaunchError> {
    mount_point(target, source.is_dir())?;
    rustix::mount::mount_bind(source, target).map_err(step("bind mount"))?;

    rustix::mount::mount_remount(target, MountFlags::BIND | flags, "")
        .map_err(step("restricting a bind mount"))
}

fn run_ip(args: &[&str]) -> Result<(), LaunchError> {
    let status = Command::new(IP)
        .args(args)
        .env_clear()
        .status()
        .map_err(step("running ip"))?;

    if status.success() {
        Ok(())
    } else {
        Err(LaunchError {
            step: "running ip",
            detail: format!("ip {} failed with {status}", args.join(" ")),
        })
    }
}

/// Files opened while host paths are still visible.
struct HostFiles {
    log: File,
    null: File,
    authority: Option<Vec<u8>>,
    events: Option<File>,
}

fn open_append(path: &Path, what: &'static str) -> Result<File, LaunchError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(step(what))
}

fn read_authority(path: &Path) -> Result<Vec<u8>, LaunchError> {
    let mut pem = Vec::new();
    File::open(path)
        .and_then(|f| f.take(64 * 1024).read_to_end(&mut pem))
        .map_err(step("reading the TLS authority"))?;

    Ok(pem)
}

fn open_host_files(spec: &JailSpec) -> Result<HostFiles, LaunchError> {
    let log = open_append(&spec.log, "opening the log")?;
    let null = File::open("/dev/null").map_err(step("opening /dev/null"))?;
    let authority = spec
        .sinks
        .as_ref()
        .and_then(|sinks| sinks.authority.as_deref())
        .map(read_authority)
        .transpose()?;

    let events = spec
        .sinks
        .as_ref()
        .map(|sinks| open_append(&sinks.events, "opening the network event log"))
        .transpose()?;

    Ok(HostFiles {
        log,
        null,
        authority,
        events,
    })
}

/// Moves into new mount, network, IPC and UTS namespaces.
fn isolate(spec: &JailSpec) -> Result<(), LaunchError> {
    unshare(Namespaces::Isolation).map_err(step("unsharing mount, network, IPC and UTS"))?;

    // Nothing done below may propagate back to the host's mount namespace.
    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(step("making mounts private"))?;

    rustix::system::sethostname(spec.id.as_bytes()).map_err(step("setting the hostname"))
}

fn bind_device(root: &Path, device: &Path) -> Result<(), LaunchError> {
    let target = root.join(device.strip_prefix("/").unwrap_or(device));
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(step("creating /dev in the jail"))?;
    }

    bind(device, &target, MountFlags::NOSUID | MountFlags::NOEXEC)
}

/// Fills the jail root with bind mounts: Firecracker, the VM's files, the
/// device nodes and the fake internet.
fn mount_root(spec: &JailSpec) -> Result<(), LaunchError> {
    let root = &spec.root;

    // pivot_root needs the new root to be a mount point.
    rustix::mount::mount_bind(root, root).map_err(step("binding the jail root"))?;
    let hardened = MountFlags::NOSUID | MountFlags::NODEV;
    bind(
        &spec.firecracker,
        &root.join(FIRECRACKER_IN_JAIL.trim_start_matches('/')),
        MountFlags::RDONLY | hardened,
    )?;

    for mount in &spec.mounts {
        let flags = if mount.writable {
            hardened | MountFlags::NOEXEC
        } else {
            hardened | MountFlags::NOEXEC | MountFlags::RDONLY
        };

        bind(&mount.source, &root.join(&mount.target), flags)?;
    }

    for device in &spec.devices {
        bind_device(root, device)?;
    }

    if let Some(sinks) = &spec.sinks {
        bind(
            &sinks.binary,
            &root.join(FAKE_INTERNET_IN_JAIL.trim_start_matches('/')),
            MountFlags::RDONLY | hardened,
        )?;
    }

    Ok(())
}

/// Brings up the loopback and the tap device, and sends the guest's traffic
/// to the fake internet when there is one.
fn set_up_network(spec: &JailSpec) -> Result<(), LaunchError> {
    run_ip(&["link", "set", "lo", "up"])?;
    let Some(tap) = &spec.tap else {
        return Ok(());
    };

    let owner = INSIDE_VM_ID.to_string();
    run_ip(&[
        "tuntap", "add", "dev", tap, "mode", "tap", "user", &owner, "group", &owner,
    ])?;

    // A fixed host side MAC lets the fake internet skip frames the host
    // sent, and without an IPv6 link local address the host sends no IPv6
    // at all: every IPv6 frame on the tap is the guest's.
    let mac = crateward_fake_internet::capture::HOST_MAC
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    run_ip(&["link", "set", "dev", tap, "address", &mac])?;
    run_ip(&["link", "set", "dev", tap, "addrgenmode", "none"])?;
    run_ip(&["link", "set", tap, "up"])?;

    if spec.sinks.is_some() {
        let address = format!("{HOST_ADDRESS}/{PREFIX_LEN}");
        run_ip(&["addr", "add", &address, "dev", tap])?;
        run_nft(&ruleset(tap))?;
    }

    Ok(())
}

/// Swaps the root: the old one is stacked under the new one and then
/// detached, so no host path remains reachable.
fn pivot(root: &Path) -> Result<(), LaunchError> {
    std::env::set_current_dir(root).map_err(step("entering the jail root"))?;
    rustix::process::pivot_root(".", ".").map_err(step("pivot_root"))?;
    rustix::mount::unmount(".", UnmountFlags::DETACH).map_err(step("detaching the old root"))?;

    std::env::set_current_dir("/").map_err(step("entering the new root"))
}

fn set_limit(resource: Resource, value: u64) -> Result<(), LaunchError> {
    let limit = Rlimit {
        current: Some(value),
        maximum: Some(value),
    };

    rustix::process::setrlimit(resource, limit).map_err(step("setting a resource limit"))
}

/// Everything between the ID maps and `exec`.
fn build_jail(spec: &JailSpec) -> Result<(File, File), LaunchError> {
    let files = open_host_files(spec)?;
    isolate(spec)?;
    mount_root(spec)?;
    set_up_network(spec)?;
    pivot(&spec.root)?;
    set_limit(Resource::Nofile, spec.max_open_files)?;
    set_limit(Resource::Fsize, spec.max_file_size)?;

    if let Some(events) = files.events {
        start_sinks(events, &files.log, &files.null, files.authority)?;
    }

    Ok((files.log, files.null))
}

/// Starts the fake internet as the slot's user in the jail. It ends with
/// the slot: the orchestrator kills the slot's cgroup after every run.
fn start_sinks(
    events: File,
    log: &File,
    null: &File,
    authority: Option<Vec<u8>>,
) -> Result<(), LaunchError> {
    // Also covers the launcher itself from here on. Nothing it still
    // executes needs new privileges.
    rustix::thread::set_no_new_privs(true).map_err(step("setting no_new_privs"))?;
    let errors = log.try_clone().map_err(step("duplicating the log"))?;

    // The jail has no /dev/null to open. Reuse the one opened before. With
    // an authority, stdin is a pipe that carries it and is then closed.
    let stdin = match authority {
        Some(_) => std::process::Stdio::piped(),
        None => null
            .try_clone()
            .map_err(step("duplicating /dev/null"))?
            .into(),
    };

    // Started with the namespace's privileges so that it can open its
    // packet socket. It switches to the slot's user itself before it reads
    // anything from the guest.
    let mut child = Command::new(FAKE_INTERNET_IN_JAIL)
        .arg("slot")
        .arg(INSIDE_VM_ID.to_string())
        .env_clear()
        .stdin(stdin)
        .stdout(events)
        .stderr(errors)
        .spawn()
        .map_err(step("starting the fake internet"))?;
    if let (Some(pem), Some(mut pipe)) = (authority, child.stdin.take()) {
        pipe.write_all(&pem)
            .map_err(step("passing the TLS authority"))?;
    }

    Ok(())
}

/// Switches to the slot's UID. Moving every UID from 0 to a non zero value
/// clears the permitted and effective capability sets.
fn drop_privileges() -> Result<(), LaunchError> {
    let id = INSIDE_VM_ID;
    let gid = Gid::from_raw(id);
    rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(step("switching group"))?;
    let uid = Uid::from_raw(id);
    rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(step("switching user"))?;
    rustix::thread::set_no_new_privs(true).map_err(step("setting no_new_privs"))?;

    Ok(())
}

/// Runs the launcher. Returns only on failure.
pub fn run() -> LaunchError {
    let result = (|| -> Result<std::convert::Infallible, LaunchError> {
        let mut input = std::io::stdin().lock();
        let spec: JailSpec = serde_json::from_str(&read_line(&mut input, MAX_SPEC_BYTES)?)
            .map_err(step("parsing the jail specification"))?;

        spec.validate()
            .map_err(step("validating the jail specification"))?;

        if let Some(cgroup) = &spec.cgroup {
            std::fs::write(cgroup.join("cgroup.procs"), std::process::id().to_string())
                .map_err(step("joining the cgroup"))?;
        }

        unshare(Namespaces::User).map_err(step("unsharing the user namespace"))?;
        say("unshared")?;

        if read_line(&mut input, 16)? != "mapped" {
            return Err(LaunchError {
                step: "waiting for the ID maps",
                detail: "unexpected answer".into(),
            });
        }

        let (log, null) = build_jail(&spec)?;
        drop(input);

        // Sockets and snapshot files Firecracker creates must be usable by
        // the orchestrator. The jail root itself is closed to everybody else.
        rustix::process::umask(rustix::fs::Mode::empty());
        drop_privileges()?;
        say("exec")?;
        rustix::stdio::dup2_stdin(&null).map_err(step("redirecting stdin"))?;
        rustix::stdio::dup2_stdout(&log).map_err(step("redirecting stdout"))?;
        rustix::stdio::dup2_stderr(&log).map_err(step("redirecting stderr"))?;
        let api = PathBuf::from("/api.sock");
        let error = Command::new(FIRECRACKER_IN_JAIL)
            .arg("--api-sock")
            .arg(&api)
            .arg("--id")
            .arg(&spec.id)
            .env_clear()
            .exec();

        Err(LaunchError {
            step: "executing firecracker",
            detail: error.to_string(),
        })
    })();

    match result {
        Ok(never) => match never {},
        Err(error) => {
            // Before `exec` stdout is the control channel. After the
            // redirection this line lands in the log.
            let _ = say(&format!("error: {error}"));
            error
        }
    }
}
