//! The launcher side of the jail: runs in `crateward-vmjail`, single
//! threaded, and ends by executing Firecracker.
//!
//! Control protocol with the orchestrator, one line each over stdin and
//! stdout: the orchestrator sends the [`JailSpec`] as JSON; the launcher
//! answers `unshared` once it is in its new user namespace; the orchestrator
//! writes the ID maps and answers `mapped`; the launcher answers `exec` right
//! before it replaces itself with Firecracker, or `error: <reason>` if a
//! step fails. From then on Firecracker's stdout and stderr go to the log.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::fs::{Gid, Uid};
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::process::{Resource, Rlimit};

use super::{FAKE_INTERNET_IN_JAIL, FIRECRACKER_IN_JAIL, INSIDE_VM_ID, JailSpec, MAX_SPEC_BYTES};
use crate::firecracker::vm::{HOST_ADDRESS, PREFIX_LEN};
use crateward_core::sandbox::{Namespaces, unshare};

/// `ip` on the host, used to create the tap device before `pivot_root`.
const IP: &str = "/usr/sbin/ip";

/// `nft` on the host, used to redirect guest traffic to the fake internet.
const NFT: &str = "/usr/sbin/nft";

/// Redirects everything the guest sends to the fake internet's ports
/// (`crateward_fake_internet::server::SlotConfig::default`). The namespace
/// has no other interface and no route, so nothing leaves it anyway; the
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
    let mut limited = std::io::Read::take(&mut *input, u64::try_from(limit).unwrap_or(u64::MAX));
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

/// Everything between the ID maps and `exec`.
fn build_jail(spec: &JailSpec) -> Result<(File, File), LaunchError> {
    // Opened while host paths are still visible.
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&spec.log)
        .map_err(step("opening the log"))?;
    let null = File::open("/dev/null").map_err(step("opening /dev/null"))?;
    let authority = spec
        .sinks
        .as_ref()
        .and_then(|sinks| sinks.authority.as_ref())
        .map(|path| {
            let mut pem = Vec::new();
            File::open(path)
                .and_then(|f| {
                    std::io::Read::read_to_end(&mut std::io::Read::take(f, 64 * 1024), &mut pem)
                })
                .map(|_| pem)
                .map_err(step("reading the TLS authority"))
        })
        .transpose()?;
    let events = spec
        .sinks
        .as_ref()
        .map(|sinks| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&sinks.events)
                .map_err(step("opening the network event log"))
        })
        .transpose()?;

    unshare(Namespaces::Isolation).map_err(step("unsharing mount, network, IPC and UTS"))?;
    // Nothing done below may propagate back to the host's mount namespace.
    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(step("making mounts private"))?;
    rustix::system::sethostname(spec.id.as_bytes()).map_err(step("setting the hostname"))?;

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
        let relative = device.strip_prefix("/").unwrap_or(device);
        let target = root.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(step("creating /dev in the jail"))?;
        }
        bind(device, &target, MountFlags::NOSUID | MountFlags::NOEXEC)?;
    }
    if let Some(sinks) = &spec.sinks {
        bind(
            &sinks.binary,
            &root.join(FAKE_INTERNET_IN_JAIL.trim_start_matches('/')),
            MountFlags::RDONLY | hardened,
        )?;
    }

    run_ip(&["link", "set", "lo", "up"])?;
    if let Some(tap) = &spec.tap {
        let owner = INSIDE_VM_ID.to_string();
        run_ip(&[
            "tuntap", "add", "dev", tap, "mode", "tap", "user", &owner, "group", &owner,
        ])?;
        run_ip(&["link", "set", tap, "up"])?;
        if spec.sinks.is_some() {
            run_ip(&[
                "addr",
                "add",
                &format!("{HOST_ADDRESS}/{PREFIX_LEN}"),
                "dev",
                tap,
            ])?;
            run_nft(&ruleset(tap))?;
        }
    }

    // Swap the root: the old one is stacked under the new one and then
    // detached, so no host path remains reachable.
    std::env::set_current_dir(root).map_err(step("entering the jail root"))?;
    rustix::process::pivot_root(".", ".").map_err(step("pivot_root"))?;
    rustix::mount::unmount(".", UnmountFlags::DETACH).map_err(step("detaching the old root"))?;
    std::env::set_current_dir("/").map_err(step("entering the new root"))?;

    let limit = |resource, value| {
        rustix::process::setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(step("setting a resource limit"))
    };
    limit(Resource::Nofile, spec.max_open_files)?;
    limit(Resource::Fsize, spec.max_file_size)?;
    if let Some(events) = events {
        start_sinks(events, &log, &null, authority)?;
    }
    Ok((log, null))
}

/// Starts the fake internet as the slot's user in the jail. It ends with
/// the slot: the orchestrator kills the slot's cgroup after every run.
fn start_sinks(
    events: File,
    log: &File,
    null: &File,
    authority: Option<Vec<u8>>,
) -> Result<(), LaunchError> {
    // Also covers the launcher itself from here on; nothing it still
    // executes needs new privileges.
    rustix::thread::set_no_new_privs(true).map_err(step("setting no_new_privs"))?;
    let errors = log.try_clone().map_err(step("duplicating the log"))?;
    // The jail has no /dev/null to open; reuse the one opened before. With
    // an authority, stdin is a pipe that carries it and is then closed.
    let stdin = match authority {
        Some(_) => std::process::Stdio::piped(),
        None => null
            .try_clone()
            .map_err(step("duplicating /dev/null"))?
            .into(),
    };
    let mut child = Command::new(FAKE_INTERNET_IN_JAIL)
        .arg("slot")
        .env_clear()
        .uid(INSIDE_VM_ID)
        .gid(INSIDE_VM_ID)
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
        // the orchestrator; the jail root itself is closed to everybody else.
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
            // Before `exec` stdout is the control channel; after the
            // redirection this line lands in the log.
            let _ = say(&format!("error: {error}"));
            error
        }
    }
}
