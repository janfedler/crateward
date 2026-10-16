//! The launcher side of the jail: runs in `crateward-vmjail`, single
//! threaded, in the two stages the [module documentation](super) describes.
//! The second stage ends by executing Firecracker.
//!
//! Control protocol with the orchestrator, one line each over stdin and
//! stdout: the orchestrator sends the [`JailSpec`] as JSON. The launcher
//! answers `unshared` once it is in its new user namespace. The orchestrator
//! writes the ID maps and answers `mapped`. The second stage, which shares
//! stdout with the first, answers `exec` right before it replaces itself
//! with Firecracker. Either stage answers `error: <reason>` if one of its
//! steps fails. From then on Firecracker's stdout and stderr go to the log.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitCode, ExitStatus, Stdio};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{Gid, OFlags, Uid};
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::process::{Resource, Rlimit, Signal};

use super::{FAKE_INTERNET_IN_JAIL, FIRECRACKER_IN_JAIL, INSIDE_VM_ID, JailSpec, MAX_SPEC_BYTES};
use crate::firecracker::vm::PREFIX_LEN;
use crateward_core::paths::host::{IP, NFT};
use crateward_core::report::network::HOST_ADDRESS;
use crateward_core::sandbox::{Namespaces, unshare};

/// The argument that starts the launcher's second stage.
pub const SECOND_STAGE: &str = "--second-stage";

/// The launcher's own binary, for the second stage. The magic link executes
/// the same file even if it was replaced on disk since.
const OWN_BINARY: &str = "/proc/self/exe";

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
        .stdin(Stdio::piped())
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

/// Reads one line of at most `limit` bytes from the orchestrator on stdin:
/// the jail specification, then `mapped`. The second stage reads the
/// specification as the first stage relays it.
fn read_from_orchestrator<R: BufRead>(input: &mut R, limit: u64) -> Result<String, LaunchError> {
    let mut line = String::new();
    let mut limited = input.by_ref().take(limit);

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

/// Sends one line to the orchestrator on stdout, the control channel until
/// `exec`: `unshared`, `exec` or an error.
fn tell_orchestrator(line: &str) -> Result<(), LaunchError> {
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

    // pivot_root needs the new root to be a mount point. Firecracker writes
    // its sockets and snapshots there, so it stays writable, but nothing on
    // it may be executed, be a device or gain privileges. The bind mounts
    // below carry their own flags.
    rustix::mount::mount_bind(root, root).map_err(step("binding the jail root"))?;
    let hardened = MountFlags::NOSUID | MountFlags::NODEV;
    rustix::mount::mount_remount(root, MountFlags::BIND | hardened | MountFlags::NOEXEC, "")
        .map_err(step("restricting the jail root"))?;

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

/// Fails if a descriptor besides stdin, stdout and stderr would survive
/// `exec`. The fake internet and Firecracker must inherit nothing else,
/// whatever the orchestrator or a library left open. Rust opens every
/// descriptor with close on exec, so this only fails on a bug.
fn check_close_on_exec() -> Result<(), LaunchError> {
    match inherited()?.first() {
        Some(fd) => Err(LaunchError {
            step: "checking inherited descriptors",
            detail: format!("descriptor {fd} is not close on exec"),
        }),
        None => Ok(()),
    }
}

/// The descriptors besides stdin, stdout and stderr that would survive
/// `exec`, in ascending order.
fn inherited() -> Result<Vec<u32>, LaunchError> {
    let fail = |detail: String| LaunchError {
        step: "checking inherited descriptors",
        detail,
    };

    let mut inherited = Vec::new();
    let entries = std::fs::read_dir("/proc/self/fdinfo").map_err(step("listing descriptors"))?;
    for entry in entries {
        let entry = entry.map_err(step("listing descriptors"))?;
        let name = entry.file_name();
        let fd: u32 = name
            .to_str()
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| fail(format!("unexpected entry {name:?}")))?;

        if fd <= 2 {
            continue;
        }

        let info = match std::fs::read_to_string(entry.path()) {
            Ok(info) => info,
            // The listing's own descriptor, closed by now.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(step("reading a descriptor's flags")(e)),
        };

        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|octal| u32::from_str_radix(octal.trim(), 8).ok())
            .ok_or_else(|| fail(format!("no flags for descriptor {fd}")))?;

        if flags & OFlags::CLOEXEC.bits() == 0 {
            inherited.push(fd);
        }
    }

    inherited.sort_unstable();

    Ok(inherited)
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

/// Everything in the second stage before it drops privileges: step 4 and
/// the limits of step 5 in the [module documentation](super), which ADR 0002 explains.
/// Each step needs the one before it.
fn build_jail(spec: &JailSpec) -> Result<(File, File), LaunchError> {
    // The jail has no log, `/dev/null` or TLS authority of its own. They are
    // opened while host paths are still visible and kept as descriptors.
    let files = open_host_files(spec)?;

    // New mount, network, IPC and UTS namespaces, so that none of the steps
    // below changes anything on the host.
    isolate(spec)?;

    // Bind mounts what the VM needs into the jail root. This needs the
    // private mount namespace and the host paths, so it comes in between.
    mount_root(spec)?;

    // Creates the tap device and its nftables rules in the new network
    // namespace. Runs the host's `ip` and `nft`, which the jail lacks.
    set_up_network(spec)?;

    // Reads `/proc`, so it comes before the root switch. Nothing after it
    // opens a descriptor without close on exec.
    check_close_on_exec()?;

    // Makes the jail root `/` and detaches the host's root. From here on
    // no host path is reachable.
    pivot(&spec.root)?;

    // Inherited by the fake internet and by Firecracker, so they are set
    // before either of them starts.
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
        Some(_) => Stdio::piped(),
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

/// Reads and checks the jail specification, one JSON line.
fn parse_spec(line: &str) -> Result<JailSpec, LaunchError> {
    let spec: JailSpec =
        serde_json::from_str(line).map_err(step("parsing the jail specification"))?;

    spec.validate()
        .map_err(step("validating the jail specification"))?;

    Ok(spec)
}

/// Tells the orchestrator why the launcher failed, and returns the error.
fn report(error: LaunchError) -> LaunchError {
    // Before `exec` stdout is the control channel. After the redirection
    // this line lands in the log.
    let _ = tell_orchestrator(&format!("error: {error}"));

    error
}

/// Steps 1 to 3 of the [module documentation](super): everything up to
/// the second stage, PID 1 of a new PID namespace. Returns the second stage and the
/// pipe it reads the jail specification from.
fn start_second_stage() -> Result<(Child, ChildStdin), LaunchError> {
    let mut input = std::io::stdin().lock();
    let line = read_from_orchestrator(&mut input, MAX_SPEC_BYTES)?;
    let spec = parse_spec(&line)?;

    if let Some(cgroup) = &spec.cgroup {
        std::fs::write(cgroup.join("cgroup.procs"), std::process::id().to_string())
            .map_err(step("joining the cgroup"))?;
    }

    unshare(Namespaces::User).map_err(step("unsharing the user namespace"))?;
    tell_orchestrator("unshared")?;

    if read_from_orchestrator(&mut input, 16)? != "mapped" {
        return Err(LaunchError {
            step: "waiting for the ID maps",
            detail: "unexpected answer".into(),
        });
    }

    // The next process this one starts is PID 1 of the new namespace.
    unshare(Namespaces::Pid).map_err(step("unsharing the PID namespace"))?;
    let mut jail = Command::new(OWN_BINARY)
        .arg(SECOND_STAGE)
        .env_clear()
        .stdin(Stdio::piped())
        .spawn()
        .map_err(step("starting the second stage"))?;

    let mut pipe = jail.stdin.take().ok_or_else(|| LaunchError {
        step: "starting the second stage",
        detail: "no stdin".into(),
    })?;

    writeln!(pipe, "{line}").map_err(step("passing the jail specification"))?;

    Ok((jail, pipe))
}

/// Runs the launcher's first stage: everything up to the ID maps, then the
/// second stage, which builds the jail and becomes Firecracker. This stage
/// stays outside the jail's PID namespace as the orchestrator's handle on
/// it, without privileges, and returns Firecracker's exit.
///
/// # Errors
///
/// Fails if a step fails. The orchestrator has then been told why, and the
/// second stage, if it started, is killed.
pub fn run() -> Result<ExitStatus, LaunchError> {
    let (mut jail, pipe) = start_second_stage().map_err(report)?;

    // From here on the second stage talks to the orchestrator.
    if let Err(error) = drop_privileges() {
        let _ = jail.kill();
        let _ = jail.wait();
        return Err(report(error));
    }

    let status = jail.wait().map_err(step("waiting for firecracker"));

    // Open until here, so the second stage can tell whether this stage
    // still runs.
    drop(pipe);

    status
}

/// Ends this process the way Firecracker ended, with its exit code or by
/// its signal, so the orchestrator classifies the exit as if it had
/// started Firecracker itself.
#[must_use]
pub fn exit_like(status: ExitStatus) -> ExitCode {
    let signal = status.signal();
    if let Some(signal) = signal.and_then(Signal::from_named_raw) {
        let _ = rustix::process::kill_process(rustix::process::getpid(), signal);
    }

    // Reached for an exit code, or a signal that does not end this process.
    status
        .code()
        .or(signal.map(|s| 128 + s))
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from)
}

/// Fails if the first stage has ended. Its end of stdin is then closed.
/// After this check the parent death signal covers the rest.
fn check_first_stage() -> Result<(), LaunchError> {
    let stdin = std::io::stdin();
    let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
    rustix::event::poll(&mut fds, Some(&Timespec::default()))
        .map_err(step("checking the first stage"))?;

    // The first stage never writes after the specification, so any event
    // means its end closed.
    let [fd] = &fds;

    if fd.revents().is_empty() {
        Ok(())
    } else {
        Err(LaunchError {
            step: "checking the first stage",
            detail: "it has ended".into(),
        })
    }
}

/// Runs the launcher's second stage, PID 1 of the jail's PID namespace:
/// steps 4 and 5 of the [module documentation](super), then `exec` of
/// Firecracker, which stays PID 1. Returns only on failure.
pub fn run_second_stage() -> LaunchError {
    let result = (|| -> Result<std::convert::Infallible, LaunchError> {
        // The first stage relays the orchestrator's specification.
        let spec = parse_spec(&read_from_orchestrator(
            &mut std::io::stdin().lock(),
            MAX_SPEC_BYTES,
        )?)?;

        let (log, null) = build_jail(&spec)?;

        // Sockets and snapshot files Firecracker creates must be usable by
        // the orchestrator. The jail root itself is closed to everybody else.
        rustix::process::umask(rustix::fs::Mode::empty());
        drop_privileges()?;

        // Kills the jail with the first stage, the process the orchestrator
        // kills. Set after the switch of user, which clears it, and checked
        // once, for a first stage that ended before.
        rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
            .map_err(step("setting the parent death signal"))?;
        check_first_stage()?;

        tell_orchestrator("exec")?;
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
        Err(error) => report(error),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    fn a_descriptor_without_close_on_exec_is_found() {
        // The test runner or a test running in parallel may hold such
        // descriptors already, so only this one is checked.
        let file = File::open("/dev/null").unwrap();
        let fd = u32::try_from(file.as_raw_fd()).unwrap();

        assert!(!inherited().unwrap().contains(&fd));

        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty()).unwrap();

        assert!(inherited().unwrap().contains(&fd));
        let error = check_close_on_exec().unwrap_err();

        assert!(
            error.to_string().contains("is not close on exec"),
            "{error}"
        );
    }
}
