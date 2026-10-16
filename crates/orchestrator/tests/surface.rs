//! What a jailed Firecracker and its guest can see, compared with what they
//! should see. Each test boots a VM the way production builds a job slot:
//! the jail with its own cgroup, the fake internet with its TLS authority,
//! the network and the job drives (placeholders here, as in the base
//! snapshot). Every list below is exhaustive, so anything that appears in
//! addition fails the test.
//!
//! The host side is read from `/proc`. Firecracker is not dumpable after
//! its switch of user, so its descriptors, environment and namespaces are
//! read with `nsenter` in the jail's user namespace, which the test's user
//! owns. In the guest only the agent and standard programs of the guest
//! image run, no crate.
//!
//! Needs `/dev/kvm`, the guest images, subordinate IDs, the static fake
//! internet and a delegated cgroup, so it runs on the server through
//! `cargo xtask surface`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use crateward_core::paths::{build, guest, host};
use crateward_core::protocol::{JobSpec, WallClock};
use crateward_core::report::network::{GUEST_ADDRESS, HOST_ADDRESS};
use crateward_orchestrator::backend::{FirecrackerBackend, FirecrackerConfig};
use crateward_orchestrator::cgroup::{CgroupTree, SlotCgroup, SlotLimits};
use crateward_orchestrator::firecracker::agent::AgentConnection;
use crateward_orchestrator::firecracker::vm::{BootSpec, GUEST_HOSTNAME, TAP, Vm};
use tokio::time::Instant;

use common::{kernel, root};

/// Subordinate IDs of these tests, apart from the other microVM tests.
const UID_BASE: u32 = 160_040;

/// The files in a jail root: the bind mount points, the sockets Firecracker
/// creates and the decoy.
const JAIL_ROOT: [&str; 11] = [
    "api.sock",
    "dev",
    "fake-internet",
    "firecracker",
    "host-credentials",
    "kernel",
    "payload.img",
    "rootfs.erofs",
    "scratch.img",
    "vsock.sock",
    "warm.img",
];

/// The drives in the jail, which Firecracker keeps open.
const DRIVES: [&str; 4] = ["/payload.img", "/rootfs.erofs", "/scratch.img", "/warm.img"];

/// Both tests share the delegated cgroup tree, which is taken over once.
fn cgroups() -> &'static CgroupTree {
    static TREE: OnceLock<CgroupTree> = OnceLock::new();

    TREE.get_or_init(|| {
        CgroupTree::own().expect("run through `cargo xtask surface` for a delegated cgroup")
    })
}

/// One running job slot.
struct Slot {
    number: u32,
    work: PathBuf,
    config: FirecrackerConfig,
    boot: BootSpec,
    cgroup: SlotCgroup,
    vm: Vm,
    agent: AgentConnection,
    /// The launcher's first stage.
    launcher: u32,
    /// Firecracker's host PID.
    firecracker: u32,
}

impl Slot {
    async fn start(number: u32) -> Self {
        let work = root()
            .join("target/surface")
            .join(format!("{}-{number}", std::process::id()));

        let _ = std::fs::remove_dir_all(&work);
        let slots_dir = work.join("slots");
        std::fs::create_dir_all(&slots_dir).unwrap();
        let config = FirecrackerConfig {
            firecracker: root().join(build::FIRECRACKER),
            launcher: PathBuf::from(env!("CARGO_BIN_EXE_crateward-vmjail")),
            slots_dir,
            slots: 2,
            uid_base: UID_BASE,
            gid_base: UID_BASE,
            limits: SlotLimits {
                cpus: 1,
                memory_mib: 1024 + 256,
                pids: 64,
            },
            max_file_size: 3 << 30,
            fake_internet: Some(root().join(build::FAKE_INTERNET)),
            authority: Some(root().join(build::AUTHORITY)),
        };

        let boot = BootSpec {
            kernel: kernel(),
            rootfs: root().join(build::ROOTFS_IMAGE),
            boot_args: format!(
                "{} {}",
                BootSpec::default_boot_args(guest::AGENT),
                BootSpec::network_boot_args()
            ),
            vcpus: 1,
            memory_mib: 1024,
            drives: Some(FirecrackerBackend::placeholders(&config, &work).unwrap()),
            network: true,
        };

        let cgroup = cgroups()
            .create_slot(&number.to_string(), config.limits)
            .unwrap();

        let launch = FirecrackerBackend::launch(
            &config,
            number,
            Some(cgroup.path().to_path_buf()),
            Some(work.join("network.log")),
        );

        let vm = Vm::boot(&launch, &boot).await.unwrap();
        let agent = vm
            .agent(Instant::now() + Duration::from_secs(20))
            .await
            .unwrap();

        let launcher = vm.pid().unwrap();
        let firecracker = only_child(launcher);

        Self {
            number,
            work,
            config,
            boot,
            cgroup,
            vm,
            agent,
            launcher,
            firecracker,
        }
    }

    /// The slot's subordinate UID and GID.
    fn uid(&self) -> String {
        (self.config.uid_base + self.number).to_string()
    }

    /// Runs `script` in the guest and returns its standard output.
    async fn guest(&mut self, script: &str) -> String {
        let spec = JobSpec {
            job_id: 1,
            wall_clock: WallClock::now(),
            argv: vec!["/bin/sh".into(), "-c".into(), script.into()],
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            cwd: "/tmp".into(),
            timeout_secs: 30,
            output_limit: 64 * 1024,
        };

        let outcome = self.agent.run(spec).await.unwrap();

        String::from_utf8(outcome.stdout).unwrap()
    }

    async fn stop(self) {
        drop(self.agent);
        self.cgroup.kill_and_wait().unwrap();
        let mut vm = self.vm;
        vm.kill().await.unwrap();
        vm.remove().await.unwrap();
        self.cgroup.remove().unwrap();
        std::fs::remove_dir_all(&self.work).unwrap();
    }
}

/// The only child of `pid`.
fn only_child(pid: u32) -> u32 {
    let list = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap();
    let pids: Vec<u32> = list
        .split_whitespace()
        .map(|p| p.parse().unwrap())
        .collect();

    assert_eq!(pids.len(), 1, "{pid} has children {list:?}");

    pids[0]
}

/// Runs a host command and returns its standard output.
fn run(program: &str, args: &[&str]) -> String {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).unwrap()
}

/// Runs a host command in the user namespace of the jail around `pid`, and
/// with `net` in its network namespace too.
fn in_jail(pid: u32, net: bool, command: &[&str]) -> String {
    let target = pid.to_string();
    let mut args = vec!["-t", &target, "-U", "--preserve-credentials"];
    if net {
        args.push("-n");
    }

    args.extend(command);

    run("nsenter", &args)
}

/// A field of `/proc/<pid>/status`, with single spaces.
fn status(pid: u32, field: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{field}:")))
        .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

fn set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.into_iter().map(str::to_owned).collect()
}

/// UID, groups, capabilities, `no_new_privs`, seccomp and the PID inside.
fn check_credentials(slot: &Slot) {
    let uid = slot.uid();
    let fc = slot.firecracker;

    for pid in [slot.launcher, fc] {
        assert_eq!(status(pid, "Uid"), format!("{uid} {uid} {uid} {uid}"));
        assert_eq!(status(pid, "Gid"), format!("{uid} {uid} {uid} {uid}"));
        assert_eq!(status(pid, "NoNewPrivs"), "1");

        for caps in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            assert_eq!(status(pid, caps), "0000000000000000", "{pid} {caps}");
        }
    }

    // The launcher keeps the orchestrator's groups, so `kvm` opens
    // `/dev/kvm`. In production `kvm` is the only one (OPERATIONS.md).
    let own = status(std::process::id(), "Groups");
    let kvm = run("getent", &["group", "kvm"]);
    let kvm = kvm.split(':').nth(2).unwrap();

    assert_eq!(status(fc, "Groups"), own);
    assert!(own.split(' ').any(|g| g == kvm), "kvm is not among {own}");
    assert_eq!(status(fc, "Seccomp"), "2");
    assert_eq!(status(fc, "NSpid"), format!("{fc} 1"));
}

/// Exactly the expected bind mounts, each with the expected flags.
fn check_mounts(slot: &Slot) {
    let mountinfo = std::fs::read_to_string(format!("/proc/{}/mountinfo", slot.firecracker));
    let mounts: BTreeMap<String, BTreeSet<String>> = mountinfo
        .unwrap()
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let flags = fields[5]
                .split(',')
                .filter(|f| *f != "relatime")
                .map(str::to_owned)
                .collect();

            (fields[4].to_owned(), flags)
        })
        .collect();

    let file = set(["ro", "nosuid", "nodev", "noexec"]);
    let program = set(["ro", "nosuid", "nodev"]);
    let device = set(["rw", "nosuid", "noexec"]);
    let expected = BTreeMap::from([
        ("/".to_owned(), set(["rw"])),
        ("/firecracker".to_owned(), program.clone()),
        ("/fake-internet".to_owned(), program),
        ("/kernel".to_owned(), file.clone()),
        ("/rootfs.erofs".to_owned(), file.clone()),
        ("/payload.img".to_owned(), file.clone()),
        ("/warm.img".to_owned(), file),
        (
            "/scratch.img".to_owned(),
            set(["rw", "nosuid", "nodev", "noexec"]),
        ),
        ("/dev/kvm".to_owned(), device.clone()),
        ("/dev/net/tun".to_owned(), device),
    ]);

    assert_eq!(mounts, expected);
}

/// Only Firecracker's own descriptors, the drives, the devices, the log and
/// `/dev/null`: no other host file and no pipe. An empty environment.
fn check_descriptors(slot: &Slot) {
    let fc = slot.firecracker;
    let log = slot.vm.dir().join("firecracker.log");
    let log = log.to_str().unwrap();
    let script = format!("for f in /proc/{fc}/fd/*; do readlink $f; done");
    let targets = in_jail(fc, false, &["sh", "-c", &script]);

    for target in targets.lines() {
        let allowed = target.starts_with("anon_inode:")
            || target.starts_with("socket:")
            || ["/dev/null", "/dev/kvm", "/dev/net/tun", log].contains(&target)
            || DRIVES.contains(&target);

        assert!(allowed, "firecracker holds {target}");
    }

    for needed in ["/dev/kvm", "/dev/net/tun", "/dev/null", log] {
        assert!(targets.lines().any(|t| t == needed), "{needed} not open");
    }

    let environ = in_jail(fc, false, &["cat", &format!("/proc/{fc}/environ")]);

    assert_eq!(environ, "", "firecracker has an environment");
}

/// Limits, namespaces and the cgroup.
fn check_limits_and_namespaces(slot: &Slot) {
    let fc = slot.firecracker;
    let limits = std::fs::read_to_string(format!("/proc/{fc}/limits")).unwrap();
    let limit = |name: &str| {
        let line = limits.lines().find(|l| l.starts_with(name)).unwrap();

        line[name.len()..]
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    };

    let size = slot.config.max_file_size.to_string();

    assert_eq!(limit("Max open files"), "2048 2048");
    assert_eq!(limit("Max file size"), format!("{size} {size}"));

    let script = "for n in mnt net ipc uts pid user cgroup time; do readlink /proc/PID/ns/$n; done";
    let jail = in_jail(
        fc,
        false,
        &["sh", "-c", &script.replace("PID", &fc.to_string())],
    );

    let own = run("sh", &["-c", &script.replace("PID", "self")]);

    // The cgroup and time namespaces are the host's, as with the jailer.
    // The jail has no `/proc` to read them through.
    for (jail, own) in jail.lines().zip(own.lines()) {
        let shared = own.starts_with("cgroup:") || own.starts_with("time:");

        assert_eq!(jail == own, shared, "{jail} against the host's {own}");
    }

    let cgroup = slot.cgroup.path().strip_prefix(host::CGROUPS).unwrap();
    for pid in [slot.launcher, fc, only_child(fc)] {
        let line = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();

        assert_eq!(line.trim(), format!("0::/{}", cgroup.display()));
    }
}

/// The fake internet is the only other process in the jail, as the slot's
/// user without capabilities.
fn check_fake_internet(slot: &Slot) {
    let sinks = only_child(slot.firecracker);
    let uid = slot.uid();
    let cmdline = std::fs::read_to_string(format!("/proc/{sinks}/cmdline")).unwrap();

    assert_eq!(
        cmdline.split('\0').collect::<Vec<_>>(),
        ["/fake-internet", "slot", "1", ""]
    );
    assert_eq!(status(sinks, "Uid"), format!("{uid} {uid} {uid} {uid}"));
    assert_eq!(status(sinks, "CapEff"), "0000000000000000");
    assert_eq!(status(sinks, "NoNewPrivs"), "1");
}

/// The jail's network namespace: loopback and the tap device, one route to
/// the guest, and the redirect to the fake internet.
fn check_jail_network(slot: &Slot) {
    let fc = slot.firecracker;
    let proc = |file: &str| std::fs::read_to_string(format!("/proc/{fc}/net/{file}")).unwrap();
    let links: BTreeSet<String> = proc("dev")
        .lines()
        .skip(2)
        .map(|l| l.split(':').next().unwrap().trim().to_owned())
        .collect();

    assert_eq!(links, set(["lo", TAP]));

    let routes: Vec<String> = proc("route")
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .collect();

    assert_eq!(routes, [format!("{TAP} 0002000A 00000000")]);
    assert!(proc("if_inet6").lines().all(|l| l.ends_with(" lo")));

    let addresses = in_jail(fc, true, &[host::IP, "-br", "addr"]);

    assert!(
        addresses.contains(&format!("{HOST_ADDRESS}/30")),
        "{addresses}"
    );

    let rules = in_jail(fc, true, &[host::NFT, "list", "ruleset"]);
    let rules: Vec<&str> = rules.lines().map(str::trim).collect();

    assert_eq!(rules.iter().filter(|l| l.starts_with("table")).count(), 1);
    assert_eq!(rules.iter().filter(|l| l.contains("redirect")).count(), 3);

    for redirect in [
        format!("iifname \"{TAP}\" udp dport 53 redirect to :5353"),
        format!("iifname \"{TAP}\" tcp dport 0-65535 redirect to :8080"),
        format!("iifname \"{TAP}\" udp dport 0-65535 redirect to :5354"),
    ] {
        assert!(rules.contains(&redirect.as_str()), "{redirect} missing");
    }
}

/// The jail root holds exactly the expected files, and only the slot's UID
/// may enter it.
fn check_jail_root(slot: &Slot) {
    let root = slot.vm.jail_root().unwrap();
    let entries: BTreeSet<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();

    assert_eq!(entries, set(JAIL_ROOT));

    let acl = run(
        "getfacl",
        &["--omit-header", "--numeric", root.to_str().unwrap()],
    );

    let acl: Vec<&str> = acl.lines().filter(|l| !l.is_empty()).collect();
    let uid = format!("user:{}:rwx", slot.uid());

    assert_eq!(
        acl,
        ["user::rwx", &uid, "group::---", "mask::rwx", "other::---"]
    );
}

#[tokio::test]
#[ignore = "run through `cargo xtask surface`"]
async fn jailed_firecracker_sees_only_what_it_needs() {
    let slot = Slot::start(0).await;

    check_credentials(&slot);
    check_mounts(&slot);
    check_descriptors(&slot);
    check_limits_and_namespaces(&slot);
    check_fake_internet(&slot);
    check_jail_network(&slot);
    check_jail_root(&slot);

    slot.stop().await;
}

/// Who the job runs as and what it is given: its own environment, the boot
/// arguments and the hostname, and nothing that names the host.
async fn check_identity(slot: &mut Slot) {
    let id = slot.guest("id").await;

    assert_eq!(
        id.trim(),
        "uid=1000(builder) gid=1000(builder) groups=1000(builder)"
    );

    let env: BTreeSet<String> = slot.guest("env").await.lines().map(str::to_owned).collect();

    assert_eq!(env, set(["PATH=/usr/bin:/bin", "PWD=/tmp"]));
    assert_eq!(slot.guest("hostname").await.trim(), GUEST_HOSTNAME);

    // Firecracker appends its own arguments: the root and the devices.
    let cmdline = slot.guest("cat /proc/cmdline").await;
    let appended = cmdline.trim().strip_prefix(&slot.boot.boot_args).unwrap();
    for arg in appended.split_whitespace() {
        let known = matches!(arg, "pci=off" | "root=/dev/vda" | "ro")
            || arg.starts_with("virtio_mmio.device=");

        assert!(known, "unexpected boot argument {arg}");
    }

    // Facts unique to this host: its machine and boot IDs and the
    // workspace path.
    let read = |path: &str| std::fs::read_to_string(path).unwrap().trim().to_owned();
    let host_facts = [
        read("/etc/machine-id"),
        read("/proc/sys/kernel/random/boot_id"),
        root().display().to_string(),
    ];

    let seen = slot
        .guest("cat /proc/cmdline /proc/mounts /etc/hosts; env; hostname")
        .await;

    for fact in &host_facts {
        assert!(!seen.contains(fact.as_str()), "the guest sees {fact}");
    }
}

/// Four block devices, the network and vsock, nothing on a PCI bus.
async fn check_devices(slot: &mut Slot) {
    let virtio = slot
        .guest("for d in /sys/bus/virtio/devices/*; do cat $d/device; done")
        .await;

    let mut ids: Vec<&str> = virtio.lines().collect();
    ids.sort_unstable();

    // Network, four drives, vsock.
    assert_eq!(
        ids,
        ["0x0001", "0x0002", "0x0002", "0x0002", "0x0002", "0x0013"]
    );

    // Root, payload and warm cache read only, scratch writable.
    let drives = slot
        .guest("for b in /sys/block/vd*; do echo ${b##*/} $(cat $b/ro); done")
        .await;

    assert_eq!(
        drives.lines().collect::<Vec<_>>(),
        ["vda 1", "vdb 1", "vdc 0", "vdd 1"]
    );

    let pci = slot
        .guest("ls /sys/bus/pci/devices 2>/dev/null | wc -l")
        .await;

    assert_eq!(pci.trim(), "0");
}

/// Before the agent prepares a workspace: the read only root and the
/// kernel's own filesystems.
async fn check_guest_mounts(slot: &mut Slot) {
    let mounts: BTreeSet<String> = slot
        .guest("cat /proc/mounts")
        .await
        .lines()
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            let mode = f[3].split(',').next().unwrap();

            format!("{} {} {mode}", f[1], f[2])
        })
        .collect();

    assert_eq!(
        mounts,
        set([
            "/ erofs ro",
            "/dev devtmpfs rw",
            "/proc proc rw",
            "/sys sysfs rw",
            "/tmp tmpfs rw",
            "/run tmpfs rw",
        ])
    );
}

/// An address as `/proc/net/route` prints it.
fn route_hex(address: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_le_bytes(address.octets()))
}

/// `eth0` with a route to the host side of the tap device only, no IPv6,
/// and the host side as the resolver.
async fn check_guest_network(slot: &mut Slot) {
    let links: BTreeSet<String> = slot
        .guest("ls /sys/class/net")
        .await
        .lines()
        .map(str::to_owned)
        .collect();

    assert_eq!(links, set(["eth0", "lo"]));

    let gateway: Ipv4Addr = HOST_ADDRESS.parse().unwrap();
    let [a, b, c, d] = GUEST_ADDRESS.parse::<Ipv4Addr>().unwrap().octets();
    let network = Ipv4Addr::new(a, b, c, d & 0xfc);
    let routes = slot.guest("cat /proc/net/route").await;
    let routes: Vec<String> = routes
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .collect();

    assert_eq!(
        routes,
        [
            format!("eth0 00000000 {}", route_hex(gateway)),
            format!("eth0 {} 00000000", route_hex(network)),
        ]
    );

    let ipv6 = slot.guest("cat /proc/net/ipv6_route").await;

    assert!(ipv6.lines().all(|l| l.ends_with(" lo")), "{ipv6}");

    let resolvers = slot.guest("grep ^nameserver /etc/resolv.conf").await;

    assert_eq!(resolvers.trim(), format!("nameserver {HOST_ADDRESS}"));
}

/// Name lookups, HTTP and the metadata address all reach the fake internet,
/// which records them. IPv6 reaches nothing.
async fn check_egress(slot: &mut Slot) {
    let ipv6 = slot
        .guest(
            "curl -s -m 5 -o /dev/null http://crateward-surface.example/ \
             http://169.254.169.254/latest/meta-data/; \
             curl -6 -s -m 5 -o /dev/null http://[2001:db8::1]/; echo $?",
        )
        .await;

    assert_ne!(ipv6.trim(), "0", "an IPv6 request got an answer");

    let log = slot.work.join("network.log");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let events = std::fs::read_to_string(&log).unwrap_or_default();
        let recorded = ["crateward-surface.example", "\"169.254.169.254:80\""]
            .iter()
            .all(|needle| events.contains(needle));

        if recorded {
            break;
        }

        assert!(Instant::now() < deadline, "not recorded: {events}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "run through `cargo xtask surface`"]
async fn the_guest_sees_only_what_it_needs() {
    let mut slot = Slot::start(1).await;

    check_identity(&mut slot).await;
    check_devices(&mut slot).await;
    check_guest_mounts(&mut slot).await;
    check_guest_network(&mut slot).await;
    check_egress(&mut slot).await;

    slot.stop().await;
}
