//! DNS, HTTP and HTTPS sinks that stand in for the internet.
//!
//! Zone: untrusted. The sinks run unprivileged in a network namespace that
//! has no uplink at all, so even a compromise of this component gives a
//! crate no path to the real internet.
//!
//! Why it looks the way it does:
//!
//! * One instance runs per VM slot, started by the jail launcher inside the
//!   slot's network namespace as the slot's user, with no filesystem access
//!   (Landlock) and resource limits. nftables there redirects every DNS
//!   query, TCP connection and UDP datagram of the guest to it.
//! * Every connection attempt is logged with its intended destination,
//!   recovered with `SO_ORIGINAL_DST`, and the first 64 KiB of what the
//!   guest sent. This log is host side ground truth: a guest that controls
//!   its own kernel still cannot reach anything without appearing here.
//! * DNS answers every `A` question with the sink's address, so name based
//!   downloaders connect and reveal what they want. HTTP requests get a 404.
//! * TLS is terminated with Crateward's own certificate authority, which the
//!   guest image trusts; its private key reaches this process only through
//!   stdin from the launcher and never exists inside a VM. Clients that
//!   bring their own root list refuse the handshake; the server name is
//!   logged either way.
//! * A packet socket on the tap device logs every frame the proxies do not
//!   see, such as IPv6 and ICMP. The process opens it with the namespace's
//!   privileges, then drops to the slot's user before it reads anything
//!   from the guest.
//! * Parsers of guest traffic are property tested and fuzz targets, because
//!   the guest controls every byte they see.

#![forbid(unsafe_code)]

pub mod capture;
pub mod dns;
pub mod server;
pub mod sniff;
pub mod tls;

use crateward_core::app::ComponentError;
use crateward_core::component::Component;
use crateward_core::config::Config;

/// The component this package implements.
pub const COMPONENT: Component = Component::FakeInternet;

/// First argument of the per slot mode.
pub const SLOT: &str = "slot";

/// There is no standalone service: the jail launcher starts one instance
/// per slot with [`SLOT`] as its first argument.
///
/// # Errors
///
/// Always returns [`ComponentError::Fatal`] explaining that.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(ComponentError::Fatal {
        component: COMPONENT,
        reason: "the fake internet runs per slot and is started by the orchestrator".into(),
    })
}

/// Runs the per slot server if `args` names it (`slot <uid>`): opens the
/// packet socket, switches to `uid`, enters its sandbox, then serves until
/// killed, logging to stdout.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<std::process::ExitCode> {
    use crateward_core::sandbox::{self, FsAccess, Limits};
    if args.get(1).map(String::as_str) != Some(SLOT) {
        return None;
    }
    let fail = |message: &str| {
        eprintln!("crateward fake internet: {message}");
        std::process::ExitCode::FAILURE
    };
    // The launcher writes the authority's certificate and key to stdin
    // and closes it; an empty stdin means no TLS termination.
    let mut pem = String::new();
    if let Err(error) = std::io::Read::read_to_string(
        &mut std::io::Read::take(std::io::stdin().lock(), 64 * 1024),
        &mut pem,
    ) {
        return Some(fail(&format!("reading the authority: {error}")));
    }
    let tls = if pem.trim().is_empty() {
        None
    } else {
        let authority = tls::split_pem(&pem)
            .ok_or_else(|| "the authority is not a certificate and a key".to_owned())
            .and_then(|(cert, key)| tls::Authority::from_pem(&cert, &key))
            .and_then(|a| tls::server_config(std::sync::Arc::new(a)).map_err(|e| e.to_string()));
        match authority {
            Ok(config) => Some(config),
            Err(error) => return Some(fail(&error)),
        }
    };
    drop(pem);
    let Some(uid) = args.get(2).and_then(|a| a.parse::<u32>().ok()) else {
        return Some(fail("usage: slot <uid>"));
    };
    let capture = match capture::open() {
        Ok(socket) => socket,
        Err(error) => return Some(fail(&format!("opening the packet socket: {error}"))),
    };
    // Still single threaded, so the switch covers every thread started
    // later. Moving every UID away from 0 clears all capabilities.
    let switched = rustix::thread::set_thread_res_gid(
        rustix::process::Gid::from_raw(uid),
        rustix::process::Gid::from_raw(uid),
        rustix::process::Gid::from_raw(uid),
    )
    .and_then(|()| {
        let id = rustix::process::Uid::from_raw(uid);
        rustix::thread::set_thread_res_uid(id, id, id)
    });
    if let Err(error) = switched {
        return Some(fail(&format!("switching to user {uid}: {error}")));
    }
    if rustix::process::getuid().as_raw() == 0 {
        return Some(fail("still root after switching users"));
    }
    let entered = sandbox::limit(Limits {
        address_space: 1 << 30,
        cpu_seconds: 3_600,
        file_size: 64 * 1024 * 1024,
        open_files: 128,
    })
    .and_then(|()| sandbox::restrict_fs(&FsAccess::default()));
    if let Err(error) = entered {
        return Some(fail(&error.to_string()));
    }
    let out = Box::new(std::io::stdout());
    match server::serve(server::SlotConfig::default(), out, tls, Some(capture)) {
        Ok(()) => Some(std::process::ExitCode::SUCCESS),
        Err(error) => Some(fail(&error.to_string())),
    }
}
