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
//!   guest image trusts. Its private key reaches this process only through
//!   stdin from the launcher and never exists inside a VM. Clients that
//!   bring their own root list refuse the handshake. The server name is
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

use std::error::Error;
use std::io::{self, Read};
use std::process::ExitCode;
use std::sync::Arc;

use crateward_core::app::{ComponentError, fatal};
use crateward_core::component::Component;
use crateward_core::config::Config;
use crateward_core::sandbox::{self, FsAccess, Limits};
use rustix::process::{Gid, Uid};

/// The component this package implements.
pub const COMPONENT: Component = Component::FakeInternet;

/// First argument of the per slot mode.
pub const SLOT: &str = "slot";

/// There is no standalone service: the jail launcher starts one instance
/// per slot with [`SLOT`] as its first argument.
///
/// # Errors
///
/// Always returns a [`ComponentError`] explaining that.
pub fn run(_config: &Config) -> Result<(), ComponentError> {
    Err(fatal(
        "the fake internet runs per slot and is started by the orchestrator",
    ))
}

/// Runs the per slot server if `args` names it (`slot <uid>`): opens the
/// packet socket, switches to `uid`, enters its sandbox, then serves until
/// killed, logging to stdout.
#[must_use]
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    if args.get(1).map(String::as_str) != Some(SLOT) {
        return None;
    }
    Some(match serve_slot(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crateward fake internet: {error}");
            ExitCode::FAILURE
        }
    })
}

/// The TLS configuration for the authority text the launcher wrote to
/// stdin. Empty text means no TLS termination.
fn tls_config(pem: &str) -> Result<Option<Arc<rustls::ServerConfig>>, Box<dyn Error>> {
    if pem.trim().is_empty() {
        return Ok(None);
    }
    let (cert, key) = tls::split_pem(pem).ok_or("the authority is not a certificate and a key")?;
    let authority = tls::Authority::from_pem(&cert, &key)?;
    Ok(Some(tls::server_config(Arc::new(authority))?))
}

/// Moves the thread's real, effective and saved IDs to `id`, group first.
fn become_user(id: u32) -> rustix::io::Result<()> {
    let gid = Gid::from_raw(id);
    rustix::thread::set_thread_res_gid(gid, gid, gid)?;
    let uid = Uid::from_raw(id);
    rustix::thread::set_thread_res_uid(uid, uid, uid)
}

fn serve_slot(args: &[String]) -> Result<(), Box<dyn Error>> {
    // The launcher writes the authority's certificate and key to stdin
    // and closes it.
    let mut pem = String::new();
    io::stdin()
        .lock()
        .take(64 * 1024)
        .read_to_string(&mut pem)
        .map_err(|e| format!("reading the authority: {e}"))?;
    let tls = tls_config(&pem)?;
    drop(pem);
    let uid: u32 = args
        .get(2)
        .and_then(|a| a.parse().ok())
        .ok_or("usage: slot <uid>")?;
    let capture = capture::open().map_err(|e| format!("opening the packet socket: {e}"))?;
    // Still single threaded, so the switch covers every thread started
    // later. Moving every UID away from 0 clears all capabilities.
    become_user(uid).map_err(|e| format!("switching to user {uid}: {e}"))?;
    if rustix::process::getuid().as_raw() == 0 {
        return Err("still root after switching users".into());
    }
    sandbox::limit(Limits {
        address_space: 1 << 30,
        cpu_seconds: 3_600,
        file_size: 64 * 1024 * 1024,
        open_files: 128,
    })?;
    sandbox::restrict_fs(&FsAccess::default())?;
    let out = Box::new(io::stdout());
    server::serve(server::SlotConfig::default(), out, tls, Some(capture))?;
    Ok(())
}
