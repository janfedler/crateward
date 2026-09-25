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
//! * TLS is not terminated yet; the server name is logged. Terminating it
//!   with a certificate authority baked into the guest image is planned.
//! * Parsers of guest traffic are property tested and fuzz targets, because
//!   the guest controls every byte they see.

#![forbid(unsafe_code)]

pub mod dns;
pub mod server;
pub mod sniff;

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

/// Runs the per slot server if `args` names it: enters its sandbox, then
/// serves until killed, logging to stdout.
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
    match server::serve(server::SlotConfig::default(), out) {
        Ok(()) => Some(std::process::ExitCode::SUCCESS),
        Err(error) => Some(fail(&error.to_string())),
    }
}
