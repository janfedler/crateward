//! Entry point of the guest agent, built as a static musl binary. In the
//! microVM it runs as PID 1 (`init=/sbin/crateward-agent`).

use std::process::ExitCode;

use crateward_core::protocol::AGENT_PORT;
use crateward_guest_agent::{init, server};

fn main() -> ExitCode {
    let pid1 = init::is_pid1();
    if pid1 && let Err(error) = init::mount_filesystems() {
        eprintln!("crateward agent: {error}");
        init::shut_down();
    }
    if pid1 {
        init::disable_ipv6();
    }
    let result = server::serve(AGENT_PORT);
    if let Err(error) = &result {
        eprintln!("crateward agent: {error}");
    }
    if pid1 {
        init::shut_down();
    }
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
