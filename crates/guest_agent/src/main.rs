//! Entry point of the guest agent, built as a static musl binary.

use std::process::ExitCode;

/// `EX_UNAVAILABLE` from `sysexits.h`.
const EXIT_UNAVAILABLE: u8 = 69;

fn main() -> ExitCode {
    eprintln!(
        "{} {}: not implemented yet (planned for milestone {})",
        crateward_guest_agent::COMPONENT,
        env!("CARGO_PKG_VERSION"),
        crateward_guest_agent::MILESTONE
    );
    ExitCode::from(EXIT_UNAVAILABLE)
}
