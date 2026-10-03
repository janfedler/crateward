//! Entry point of the `crateward-fake-internet` service. The logic lives in the
//! library so that it can be tested without a process boundary.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = crateward_fake_internet::dispatch(&args) {
        return code;
    }

    crateward_core::app::run_component(
        crateward_fake_internet::COMPONENT,
        crateward_fake_internet::run,
    )
}
