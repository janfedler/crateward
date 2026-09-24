//! Entry point of the `crateward_fetcher` service. The logic lives in the
//! library so that it can be tested without a process boundary.

use std::process::ExitCode;

fn main() -> ExitCode {
    // The fetcher starts itself again for its sandboxed children.
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = crateward_fetcher::sandboxed::dispatch(&args) {
        return code;
    }
    crateward_core::app::run_component(crateward_fetcher::COMPONENT, crateward_fetcher::run)
}
