//! Entry point of the `crateward_static_analysis` service. The logic lives in the
//! library so that it can be tested without a process boundary.

use std::process::ExitCode;

fn main() -> ExitCode {
    // The service starts itself again for its sandboxed analysis child.
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = crateward_static_analysis::sandboxed::dispatch(&args) {
        return code;
    }
    crateward_core::app::run_component(
        crateward_static_analysis::COMPONENT,
        crateward_static_analysis::run,
    )
}
