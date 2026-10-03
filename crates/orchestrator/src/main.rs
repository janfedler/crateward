//! Entry point of the `crateward-orchestrator` service. The logic lives in the
//! library so that it can be tested without a process boundary.

use std::process::ExitCode;

fn main() -> ExitCode {
    // The orchestrator starts itself again to build payload images and to
    // read scratch disks, each in a sandbox.
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = crateward_orchestrator::payload::dispatch(&args) {
        return code;
    }

    if let Some(code) = crateward_orchestrator::scratch::dispatch(&args) {
        return code;
    }

    if let Some(code) = crateward_orchestrator::scratch::dispatch_export(&args) {
        return code;
    }

    crateward_core::app::run_component(
        crateward_orchestrator::COMPONENT,
        crateward_orchestrator::run,
    )
}
