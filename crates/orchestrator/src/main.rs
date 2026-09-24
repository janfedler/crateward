//! Entry point of the `crateward_orchestrator` service. The logic lives in the
//! library so that it can be tested without a process boundary.

use std::process::ExitCode;

fn main() -> ExitCode {
    crateward_core::app::run_component(
        crateward_orchestrator::COMPONENT,
        crateward_orchestrator::run,
    )
}
