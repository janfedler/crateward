//! Entry point of the `crateward_static_analysis` service. The logic lives in the
//! library so that it can be tested without a process boundary.

use std::process::ExitCode;

fn main() -> ExitCode {
    crateward_core::app::run_component(
        crateward_static_analysis::COMPONENT,
        crateward_static_analysis::run,
    )
}
