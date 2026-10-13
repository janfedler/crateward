//! Entry point of the `crateward-api` service. The logic lives in the
//! library so that it can be tested without a process boundary.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    crateward_core::app::run_component(crateward_api::COMPONENT, crateward_api::run)
}
