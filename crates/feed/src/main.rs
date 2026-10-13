//! Entry point of the `crateward-feed` service. The logic lives in the
//! library so that it can be tested without a process boundary.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    crateward_core::app::run_component(crateward_feed::COMPONENT, crateward_feed::run)
}
