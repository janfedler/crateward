//! `crateward-vmjail`: builds one rootless jail and becomes Firecracker.
//! Started only by the orchestrator. See `crateward_orchestrator::jail`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let error = crateward_orchestrator::jail::launcher::run();
    eprintln!("crateward-vmjail: {error}");
    ExitCode::FAILURE
}
