//! `crateward-vmjail`: builds one rootless jail and becomes Firecracker.
//! Started only by the orchestrator. See `crateward_orchestrator::jail`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use crateward_orchestrator::jail::launcher;

fn main() -> ExitCode {
    let result = if std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == launcher::SECOND_STAGE)
    {
        Err(launcher::run_second_stage())
    } else {
        launcher::run()
    };

    match result {
        Ok(status) => launcher::exit_like(status),
        Err(error) => {
            eprintln!("crateward-vmjail: {error}");
            ExitCode::FAILURE
        }
    }
}
