//! `crateward`, the command line tool for the maintainer.
//!
//! Zone: control plane. It checks the configuration and the host's
//! integrity, shows the pipeline's status, controls quarantine and circuit
//! breakers, and writes evidence packs and disclosure records.
//! Everything it can do is also visible on the dashboard. The tool exists so
//! that recovery works over SSH when the web interface does not.

#![forbid(unsafe_code)]

/// Like `println!`, but a closed pipe (`crateward status | head`) ends the
/// program quietly instead of panicking.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;

        if let Err(error) = writeln!(std::io::stdout().lock(), $($arg)*) {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }

            eprintln!("writing to stdout: {error}");
            std::process::exit(1);
        }
    }};
}

mod disclosure;
mod egress;
mod error;
mod evidence;
mod integrity;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crateward_core::breaker::BreakerState;
use crateward_core::config::Config;
use crateward_core::job::{JobId, JobState, Stage, mermaid_diagram};
use crateward_core::paths::host;
use crateward_core::store::{PauseReason, Store};
use secrecy::ExposeSecret;

use crate::error::CliError;

#[derive(Debug, Parser)]
#[command(name = "crateward", version, about = "Crateward maintainer tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Configuration commands.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Inspect the job state machine.
    StateMachine {
        #[command(subcommand)]
        command: StateMachineCommand,
    },
    /// Show pauses, circuit breakers, canaries and pending alerts.
    Status {
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
    /// Quarantine control.
    Quarantine {
        #[command(subcommand)]
        command: QuarantineCommand,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
    /// The host integrity manifest (ADR 0008).
    Integrity {
        #[command(subcommand)]
        command: integrity::Command,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
    /// Print the nftables script that fills the egress allowlist sets
    /// (`deploy/nftables/crateward.nft`) from the configured hosts.
    Egress {
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
    /// Write the evidence pack of a job for a report (DISCLOSURE.md).
    Evidence {
        /// The job's number, as the dashboard shows it.
        job: i64,
        /// A new directory for the pack.
        #[arg(long)]
        out: PathBuf,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
    /// Record the steps of a disclosure (DISCLOSURE.md).
    Disclosure {
        #[command(subcommand)]
        command: disclosure::Command,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
    /// Circuit breaker control.
    Breaker {
        #[command(subcommand)]
        command: BreakerCommand,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum QuarantineCommand {
    /// Lift the quarantine. Only after the cause is understood (RUNBOOK.md).
    Lift,
}

#[derive(Debug, Subcommand)]
enum BreakerCommand {
    /// Close a stage's breaker, after the cause was fixed.
    Close {
        /// The stage, for example `sandbox`.
        stage: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Load and validate a configuration file.
    Check {
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum StateMachineCommand {
    /// Print the state diagram in Mermaid syntax.
    Diagram,
    /// List the states and the stage that owns each.
    States,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            error.exit_code()
        }
    }
}

fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Config {
            command: ConfigCommand::Check { config },
        } => config_check(&config),
        Command::StateMachine { command } => {
            state_machine(&command);
            Ok(())
        }
        Command::Status { config } => with_store(&Config::load(&config)?, status),
        Command::Quarantine {
            command: QuarantineCommand::Lift,
            config,
        } => with_store(&Config::load(&config)?, quarantine_lift),
        Command::Integrity { command, config } => integrity::run(&Config::load(&config)?, &command),
        Command::Egress { config } => {
            egress::run(&Config::load(&config)?);
            Ok(())
        }
        Command::Evidence { job, out, config } => {
            let config = Config::load(&config)?;
            with_store(&config, |store| {
                evidence::run(store, &config.instance.data_dir, JobId(job), &out)
            })
        }
        Command::Disclosure { command, config } => with_store(&Config::load(&config)?, |store| {
            disclosure::run(store, command)
        }),
        Command::Breaker {
            command: BreakerCommand::Close { stage },
            config,
        } => breaker_close(&config, &stage),
    }
}

/// Runs a store command against the configured database.
fn with_store<F, Fut>(config: &Config, action: F) -> Result<(), CliError>
where
    F: FnOnce(Store) -> Fut,
    Fut: Future<Output = Result<(), CliError>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    runtime.block_on(async {
        let store = Store::connect(config.database.url.expose_secret()).await?;
        action(store).await
    })
}

async fn status(store: Store) -> Result<(), CliError> {
    let now = store.now_epoch().await?;
    let pauses = store.pauses().await?;
    if pauses.is_empty() {
        out!("pauses: none");
    }

    for p in pauses {
        let job = p.job.map_or(String::new(), |j| format!(", job {}", j.0));
        out!(
            "paused: {} for {} s{job}: {}",
            p.reason.name(),
            now - p.since,
            p.detail
        );
    }

    let breakers = store.breakers().await?;
    for stage in Stage::ALL {
        let state = breakers
            .get(&stage)
            .copied()
            .unwrap_or(BreakerState::Closed);
        out!("breaker {:<16} {}", stage.name(), state.name());
    }

    for (name, passed, at) in store.latest_canaries().await? {
        let result = if passed { "passed" } else { "FAILED" };
        out!("canary {name:<16} {result} {} s ago", now - at);
    }

    out!(
        "alerts waiting: {}",
        store.pending_alerts(1000).await?.len()
    );
    Ok(())
}

async fn quarantine_lift(store: Store) -> Result<(), CliError> {
    if store.lift_pause(PauseReason::Quarantine).await? {
        out!("quarantine lifted");
    } else {
        out!("no quarantine was active");
    }

    Ok(())
}

fn breaker_close(config: &Path, stage: &str) -> Result<(), CliError> {
    let stage = Stage::ALL
        .into_iter()
        .find(|s| s.name() == stage)
        .ok_or_else(|| CliError::UnknownStage(stage.to_owned()))?;
    with_store(&Config::load(config)?, |store| async move {
        store.set_breaker(stage, BreakerState::Closed).await?;
        out!("breaker of {} closed", stage.name());
        Ok(())
    })
}

fn config_check(path: &Path) -> Result<(), CliError> {
    Config::load(path)?;
    out!("{} is valid", path.display());
    Ok(())
}

fn state_machine(command: &StateMachineCommand) {
    match command {
        StateMachineCommand::Diagram => out!("{}", mermaid_diagram().trim_end()),
        StateMachineCommand::States => {
            for state in JobState::ALL {
                let owner = state
                    .stage()
                    .map_or("none (terminal)", |stage| stage.name());
                out!("{:<20} {owner}", state.name());
            }
        }
    }
}
