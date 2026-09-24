//! Process harness shared by the host services.
//!
//! Every service starts the same way: parse the command line, load and
//! validate the configuration, set up structured logging, then run. Doing it
//! in one place guarantees that no service can start with an unvalidated
//! configuration and that every log line carries the component name.
//!
//! Exit codes follow `sysexits.h`, so systemd and the supervisor can tell a
//! configuration error (78) from a runtime failure (1).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::component::Component;
use crate::config::{Config, DEFAULT_CONFIG_PATH, LogFormat};

/// Exit code for an invalid configuration (`EX_CONFIG`).
pub const EXIT_CONFIG: u8 = 78;
/// Exit code for a feature that is not built yet (`EX_UNAVAILABLE`).
pub const EXIT_UNAVAILABLE: u8 = 69;

/// Why a component stopped.
#[derive(Debug, thiserror::Error)]
pub enum ComponentError {
    /// The component is planned for a later milestone.
    #[error("{component} is not implemented yet (planned for milestone {milestone})")]
    NotImplemented {
        /// The component.
        component: Component,
        /// The milestone that delivers it.
        milestone: &'static str,
    },
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Configuration file.
    #[arg(long, env = "CRATEWARD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the service (the default).
    Run,
    /// Load and validate the configuration, then exit.
    CheckConfig,
}

/// Runs a host service: parses arguments, loads the configuration, sets up
/// logging and calls `run`.
pub fn run_component<F>(component: Component, run: F) -> ExitCode
where
    F: FnOnce(&Config) -> Result<(), ComponentError>,
{
    let args = Args::parse();
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{component}: {error}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    if matches!(args.command, Some(Command::CheckConfig)) {
        println!(
            "{component}: configuration {} is valid",
            args.config.display()
        );
        return ExitCode::SUCCESS;
    }
    if let Err(error) = init_tracing(&config) {
        eprintln!("{component}: cannot set up logging: {error}");
        return ExitCode::from(EXIT_CONFIG);
    }
    tracing::info!(
        component = component.name(),
        zone = ?component.zone(),
        version = env!("CARGO_PKG_VERSION"),
        "starting"
    );
    match run(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error @ ComponentError::NotImplemented { .. }) => {
            tracing::error!(component = component.name(), %error, "stopping");
            ExitCode::from(EXIT_UNAVAILABLE)
        }
    }
}

fn init_tracing(config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(directive) => EnvFilter::try_new(directive)?,
        Err(_) => EnvFilter::try_new(&config.telemetry.log_filter)?,
    };
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match config.telemetry.log_format {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Pretty => builder.pretty().try_init(),
    }
}
