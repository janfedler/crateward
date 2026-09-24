//! `crateward`, the command line tool for the maintainer.
//!
//! Zone: control plane. It grows with the milestones: configuration checks
//! now, then job inspection, quarantine control and disclosure helpers.
//! Everything it can do is also visible on the dashboard; the tool exists so
//! that recovery works over SSH when the web interface does not.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crateward_core::config::{Config, DEFAULT_CONFIG_PATH};
use crateward_core::job::{JobState, mermaid_diagram};

/// `EX_CONFIG` from `sysexits.h`.
const EXIT_CONFIG: u8 = 78;

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
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Load and validate a configuration file.
    Check {
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
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
    match Cli::parse().command {
        Command::Config {
            command: ConfigCommand::Check { config },
        } => match Config::load(&config) {
            Ok(_) => {
                println!("{} is valid", config.display());
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(EXIT_CONFIG)
            }
        },
        Command::StateMachine {
            command: StateMachineCommand::Diagram,
        } => {
            print!("{}", mermaid_diagram());
            ExitCode::SUCCESS
        }
        Command::StateMachine {
            command: StateMachineCommand::States,
        } => {
            for state in JobState::ALL {
                let owner = state
                    .stage()
                    .map_or("none (terminal)", |stage| stage.name());
                println!("{:<20} {owner}", state.name());
            }
            ExitCode::SUCCESS
        }
    }
}
