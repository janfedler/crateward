//! `crateward`, the command line tool for the maintainer.
//!
//! Zone: control plane. It grows with the milestones: configuration checks
//! now, then job inspection, quarantine control and disclosure helpers.
//! Everything it can do is also visible on the dashboard; the tool exists so
//! that recovery works over SSH when the web interface does not.

#![forbid(unsafe_code)]

mod egress;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use crateward_core::breaker::BreakerState;
use crateward_core::config::{Config, DEFAULT_CONFIG_PATH};
use crateward_core::job::{JobState, Stage, mermaid_diagram};
use crateward_core::store::{PauseReason, Store};
use secrecy::ExposeSecret;

/// `EX_CONFIG` from `sysexits.h`.
const EXIT_CONFIG: u8 = 78;

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
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Quarantine control.
    Quarantine {
        #[command(subcommand)]
        command: QuarantineCommand,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// The host integrity manifest (ADR 0023).
    Integrity {
        #[command(subcommand)]
        command: IntegrityCommand,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Print the nftables script that fills the egress allowlist sets
    /// (`deploy/nftables/crateward.nft`) from the configured hosts.
    Egress {
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Circuit breaker control.
    Breaker {
        #[command(subcommand)]
        command: BreakerCommand,
        /// Configuration file.
        #[arg(long, env = "CRATEWARD_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum IntegrityCommand {
    /// Record the digests of the trusted files, after a deploy.
    Record,
    /// Compare the trusted files with the manifest.
    Check,
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

/// Runs a store command against the configured database.
fn with_store<F, Fut>(config: &Path, action: F) -> ExitCode
where
    F: FnOnce(Store) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let config = match Config::load(config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        let store = Store::connect(config.database.url.expose_secret())
            .await
            .map_err(|e| e.to_string())?;
        action(store).await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Records or checks the manifest in `instance.data_dir`. The Crateward
/// binaries are the ones next to this tool.
fn integrity(config: &Path, command: &IntegrityCommand) -> ExitCode {
    use crateward_core::integrity;
    let config = match Config::load(config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    let manifest = config.instance.data_dir.join(integrity::MANIFEST);
    let result =
        match command {
            IntegrityCommand::Record => std::env::current_exe()
                .map_err(|e| e.to_string())
                .and_then(|exe| {
                    let dir = exe.parent().ok_or("the tool has no directory")?;
                    let files = integrity::covered(&config, dir).map_err(|e| e.to_string())?;
                    let text = integrity::record(&files).map_err(|e| e.to_string())?;
                    let temporary = manifest.with_extension("tmp");
                    std::fs::write(&temporary, &text).map_err(|e| e.to_string())?;
                    std::fs::rename(&temporary, &manifest).map_err(|e| e.to_string())?;
                    out!("recorded {} files in {}", files.len(), manifest.display());
                    Ok(())
                }),
            IntegrityCommand::Check => std::fs::read_to_string(&manifest)
                .map_err(|e| format!("{}: {e}", manifest.display()))
                .and_then(|text| integrity::parse(&text).map_err(|e| e.to_string()))
                .and_then(|parsed| {
                    let mismatches = integrity::verify(&parsed);
                    for m in &mismatches {
                        out!("MISMATCH {}: {}", m.path.display(), m.reason);
                    }
                    if mismatches.is_empty() {
                        out!("{} files match", parsed.len());
                        Ok(())
                    } else {
                        Err(format!("{} files differ", mismatches.len()))
                    }
                }),
        };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn status(store: Store) -> Result<(), String> {
    let now = store.now_epoch().await.map_err(|e| e.to_string())?;
    let pauses = store.pauses().await.map_err(|e| e.to_string())?;
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
    let breakers = store.breakers().await.map_err(|e| e.to_string())?;
    for stage in Stage::ALL {
        let state = breakers
            .get(&stage)
            .copied()
            .unwrap_or(BreakerState::Closed);
        out!("breaker {:<16} {}", stage.name(), state.name());
    }
    for (name, passed, at) in store.latest_canaries().await.map_err(|e| e.to_string())? {
        let result = if passed { "passed" } else { "FAILED" };
        out!("canary {name:<16} {result} {} s ago", now - at);
    }
    let pending = store
        .pending_alerts(1000)
        .await
        .map_err(|e| e.to_string())?;
    out!("alerts waiting: {}", pending.len());
    Ok(())
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Status { config } => with_store(&config, status),
        Command::Quarantine {
            command: QuarantineCommand::Lift,
            config,
        } => with_store(&config, |store| async move {
            if store
                .lift_pause(PauseReason::Quarantine)
                .await
                .map_err(|e| e.to_string())?
            {
                out!("quarantine lifted");
            } else {
                out!("no quarantine was active");
            }
            Ok(())
        }),
        Command::Integrity { command, config } => integrity(&config, &command),
        Command::Egress { config } => {
            let config = match Config::load(&config) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(EXIT_CONFIG);
                }
            };
            let (sets, errors) = egress::resolve(&egress::allowances(&config));
            for error in &errors {
                eprintln!("not resolved: {error}");
            }
            // A host that stops resolving ages out of its set.
            out!("{}", egress::render(&sets).trim_end());
            ExitCode::SUCCESS
        }
        Command::Breaker {
            command: BreakerCommand::Close { stage },
            config,
        } => {
            let Some(stage) = Stage::ALL.into_iter().find(|s| s.name() == stage) else {
                eprintln!("unknown stage {stage}");
                return ExitCode::FAILURE;
            };
            with_store(&config, move |store| async move {
                store
                    .set_breaker(stage, BreakerState::Closed)
                    .await
                    .map_err(|e| e.to_string())?;
                out!("breaker of {} closed", stage.name());
                Ok(())
            })
        }
        Command::Config {
            command: ConfigCommand::Check { config },
        } => match Config::load(&config) {
            Ok(_) => {
                out!("{} is valid", config.display());
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
                out!("{:<20} {owner}", state.name());
            }
            ExitCode::SUCCESS
        }
    }
}
