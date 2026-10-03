//! Process harness shared by the host services.
//!
//! Every service starts the same way: parse the command line, load and
//! validate the configuration, set up structured logging, then run. Doing it
//! in one place guarantees that no service can start with an unvalidated
//! configuration and that every log line carries the component name. The
//! runtime and the stop signal are shared the same way.
//!
//! Exit codes follow `sysexits.h`, so systemd and the supervisor can tell a
//! configuration error (78) from a runtime failure (1).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use crate::component::Component;
use crate::config::{Config, LogFormat};
use crate::paths::host;
#[cfg(feature = "store")]
use crate::store::{Policies, Store};

/// Exit code for an invalid configuration (`EX_CONFIG`).
pub const EXIT_CONFIG: u8 = 78;

/// Why a component stopped: it could not continue, and systemd restarts
/// it. [`run_component`] logs it with the component's name.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ComponentError(String);

/// A [`ComponentError`] for `reason`, for use with `map_err`.
pub fn fatal(reason: impl std::fmt::Display) -> ComponentError {
    ComponentError(reason.to_string())
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Configuration file.
    #[arg(long, env = "CRATEWARD_CONFIG", default_value = host::CONFIG)]
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
        Err(error) => {
            tracing::error!(component = component.name(), %error, "stopping");
            ExitCode::FAILURE
        }
    }
}

/// The runtime of a host service, with two worker threads.
///
/// # Errors
///
/// Fails if the operating system refuses the threads.
pub fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

/// Set once the process receives SIGTERM or `Ctrl-C`. A service checks it
/// between jobs, so a job in progress finishes and no lease is left to
/// expire. Clones share the signal.
#[derive(Debug, Clone)]
pub struct Stop(watch::Receiver<bool>);

impl Stop {
    /// Listens for the signals from now on. Call it inside the runtime.
    ///
    /// # Errors
    ///
    /// Fails if the SIGTERM handler cannot be installed.
    pub fn install() -> std::io::Result<Self> {
        let mut terminate = signal(SignalKind::terminate())?;
        let (sender, receiver) = watch::channel(false);
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }

            sender.send_replace(true);
        });

        Ok(Self(receiver))
    }

    /// Whether a signal arrived.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        *self.0.borrow()
    }

    /// Completes once a signal arrived, at once if one already did.
    pub async fn wait(&self) {
        let _ = self.0.clone().wait_for(|requested| *requested).await;
    }

    /// Sleeps for `duration`, or less if a signal arrives.
    pub async fn sleep(&self, duration: Duration) {
        tokio::select! {
            () = tokio::time::sleep(duration) => {}
            () = self.wait() => {}
        }
    }
}

/// How often [`reap_loop`] looks for jobs whose worker died.
#[cfg(feature = "store")]
const REAP_EVERY: Duration = Duration::from_secs(60);

/// Expires the leases of jobs whose worker died, once a minute until
/// `stop`. The store is the loop's own, since reaping is a transaction.
#[cfg(feature = "store")]
pub async fn reap_loop(mut store: Store, policies: Policies, stop: Stop) {
    loop {
        stop.sleep(REAP_EVERY).await;

        if stop.is_requested() {
            return;
        }

        match store.reap_expired(&policies).await {
            Ok(0) => {}
            Ok(reaped) => tracing::warn!(reaped, "reaped expired leases"),
            Err(error) => tracing::warn!(%error, "reaping expired leases failed"),
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

#[cfg(test)]
mod tests {
    use tokio::time::Instant;

    use super::*;

    fn stop() -> (watch::Sender<bool>, Stop) {
        let (sender, receiver) = watch::channel(false);

        (sender, Stop(receiver))
    }

    #[tokio::test(start_paused = true)]
    async fn a_signal_ends_a_sleep_early() {
        let (sender, stop) = stop();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sender.send_replace(true);
        });
        let start = Instant::now();
        stop.sleep(Duration::from_secs(3600)).await;

        assert!(start.elapsed() < Duration::from_secs(60));
        assert!(stop.is_requested());
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_signal_a_sleep_takes_its_time() {
        let (_sender, stop) = stop();
        let start = Instant::now();
        stop.sleep(Duration::from_secs(5)).await;

        assert!(start.elapsed() >= Duration::from_secs(5));
        assert!(!stop.is_requested());
    }

    #[tokio::test]
    async fn waiting_after_the_signal_returns_at_once() {
        let (sender, stop) = stop();
        let clone = stop.clone();
        sender.send_replace(true);
        stop.wait().await;
        clone.wait().await;

        assert!(clone.is_requested());
    }
}
