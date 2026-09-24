//! The components of Crateward and the trust zone each one runs in.
//!
//! The zone decides what a component may touch: only the untrusted zone and
//! the guest ever execute crate code, and only the trusted zone talks to the
//! real internet. Encoding the mapping once lets logs, metrics and the threat
//! model refer to the same names.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A trust zone on the server. See `docs/ARCHITECTURE.md` for the boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    /// Handles untrusted bytes but never executes crate code. The only zone
    /// with (allowlisted) internet access.
    Trusted,
    /// Starts and supervises microVMs that execute crate code, and the fake
    /// internet those VMs talk to. Has no route to the real internet.
    Untrusted,
    /// Scores, stores and presents results. Receives only data that the
    /// other zones already parsed and validated.
    ControlPlane,
    /// Inside a microVM. Everything here is assumed hostile.
    Guest,
}

/// A deployable component. Each maps to one package of the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    /// Discovers new crate versions and creates jobs.
    Feed,
    /// Downloads, verifies, extracts and vendors crates.
    Fetcher,
    /// Parses crate sources without executing them.
    StaticAnalysis,
    /// Runs jobs in Firecracker microVMs.
    Orchestrator,
    /// Builds the prewarmed base snapshot and shared build cache. Ships as a
    /// binary of the orchestrator package (milestone M1.5).
    Warmer,
    /// Runs inside the microVM and streams observed behavior to the host.
    GuestAgent,
    /// DNS, HTTP and HTTPS sinks that stand in for the internet.
    FakeInternet,
    /// Scores runs and stores behavior profiles.
    Analyzer,
    /// Serves the dashboard and the read only API.
    Api,
    /// Health checks, circuit breakers, canaries, retention and alerts.
    Supervisor,
    /// Command line tool for the maintainer.
    Cli,
}

impl Component {
    /// Every component, in pipeline order.
    pub const ALL: [Self; 11] = [
        Self::Feed,
        Self::Fetcher,
        Self::StaticAnalysis,
        Self::Orchestrator,
        Self::Warmer,
        Self::GuestAgent,
        Self::FakeInternet,
        Self::Analyzer,
        Self::Api,
        Self::Supervisor,
        Self::Cli,
    ];

    /// Short name used in logs, metrics and unit names.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Feed => "feed",
            Self::Fetcher => "fetcher",
            Self::StaticAnalysis => "static_analysis",
            Self::Orchestrator => "orchestrator",
            Self::Warmer => "warmer",
            Self::GuestAgent => "guest_agent",
            Self::FakeInternet => "fake_internet",
            Self::Analyzer => "analyzer",
            Self::Api => "api",
            Self::Supervisor => "supervisor",
            Self::Cli => "cli",
        }
    }

    /// The trust zone the component runs in.
    #[must_use]
    pub const fn zone(self) -> Zone {
        match self {
            Self::Feed | Self::Fetcher | Self::StaticAnalysis => Zone::Trusted,
            Self::Orchestrator | Self::Warmer | Self::FakeInternet => Zone::Untrusted,
            Self::GuestAgent => Zone::Guest,
            Self::Analyzer | Self::Api | Self::Supervisor | Self::Cli => Zone::ControlPlane,
        }
    }

    /// Whether this component may ever execute code from a crate under
    /// analysis. Only the guest does; the host side only observes.
    #[must_use]
    pub const fn executes_crate_code(self) -> bool {
        matches!(self.zone(), Zone::Guest)
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_guest_executes_crate_code() {
        let executing: Vec<_> = Component::ALL
            .into_iter()
            .filter(|c| c.executes_crate_code())
            .collect();
        assert_eq!(executing, vec![Component::GuestAgent]);
    }

    #[test]
    fn trusted_zone_matches_the_architecture() {
        let trusted: Vec<_> = Component::ALL
            .into_iter()
            .filter(|c| c.zone() == Zone::Trusted)
            .collect();
        assert_eq!(
            trusted,
            vec![
                Component::Feed,
                Component::Fetcher,
                Component::StaticAnalysis
            ]
        );
    }
}
