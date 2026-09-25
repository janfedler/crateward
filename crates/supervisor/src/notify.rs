//! Alert delivery (ADR 0009, ADR 0020).
//!
//! Alerts leave the server through a third party, so they carry no crate
//! names and no details: a category, a short title, and where to look. The
//! evidence stays on the server, behind WireGuard.

use crateward_core::config::NotifierConfig;
use crateward_core::escalation::{EscalationCategory, HumanEscalation};
use secrecy::ExposeSecret;

/// The user agent of the supervisor's requests.
pub const USER_AGENT: &str = concat!("crateward-supervisor/", env!("CARGO_PKG_VERSION"));

/// Title, body and ntfy priority (1 to 5) of an alert.
#[must_use]
pub fn message(escalation: &HumanEscalation) -> (String, String, u8) {
    let (title, body) = match escalation {
        HumanEscalation::StageFailingAfterRetries { stage } => (
            format!("Stage {} paused", stage.name()),
            "Its circuit breaker opened after repeated infrastructure failures.".to_owned(),
        ),
        HumanEscalation::DiskUsageAboveThreshold { percent } => (
            format!("Disk {percent}% full"),
            "A filesystem passed the alert threshold.".to_owned(),
        ),
        HumanEscalation::KvmError => (
            "KVM error".to_owned(),
            "The sandbox stage stopped starting VMs.".to_owned(),
        ),
        HumanEscalation::CanaryFailure => (
            "Canary failed".to_owned(),
            "Verdicts cannot be trusted; producing stages are paused.".to_owned(),
        ),
        HumanEscalation::HighRiskVerdict { .. } => (
            "High risk verdict".to_owned(),
            "A verdict waits for review.".to_owned(),
        ),
        HumanEscalation::SandboxEscapeIndicator { .. } => (
            "Sandbox escape indicator".to_owned(),
            "Quarantine is on. Do not reboot; see the runbook.".to_owned(),
        ),
    };
    let priority = match escalation.category() {
        EscalationCategory::Escape => 5,
        EscalationCategory::Canary | EscalationCategory::Verdict => 4,
        EscalationCategory::Operations => 3,
    };
    (
        format!("Crateward: {title}"),
        format!("{body} Details on the dashboard (RUNBOOK.md)."),
        priority,
    )
}

/// Sends alerts where the configuration says.
#[derive(Debug)]
pub enum Notifier {
    /// Logs them only.
    Log,
    /// Publishes them to an ntfy topic.
    Ntfy {
        /// HTTP client.
        client: reqwest::Client,
        /// `server_url/topic`.
        url: String,
    },
}

impl Notifier {
    /// The notifier of a configuration.
    ///
    /// # Errors
    ///
    /// Fails if the HTTP client cannot be built.
    pub fn new(config: &NotifierConfig, client: &reqwest::Client) -> Result<Self, String> {
        Ok(match config {
            NotifierConfig::Log => Self::Log,
            NotifierConfig::Ntfy { server_url, topic } => Self::Ntfy {
                client: client.clone(),
                url: format!(
                    "{}/{}",
                    server_url.as_str().trim_end_matches('/'),
                    topic.expose_secret()
                ),
            },
        })
    }

    /// Delivers one alert.
    ///
    /// # Errors
    ///
    /// Fails if the server does not accept it.
    pub async fn send(&self, escalation: &HumanEscalation) -> Result<(), String> {
        let (title, body, priority) = message(escalation);
        match self {
            Self::Log => {
                tracing::warn!(%title, %body, priority, "alert (log only)");
                Ok(())
            }
            Self::Ntfy { client, url } => {
                let response = client
                    .post(url)
                    .header("Title", title)
                    .header("Priority", priority.to_string())
                    .body(body)
                    .send()
                    .await
                    .map_err(|e| e.without_url().to_string())?;
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(format!("ntfy answered {}", response.status()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crateward_core::job::{JobId, Stage};

    use super::*;

    #[test]
    fn messages_carry_no_details_and_escapes_are_urgent() {
        let escape = message(&HumanEscalation::SandboxEscapeIndicator {
            job: Some(JobId(4711)),
        });
        assert_eq!(escape.2, 5);
        let verdict = message(&HumanEscalation::HighRiskVerdict { job: JobId(4711) });
        for (title, body, _) in [escape, verdict] {
            assert!(!title.contains("4711") && !body.contains("4711"));
        }
        let stage = message(&HumanEscalation::StageFailingAfterRetries {
            stage: Stage::Fetch,
        });
        assert!(stage.0.contains("fetch"));
        assert_eq!(stage.2, 3);
    }
}
