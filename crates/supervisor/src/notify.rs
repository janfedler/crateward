//! Alert delivery (ADR 0001, ADR 0008).
//!
//! Alerts leave the server through a third party, so they carry no crate
//! names and no details: a category, a short title, and where to look. The
//! evidence stays on the server, behind SSH.

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

/// Why an alert was not delivered.
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    /// The request failed.
    #[error(transparent)]
    Request(reqwest::Error),
    /// The server did not accept the alert.
    #[error("ntfy answered {0}")]
    Refused(reqwest::StatusCode),
}

/// The request URL holds the secret topic, so it never stays in an error.
impl From<reqwest::Error> for NotifyError {
    fn from(error: reqwest::Error) -> Self {
        Self::Request(error.without_url())
    }
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
    #[must_use]
    pub fn new(config: &NotifierConfig, client: &reqwest::Client) -> Self {
        match config {
            NotifierConfig::Log => Self::Log,
            NotifierConfig::Ntfy { server_url, topic } => Self::Ntfy {
                client: client.clone(),
                url: format!(
                    "{}/{}",
                    server_url.as_str().trim_end_matches('/'),
                    topic.expose_secret()
                ),
            },
        }
    }

    /// Delivers one alert.
    ///
    /// # Errors
    ///
    /// Fails if the server does not accept it.
    pub async fn send(&self, escalation: &HumanEscalation) -> Result<(), NotifyError> {
        let (title, body, priority) = message(escalation);
        let Self::Ntfy { client, url } = self else {
            tracing::warn!(%title, %body, priority, "alert (log only)");
            return Ok(());
        };
        let response = client
            .post(url)
            .header("Title", title)
            .header("Priority", priority.to_string())
            .body(body)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(NotifyError::Refused(status));
        }
        Ok(())
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

    #[tokio::test]
    async fn a_failed_request_does_not_reveal_the_topic() {
        let notifier = Notifier::Ntfy {
            client: reqwest::Client::new(),
            url: "https://127.0.0.1:1/secret-topic".to_owned(),
        };
        let error = notifier.send(&HumanEscalation::KvmError).await.unwrap_err();
        assert!(matches!(error, NotifyError::Request(_)), "{error}");
        assert!(!format!("{error:?} {error}").contains("secret-topic"));
    }

    #[tokio::test]
    async fn a_log_notifier_always_delivers() {
        let notifier = Notifier::new(&NotifierConfig::Log, &reqwest::Client::new());
        notifier.send(&HumanEscalation::KvmError).await.unwrap();
    }
}
