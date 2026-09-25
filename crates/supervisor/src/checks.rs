//! Decisions of the supervisor that need no I/O, so they can be tested.

/// Percent of a filesystem in use, rounded up, from `statvfs` numbers:
/// blocks in total, free blocks, and blocks available to unprivileged users.
/// Blocks reserved for root count as used, as `df` does.
#[must_use]
pub fn used_percent(total: u64, free: u64, available: u64) -> u8 {
    let used = total.saturating_sub(free);
    let usable = used.saturating_add(available);
    if usable == 0 {
        return 0;
    }
    let percent = (u128::from(used) * 100).div_ceil(u128::from(usable));
    u8::try_from(percent.min(100)).unwrap_or(100)
}

/// What to do about the canaries, from the latest result of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryAction {
    /// No results yet: leave everything as it is.
    Wait,
    /// Every canary passed: lift a canary pause.
    AllPassed,
    /// These canaries gave the wrong result: pause and alert.
    Failed(Vec<String>),
}

/// Decides from `(name, passed, when)` for the latest run of each canary.
#[must_use]
pub fn canary_action(latest: &[(String, bool, i64)]) -> CanaryAction {
    if latest.is_empty() {
        return CanaryAction::Wait;
    }
    let failed: Vec<String> = latest
        .iter()
        .filter(|(_, passed, _)| !passed)
        .map(|(name, _, _)| name.clone())
        .collect();
    if failed.is_empty() {
        CanaryAction::AllPassed
    } else {
        CanaryAction::Failed(failed)
    }
}

/// Whether an alert is sent again, given when the same alert last went out.
#[must_use]
pub fn should_send(seconds_since_sent: Option<i64>, repeat_hours: u64) -> bool {
    let repeat = i64::try_from(repeat_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    seconds_since_sent.is_none_or(|since| since >= repeat)
}

/// Whether a ping URL is the placeholder of the example configuration.
#[must_use]
pub fn is_placeholder_ping(url: &str) -> bool {
    url.trim_end_matches('/')
        .ends_with("00000000-0000-0000-0000-000000000000")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_usage_counts_reserved_blocks_as_used() {
        assert_eq!(used_percent(1000, 1000, 950), 0);
        // 500 used, 450 available to users (50 reserved): 500 / 950.
        assert_eq!(used_percent(1000, 500, 450), 53);
        assert_eq!(used_percent(1000, 0, 0), 100);
        assert_eq!(used_percent(0, 0, 0), 0);
    }

    #[test]
    fn canaries_pause_on_any_failure_and_lift_when_all_pass() {
        assert_eq!(canary_action(&[]), CanaryAction::Wait);
        let ok = ("canary-inert".to_owned(), true, 1);
        let bad = ("canary-exfil".to_owned(), false, 2);
        assert_eq!(
            canary_action(std::slice::from_ref(&ok)),
            CanaryAction::AllPassed
        );
        assert_eq!(
            canary_action(&[ok, bad]),
            CanaryAction::Failed(vec!["canary-exfil".into()])
        );
    }

    #[test]
    fn alerts_repeat_only_after_the_interval() {
        assert!(should_send(None, 24));
        assert!(!should_send(Some(3600), 24));
        assert!(should_send(Some(24 * 3600), 24));
    }

    #[test]
    fn the_example_ping_url_is_recognized() {
        assert!(is_placeholder_ping(
            "https://hc-ping.com/00000000-0000-0000-0000-000000000000"
        ));
        assert!(!is_placeholder_ping(
            "https://hc-ping.com/5d3f9a2e-1c4b-4e8a-9f0d-2b7c6a1e3f40"
        ));
    }
}
