//! Typed configuration, validated at startup.
//!
//! Every service reads the same TOML file (`config/crateward.example.toml`
//! documents every key). Parsing rejects unknown keys, so a typo cannot
//! silently fall back to a default. Validation then checks the rules that
//! types cannot express, collects every problem instead of stopping at the
//! first, and encodes external policy where it applies: the crates.io data
//! access policy asks for a user agent with contact details, so one without
//! is a configuration error, not a style choice.
//!
//! Secrets (database URL, ntfy topic) are [`SecretString`]s.
//! Their `Debug` output is redacted, so logging a configuration never leaks
//! them. They are only needed on the host. Nothing here is ever sent to a
//! guest.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use crate::job::{Limits, Stage, StageLimits};
use crate::retry::RetryPolicy;

/// Largest configuration file accepted, as a guard against reading
/// something that is not a configuration file.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The complete configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Identity and directories of this installation.
    pub instance: InstanceConfig,
    /// Logging.
    pub telemetry: TelemetryConfig,
    /// Postgres connection.
    pub database: DatabaseConfig,
    /// Access to crates.io, following its data access policy.
    pub crates_io: CratesIoConfig,
    /// Concurrency and retry budgets per stage.
    pub stages: StagesConfig,
    /// Which versions get dynamic analysis.
    pub triage: TriageConfig,
    /// MicroVM slots and hard limits.
    pub sandbox: SandboxConfig,
    /// Disk thresholds and retention.
    pub storage: StorageConfig,
    /// The fetch stage.
    pub fetcher: FetcherConfig,
    /// Breakers, deadlines and alert delivery.
    pub supervisor: SupervisorConfig,
    /// Push notifications for alerts. Without this table alerts are only
    /// logged, as on development installations.
    #[serde(default)]
    pub ntfy: Option<NtfyConfig>,
    /// The admin dashboard.
    pub web: WebConfig,
    /// Where the public site is pushed (ADR 0001). Without this table the
    /// site is only written below `instance.run_dir`.
    #[serde(default)]
    pub export: Option<ExportConfig>,
}

/// The public site's repository.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    /// SSH URL of the site repository, for example
    /// `git@github.com:janfedler/crateward-site.git`.
    pub repository: String,
    /// Branch GitHub Pages serves.
    pub branch: String,
    /// Private key of a deploy key with write access to that repository
    /// only. Readable by the dashboard's user only.
    pub deploy_key: PathBuf,
    /// Hours between two exports.
    pub interval_hours: u64,
    /// Whether every export also refreshes the published job reports from
    /// the selection `crateward archive --publish` saved.
    #[serde(default)]
    pub reports: bool,
}

/// Identity and directories of this installation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    /// Name used in alerts and the public export.
    pub name: String,
    /// Durable state on disk (content addressed store, evidence).
    pub data_dir: PathBuf,
    /// Volatile state in tmpfs (promoted images, sockets, scratch).
    pub run_dir: PathBuf,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line, for journald and log shipping.
    Json,
    /// Human readable output for development.
    Pretty,
}

/// Logging.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Log line format.
    pub log_format: LogFormat,
    /// A `tracing` filter directive such as `info,crateward_feed=debug`.
    /// The `RUST_LOG` environment variable overrides it.
    pub log_filter: String,
}

/// Postgres connection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Connection URL. Secret because it may contain a password.
    pub url: SecretString,
}

/// Access to crates.io.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CratesIoConfig {
    /// User agent for every request. Must identify Crateward and give a way
    /// to reach the maintainer, as the data access policy asks.
    pub user_agent: String,
    /// Sparse index root.
    pub index_url: Url,
    /// Crate file CDN root.
    pub static_url: Url,
    /// Feed of recent version publishes.
    pub rss_updates_url: Url,
    /// Feed of newly registered crates.
    pub rss_new_crates_url: Url,
    /// Daily database dump.
    pub db_dump_url: Url,
    /// Request rate towards `static.crates.io` (feeds, crate files).
    /// crates.io sets no limit there. This is our own courtesy.
    pub static_requests_per_second: f64,
    /// Request rate towards the sparse index. crates.io sets no limit there
    /// either.
    pub index_requests_per_second: f64,
    /// How often the RSS feeds are polled. The feeds cover the last 60
    /// minutes, so this must stay well below that.
    pub rss_poll_interval_secs: u64,
    /// How often the database dump is downloaded. It is refreshed daily.
    pub db_dump_refresh_hours: u64,
}

/// Lease and retry budgets of one stage.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageConfig {
    /// How long a claim is valid without a heartbeat.
    pub lease_secs: u64,
    /// Attempts before the job fails.
    pub max_attempts: u32,
    /// Infrastructure retries before the job fails.
    pub max_infrastructure_retries: u32,
    /// First backoff ceiling.
    pub backoff_base_secs: u64,
    /// Largest backoff ceiling.
    pub backoff_cap_secs: u64,
}

impl StageConfig {
    /// The retry budgets for the state machine.
    #[must_use]
    pub const fn limits(&self) -> StageLimits {
        StageLimits {
            max_attempts: self.max_attempts,
            max_infrastructure_retries: self.max_infrastructure_retries,
        }
    }

    /// The backoff policy.
    ///
    /// # Errors
    ///
    /// Fails for a zero base or a cap below the base. [`Config::validate`]
    /// reports both.
    pub fn retry_policy(&self) -> Result<RetryPolicy, crate::retry::RetryPolicyError> {
        RetryPolicy::new(
            std::time::Duration::from_secs(self.backoff_base_secs),
            std::time::Duration::from_secs(self.backoff_cap_secs),
        )
    }
}

/// Per stage configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagesConfig {
    /// Fetch stage.
    pub fetch: StageConfig,
    /// Static analysis stage.
    pub static_analysis: StageConfig,
    /// Sandbox stage. Its concurrency may not exceed the VM slots.
    pub sandbox: StageConfig,
    /// Analysis stage.
    pub analysis: StageConfig,
    /// Finalize stage.
    pub finalize: StageConfig,
}

impl StagesConfig {
    /// The configuration of one stage.
    #[must_use]
    pub const fn get(&self, stage: Stage) -> &StageConfig {
        match stage {
            Stage::Fetch => &self.fetch,
            Stage::StaticAnalysis => &self.static_analysis,
            Stage::Sandbox => &self.sandbox,
            Stage::Analysis => &self.analysis,
            Stage::Finalize => &self.finalize,
        }
    }

    /// Retry budgets of every stage for the state machine.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        Limits {
            fetch: self.fetch.limits(),
            static_analysis: self.static_analysis.limits(),
            sandbox: self.sandbox.limits(),
            analysis: self.analysis.limits(),
            finalize: self.finalize.limits(),
        }
    }
}

/// Which versions get dynamic analysis.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageConfig {
    /// A dynamic job that waits longer than this for a VM slot is scored
    /// as static only, with that reason on its label.
    pub dynamic_deadline_hours: u64,
    /// Reverse dependency count from which a crate counts as popular.
    pub popular_min_reverse_dependencies: u32,
    /// All time downloads from which a crate counts as popular. Crates that
    /// other crates pull in indirectly (platform shims, derive crates) have
    /// few direct dependents but many downloads.
    pub popular_min_downloads: u64,
}

/// MicroVM slots and hard limits.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Concurrent microVMs.
    pub slots: u32,
    /// vCPUs per microVM.
    pub vcpus_per_slot: u32,
    /// Guest memory per microVM.
    pub memory_mib_per_slot: u64,
    /// Size cap of the per job scratch disk (tmpfs backed).
    pub scratch_mib_per_slot: u64,
    /// Wall clock limit for a `cargo check` run.
    pub check_timeout_secs: u64,
    /// Wall clock limit for an escalated full build and test.
    pub full_timeout_secs: u64,
    /// The Firecracker binary.
    pub firecracker_bin: PathBuf,
    /// The `crateward-vmjail` launcher (ADR 0002).
    pub vmjail_bin: PathBuf,
    /// The `crateward-fake-internet` binary, started in every slot.
    pub fake_internet_bin: PathBuf,
    /// The fake internet's TLS authority: certificate and private key in
    /// one PEM file, readable only by the orchestrator. The guest image
    /// trusts the certificate.
    pub fake_internet_authority: PathBuf,
    /// The guest kernel (bzImage).
    pub kernel_image: PathBuf,
    /// The guest root filesystem (EROFS).
    pub rootfs_image: PathBuf,
    /// Directory holding one subdirectory per slot. Must be private to the
    /// orchestrator user.
    pub slots_dir: PathBuf,
    /// First subordinate UID for slots. Slot `n` runs as `slot_uid_base + n`.
    /// The range must be in the orchestrator user's `/etc/subuid` entry.
    pub slot_uid_base: u32,
    /// First subordinate GID for slots, from `/etc/subgid`.
    pub slot_gid_base: u32,
    /// Minutes between two canary runs (ADR 0008). 0 turns them off.
    pub canary_interval_minutes: u64,
    /// The warm build cache (ADR 0006). Without this table, jobs build
    /// cold.
    #[serde(default)]
    pub warm: Option<WarmConfig>,
}

/// The warm build cache: which past builds it replays and what may enter it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmConfig {
    /// Recent fetch records the warm build chooses from.
    pub sample_jobs: u32,
    /// Probes the warm build replays at most.
    pub max_probes: u32,
    /// A crate version enters only if at least this many sampled jobs lock
    /// it.
    pub min_jobs: u32,
    /// A crate version enters only if Crateward stored its file at least
    /// this many hours ago.
    pub min_age_hours: u64,
    /// Guest side wall clock limit of the warm build.
    pub timeout_secs: u64,
    /// Largest warm image. A larger one is discarded.
    pub max_image_mib: u64,
}

/// Disk thresholds and retention.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Disk usage in percent that escalates to a human.
    pub disk_alert_percent: u8,
    /// Days to keep raw logs of runs that were not flagged.
    pub raw_log_retention_days: u32,
}

/// The fetch stage.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetcherConfig {
    /// The real `cargo` binary of the pinned toolchain (not the rustup
    /// proxy), for dependency resolution in the sandbox. Its toolchain
    /// directory becomes readable inside the sandbox.
    pub cargo_bin: PathBuf,
    /// Keep the original `.crate` file of every analyzed version, so that
    /// evidence stays verifiable against the crates.io checksum.
    pub keep_originals: bool,
}

impl SupervisorConfig {
    /// The breaker policy these settings describe.
    #[must_use]
    pub const fn breaker_policy(&self) -> crate::breaker::BreakerPolicy {
        crate::breaker::BreakerPolicy {
            window: std::time::Duration::from_secs(self.breaker_window_secs),
            min_failures: self.breaker_min_failures,
            failure_percent: self.breaker_failure_percent,
            cooldown: std::time::Duration::from_secs(self.breaker_cooldown_secs),
            max_cooldown: std::time::Duration::from_secs(self.breaker_max_cooldown_secs),
        }
    }
}

/// Breakers, deadlines and alert delivery (ADR 0008).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorConfig {
    /// Seconds between two rounds of checks.
    pub interval_secs: u64,
    /// Sliding window over which a stage's breaker counts.
    pub breaker_window_secs: u64,
    /// Infrastructure failures in the window needed to open a breaker.
    pub breaker_min_failures: u32,
    /// Share of failures among failures and completions needed to open a
    /// breaker, in percent.
    pub breaker_failure_percent: u8,
    /// First cooldown of an open breaker.
    pub breaker_cooldown_secs: u64,
    /// Longest cooldown, after repeated failed probes.
    pub breaker_max_cooldown_secs: u64,
    /// The same alert is sent again at most this often.
    pub alert_repeat_hours: u64,
    /// Minutes between two checks of the integrity manifest (ADR 0008).
    pub integrity_interval_minutes: u64,
    /// Decoy files on the host. The supervisor plants each one that is
    /// missing and treats any open of one as a sign of compromise. Backups
    /// and indexers must skip them.
    #[serde(default)]
    pub decoys: Vec<PathBuf>,
}

/// Push notifications through an ntfy server.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    /// Server root, for example `https://ntfy.sh`.
    pub server_url: Url,
    /// Topic name. Without access control, the topic name is the password,
    /// so it must be long and random.
    pub topic: SecretString,
}

/// The admin dashboard.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    /// Listen address. Must be a loopback address: the dashboard is reached
    /// through an SSH tunnel (ADR 0009).
    pub listen: SocketAddr,
}

/// One broken rule, with the key it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    /// Dotted path of the key, for example `sandbox.slots`.
    pub key: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.message)
    }
}

/// Why a configuration could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file is larger than [`MAX_CONFIG_BYTES`].
    #[error("{path} is larger than {MAX_CONFIG_BYTES} bytes")]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// The file is not valid TOML or does not match the schema.
    #[error("invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),
    /// The file parsed, but breaks one or more rules.
    #[error("configuration has {} problem(s):\n{}", .0.len(), format_issues(.0))]
    Invalid(Vec<ConfigIssue>),
}

fn format_issues(issues: &[ConfigIssue]) -> String {
    issues
        .iter()
        .map(|issue| format!("  {issue}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Collects issues during validation.
#[derive(Default)]
struct Issues(Vec<ConfigIssue>);

impl Issues {
    fn check(&mut self, ok: bool, key: &str, message: impl Into<String>) {
        if !ok {
            self.0.push(ConfigIssue {
                key: key.to_owned(),
                message: message.into(),
            });
        }
    }

    fn absolute(&mut self, path: &Path, key: &str) {
        self.check(path.is_absolute(), key, "must be an absolute path");
    }

    fn https(&mut self, url: &Url, key: &str) {
        self.check(url.scheme() == "https", key, "must use https");
    }

    fn at_least<T: Copy + PartialOrd + fmt::Display>(&mut self, value: T, min: T, key: &str) {
        self.check(value >= min, key, format!("must be at least {min}"));
    }

    fn at_most<T: Copy + PartialOrd + fmt::Display>(&mut self, value: T, max: T, key: &str) {
        self.check(value <= max, key, format!("must be at most {max}"));
    }

    fn between<T: Copy + PartialOrd + fmt::Display>(
        &mut self,
        value: T,
        min: T,
        max: T,
        key: &str,
    ) {
        let message = format!("must be between {min} and {max}");
        self.check(min <= value && value <= max, key, message);
    }

    // Subordinate IDs start at 65536. A lower value is a real user or group.
    fn subordinate_ids(&mut self, base: u32, slots: u32, key: &str, kind: &str) {
        self.check(
            base >= 65_536 && base.checked_add(slots).is_some(),
            key,
            format!("must be a subordinate {kind} range (at least 65536)"),
        );
    }
}

/// Branch and topic names: ASCII letters, digits, `-` and `_`.
fn is_plain_name(name: &str) -> bool {
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Config {
    /// Reads, parses and validates a configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read, is too large, does
    /// not parse, or breaks a validation rule.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let read_error = |source| ConfigError::Read {
            path: path.to_owned(),
            source,
        };

        let size = std::fs::metadata(path).map_err(read_error)?.len();
        if size > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                path: path.to_owned(),
            });
        }

        let text = std::fs::read_to_string(path).map_err(read_error)?;

        Self::from_toml(&text)
    }

    /// Parses and validates configuration text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] or [`ConfigError::Invalid`].
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate().map_err(ConfigError::Invalid)?;

        Ok(config)
    }

    /// Checks every rule the types cannot express.
    ///
    /// # Errors
    ///
    /// Returns every broken rule.
    pub fn validate(&self) -> Result<(), Vec<ConfigIssue>> {
        let mut v = Issues::default();
        self.validate_instance(&mut v);
        self.validate_crates_io(&mut v);
        self.validate_stages(&mut v);
        self.validate_sandbox(&mut v);
        self.validate_operations(&mut v);

        if v.0.is_empty() { Ok(()) } else { Err(v.0) }
    }

    fn validate_instance(&self, v: &mut Issues) {
        v.check(
            !self.instance.name.trim().is_empty(),
            "instance.name",
            "must not be empty",
        );
        v.absolute(&self.instance.data_dir, "instance.data_dir");
        v.absolute(&self.instance.run_dir, "instance.run_dir");
        v.check(
            !self.telemetry.log_filter.trim().is_empty(),
            "telemetry.log_filter",
            "must not be empty",
        );
        let db = self.database.url.expose_secret();
        v.check(
            db.starts_with("postgres://") || db.starts_with("postgresql://"),
            "database.url",
            "must be a postgres:// or postgresql:// URL",
        );
    }

    fn validate_crates_io(&self, v: &mut Issues) {
        let c = &self.crates_io;
        v.check(
            c.user_agent.starts_with("crateward/")
                && (c.user_agent.contains("http") || c.user_agent.contains('@')),
            "crates_io.user_agent",
            "must start with 'crateward/' and include contact details (a URL or an email address)",
        );

        for (url, key) in [
            (&c.index_url, "crates_io.index_url"),
            (&c.static_url, "crates_io.static_url"),
            (&c.rss_updates_url, "crates_io.rss_updates_url"),
            (&c.rss_new_crates_url, "crates_io.rss_new_crates_url"),
            (&c.db_dump_url, "crates_io.db_dump_url"),
        ] {
            v.https(url, key);
        }

        for (rate, key) in [
            (
                c.static_requests_per_second,
                "crates_io.static_requests_per_second",
            ),
            (
                c.index_requests_per_second,
                "crates_io.index_requests_per_second",
            ),
        ] {
            v.check(
                rate > 0.0 && rate <= 20.0,
                key,
                "must be above 0 and at most 20 (our own politeness bound)",
            );
        }

        v.check(
            (60..=1800).contains(&c.rss_poll_interval_secs),
            "crates_io.rss_poll_interval_secs",
            "must be between 60 and 1800 (the feeds cover the last 60 minutes)",
        );
        v.check(
            c.db_dump_refresh_hours >= 24,
            "crates_io.db_dump_refresh_hours",
            "must be at least 24 (the dump is refreshed daily)",
        );
    }

    fn validate_stages(&self, v: &mut Issues) {
        for stage in Stage::ALL {
            let s = self.stages.get(stage);
            let key = |field: &str| format!("stages.{}.{field}", stage.name());
            v.at_least(s.lease_secs, 10, &key("lease_secs"));
            v.between(s.max_attempts, 1, 20, &key("max_attempts"));
            let retries = s.max_infrastructure_retries;
            v.at_most(retries, 1000, &key("max_infrastructure_retries"));
            v.check(
                s.retry_policy().is_ok(),
                &key("backoff_base_secs"),
                "must be at least 1 and not above backoff_cap_secs",
            );
        }

        let hours = self.triage.dynamic_deadline_hours;
        v.at_least(hours, 1, "triage.dynamic_deadline_hours");
    }

    fn validate_sandbox(&self, v: &mut Issues) {
        let s = &self.sandbox;
        v.at_least(s.slots, 1, "sandbox.slots");
        v.at_least(s.vcpus_per_slot, 1, "sandbox.vcpus_per_slot");
        v.at_least(s.memory_mib_per_slot, 1024, "sandbox.memory_mib_per_slot");
        v.at_least(s.scratch_mib_per_slot, 512, "sandbox.scratch_mib_per_slot");
        v.check(
            s.check_timeout_secs >= 60 && s.check_timeout_secs <= s.full_timeout_secs,
            "sandbox.check_timeout_secs",
            "must be at least 60 and not above full_timeout_secs",
        );

        for (path, key) in [
            (&s.firecracker_bin, "sandbox.firecracker_bin"),
            (&s.vmjail_bin, "sandbox.vmjail_bin"),
            (&s.fake_internet_bin, "sandbox.fake_internet_bin"),
            (
                &s.fake_internet_authority,
                "sandbox.fake_internet_authority",
            ),
            (&s.kernel_image, "sandbox.kernel_image"),
            (&s.rootfs_image, "sandbox.rootfs_image"),
            (&s.slots_dir, "sandbox.slots_dir"),
        ] {
            v.absolute(path, key);
        }

        self.validate_warm(v);
        v.subordinate_ids(s.slot_uid_base, s.slots, "sandbox.slot_uid_base", "UID");
        v.subordinate_ids(s.slot_gid_base, s.slots, "sandbox.slot_gid_base", "GID");
    }

    fn validate_warm(&self, v: &mut Issues) {
        let Some(w) = &self.sandbox.warm else {
            return;
        };

        v.at_least(w.min_jobs, 2, "sandbox.warm.min_jobs");
        v.check(
            w.max_probes >= 1 && w.max_probes <= w.sample_jobs,
            "sandbox.warm.max_probes",
            "must be at least 1 and not above sample_jobs",
        );
        v.at_least(w.timeout_secs, 60, "sandbox.warm.timeout_secs");
    }

    fn validate_operations(&self, v: &mut Issues) {
        self.validate_export(v);
        let storage = &self.storage;
        v.between(
            storage.disk_alert_percent,
            50,
            95,
            "storage.disk_alert_percent",
        );
        v.at_least(
            storage.raw_log_retention_days,
            1,
            "storage.raw_log_retention_days",
        );
        v.absolute(&self.fetcher.cargo_bin, "fetcher.cargo_bin");
        self.validate_supervisor(v);
        self.validate_ntfy(v);
        v.check(
            self.web.listen.ip().is_loopback(),
            "web.listen",
            "must be a loopback address, because the dashboard is reached through an SSH tunnel (ADR 0009)",
        );
    }

    fn validate_export(&self, v: &mut Issues) {
        let Some(export) = &self.export else {
            return;
        };

        v.check(
            export.repository.starts_with("git@github.com:") && export.repository.ends_with(".git"),
            "export.repository",
            "must be an SSH URL of a GitHub repository (git@github.com:owner/name.git)",
        );
        v.check(
            !export.branch.is_empty() && is_plain_name(&export.branch),
            "export.branch",
            "must be a plain branch name",
        );
        v.absolute(&export.deploy_key, "export.deploy_key");
        v.between(export.interval_hours, 1, 168, "export.interval_hours");
    }

    fn validate_supervisor(&self, v: &mut Issues) {
        let sup = &self.supervisor;
        v.between(sup.interval_secs, 5, 300, "supervisor.interval_secs");
        v.at_least(
            sup.breaker_min_failures,
            1,
            "supervisor.breaker_min_failures",
        );
        v.between(
            sup.breaker_failure_percent,
            1,
            100,
            "supervisor.breaker_failure_percent",
        );
        v.at_least(
            sup.breaker_window_secs,
            60,
            "supervisor.breaker_window_secs",
        );
        v.check(
            sup.breaker_cooldown_secs >= 30
                && sup.breaker_cooldown_secs <= sup.breaker_max_cooldown_secs,
            "supervisor.breaker_cooldown_secs",
            "must be at least 30 and not above breaker_max_cooldown_secs",
        );
        v.at_least(sup.alert_repeat_hours, 1, "supervisor.alert_repeat_hours");
        let minutes = sup.integrity_interval_minutes;
        v.at_least(minutes, 1, "supervisor.integrity_interval_minutes");

        for decoy in &sup.decoys {
            v.absolute(decoy, "supervisor.decoys");
        }
    }

    fn validate_ntfy(&self, v: &mut Issues) {
        let Some(ntfy) = &self.ntfy else {
            return;
        };

        v.https(&ntfy.server_url, "ntfy.server_url");
        let topic = ntfy.topic.expose_secret();
        v.check(
            (32..=64).contains(&topic.len()) && is_plain_name(topic),
            "ntfy.topic",
            "must be 32 to 64 characters of [A-Za-z0-9_-]; the topic name is the password",
        );
    }
}

#[cfg(test)]
mod tests;
