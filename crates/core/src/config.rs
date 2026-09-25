//! Typed configuration, validated at startup.
//!
//! Every service reads the same TOML file (`config/crateward.example.toml`
//! documents every key). Parsing rejects unknown keys, so a typo cannot
//! silently fall back to a default. Validation then checks the rules that
//! types cannot express, collects every problem instead of stopping at the
//! first, and encodes external policy where it applies: the crates.io data
//! access policy limits API use to one request per second, so a larger value
//! is a configuration error, not a tuning choice.
//!
//! Secrets (database URL, ntfy topic, heartbeat URL) are [`SecretString`]s.
//! Their `Debug` output is redacted, so logging a configuration never leaks
//! them. They are only needed on the host; nothing here is ever sent to a
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

/// Default location of the configuration file on the server.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/crateward/crateward.toml";

/// The complete configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Identity and directories of this installation.
    pub instance: InstanceConfig,
    /// Logging and metrics.
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
    /// Where alerts go.
    pub notifier: NotifierConfig,
    /// The external dead man's switch.
    pub heartbeat: HeartbeatConfig,
    /// The admin dashboard.
    pub web: WebConfig,
    /// Where the public site is pushed (ADR 0009). Without this table the
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
}

/// Identity and directories of this installation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    /// Name used in alerts and the public export.
    pub name: String,
    /// Durable state on the HDD array (content addressed store, evidence).
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

/// Logging and metrics.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Log line format.
    pub log_format: LogFormat,
    /// A `tracing` filter directive such as `info,crateward_feed=debug`.
    /// The `RUST_LOG` environment variable overrides it.
    pub log_filter: String,
    /// Address of the Prometheus metrics endpoint.
    pub metrics_listen: SocketAddr,
}

/// Postgres connection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Connection URL. Secret because it may contain a password.
    pub url: SecretString,
    /// Connection pool size per process.
    pub max_connections: u32,
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
    /// Web API root, used only when nothing else provides the data.
    pub api_url: Url,
    /// API rate limit. The data access policy allows at most 1.
    pub api_max_requests_per_second: f64,
    /// Parallel downloads from the CDN.
    pub static_max_concurrent_downloads: u32,
    /// Request rate towards `static.crates.io` (feeds, crate files).
    /// crates.io sets no limit there; this is our own courtesy.
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

/// Concurrency and retry budgets of one stage.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageConfig {
    /// Parallel workers.
    pub concurrency: u32,
    /// How long a claim is valid without a heartbeat.
    pub lease_secs: u64,
    /// Heartbeat interval. At most half the lease, so one missed heartbeat
    /// never expires a healthy lease.
    pub heartbeat_secs: u64,
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
    /// Fails for a zero base or a cap below the base; [`Config::validate`]
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
    /// Physical cores on the host with SMT disabled.
    pub host_cores: u32,
    /// Cores kept free for host services.
    pub host_reserved_cores: u32,
    /// Memory the whole sandbox may use: VMs, scratch and images.
    pub host_memory_budget_mib: u64,
    /// Concurrent microVMs.
    pub slots: u32,
    /// vCPUs per microVM.
    pub vcpus_per_slot: u32,
    /// Guest memory per microVM.
    pub memory_mib_per_slot: u64,
    /// Size cap of the per job scratch disk (tmpfs backed).
    pub scratch_mib_per_slot: u64,
    /// Size of the tmpfs holding the promoted images.
    pub images_tmpfs_mib: u64,
    /// Wall clock limit for a `cargo check` run.
    pub check_timeout_secs: u64,
    /// Wall clock limit for an escalated full build and test.
    pub full_timeout_secs: u64,
    /// The Firecracker binary.
    pub firecracker_bin: PathBuf,
    /// The `crateward-vmjail` launcher (ADR 0012).
    pub vmjail_bin: PathBuf,
    /// The `crateward_fake_internet` binary, started in every slot.
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
    /// First subordinate UID for slots; slot `n` runs as `slot_uid_base + n`.
    /// The range must be in the orchestrator user's `/etc/subuid` entry.
    pub slot_uid_base: u32,
    /// First subordinate GID for slots, from `/etc/subgid`.
    pub slot_gid_base: u32,
    /// Minutes between two canary runs (ADR 0020); 0 turns them off.
    pub canary_interval_minutes: u64,
    /// The warm build cache (ADR 0008). Without this table, jobs build
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
    /// Largest warm image; a larger one is discarded.
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

/// Breakers, deadlines and alert delivery (ADR 0020).
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
}

/// Where alerts go.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotifierConfig {
    /// Only log alerts, for development installations.
    Log,
    /// Push notifications through an ntfy server.
    Ntfy {
        /// Server root, for example `https://ntfy.sh`.
        server_url: Url,
        /// Topic name. Without access control, the topic name is the
        /// password, so it must be long and random.
        topic: SecretString,
    },
}

/// The external dead man's switch.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatConfig {
    /// Ping URL of the healthchecks.io check. Secret, since anyone holding
    /// it can fake a heartbeat.
    pub ping_url: SecretString,
    /// Seconds between pings.
    pub interval_secs: u64,
}

/// The admin dashboard.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    /// Listen address. Must be a loopback address: the dashboard is reached
    /// through WireGuard and an SSH tunnel (ADR 0022).
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
        v.check(
            (1..=100).contains(&self.database.max_connections),
            "database.max_connections",
            "must be between 1 and 100",
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
            (&c.api_url, "crates_io.api_url"),
        ] {
            v.https(url, key);
        }
        v.check(
            c.api_max_requests_per_second > 0.0 && c.api_max_requests_per_second <= 1.0,
            "crates_io.api_max_requests_per_second",
            "must be above 0 and at most 1 (crates.io data access policy)",
        );
        v.check(
            (1..=16).contains(&c.static_max_concurrent_downloads),
            "crates_io.static_max_concurrent_downloads",
            "must be between 1 and 16",
        );
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
            v.check(
                s.concurrency >= 1,
                &key("concurrency"),
                "must be at least 1",
            );
            v.check(
                s.lease_secs >= 10,
                &key("lease_secs"),
                "must be at least 10",
            );
            v.check(
                s.heartbeat_secs >= 1 && s.heartbeat_secs.saturating_mul(2) <= s.lease_secs,
                &key("heartbeat_secs"),
                "must be at least 1 and at most half of lease_secs",
            );
            v.check(
                (1..=20).contains(&s.max_attempts),
                &key("max_attempts"),
                "must be between 1 and 20",
            );
            v.check(
                s.max_infrastructure_retries <= 1000,
                &key("max_infrastructure_retries"),
                "must be at most 1000",
            );
            v.check(
                s.retry_policy().is_ok(),
                &key("backoff_base_secs"),
                "must be at least 1 and not above backoff_cap_secs",
            );
        }
        v.check(
            self.stages.sandbox.concurrency <= self.sandbox.slots,
            "stages.sandbox.concurrency",
            "must not exceed sandbox.slots",
        );
        v.check(
            self.triage.dynamic_deadline_hours >= 1,
            "triage.dynamic_deadline_hours",
            "must be at least 1",
        );
    }

    fn validate_sandbox(&self, v: &mut Issues) {
        let s = &self.sandbox;
        v.check(s.slots >= 1, "sandbox.slots", "must be at least 1");
        v.check(
            s.vcpus_per_slot >= 1,
            "sandbox.vcpus_per_slot",
            "must be at least 1",
        );
        v.check(
            s.host_reserved_cores >= 1 && s.host_reserved_cores < s.host_cores,
            "sandbox.host_reserved_cores",
            "must be at least 1 and leave at least one core for VMs",
        );
        let vm_cores = s.host_cores.saturating_sub(s.host_reserved_cores);
        v.check(
            s.slots.saturating_mul(s.vcpus_per_slot) <= vm_cores,
            "sandbox.slots",
            format!(
                "slots times vcpus_per_slot must not exceed host_cores minus host_reserved_cores ({vm_cores})"
            ),
        );
        v.check(
            s.memory_mib_per_slot >= 1024,
            "sandbox.memory_mib_per_slot",
            "must be at least 1024",
        );
        v.check(
            s.scratch_mib_per_slot >= 512,
            "sandbox.scratch_mib_per_slot",
            "must be at least 512",
        );
        let needed = u64::from(s.slots)
            .saturating_mul(s.memory_mib_per_slot.saturating_add(s.scratch_mib_per_slot))
            .saturating_add(s.images_tmpfs_mib);
        v.check(
            needed <= s.host_memory_budget_mib,
            "sandbox.host_memory_budget_mib",
            format!("slots, scratch and images need {needed} MiB, more than the budget"),
        );
        v.check(
            s.check_timeout_secs >= 60 && s.check_timeout_secs <= s.full_timeout_secs,
            "sandbox.check_timeout_secs",
            "must be at least 60 and not above full_timeout_secs",
        );
        v.absolute(&s.firecracker_bin, "sandbox.firecracker_bin");
        v.absolute(&s.vmjail_bin, "sandbox.vmjail_bin");
        v.absolute(&s.fake_internet_bin, "sandbox.fake_internet_bin");
        v.absolute(
            &s.fake_internet_authority,
            "sandbox.fake_internet_authority",
        );
        v.absolute(&s.kernel_image, "sandbox.kernel_image");
        v.absolute(&s.rootfs_image, "sandbox.rootfs_image");
        v.absolute(&s.slots_dir, "sandbox.slots_dir");
        if let Some(w) = &s.warm {
            v.check(
                w.min_jobs >= 2,
                "sandbox.warm.min_jobs",
                "must be at least 2",
            );
            v.check(
                w.max_probes >= 1 && w.max_probes <= w.sample_jobs,
                "sandbox.warm.max_probes",
                "must be at least 1 and not above sample_jobs",
            );
            v.check(
                w.timeout_secs >= 60,
                "sandbox.warm.timeout_secs",
                "must be at least 60",
            );
            v.check(
                w.max_image_mib <= s.images_tmpfs_mib,
                "sandbox.warm.max_image_mib",
                "must fit into images_tmpfs_mib",
            );
        }
        // Subordinate IDs are never below 65536 in practice; a low value is
        // almost certainly a real user or group on the host.
        v.check(
            s.slot_uid_base >= 65_536 && s.slot_uid_base.checked_add(s.slots).is_some(),
            "sandbox.slot_uid_base",
            "must be a subordinate UID range (at least 65536)",
        );
        v.check(
            s.slot_gid_base >= 65_536 && s.slot_gid_base.checked_add(s.slots).is_some(),
            "sandbox.slot_gid_base",
            "must be a subordinate GID range (at least 65536)",
        );
    }

    fn validate_operations(&self, v: &mut Issues) {
        if let Some(export) = &self.export {
            v.check(
                export.repository.starts_with("git@github.com:")
                    && export.repository.ends_with(".git"),
                "export.repository",
                "must be an SSH URL of a GitHub repository (git@github.com:owner/name.git)",
            );
            v.check(
                !export.branch.is_empty()
                    && export
                        .branch
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "export.branch",
                "must be a plain branch name",
            );
            v.absolute(&export.deploy_key, "export.deploy_key");
            v.check(
                (1..=168).contains(&export.interval_hours),
                "export.interval_hours",
                "must be between 1 and 168",
            );
        }
        v.check(
            (50..=95).contains(&self.storage.disk_alert_percent),
            "storage.disk_alert_percent",
            "must be between 50 and 95",
        );
        v.check(
            self.storage.raw_log_retention_days >= 1,
            "storage.raw_log_retention_days",
            "must be at least 1",
        );
        v.absolute(&self.fetcher.cargo_bin, "fetcher.cargo_bin");
        let sup = &self.supervisor;
        v.check(
            (5..=300).contains(&sup.interval_secs),
            "supervisor.interval_secs",
            "must be between 5 and 300",
        );
        v.check(
            sup.breaker_min_failures >= 1,
            "supervisor.breaker_min_failures",
            "must be at least 1",
        );
        v.check(
            (1..=100).contains(&sup.breaker_failure_percent),
            "supervisor.breaker_failure_percent",
            "must be between 1 and 100",
        );
        v.check(
            sup.breaker_window_secs >= 60,
            "supervisor.breaker_window_secs",
            "must be at least 60",
        );
        v.check(
            sup.breaker_cooldown_secs >= 30
                && sup.breaker_cooldown_secs <= sup.breaker_max_cooldown_secs,
            "supervisor.breaker_cooldown_secs",
            "must be at least 30 and not above breaker_max_cooldown_secs",
        );
        v.check(
            sup.alert_repeat_hours >= 1,
            "supervisor.alert_repeat_hours",
            "must be at least 1",
        );
        match &self.notifier {
            NotifierConfig::Log => {}
            NotifierConfig::Ntfy { server_url, topic } => {
                v.https(server_url, "notifier.server_url");
                let topic = topic.expose_secret();
                v.check(
                    topic.len() >= 32
                        && topic.len() <= 64
                        && topic
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                    "notifier.topic",
                    "must be 32 to 64 characters of [A-Za-z0-9_-]; the topic name is the password",
                );
            }
        }
        let ping_ok = Url::parse(self.heartbeat.ping_url.expose_secret())
            .is_ok_and(|url| url.scheme() == "https");
        v.check(
            ping_ok,
            "heartbeat.ping_url",
            "must be an https URL (value not shown, it is secret)",
        );
        v.check(
            (10..=600).contains(&self.heartbeat.interval_secs),
            "heartbeat.interval_secs",
            "must be between 10 and 600",
        );
        v.check(
            self.web.listen.ip().is_loopback(),
            "web.listen",
            "must be a loopback address; the dashboard is reached through an SSH tunnel (ADR 0022)",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../config/crateward.example.toml");

    #[test]
    fn example_configuration_is_valid() {
        let config = Config::from_toml(EXAMPLE).unwrap();
        assert_eq!(config.sandbox.slots, 3);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let text = EXAMPLE.replace("[instance]\n", "[instance]\ntypo_key = 1\n");
        assert!(matches!(
            Config::from_toml(&text),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let config = Config::from_toml(EXAMPLE).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(config.heartbeat.ping_url.expose_secret()));
        assert!(!debug.contains(config.database.url.expose_secret()));
    }

    fn issues_for(from: &str, to: &str) -> Vec<ConfigIssue> {
        assert!(EXAMPLE.contains(from), "example lacks {from:?}");
        match Config::from_toml(&EXAMPLE.replacen(from, to, 1)) {
            Err(ConfigError::Invalid(issues)) => issues,
            other => panic!("expected validation issues, got {other:?}"),
        }
    }

    #[test]
    fn api_rate_above_the_policy_is_rejected() {
        let issues = issues_for(
            "api_max_requests_per_second = 1.0",
            "api_max_requests_per_second = 2.0",
        );
        assert_eq!(issues[0].key, "crates_io.api_max_requests_per_second");
    }

    #[test]
    fn overcommitted_cores_are_rejected() {
        let issues = issues_for("slots = 3", "slots = 4");
        assert!(issues.iter().any(|i| i.key == "sandbox.slots"));
    }

    #[test]
    fn dashboard_off_loopback_is_rejected() {
        for address in ["0.0.0.0:8080", "10.77.0.1:8080", "[::]:8080"] {
            let issues = issues_for(
                "listen = \"127.0.0.1:8080\"",
                &format!("listen = \"{address}\""),
            );
            assert_eq!(issues[0].key, "web.listen", "{address}");
        }
    }

    #[test]
    fn short_ntfy_topic_is_rejected() {
        let config = Config::from_toml(EXAMPLE).unwrap();
        let NotifierConfig::Ntfy { topic, .. } = &config.notifier else {
            panic!("the example uses ntfy");
        };
        let issues = issues_for(topic.expose_secret(), "alerts");
        assert_eq!(issues[0].key, "notifier.topic");
    }

    #[test]
    fn all_problems_are_reported_at_once() {
        let text = EXAMPLE.replacen("slots = 3", "slots = 0", 1).replacen(
            "disk_alert_percent = 85",
            "disk_alert_percent = 99",
            1,
        );
        match Config::from_toml(&text) {
            Err(ConfigError::Invalid(issues)) => {
                let keys: Vec<_> = issues.iter().map(|i| i.key.as_str()).collect();
                assert!(keys.contains(&"sandbox.slots"));
                assert!(keys.contains(&"storage.disk_alert_percent"));
            }
            other => panic!("expected validation issues, got {other:?}"),
        }
    }
}
