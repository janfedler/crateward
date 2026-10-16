use super::*;

const EXAMPLE: &str = include_str!("../../../../config/crateward.example.toml");

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
    let topic = &config.ntfy.as_ref().unwrap().topic;

    assert!(!debug.contains(topic.expose_secret()));
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
    let topic = &config.ntfy.as_ref().unwrap().topic;
    let issues = issues_for(topic.expose_secret(), "alerts");

    assert_eq!(issues[0].key, "ntfy.topic");
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

const ABSOLUTE: &str = "must be an absolute path";
const HTTPS: &str = "must use https";

fn issues_after(edit: impl FnOnce(&mut Config)) -> Vec<(String, String)> {
    let mut config = Config::from_toml(EXAMPLE).unwrap();
    edit(&mut config);
    let issues = config.validate().err().unwrap_or_default();

    issues.into_iter().map(|i| (i.key, i.message)).collect()
}

fn rule(edit: impl FnOnce(&mut Config), key: &str, message: &str) {
    let expected = [(key.to_owned(), message.to_owned())];

    assert_eq!(issues_after(edit), expected, "{key}");
}

fn accepted(edit: impl FnOnce(&mut Config)) {
    let issues = issues_after(edit);

    assert!(issues.is_empty(), "{issues:?}");
}

/// Every value of `ok` passes. Every value of `bad` breaks this rule and no other.
fn limits<T: Copy + fmt::Debug>(
    set: impl Fn(&mut Config, T),
    ok: &[T],
    bad: &[T],
    key: &str,
    message: &str,
) {
    for &n in ok {
        let issues = issues_after(|c| set(c, n));

        assert!(issues.is_empty(), "{key} = {n:?}: {issues:?}");
    }

    for &n in bad {
        let expected = [(key.to_owned(), message.to_owned())];

        assert_eq!(issues_after(|c| set(c, n)), expected, "{key} = {n:?}");
    }
}

fn stage_mut(config: &mut Config, stage: Stage) -> &mut StageConfig {
    match stage {
        Stage::Fetch => &mut config.stages.fetch,
        Stage::StaticAnalysis => &mut config.stages.static_analysis,
        Stage::Sandbox => &mut config.stages.sandbox,
        Stage::Analysis => &mut config.stages.analysis,
        Stage::Finalize => &mut config.stages.finalize,
    }
}

fn http() -> Url {
    Url::parse("http://example.com/").unwrap()
}

#[test]
fn instance_rules() {
    rule(
        |c| c.instance.name = "  ".into(),
        "instance.name",
        "must not be empty",
    );

    // The user agent names each, so only the address is wrong.
    for email in [
        "",
        "me",
        "@example.com",
        "me@localhost",
        "me @example.com",
        "<me@x.example>",
    ] {
        rule(
            |c| {
                c.instance.contact_email = email.into();
                c.crates_io.user_agent = format!("crateward/0.1 ({email})");
            },
            "instance.contact_email",
            "must be an email address",
        );
    }

    rule(
        |c| c.instance.data_dir = "data".into(),
        "instance.data_dir",
        ABSOLUTE,
    );
    rule(
        |c| c.instance.run_dir = "run".into(),
        "instance.run_dir",
        ABSOLUTE,
    );
    rule(
        |c| c.telemetry.log_filter = " ".into(),
        "telemetry.log_filter",
        "must not be empty",
    );

    for url in ["mysql://x/y", "localhost", ""] {
        let message = "must be a postgres:// or postgresql:// URL";
        rule(|c| c.database.url = url.into(), "database.url", message);
    }

    accepted(|c| c.database.url = "postgres://x/y".into());
}

#[test]
fn crates_io_rules() {
    let message = "must start with 'crateward/' and name instance.contact_email";
    for agent in [
        "curl/8.0",
        "crateward/0.1",
        "crateward/0.1 (+https://x.example)",
        "crateward/0.1 (me@x.example)",
        "x crateward/0.1 (+https://x; security@example.com)",
    ] {
        rule(
            |c| c.crates_io.user_agent = agent.into(),
            "crates_io.user_agent",
            message,
        );
    }

    for agent in [
        "crateward/0.1 (+https://x.example; security@example.com)",
        "crateward/0.1 (security@example.com)",
    ] {
        accepted(|c| c.crates_io.user_agent = agent.into());
    }

    rule(
        |c| c.crates_io.index_url = http(),
        "crates_io.index_url",
        HTTPS,
    );
    rule(
        |c| c.crates_io.static_url = http(),
        "crates_io.static_url",
        HTTPS,
    );
    rule(
        |c| c.crates_io.rss_updates_url = http(),
        "crates_io.rss_updates_url",
        HTTPS,
    );
    rule(
        |c| c.crates_io.rss_new_crates_url = http(),
        "crates_io.rss_new_crates_url",
        HTTPS,
    );
    rule(
        |c| c.crates_io.db_dump_url = http(),
        "crates_io.db_dump_url",
        HTTPS,
    );
    let politeness = "must be above 0 and at most 20 (our own politeness bound)";
    limits(
        |c, n| c.crates_io.static_requests_per_second = n,
        &[0.1, 20.0],
        &[0.0, 20.5],
        "crates_io.static_requests_per_second",
        politeness,
    );
    limits(
        |c, n| c.crates_io.index_requests_per_second = n,
        &[0.1, 20.0],
        &[0.0, 20.5],
        "crates_io.index_requests_per_second",
        politeness,
    );
    limits(
        |c, n| c.crates_io.rss_poll_interval_secs = n,
        &[60, 1800],
        &[59, 1801],
        "crates_io.rss_poll_interval_secs",
        "must be between 60 and 1800 (the feeds cover the last 60 minutes)",
    );
    limits(
        |c, n| c.crates_io.db_dump_refresh_hours = n,
        &[24, 25],
        &[23, 0],
        "crates_io.db_dump_refresh_hours",
        "must be at least 24 (the dump is refreshed daily)",
    );
}

#[test]
fn stage_rules() {
    for stage in Stage::ALL {
        let key = |field: &str| format!("stages.{}.{field}", stage.name());
        limits(
            |c, n| stage_mut(c, stage).lease_secs = n,
            &[10, 11],
            &[9],
            &key("lease_secs"),
            "must be at least 10",
        );
        limits(
            |c, n| stage_mut(c, stage).max_attempts = n,
            &[1, 20],
            &[0, 21],
            &key("max_attempts"),
            "must be between 1 and 20",
        );
        limits(
            |c, n| stage_mut(c, stage).max_infrastructure_retries = n,
            &[0, 1000],
            &[1001],
            &key("max_infrastructure_retries"),
            "must be at most 1000",
        );
        let backoff = |c: &mut Config, n| {
            let s = stage_mut(c, stage);
            s.backoff_cap_secs = 100;
            s.backoff_base_secs = n;
        };

        limits(
            backoff,
            &[1, 100],
            &[0, 101],
            &key("backoff_base_secs"),
            "must be at least 1 and not above backoff_cap_secs",
        );
    }

    limits(
        |c, n| c.triage.dynamic_deadline_hours = n,
        &[1, 12],
        &[0],
        "triage.dynamic_deadline_hours",
        "must be at least 1",
    );
}

#[test]
fn sandbox_resource_rules() {
    limits(
        |c, n| c.sandbox.slots = n,
        &[1, 3],
        &[0],
        "sandbox.slots",
        "must be at least 1",
    );
    limits(
        |c, n| c.sandbox.vcpus_per_slot = n,
        &[1],
        &[0],
        "sandbox.vcpus_per_slot",
        "must be at least 1",
    );
    limits(
        |c, n| c.sandbox.memory_mib_per_slot = n,
        &[1024, 4096],
        &[1023],
        "sandbox.memory_mib_per_slot",
        "must be at least 1024",
    );
    limits(
        |c, n| c.sandbox.scratch_mib_per_slot = n,
        &[512, 4096],
        &[511],
        "sandbox.scratch_mib_per_slot",
        "must be at least 512",
    );
    limits(
        |c, n| c.sandbox.check_timeout_secs = n,
        &[60, 2700],
        &[59, 2701],
        "sandbox.check_timeout_secs",
        "must be at least 60 and not above full_timeout_secs",
    );
}

#[test]
fn sandbox_path_warm_and_id_rules() {
    rule(
        |c| c.sandbox.firecracker_bin = "fc".into(),
        "sandbox.firecracker_bin",
        ABSOLUTE,
    );
    rule(
        |c| c.sandbox.vmjail_bin = "jail".into(),
        "sandbox.vmjail_bin",
        ABSOLUTE,
    );
    rule(
        |c| c.sandbox.fake_internet_bin = "fi".into(),
        "sandbox.fake_internet_bin",
        ABSOLUTE,
    );
    rule(
        |c| c.sandbox.fake_internet_authority = "ca".into(),
        "sandbox.fake_internet_authority",
        ABSOLUTE,
    );
    rule(
        |c| c.sandbox.kernel_image = "k".into(),
        "sandbox.kernel_image",
        ABSOLUTE,
    );
    rule(
        |c| c.sandbox.rootfs_image = "r".into(),
        "sandbox.rootfs_image",
        ABSOLUTE,
    );
    rule(
        |c| c.sandbox.slots_dir = "s".into(),
        "sandbox.slots_dir",
        ABSOLUTE,
    );
    accepted(|c| c.sandbox.warm = None);
    limits(
        |c, n| c.sandbox.warm.as_mut().unwrap().min_jobs = n,
        &[2, 3],
        &[1, 0],
        "sandbox.warm.min_jobs",
        "must be at least 2",
    );
    limits(
        |c, n| c.sandbox.warm.as_mut().unwrap().max_probes = n,
        &[1, 400],
        &[0, 401],
        "sandbox.warm.max_probes",
        "must be at least 1 and not above sample_jobs",
    );
    limits(
        |c, n| c.sandbox.warm.as_mut().unwrap().timeout_secs = n,
        &[60],
        &[59],
        "sandbox.warm.timeout_secs",
        "must be at least 60",
    );
    limits(
        |c, n| c.sandbox.slot_uid_base = n,
        &[65_536, 200_000, u32::MAX - 3],
        &[65_535, 0, u32::MAX - 2],
        "sandbox.slot_uid_base",
        "must be a subordinate UID range (at least 65536)",
    );
    limits(
        |c, n| c.sandbox.slot_gid_base = n,
        &[65_536, 200_000, u32::MAX - 3],
        &[65_535, 0, u32::MAX - 2],
        "sandbox.slot_gid_base",
        "must be a subordinate GID range (at least 65536)",
    );
}

#[test]
fn export_rules() {
    accepted(|c| c.export = None);
    let message = "must be an SSH URL of a GitHub repository (git@github.com:owner/name.git)";

    for repository in [
        "https://github.com/a/b.git",
        "git@github.com:a/b",
        "git@gitlab.com:a/b.git",
        "",
    ] {
        let edit = |c: &mut Config| c.export.as_mut().unwrap().repository = repository.into();
        rule(edit, "export.repository", message);
    }

    accepted(|c| c.export.as_mut().unwrap().repository = "git@github.com:a/b.git".into());

    for branch in ["", "a b", "a/b", "a.b"] {
        let edit = |c: &mut Config| c.export.as_mut().unwrap().branch = branch.into();
        rule(edit, "export.branch", "must be a plain branch name");
    }

    for branch in ["main", "gh-pages", "site_1"] {
        accepted(|c| c.export.as_mut().unwrap().branch = branch.into());
    }

    rule(
        |c| c.export.as_mut().unwrap().deploy_key = "key".into(),
        "export.deploy_key",
        ABSOLUTE,
    );
    limits(
        |c, n| c.export.as_mut().unwrap().interval_hours = n,
        &[1, 168],
        &[0, 169],
        "export.interval_hours",
        "must be between 1 and 168",
    );
}

#[test]
fn storage_fetcher_and_supervisor_rules() {
    limits(
        |c, n| c.storage.disk_alert_percent = n,
        &[50, 95],
        &[49, 96],
        "storage.disk_alert_percent",
        "must be between 50 and 95",
    );
    limits(
        |c, n| c.storage.raw_log_retention_days = n,
        &[1, 7],
        &[0],
        "storage.raw_log_retention_days",
        "must be at least 1",
    );
    rule(
        |c| c.fetcher.cargo_bin = "cargo".into(),
        "fetcher.cargo_bin",
        ABSOLUTE,
    );
    limits(
        |c, n| c.supervisor.interval_secs = n,
        &[5, 300],
        &[4, 301],
        "supervisor.interval_secs",
        "must be between 5 and 300",
    );
    limits(
        |c, n| c.supervisor.breaker_min_failures = n,
        &[1],
        &[0],
        "supervisor.breaker_min_failures",
        "must be at least 1",
    );
    limits(
        |c, n| c.supervisor.breaker_failure_percent = n,
        &[1, 100],
        &[0, 101],
        "supervisor.breaker_failure_percent",
        "must be between 1 and 100",
    );
    limits(
        |c, n| c.supervisor.breaker_window_secs = n,
        &[60],
        &[59],
        "supervisor.breaker_window_secs",
        "must be at least 60",
    );
    limits(
        |c, n| c.supervisor.breaker_cooldown_secs = n,
        &[30, 7200],
        &[29, 7201],
        "supervisor.breaker_cooldown_secs",
        "must be at least 30 and not above breaker_max_cooldown_secs",
    );
    limits(
        |c, n| c.supervisor.alert_repeat_hours = n,
        &[1],
        &[0],
        "supervisor.alert_repeat_hours",
        "must be at least 1",
    );
    limits(
        |c, n| c.supervisor.integrity_interval_minutes = n,
        &[1],
        &[0],
        "supervisor.integrity_interval_minutes",
        "must be at least 1",
    );
    let issues = issues_after(|c| c.supervisor.decoys = vec!["a".into(), "/b".into(), "c".into()]);

    let one = ("supervisor.decoys".to_owned(), ABSOLUTE.to_owned());

    assert_eq!(issues, [one.clone(), one]);
}

#[test]
fn ntfy_and_web_rules() {
    accepted(|c| c.ntfy = None);
    let ntfy = |server_url: Url, topic: &str| {
        Some(NtfyConfig {
            server_url,
            topic: topic.into(),
        })
    };

    let topic = "a".repeat(32);
    rule(|c| c.ntfy = ntfy(http(), &topic), "ntfy.server_url", HTTPS);
    let message = "must be 32 to 64 characters of [A-Za-z0-9_-]; the topic name is the password";

    let secure = |c: &mut Config, topic: &str| {
        c.ntfy = ntfy(Url::parse("https://ntfy.sh").unwrap(), topic);
    };

    for topic in [
        "a".repeat(31),
        "a".repeat(65),
        format!("{}!", "a".repeat(31)),
    ] {
        rule(|c| secure(c, &topic), "ntfy.topic", message);
    }

    for topic in [
        "a".repeat(32),
        "a".repeat(64),
        format!("{}-_", "a".repeat(30)),
    ] {
        accepted(|c| secure(c, &topic));
    }

    for listen in ["127.0.0.1:8080", "[::1]:8080", "127.5.5.5:1"] {
        accepted(|c| c.web.listen = listen.parse().unwrap());
    }

    for listen in ["0.0.0.0:8080", "10.77.0.1:8080", "[::]:8080"] {
        let message = "must be a loopback address, because the dashboard is reached through an SSH tunnel (ADR 0009)";
        rule(
            |c| c.web.listen = listen.parse().unwrap(),
            "web.listen",
            message,
        );
    }
}

fn break_the_common_rules(c: &mut Config) {
    c.instance.name.clear();
    c.instance.contact_email.clear();
    c.instance.data_dir = "data".into();
    c.instance.run_dir = "run".into();
    c.telemetry.log_filter.clear();
    c.database.url = "mysql://x".into();
    let crates = &mut c.crates_io;
    crates.user_agent = "curl".into();
    crates.index_url = http();
    crates.static_url = http();
    crates.rss_updates_url = http();
    crates.rss_new_crates_url = http();
    crates.db_dump_url = http();
    crates.static_requests_per_second = 0.0;
    crates.index_requests_per_second = 0.0;
    crates.rss_poll_interval_secs = 0;
    crates.db_dump_refresh_hours = 0;

    for stage in Stage::ALL {
        *stage_mut(c, stage) = StageConfig {
            lease_secs: 0,
            max_attempts: 0,
            max_infrastructure_retries: 5000,
            backoff_base_secs: 0,
            backoff_cap_secs: 0,
        };
    }

    c.triage.dynamic_deadline_hours = 0;
    c.storage.disk_alert_percent = 0;
    c.storage.raw_log_retention_days = 0;
    c.fetcher.cargo_bin = "cargo".into();
    let sup = &mut c.supervisor;
    sup.interval_secs = 0;
    sup.breaker_min_failures = 0;
    sup.breaker_failure_percent = 0;
    sup.breaker_window_secs = 0;
    sup.breaker_cooldown_secs = 0;
    sup.alert_repeat_hours = 0;
    sup.integrity_interval_minutes = 0;
    sup.decoys = vec!["a".into(), "b".into()];
    c.ntfy = Some(NtfyConfig {
        server_url: http(),
        topic: "short".into(),
    });
    c.web.listen = "0.0.0.0:1".parse().unwrap();
    let export = c.export.as_mut().unwrap();
    export.repository = "x".into();
    export.branch.clear();
    export.deploy_key = "key".into();
    export.interval_hours = 0;
}

fn break_the_sandbox_paths(c: &mut Config) {
    let s = &mut c.sandbox;
    s.firecracker_bin = "a".into();
    s.vmjail_bin = "b".into();
    s.fake_internet_bin = "c".into();
    s.fake_internet_authority = "d".into();
    s.kernel_image = "e".into();
    s.rootfs_image = "f".into();
    s.slots_dir = "g".into();
    s.check_timeout_secs = 0;
    s.memory_mib_per_slot = 0;
    s.scratch_mib_per_slot = 0;
    s.slot_uid_base = 0;
    s.slot_gid_base = 0;
    let warm = s.warm.as_mut().unwrap();
    warm.min_jobs = 0;
    warm.max_probes = 0;
    warm.timeout_secs = 0;
}

fn keys(issues: Vec<(String, String)>) -> Vec<String> {
    issues.into_iter().map(|(key, _)| key).collect()
}

/// The keys in the order the rules run, as words.
fn order(parts: &[&str]) -> Vec<String> {
    let words = parts.iter().flat_map(|part| part.split_whitespace());

    words.map(str::to_owned).collect()
}

const ORDER_BEFORE_SANDBOX: &str = concat!(
    "instance.name instance.contact_email instance.data_dir instance.run_dir telemetry.log_filter ",
    "database.url ",
    "crates_io.user_agent crates_io.index_url crates_io.static_url ",
    "crates_io.rss_updates_url crates_io.rss_new_crates_url crates_io.db_dump_url ",
    "crates_io.static_requests_per_second ",
    "crates_io.index_requests_per_second crates_io.rss_poll_interval_secs ",
    "crates_io.db_dump_refresh_hours ",
    "stages.fetch.lease_secs ",
    "stages.fetch.max_attempts stages.fetch.max_infrastructure_retries ",
    "stages.fetch.backoff_base_secs ",
    "stages.static_analysis.lease_secs stages.static_analysis.max_attempts ",
    "stages.static_analysis.max_infrastructure_retries ",
    "stages.static_analysis.backoff_base_secs ",
    "stages.sandbox.lease_secs stages.sandbox.max_attempts ",
    "stages.sandbox.max_infrastructure_retries stages.sandbox.backoff_base_secs ",
    "stages.analysis.lease_secs stages.analysis.max_attempts ",
    "stages.analysis.max_infrastructure_retries stages.analysis.backoff_base_secs ",
    "stages.finalize.lease_secs stages.finalize.max_attempts ",
    "stages.finalize.max_infrastructure_retries stages.finalize.backoff_base_secs ",
    "triage.dynamic_deadline_hours",
);

const ORDER_AFTER_SANDBOX: &str = concat!(
    "export.repository export.branch export.deploy_key export.interval_hours ",
    "storage.disk_alert_percent storage.raw_log_retention_days fetcher.cargo_bin ",
    "supervisor.interval_secs supervisor.breaker_min_failures ",
    "supervisor.breaker_failure_percent supervisor.breaker_window_secs ",
    "supervisor.breaker_cooldown_secs supervisor.alert_repeat_hours ",
    "supervisor.integrity_interval_minutes supervisor.decoys supervisor.decoys ",
    "ntfy.server_url ntfy.topic ",
    "web.listen",
);

const ORDER_SANDBOX: &str = concat!(
    "sandbox.slots sandbox.vcpus_per_slot ",
    "sandbox.memory_mib_per_slot sandbox.scratch_mib_per_slot ",
    "sandbox.check_timeout_secs sandbox.firecracker_bin sandbox.vmjail_bin ",
    "sandbox.fake_internet_bin sandbox.fake_internet_authority sandbox.kernel_image ",
    "sandbox.rootfs_image sandbox.slots_dir sandbox.warm.min_jobs ",
    "sandbox.warm.max_probes sandbox.warm.timeout_secs ",
    "sandbox.slot_uid_base sandbox.slot_gid_base",
);

#[test]
fn issues_come_in_rule_order() {
    let issues = issues_after(|c| {
        break_the_common_rules(c);
        break_the_sandbox_paths(c);
        c.sandbox.slots = 0;
        c.sandbox.vcpus_per_slot = 0;
    });

    let expected = order(&[ORDER_BEFORE_SANDBOX, ORDER_SANDBOX, ORDER_AFTER_SANDBOX]);
    assert_eq!(keys(issues), expected);
}
