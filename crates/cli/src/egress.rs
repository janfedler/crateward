//! The egress allowlist (ARCHITECTURE.md, "Egress"): which service user may
//! reach which host, taken from the configuration so the firewall cannot
//! drift from it. `crateward egress` resolves the hosts and prints an
//! nftables script that adds the addresses to the sets of the `crateward`
//! table, which `deploy/nftables/crateward.nft` defines. A root timer
//! pipes it into `nft -f -` every few minutes. CDNs answer each lookup
//! with a few of many addresses, so elements are not flushed but expire
//! an hour after they were last seen: the sets hold what the services' own
//! lookups may have returned recently.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::{IpAddr, ToSocketAddrs as _};

use crateward_core::config::Config;

/// Hosts the weekly image build downloads from: the pinned Rust toolchain,
/// the Debian snapshot the root filesystem is built from, and the kernel
/// and Firecracker sources (`guest/`).
const BUILDER_HOSTS: &[&str] = &[
    "static.rust-lang.org",
    "snapshot.debian.org",
    "cdn.kernel.org",
    "github.com",
    "objects.githubusercontent.com",
];

/// One set of the table: a service user's destinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowance {
    /// The set's name prefix, also the role in the nftables file.
    pub role: &'static str,
    /// Host names to resolve.
    pub hosts: BTreeSet<String>,
}

fn host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next()?;

    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Who may reach what, from the configuration.
#[must_use]
pub fn allowances(config: &Config) -> Vec<Allowance> {
    let cio = &config.crates_io;
    let collect = |urls: &[&str]| urls.iter().filter_map(|u| host(u)).collect();
    let feed = collect(&[
        cio.index_url.as_str(),
        cio.rss_updates_url.as_str(),
        cio.rss_new_crates_url.as_str(),
        cio.db_dump_url.as_str(),
    ]);

    // Nothing calls the crates.io API, so its host stays closed.
    // The fetcher downloads from the `dl` URL of the index's config.json,
    // which is the static host.
    let fetcher = collect(&[cio.index_url.as_str(), cio.static_url.as_str()]);
    let mut supervisor: BTreeSet<String> = BTreeSet::new();
    if let Some(ntfy) = &config.ntfy {
        supervisor.extend(host(ntfy.server_url.as_str()));
    }

    // `git@github.com:owner/name.git`
    let api = config
        .export
        .as_ref()
        .and_then(|e| e.repository.split_once('@'))
        .and_then(|(_, rest)| rest.split_once(':'))
        .map(|(host, _)| host.to_ascii_lowercase())
        .into_iter()
        .collect();

    vec![
        Allowance {
            role: "feed",
            hosts: feed,
        },
        Allowance {
            role: "fetcher",
            hosts: fetcher,
        },
        Allowance {
            role: "supervisor",
            hosts: supervisor,
        },
        Allowance {
            role: "api",
            hosts: api,
        },
        Allowance {
            role: "builder",
            hosts: BUILDER_HOSTS.iter().map(|h| (*h).to_owned()).collect(),
        },
    ]
}

/// Resolves every host. A host that does not resolve is reported and left
/// out, so one failing name does not empty the other sets.
pub fn resolve(allowances: &[Allowance]) -> (Vec<(&'static str, BTreeSet<IpAddr>)>, Vec<String>) {
    let mut errors = Vec::new();
    let sets = allowances
        .iter()
        .map(|a| {
            let mut addresses = BTreeSet::new();
            for host in &a.hosts {
                match (host.as_str(), 443).to_socket_addrs() {
                    Ok(found) => addresses.extend(found.map(|s| s.ip())),
                    Err(error) => errors.push(format!("{host}: {error}")),
                }
            }

            (a.role, addresses)
        })
        .collect();

    (sets, errors)
}

/// How long an address stays allowed after the last lookup returned it.
const ELEMENT_TIMEOUT: &str = "1h";

/// The nftables script that refreshes the sets in one transaction.
#[must_use]
pub fn render(sets: &[(&'static str, BTreeSet<IpAddr>)]) -> String {
    let mut out = String::new();

    for (role, addresses) in sets {
        for (family, v4) in [("v4", true), ("v6", false)] {
            let found: Vec<&IpAddr> = addresses.iter().filter(|a| a.is_ipv4() == v4).collect();
            if found.is_empty() {
                continue;
            }

            // `add` leaves the timeout of an existing element alone, so each
            // element is destroyed (nothing happens when it is absent) and added again
            // (checked with nftables 1.1.3).
            let plain: Vec<String> = found.iter().map(ToString::to_string).collect();
            let timed: Vec<String> = found
                .iter()
                .map(|a| format!("{a} timeout {ELEMENT_TIMEOUT}"))
                .collect();

            let set = format!("inet crateward {role}_{family}");
            let _ = writeln!(out, "destroy element {set} {{ {} }}", plain.join(", "));
            let _ = writeln!(out, "add element {set} {{ {} }}", timed.join(", "));
        }
    }

    out
}

/// Prints the script for the configured hosts. A host that does not resolve
/// is reported on stderr and left out.
pub fn run(config: &Config) {
    let (sets, errors) = resolve(&allowances(config));

    for error in &errors {
        eprintln!("not resolved: {error}");
    }

    // A host that stops resolving ages out of its set.
    out!("{}", render(&sets).trim_end());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_come_from_urls() {
        assert_eq!(
            host("https://static.crates.io/rss/updates.xml").as_deref(),
            Some("static.crates.io")
        );
        assert_eq!(host("https://ntfy.sh").as_deref(), Some("ntfy.sh"));
        assert_eq!(
            host("https://user@Ntfy.SH:443/x").as_deref(),
            Some("ntfy.sh")
        );
        assert_eq!(host("https:///x"), None);
    }

    #[test]
    fn addresses_are_added_per_family_and_expire() {
        let sets = vec![(
            "fetcher",
            ["192.0.2.1", "2001:db8::1", "192.0.2.2"]
                .iter()
                .map(|a| a.parse().unwrap())
                .collect(),
        )];

        assert_eq!(
            render(&sets),
            "destroy element inet crateward fetcher_v4 { 192.0.2.1, 192.0.2.2 }\n\
             add element inet crateward fetcher_v4 \
             { 192.0.2.1 timeout 1h, 192.0.2.2 timeout 1h }\n\
             destroy element inet crateward fetcher_v6 { 2001:db8::1 }\n\
             add element inet crateward fetcher_v6 { 2001:db8::1 timeout 1h }\n"
        );
    }

    #[test]
    fn the_example_configuration_allows_what_the_architecture_lists() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/crateward.example.toml"
        );

        let config = Config::load(std::path::Path::new(path)).unwrap();
        let get = |role: &str| {
            allowances(&config)
                .into_iter()
                .find(|a| a.role == role)
                .unwrap()
                .hosts
                .into_iter()
                .collect::<Vec<_>>()
        };

        assert_eq!(get("fetcher"), ["index.crates.io", "static.crates.io"]);
        assert_eq!(get("feed"), ["index.crates.io", "static.crates.io"]);
        assert_eq!(get("supervisor"), ["ntfy.sh"]);
        assert_eq!(get("api"), ["github.com"]);
    }
}
