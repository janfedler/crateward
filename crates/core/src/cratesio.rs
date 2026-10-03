//! Parsers for the crates.io data sources Crateward reads.
//!
//! * Sparse index files: one JSON object per published version, as
//!   specified in the Cargo book (`reference/registry-index.md`). Parsing
//!   ignores unknown fields, because the format grows over time, and applies
//!   the defaults Cargo documents for missing ones.
//! * The RSS feeds `updates.xml` and `crates.xml`, which list the last 60
//!   minutes of publishes (crates.io data access policy).
//!
//! Everything here is pure. Fetching lives in the feed and fetcher. Input is
//! bounded before parsing, and every name, version and checksum is
//! validated into its typed form, so the rest of the pipeline never handles
//! raw strings from the network.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::digest::Sha256Digest;
use crate::name::CrateName;

/// Largest index file accepted. The biggest crates have a few thousand
/// versions. This leaves a wide margin while bounding memory.
pub const MAX_INDEX_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Largest RSS document accepted.
pub const MAX_FEED_BYTES: usize = 16 * 1024 * 1024;

/// Why crates.io data could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input is larger than allowed.
    #[error("input of {len} bytes exceeds the limit of {max}")]
    TooLarge {
        /// Input length.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// A line of an index file is not a valid entry.
    #[error("index line {line}: {reason}")]
    IndexLine {
        /// Line number, counting from 1.
        line: usize,
        /// What is wrong.
        reason: String,
    },
    /// The RSS document is not well formed.
    #[error("feed: {0}")]
    Feed(String),
}

/// The kind of a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyKind {
    /// A normal dependency.
    #[default]
    Normal,
    /// A build dependency: compiled for the host and run by build scripts.
    Build,
    /// A development dependency, used only by tests and examples.
    Dev,
}

fn default_true() -> bool {
    true
}

/// One dependency of an index entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDependency {
    /// Name as used in the dependent's code (the alias if renamed).
    pub name: String,
    /// Version requirement.
    pub req: String,
    /// Features enabled on the dependency.
    #[serde(default)]
    pub features: Vec<String>,
    /// Whether the dependency is optional.
    #[serde(default)]
    pub optional: bool,
    /// Whether default features are enabled.
    #[serde(default = "default_true")]
    pub default_features: bool,
    /// Platform restriction such as `cfg(windows)`.
    #[serde(default)]
    pub target: Option<String>,
    /// Dependency kind. `null` means normal.
    #[serde(default)]
    pub kind: Option<DependencyKind>,
    /// Registry of the dependency. `null` means crates.io itself.
    #[serde(default)]
    pub registry: Option<String>,
    /// The real package name if the dependency is renamed.
    #[serde(default)]
    pub package: Option<String>,
}

impl IndexDependency {
    /// The dependency kind, with the documented default.
    #[must_use]
    pub fn kind(&self) -> DependencyKind {
        self.kind.unwrap_or_default()
    }

    /// The crate this dependency refers to, whether renamed or not.
    #[must_use]
    pub fn package_name(&self) -> &str {
        self.package.as_deref().unwrap_or(&self.name)
    }
}

/// The raw form of one index line, before validation.
#[derive(Debug, Clone, Deserialize)]
struct RawEntry {
    name: String,
    vers: String,
    #[serde(default)]
    deps: Vec<IndexDependency>,
    cksum: String,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    features2: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    links: Option<String>,
    #[serde(default)]
    v: Option<u32>,
    #[serde(default)]
    rust_version: Option<String>,
    #[serde(default)]
    pubtime: Option<String>,
}

/// One published version, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Crate name exactly as published. Downloads need this casing.
    pub name: CrateName,
    /// The version.
    pub version: semver::Version,
    /// Direct dependencies.
    pub deps: Vec<IndexDependency>,
    /// SHA-256 of the `.crate` file.
    pub cksum: Sha256Digest,
    /// Features, with `features2` merged in as Cargo does.
    pub features: BTreeMap<String, Vec<String>>,
    /// Whether the version is yanked.
    pub yanked: bool,
    /// The `links` key: a sign of a native library and usually of a build
    /// script.
    pub links: Option<String>,
    /// Schema version of the entry (1 if absent).
    pub schema: u32,
    /// Minimum supported Rust version, if declared.
    pub rust_version: Option<String>,
    /// Publish time, if the entry has one.
    pub published: Option<SystemTime>,
}

impl IndexEntry {
    /// Whether any dependency is a build dependency, which runs at build
    /// time on the host.
    #[must_use]
    pub fn has_build_dependencies(&self) -> bool {
        self.deps.iter().any(|d| d.kind() == DependencyKind::Build)
    }

    /// Whether any dependency comes from another registry. crates.io does
    /// not allow this for published crates, so it is an anomaly.
    #[must_use]
    pub fn has_foreign_registry_dependency(&self) -> bool {
        self.deps.iter().any(|d| d.registry.is_some())
    }
}

/// Parses `yyyy-mm-ddThh:mm:ssZ`, the documented `pubtime` format.
#[must_use]
pub fn parse_pubtime(text: &str) -> Option<SystemTime> {
    let b = text.as_bytes();
    if b.len() != 20
        || b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
        || b.get(19) != Some(&b'Z')
    {
        return None;
    }

    let num = |from: usize, to: usize| text.get(from..to)?.parse::<u32>().ok();
    let (year, month, day) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (hour, minute, second) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);

    unix_time(year, month, day, hour, minute, second)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`), then seconds.
fn unix_time(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<SystemTime> {
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    let secs = u64::try_from(secs).ok()?;

    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

fn validate(raw: RawEntry) -> Result<IndexEntry, String> {
    let name = CrateName::parse(&raw.name).map_err(|e| e.to_string())?;
    let version = semver::Version::parse(&raw.vers).map_err(|e| format!("version: {e}"))?;
    let cksum = raw.cksum.parse().map_err(|e| format!("cksum: {e}"))?;
    let mut features = raw.features;
    if let Some(extra) = raw.features2 {
        for (feature, enables) in extra {
            features.entry(feature).or_default().extend(enables);
        }
    }

    let published = match raw.pubtime.as_deref() {
        Some(text) => Some(parse_pubtime(text).ok_or_else(|| format!("pubtime {text:?}"))?),
        None => None,
    };

    Ok(IndexEntry {
        name,
        version,
        deps: raw.deps,
        cksum,
        features,
        yanked: raw.yanked,
        links: raw.links,
        schema: raw.v.unwrap_or(1),
        rust_version: raw.rust_version,
        published,
    })
}

/// Parses a whole sparse index file.
///
/// # Errors
///
/// Fails if the file is too large or any line is invalid. A single bad line
/// rejects the file, because an index file is written by crates.io and a
/// malformed one is an anomaly worth surfacing.
pub fn parse_index_file(text: &str) -> Result<Vec<IndexEntry>, ParseError> {
    if text.len() > MAX_INDEX_FILE_BYTES {
        return Err(ParseError::TooLarge {
            len: text.len(),
            max: MAX_INDEX_FILE_BYTES,
        });
    }

    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            let fail = |reason: String| ParseError::IndexLine {
                line: index + 1,
                reason,
            };

            let raw: RawEntry = serde_json::from_str(line).map_err(|e| fail(e.to_string()))?;
            validate(raw).map_err(fail)
        })
        .collect()
}

/// Finds one version in an index file and returns it with its raw JSON line,
/// which the job row keeps as served.
///
/// # Errors
///
/// Fails like [`parse_index_file`].
pub fn find_version(
    text: &str,
    version: &semver::Version,
) -> Result<Option<(IndexEntry, serde_json::Value)>, ParseError> {
    let entries = parse_index_file(text)?;
    let Some(position) = entries.iter().position(|e| &e.version == version) else {
        return Ok(None);
    };

    let line = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .nth(position)
        .unwrap_or_default();
    let raw = serde_json::from_str(line).map_err(|e| ParseError::IndexLine {
        line: position + 1,
        reason: e.to_string(),
    })?;

    Ok(entries.into_iter().nth(position).map(|entry| (entry, raw)))
}

/// The download URL of a version, from the `dl` value of the index's
/// `config.json`. crates.io's value has no markers, so Cargo appends
/// `/{crate}/{version}/download`. The name must keep its published casing.
#[must_use]
pub fn download_url(dl: &str, name: &CrateName, version: &semver::Version) -> String {
    let lower = name.as_str().to_ascii_lowercase();
    let prefix = |lowercase: bool| {
        let source = if lowercase {
            lower.as_str()
        } else {
            name.as_str()
        };

        match source.len() {
            1 => "1".to_owned(),
            2 => "2".to_owned(),
            3 => format!("3/{}", source.get(..1).unwrap_or_default()),
            _ => format!(
                "{}/{}",
                source.get(..2).unwrap_or_default(),
                source.get(2..4).unwrap_or_default()
            ),
        }
    };

    let markers = [
        "{crate}",
        "{version}",
        "{prefix}",
        "{lowerprefix}",
        "{sha256-checksum}",
    ];

    if markers.iter().any(|m| dl.contains(m)) {
        dl.replace("{crate}", name.as_str())
            .replace("{version}", &version.to_string())
            .replace("{prefix}", &prefix(false))
            .replace("{lowerprefix}", &prefix(true))
    } else {
        format!("{}/{}/{}/download", dl.trim_end_matches('/'), name, version)
    }
}

/// One item of an RSS feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedItem {
    /// The crate, as named in the feed.
    pub name: CrateName,
    /// The version. `updates.xml` always has one. `crates.xml` (new
    /// crates) has none, as observed on 2026-09-24.
    pub version: Option<semver::Version>,
}

/// Result of parsing a feed: valid items and the number of items dropped
/// because a field was missing or invalid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Feed {
    /// Valid items, in document order.
    pub items: Vec<FeedItem>,
    /// Items dropped as invalid.
    pub rejected: usize,
}

/// Parses `updates.xml` or `crates.xml`: the `crates:name` and, where
/// present, `crates:version` of every `item`. An item is rejected when its
/// name is missing or invalid, or its version is present but invalid.
///
/// # Errors
///
/// Fails if the document is too large or not well formed XML.
pub fn parse_feed(xml: &str) -> Result<Feed, ParseError> {
    use quick_xml::events::Event;

    if xml.len() > MAX_FEED_BYTES {
        return Err(ParseError::TooLarge {
            len: xml.len(),
            max: MAX_FEED_BYTES,
        });
    }

    let mut reader = quick_xml::Reader::from_str(xml);
    let mut feed = Feed::default();
    let mut in_item = false;
    let mut field: Option<&'static str> = None;
    let (mut name, mut version) = (None::<String>, None::<String>);

    loop {
        match reader
            .read_event()
            .map_err(|e| ParseError::Feed(e.to_string()))?
        {
            Event::Start(tag) => match tag.name().as_ref() {
                "item" => {
                    in_item = true;
                    name = None;
                    version = None;
                }
                "crates:name" if in_item => field = Some("name"),
                "crates:version" if in_item => field = Some("version"),
                _ => field = None,
            },
            Event::Text(text) => {
                if let Some(which) = field {
                    // Entity references arrive as separate events in
                    // `quick-xml` 0.42, so the raw text is the text itself.
                    // Crate names and versions never contain any.
                    let value = text.into_inner().trim().to_owned();
                    match which {
                        "name" => name = Some(value),
                        _ => version = Some(value),
                    }
                }
            }
            Event::End(tag) => {
                field = None;

                if tag.name().as_ref() == "item" {
                    in_item = false;

                    match feed_item(name.take(), version.take()) {
                        Some(item) => feed.items.push(item),
                        None => feed.rejected += 1,
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(feed)
}

/// The item of a finished `item` element, or `None` if its name is missing
/// or invalid or its version is present but invalid.
fn feed_item(name: Option<String>, version: Option<String>) -> Option<FeedItem> {
    let version = version
        .map(|v| semver::Version::parse(&v))
        .transpose()
        .ok()?;

    Some(FeedItem {
        name: CrateName::parse(&name?).ok()?,
        version,
    })
}

/// The manifest of the consumer probe: a package that depends on exactly
/// one version, the way a victim would pull it in (ADR 0004). The fetcher
/// resolves it and the microVM builds it, so both see the same dependency
/// graph. The dependency is renamed to a fixed key so that no crate name is
/// ever interpreted as manifest syntax beyond a quoted string, and the
/// library lives in `lib.rs` next to the manifest.
#[must_use]
pub fn probe_manifest(name: &CrateName, version: &semver::Version) -> String {
    format!(
        "[package]\nname = \"crateward-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n\
         [lib]\npath = \"lib.rs\"\n\n\
         [dependencies]\ntarget = {{ package = \"{name}\", version = \"={version}\" }}\n"
    )
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const SERDE_LINE: &str = r#"{"name":"serde","vers":"1.0.229","deps":[{"name":"serde_core","req":"=1.0.229","features":["result"],"optional":false,"default_features":false,"target":null,"kind":"normal"},{"name":"serde_derive","req":"^1","features":[],"optional":true,"default_features":true,"target":null,"kind":"normal"}],"cksum":"4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba","features":{"default":["std"],"derive":["serde_derive"]},"yanked":false,"rust_version":"1.56","pubtime":"2026-07-18T23:05:13Z"}"#;

    #[test]
    fn parses_a_real_index_line() {
        let entries = parse_index_file(SERDE_LINE).unwrap();
        let e = &entries[0];

        assert_eq!(e.name.as_str(), "serde");
        assert_eq!(e.version.to_string(), "1.0.229");
        assert_eq!(e.deps.len(), 2);
        assert!(!e.has_build_dependencies());
        assert_eq!(e.schema, 1);

        let secs = e
            .published
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 2026-07-18T23:05:13Z
        assert_eq!(secs, 1_784_415_913);
    }

    #[test]
    fn applies_documented_defaults_and_merges_features2() {
        let line = r#"{"name":"a","vers":"0.1.0","deps":[{"name":"cc","req":"^1","kind":"build"}],"cksum":"00000000000000000000000000000000000000000000000000000000000000ff","features":{},"features2":{"x":["dep:cc"]},"v":2}"#;
        let e = &parse_index_file(line).unwrap()[0];

        assert!(e.deps[0].default_features);
        assert!(!e.deps[0].optional);
        assert!(e.has_build_dependencies());
        assert_eq!(e.features["x"], vec!["dep:cc".to_owned()]);
        assert_eq!(e.schema, 2);
        assert_eq!(e.published, None);
    }

    #[test]
    fn rejects_invalid_names_versions_and_checksums() {
        for line in [
            r#"{"name":"../x","vers":"1.0.0","cksum":"00000000000000000000000000000000000000000000000000000000000000ff"}"#,
            r#"{"name":"x","vers":"one","cksum":"00000000000000000000000000000000000000000000000000000000000000ff"}"#,
            r#"{"name":"x","vers":"1.0.0","cksum":"zz"}"#,
            r#"{"name":"x","vers":"1.0.0","cksum":"00000000000000000000000000000000000000000000000000000000000000ff","pubtime":"yesterday"}"#,
        ] {
            assert!(parse_index_file(line).is_err(), "{line}");
        }
    }

    #[test]
    fn finds_a_version_with_its_raw_line() {
        let other = SERDE_LINE.replace("1.0.229", "1.0.228");
        let file = format!("{other}\n{SERDE_LINE}\n");
        let wanted = semver::Version::parse("1.0.229").unwrap();
        let (entry, raw) = find_version(&file, &wanted).unwrap().unwrap();

        assert_eq!(entry.version, wanted);
        assert_eq!(raw["vers"], "1.0.229");
        assert!(
            find_version(&file, &semver::Version::parse("9.9.9").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn download_urls_keep_the_published_casing() {
        let name = CrateName::parse("Inflector").unwrap();
        let v = semver::Version::parse("0.11.4").unwrap();

        assert_eq!(
            download_url("https://static.crates.io/crates", &name, &v),
            "https://static.crates.io/crates/Inflector/0.11.4/download"
        );
        assert_eq!(
            download_url("https://x/{lowerprefix}/{crate}-{version}", &name, &v),
            "https://x/in/fl/Inflector-0.11.4"
        );
    }

    #[test]
    fn parses_the_rss_feed_and_counts_bad_items() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:crates="https://crates.io/"><channel><title>t</title>
<item><title>New crate version published: onevcs v0.32.1</title>
<description><![CDATA[text with <b>tags</b>]]></description>
<crates:name>onevcs</crates:name><crates:version>0.32.1</crates:version></item>
<item><crates:name>../evil</crates:name><crates:version>1.0.0</crates:version></item>
<item><crates:name>novers</crates:name></item>
<item><crates:name>badvers</crates:name><crates:version>one</crates:version></item>
</channel></rss>"#;
        let feed = parse_feed(xml).unwrap();

        assert_eq!(feed.items.len(), 2);
        assert_eq!(feed.items[0].name.as_str(), "onevcs");
        assert_eq!(feed.items[1].version, None);
        assert_eq!(feed.rejected, 2);
    }

    fn feed_of(items: &str) -> Feed {
        let xml =
            format!("<rss xmlns:crates=\"https://crates.io/\"><channel>{items}</channel></rss>");

        parse_feed(&xml).unwrap()
    }

    fn pairs(feed: &Feed) -> Vec<(&str, Option<String>)> {
        let version = |i: &FeedItem| i.version.as_ref().map(ToString::to_string);
        feed.items
            .iter()
            .map(|i| (i.name.as_str(), version(i)))
            .collect()
    }

    #[test]
    fn feed_fields_are_trimmed_and_may_come_in_any_order() {
        let feed = feed_of(
            "<item><crates:version> 1.2.3\n</crates:version><crates:name>\n  serde </crates:name></item>",
        );

        assert_eq!(pairs(&feed), [("serde", Some("1.2.3".to_owned()))]);
        assert_eq!(feed.rejected, 0);
    }

    #[test]
    fn feed_fields_outside_an_item_are_ignored() {
        let feed = feed_of(
            "<crates:name>stray</crates:name><crates:version>9.9.9</crates:version>\
             <item><crates:name>real</crates:name></item>",
        );

        assert_eq!(pairs(&feed), [("real", None)]);
        assert_eq!(feed.rejected, 0);
    }

    #[test]
    fn feed_items_do_not_share_fields() {
        let feed = feed_of(
            "<item><crates:name>a</crates:name><crates:version>1.0.0</crates:version></item>\
             <item><crates:name>b</crates:name></item>\
             <item><crates:version>2.0.0</crates:version></item>\
             <item></item>\
             <item><crates:name>c</crates:name><crates:version>x</crates:version></item>",
        );

        assert_eq!(pairs(&feed), [("a", Some("1.0.0".to_owned())), ("b", None)]);
        assert_eq!(feed.rejected, 3);
    }

    #[test]
    fn feed_that_is_too_large_or_broken_is_an_error() {
        let big = " ".repeat(MAX_FEED_BYTES + 1);

        assert!(matches!(parse_feed(&big), Err(ParseError::TooLarge { .. })));
        assert!(matches!(
            parse_feed("<rss><item></rss>"),
            Err(ParseError::Feed(_))
        ));
    }

    #[test]
    fn pubtime_rejects_impossible_values() {
        assert!(parse_pubtime("2026-13-01T00:00:00Z").is_none());
        assert!(parse_pubtime("2026-01-01 00:00:00Z").is_none());
        assert_eq!(parse_pubtime("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
    }

    proptest! {
        #[test]
        fn index_parser_never_panics(text in "\\PC{0,400}") {
            let _ = parse_index_file(&text);
        }

        #[test]
        fn feed_parser_never_panics(text in "\\PC{0,400}") {
            let _ = parse_feed(&text);
        }

        #[test]
        fn pubtime_round_trips_through_unix_time(secs in 0_u64..253_402_300_799) {
            // Format a time and parse it back.
            let days = secs / 86_400;
            let rem = secs % 86_400;

            // civil_from_days (Howard Hinnant).
            let z = i64::try_from(days).unwrap() + 719_468;
            let era = z.div_euclid(146_097);
            let doe = z - era * 146_097;
            let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
            let y = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = if m <= 2 { y + 1 } else { y };
            let text = format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60);
            let parsed = parse_pubtime(&text).unwrap();
            prop_assert_eq!(parsed.duration_since(UNIX_EPOCH).unwrap().as_secs(), secs);
        }
    }
}
