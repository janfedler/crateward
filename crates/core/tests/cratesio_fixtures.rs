//! The crates.io parsers against real data captured on 2026-09-24:
//! serde's complete sparse index file and the first 40 items of the
//! `updates.xml` feed.

#![cfg(feature = "cratesio")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crateward_core::cratesio::{find_version, parse_feed, parse_index_file};

const SERDE: &str = include_str!("fixtures/index-serde.txt");
const UPDATES: &str = include_str!("fixtures/rss-updates.xml");

#[test]
fn every_serde_version_parses() {
    let entries = parse_index_file(SERDE).unwrap();

    assert_eq!(entries.len(), SERDE.lines().count());
    assert!(entries.iter().all(|e| e.name.as_str() == "serde"));
    assert!(entries.iter().all(|e| e.published.is_some()));

    let latest = "1.0.229".parse().unwrap();
    let (entry, raw) = find_version(SERDE, &latest).unwrap().unwrap();

    assert_eq!(
        entry.cksum.to_string(),
        "4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba"
    );
    assert_eq!(raw["name"], "serde");
}

#[test]
fn the_live_feed_parses_without_rejections() {
    let feed = parse_feed(UPDATES).unwrap();

    assert_eq!(feed.items.len(), 40);
    assert_eq!(feed.rejected, 0);
}
