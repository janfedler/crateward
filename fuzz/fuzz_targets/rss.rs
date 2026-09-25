#![no_main]

use libfuzzer_sys::fuzz_target;
use crateward_core::cratesio::parse_feed;

// The RSS feeds from crates.io.
fuzz_target!(|data: &[u8]| {
    let _ = parse_feed(&String::from_utf8_lossy(data));
});
