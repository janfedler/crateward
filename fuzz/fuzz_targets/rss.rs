#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_core::cratesio::parse_feed;
use crateward_fuzz::fuzz_target;

// The RSS feeds from crates.io.
fuzz_target!(|data: &[u8]| {
    let _ = parse_feed(&String::from_utf8_lossy(data));
});
