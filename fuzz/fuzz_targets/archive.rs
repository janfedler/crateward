#![no_main]

use libfuzzer_sys::fuzz_target;
use crateward_fetcher::archive::{ArchiveLimits, validate};

// Crate archives: gzip and tar from any publisher.
fuzz_target!(|data: &[u8]| {
    let limits = ArchiveLimits {
        max_unpacked_bytes: 8 * 1024 * 1024,
        ..ArchiveLimits::default()
    };
    let _ = validate(data, "demo", "1.0.0", &limits);
});
