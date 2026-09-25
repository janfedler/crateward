#![no_main]

use libfuzzer_sys::fuzz_target;
use crateward_fetcher::resolve::locked_packages;

// Lockfiles cargo wrote for a hostile manifest.
fuzz_target!(|data: &[u8]| {
    let _ = locked_packages(&String::from_utf8_lossy(data));
});
