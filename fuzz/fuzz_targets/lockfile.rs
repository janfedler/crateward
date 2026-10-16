#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_fetcher::resolve::locked_packages;
use crateward_fuzz::fuzz_target;

// Lockfiles cargo wrote for a hostile manifest.
fuzz_target!(|data: &[u8]| {
    let _ = locked_packages(&String::from_utf8_lossy(data));
});
