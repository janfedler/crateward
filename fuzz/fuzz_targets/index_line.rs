#![no_main]

use libfuzzer_sys::fuzz_target;
use crateward_core::cratesio::parse_index_file;

// Sparse index files from crates.io.
fuzz_target!(|data: &[u8]| {
    let _ = parse_index_file(&String::from_utf8_lossy(data));
});
