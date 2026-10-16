#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_core::cratesio::parse_index_file;
use crateward_fuzz::fuzz_target;

// Sparse index files from crates.io.
fuzz_target!(|data: &[u8]| {
    let _ = parse_index_file(&String::from_utf8_lossy(data));
});
