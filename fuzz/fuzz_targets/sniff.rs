#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_fake_internet::sniff::{content_length, http_header_end, sniff};
use crateward_fuzz::fuzz_target;

// The first bytes of every guest connection.
fuzz_target!(|data: &[u8]| {
    let _ = sniff(data);
    if let Some(end) = http_header_end(data) {
        let _ = content_length(data.get(..end).unwrap_or_default());
    }
});
