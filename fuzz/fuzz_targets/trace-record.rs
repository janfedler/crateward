#![no_main]

use libfuzzer_sys::fuzz_target;
use crateward_guest_agent::trace::decode;

// Records from the ring buffer, which guest root could forge.
fuzz_target!(|data: &[u8]| {
    let _ = decode(data, 0);
});
