#![no_main]

use libfuzzer_sys::fuzz_target;
use crateward_fake_internet::dns::{answer, parse_query};

// Every DNS query of the guest reaches this parser.
fuzz_target!(|data: &[u8]| {
    if let Some(question) = parse_query(data) {
        let _ = answer(data, &question, std::net::Ipv4Addr::new(10, 0, 2, 1));
    }
});
