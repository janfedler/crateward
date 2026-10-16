#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_fake_internet::dns::{answer, parse_query};
use crateward_fuzz::fuzz_target;

// Every DNS query of the guest reaches this parser.
fuzz_target!(|data: &[u8]| {
    if let Some(question) = parse_query(data) {
        let _ = answer(data, &question, std::net::Ipv4Addr::new(10, 0, 2, 1));
    }
});
