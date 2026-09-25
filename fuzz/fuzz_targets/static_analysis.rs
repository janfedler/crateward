#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use crateward_static_analysis::analyze::{AnalyzeLimits, analyze};
use crateward_static_analysis::yara::Rules;

static RULES: OnceLock<Rules> = OnceLock::new();

// A whole crate: tar parsing, manifest, syn and YARA-X together.
fuzz_target!(|data: &[u8]| {
    let rules = RULES.get_or_init(|| Rules::builtin().expect("the built in rules compile"));
    let _ = analyze(data, rules, &AnalyzeLimits::default());
});
