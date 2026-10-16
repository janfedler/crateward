#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_core::report::findings::CodeContext;
use crateward_fuzz::fuzz_target;
use crateward_static_analysis::rust::scan_file;

// Rust source from any publisher, parsed with syn.
fuzz_target!(|data: &[u8]| {
    let _ = scan_file(
        "build.rs",
        &String::from_utf8_lossy(data),
        CodeContext::BuildScript,
    );
});
