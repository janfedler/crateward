#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_fuzz::fuzz_target;
use crateward_orchestrator::payload::stub_manifest;

// Published manifests, rewritten into stubs for the warm build.
fuzz_target!(|data: &[u8]| {
    let _ = stub_manifest(data);
});
