#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_fuzz::fuzz_target;
use crateward_guest_agent::btf::Btf;

// The agent trusts the running kernel's BTF, but a malformed blob must
// still be an error, not a panic or a hang.
fuzz_target!(|data: &[u8]| {
    if let Ok(btf) = Btf::parse(data) {
        for (_, name, member) in crateward_guest_agent::trace::OFFSETS {
            let _ = btf.offset(name, member);
        }
    }
});
