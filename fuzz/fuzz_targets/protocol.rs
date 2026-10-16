#![cfg_attr(feature = "libfuzzer", no_main)]

use crateward_core::protocol::{Decoder, GuestMessage, HostMessage, Limits};
use crateward_fuzz::fuzz_target;

// The host decodes everything the guest sends: arbitrary bytes, split into
// arbitrary chunks, must never panic or allocate beyond the budget.
fuzz_target!(|data: &[u8]| {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };

    let chunk = usize::from(split).max(1);
    let mut guest = Decoder::<GuestMessage>::new(Limits::default());
    let mut host = Decoder::<HostMessage>::new(Limits::default());

    for piece in rest.chunks(chunk) {
        if guest.push(piece).is_err() {
            break;
        }

        while let Ok(Some(_)) = guest.next_message() {}

        if host.push(piece).is_ok() {
            while let Ok(Some(_)) = host.next_message() {}
        }
    }
});
