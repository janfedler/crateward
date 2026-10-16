//! One `fuzz_target!` for both engines, so every target builds with
//! `cargo fuzz` (feature `libfuzzer`, the default) and with `cargo afl`
//! (feature `afl`, without default features).

#[cfg(all(feature = "libfuzzer", feature = "afl"))]
compile_error!("enable exactly one of the features libfuzzer and afl");

#[cfg(not(any(feature = "libfuzzer", feature = "afl")))]
compile_error!("enable one of the features libfuzzer and afl");

#[cfg(feature = "afl")]
pub use afl;
#[cfg(feature = "libfuzzer")]
pub use libfuzzer_sys;

/// Defines the target's entry point for the enabled engine. Each target
/// starts with `#![cfg_attr(feature = "libfuzzer", no_main)]`, because
/// libFuzzer brings its own `main` and AFL++ does not.
#[macro_export]
macro_rules! fuzz_target {
    (|$data:ident: &[u8]| $body:block) => {
        #[cfg(feature = "libfuzzer")]
        $crate::libfuzzer_sys::fuzz_target!(|$data: &[u8]| $body);

        #[cfg(feature = "afl")]
        fn main() {
            $crate::afl::fuzz!(|$data: &[u8]| $body);
        }
    };
}
