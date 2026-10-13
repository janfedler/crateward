//! Little endian integers at an offset in untrusted bytes, and hex
//! encoding. Every reader returns `None` when the bytes end early or the
//! offset overflows.

use std::fmt::Write as _;

/// The `N` bytes at `at`.
fn array<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// The `u16` at `at`.
#[must_use]
pub fn u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    array(bytes, at).map(u16::from_le_bytes)
}

/// The `u32` at `at`.
#[must_use]
pub fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    array(bytes, at).map(u32::from_le_bytes)
}

/// The `i32` at `at`.
#[must_use]
pub fn i32_le(bytes: &[u8], at: usize) -> Option<i32> {
    array(bytes, at).map(i32::from_le_bytes)
}

/// The `u64` at `at`.
#[must_use]
pub fn u64_le(bytes: &[u8], at: usize) -> Option<u64> {
    array(bytes, at).map(u64::from_le_bytes)
}

/// Lowercase hex encoding of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }

    out
}

/// Decodes [`hex`] output. Invalid input gives `None`.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();

    if !rest.is_empty() {
        return None;
    }

    pairs
        .iter()
        .map(|[a, b]| {
            let digit = |c: u8| char::from(c).to_digit(16);
            u8::try_from(digit(*a)? * 16 + digit(*b)?).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_refuses_short_input() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8];

        assert_eq!(u16_le(&bytes, 0), Some(0x0201));
        assert_eq!(u32_le(&bytes, 4), Some(0x0807_0605));
        assert_eq!(i32_le(&[0xff; 4], 0), Some(-1));
        assert_eq!(u64_le(&bytes, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(u32_le(&bytes, 5), None);
        assert_eq!(u16_le(&bytes, usize::MAX), None);
    }

    #[test]
    fn hex_round_trips() {
        let data = b"\x00\xffabc";

        assert_eq!(hex(data), "00ff616263");
        assert_eq!(unhex(&hex(data)), Some(data.to_vec()));
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}
