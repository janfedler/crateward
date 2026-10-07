//! Little endian integers at an offset in untrusted bytes. Every reader
//! returns `None` when the bytes end early or the offset overflows.

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
}
