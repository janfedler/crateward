//! SHA-256 digests as published in the crates.io index (`cksum`) and the
//! database dump (`versions.tar_sha256`).
//!
//! The fetcher compares the digest of every downloaded `.crate` file with the
//! index entry before anything else touches the bytes. Keeping the digest as a
//! fixed size array rather than a string makes that comparison exact and
//! avoids case or whitespace surprises.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Why a string is not a valid hex encoded SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    /// The input does not have exactly 64 characters.
    #[error("expected 64 hex characters, found {len}")]
    WrongLength {
        /// Length of the rejected input in bytes.
        len: usize,
    },
    /// The input contains a character that is not a hex digit.
    #[error("invalid hex digit at byte {index}")]
    InvalidHex {
        /// Byte offset of the first offending character.
        index: usize,
    },
}

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl FromStr for Sha256Digest {
    type Err = DigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(DigestError::WrongLength { len: s.len() });
        }

        let mut out = [0_u8; 32];
        let (pairs, _) = s.as_bytes().as_chunks::<2>();

        for (i, (slot, [hi, lo])) in out.iter_mut().zip(pairs).enumerate() {
            let hi = hex_value(*hi).ok_or(DigestError::InvalidHex { index: 2 * i })?;
            let lo = hex_value(*lo).ok_or(DigestError::InvalidHex { index: 2 * i + 1 })?;
            *slot = (hi << 4) | lo;
        }

        Ok(Self(out))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn parses_the_index_documentation_example() {
        let hex = "d867001db0e2b6e0496f9fac96930e2d42233ecd3ca0413e0753d4c7695d289c";
        let digest: Sha256Digest = hex.parse().unwrap();

        assert_eq!(digest.to_string(), hex);
    }

    #[test]
    fn uppercase_input_is_normalized() {
        let digest: Sha256Digest = "AB".repeat(32).parse().unwrap();

        assert_eq!(digest.to_string(), "ab".repeat(32));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(
            "abc".parse::<Sha256Digest>(),
            Err(DigestError::WrongLength { len: 3 })
        );

        let mut bad = "0".repeat(64);
        bad.replace_range(10..11, "g");

        assert_eq!(
            bad.parse::<Sha256Digest>(),
            Err(DigestError::InvalidHex { index: 10 })
        );

        // Multibyte characters change the byte length and are rejected.
        assert!(
            format!("{}\u{e9}", "0".repeat(62))
                .parse::<Sha256Digest>()
                .is_err()
        );
    }

    proptest! {
        #[test]
        fn display_and_parse_round_trip(bytes in proptest::array::uniform32(any::<u8>())) {
            let digest = Sha256Digest::from_bytes(bytes);
            prop_assert_eq!(digest.to_string().parse::<Sha256Digest>().unwrap(), digest);
        }

        #[test]
        fn parsing_never_panics(input in "\\PC{0,70}") {
            let _ = input.parse::<Sha256Digest>();
        }
    }
}
