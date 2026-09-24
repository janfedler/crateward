//! Validated crate names and their sparse index paths.
//!
//! Crate names arrive from the network (RSS feeds, index files, the database
//! dump) and later become file names, URL segments and database keys. Parsing
//! them once into [`CrateName`] means no other module has to wonder whether a
//! name could contain a slash, a dot or a non ASCII character.
//!
//! The rules follow the crates.io restrictions quoted in the Cargo book
//! (`doc/book/src/reference/registry-index.md`, section "Name restrictions"):
//! ASCII only, alphanumeric plus `-` and `_`, first character alphabetic,
//! at most 64 characters.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Longest crate name crates.io accepts.
pub const MAX_CRATE_NAME_LEN: usize = 64;

/// Why a string is not a valid crate name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrateNameError {
    /// The name is empty.
    #[error("crate name is empty")]
    Empty,
    /// The name is longer than [`MAX_CRATE_NAME_LEN`].
    #[error("crate name has {len} characters, the maximum is {MAX_CRATE_NAME_LEN}")]
    TooLong {
        /// Length of the rejected name in bytes.
        len: usize,
    },
    /// The first character is not an ASCII letter.
    #[error("crate name must start with an ASCII letter")]
    InvalidFirstCharacter,
    /// A character other than ASCII alphanumerics, `-` or `_` was found.
    #[error(
        "crate name contains a character that is not ASCII alphanumeric, '-' or '_' at byte {index}"
    )]
    InvalidCharacter {
        /// Byte offset of the first offending character.
        index: usize,
    },
}

/// A crate name that satisfies the crates.io naming rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CrateName(String);

impl CrateName {
    /// Parses and validates a crate name.
    ///
    /// # Errors
    ///
    /// Returns a [`CrateNameError`] describing the first rule the input breaks.
    pub fn parse(input: &str) -> Result<Self, CrateNameError> {
        if input.is_empty() {
            return Err(CrateNameError::Empty);
        }
        if input.len() > MAX_CRATE_NAME_LEN {
            return Err(CrateNameError::TooLong { len: input.len() });
        }
        if let Some(index) = input
            .bytes()
            .position(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err(CrateNameError::InvalidCharacter { index });
        }
        if !input
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
        {
            return Err(CrateNameError::InvalidFirstCharacter);
        }
        Ok(Self(input.to_owned()))
    }

    /// The name exactly as published.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The form crates.io uses to detect collisions: lowercase, with `-`
    /// replaced by `_`. Two names with the same canonical form cannot both
    /// exist on crates.io, so a mismatch hints at typosquatting research
    /// rather than a real second crate.
    #[must_use]
    pub fn canonical(&self) -> String {
        self.0
            .chars()
            .map(|c| {
                if c == '-' {
                    '_'
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect()
    }

    /// Path of this crate's file in the sparse index, relative to the index
    /// root, following the documented layout: `1/{name}`, `2/{name}`,
    /// `3/{first}/{name}` and `{ab}/{cd}/{name}` on the lowercased name.
    #[must_use]
    pub fn index_path(&self) -> String {
        let lower = self.0.to_ascii_lowercase();
        // All characters are ASCII, so byte slicing below never splits a
        // character. `get` keeps this panic free regardless.
        match lower.len() {
            1 => format!("1/{lower}"),
            2 => format!("2/{lower}"),
            3 => format!("3/{}/{lower}", lower.get(..1).unwrap_or_default()),
            _ => format!(
                "{}/{}/{lower}",
                lower.get(..2).unwrap_or_default(),
                lower.get(2..4).unwrap_or_default()
            ),
        }
    }
}

impl fmt::Display for CrateName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for CrateName {
    type Error = CrateNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<CrateName> for String {
    fn from(value: CrateName) -> Self {
        value.0
    }
}

impl std::str::FromStr for CrateName {
    type Err = CrateNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn index_paths_match_the_documented_layout() {
        let cases = [
            ("a", "1/a"),
            ("ab", "2/ab"),
            ("abc", "3/a/abc"),
            ("cargo", "ca/rg/cargo"),
            ("MyCrate", "my/cr/mycrate"),
            ("serde_json", "se/rd/serde_json"),
        ];
        for (name, path) in cases {
            assert_eq!(CrateName::parse(name).unwrap().index_path(), path, "{name}");
        }
    }

    #[test]
    fn rejects_names_that_break_crates_io_rules() {
        assert_eq!(CrateName::parse(""), Err(CrateNameError::Empty));
        assert_eq!(
            CrateName::parse("1password"),
            Err(CrateNameError::InvalidFirstCharacter)
        );
        assert_eq!(
            CrateName::parse("_private"),
            Err(CrateNameError::InvalidFirstCharacter)
        );
        assert_eq!(
            CrateName::parse("../etc"),
            Err(CrateNameError::InvalidCharacter { index: 0 })
        );
        assert_eq!(
            CrateName::parse("caf\u{e9}"),
            Err(CrateNameError::InvalidCharacter { index: 3 })
        );
        assert_eq!(
            CrateName::parse(&"a".repeat(65)),
            Err(CrateNameError::TooLong { len: 65 })
        );
        assert!(CrateName::parse(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn canonical_form_folds_case_and_separators() {
        let name = CrateName::parse("Serde-JSON").unwrap();
        assert_eq!(name.canonical(), "serde_json");
    }

    #[test]
    fn serde_round_trip_validates() {
        let name: CrateName = toml::Value::String("tokio".into()).try_into().unwrap();
        assert_eq!(name.as_str(), "tokio");
        let bad: Result<CrateName, _> = toml::Value::String("to/kio".into()).try_into();
        assert!(bad.is_err());
    }

    proptest! {
        #[test]
        fn valid_names_are_accepted_and_paths_are_safe(name in "[A-Za-z][A-Za-z0-9_-]{0,63}") {
            let parsed = CrateName::parse(&name).unwrap();
            let path = parsed.index_path();
            prop_assert!(path.ends_with(&name.to_ascii_lowercase()));
            prop_assert!(!path.contains(".."));
            prop_assert!(!path.starts_with('/'));
            prop_assert_eq!(path.matches('/').count(), if name.len() <= 2 { 1 } else { 2 });
        }

        #[test]
        fn parsing_never_panics_and_accepts_only_safe_names(input in "\\PC{0,80}") {
            if let Ok(name) = CrateName::parse(&input) {
                prop_assert!(name.as_str().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
                prop_assert!(name.as_str().len() <= MAX_CRATE_NAME_LEN);
            }
        }
    }
}
