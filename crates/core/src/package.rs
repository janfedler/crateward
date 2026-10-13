//! What a crate's `Cargo.toml` says about its origin and licence, as the
//! static analysis reads it and the SBOM uses it (ADR 0012).

use serde::{Deserialize, Serialize};

/// The `[package]` keys that name a crate's licence, authors and links.
/// Every value is as the manifest wrote it, unchecked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PackageMeta {
    /// `license`, an SPDX expression, or an older form such as
    /// `MIT/Apache-2.0`.
    pub license: Option<String>,
    /// `license-file`, a path in the crate.
    pub license_file: Option<String>,
    /// `authors`, often `Name <email>`.
    pub authors: Vec<String>,
    /// `homepage`.
    pub homepage: Option<String>,
    /// `repository`.
    pub repository: Option<String>,
}

impl PackageMeta {
    /// Reads the keys from a parsed manifest's `[package]` table.
    #[must_use]
    pub fn from_package(package: Option<&toml::Value>) -> Self {
        let text = |key: &str| {
            package
                .and_then(|p| p.get(key))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        };

        Self {
            license: text("license"),
            license_file: text("license-file").or_else(|| text("license_file")),
            authors: package
                .and_then(|p| p.get("authors"))
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            homepage: text("homepage"),
            repository: text("repository"),
        }
    }

    /// The first email address in `authors`, with the name before it.
    #[must_use]
    pub fn author_email(&self) -> Option<(String, String)> {
        self.authors.iter().find_map(|author| {
            let (name, rest) = author.split_once('<')?;
            let email = rest.strip_suffix('>')?.trim();
            let (local, domain) = email.split_once('@')?;
            let plain = |s: &str| !s.is_empty() && !s.contains(char::is_whitespace);

            (plain(local) && plain(domain) && domain.contains('.'))
                .then(|| (name.trim().to_owned(), email.to_owned()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(manifest: &str) -> PackageMeta {
        let table: toml::Table = manifest.parse().unwrap_or_default();

        PackageMeta::from_package(table.get("package"))
    }

    #[test]
    fn reads_the_package_keys() {
        let m = meta(
            r#"[package]
name = "foo"
license = "MIT/Apache-2.0"
license-file = "LICENSE"
authors = ["Ann <ann@example.com>", "Bob"]
homepage = "https://example.com"
repository = "https://github.com/example/foo""#,
        );

        assert_eq!(m.license.as_deref(), Some("MIT/Apache-2.0"));
        assert_eq!(m.license_file.as_deref(), Some("LICENSE"));
        assert_eq!(m.authors.len(), 2);
        assert_eq!(m.homepage.as_deref(), Some("https://example.com"));
        assert_eq!(
            m.repository.as_deref(),
            Some("https://github.com/example/foo")
        );
    }

    #[test]
    fn an_author_email_needs_angle_brackets_and_a_domain() {
        let email = |authors: &[&str]| {
            PackageMeta {
                authors: authors.iter().map(|a| (*a).to_owned()).collect(),
                ..PackageMeta::default()
            }
            .author_email()
        };

        assert_eq!(
            email(&["Bob", "Ann <ann@example.com>"]),
            Some(("Ann".to_owned(), "ann@example.com".to_owned()))
        );
        assert_eq!(email(&["ann@example.com"]), None);
        assert_eq!(email(&["Ann <ann@localhost>"]), None);
        assert_eq!(email(&["Ann <a nn@example.com>"]), None);
        assert_eq!(email(&[]), None);
    }
}
