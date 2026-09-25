//! Facts from a crate's `Cargo.toml`.
//!
//! The published manifest is normalized by `cargo publish`, but older crates
//! and other tools leave keys implicit, so the rules below follow Cargo's
//! defaults: a `build.rs` at the root is the build script unless
//! `build = false`, and `proc-macro` may be spelled with an underscore.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::findings::CodeContext;

/// What the manifest says about build time code and platforms.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFacts {
    /// Path of the build script, if any.
    pub build_script: Option<String>,
    /// Whether the library is a proc macro.
    pub proc_macro: bool,
    /// The `links` key.
    pub links: Option<String>,
    /// Edition.
    pub edition: Option<String>,
    /// Dependencies per `cfg` or target triple of `[target.*]` tables.
    pub target_dependencies: BTreeMap<String, Vec<String>>,
    /// Targets listed for docs.rs, a hint at the platforms the author cares
    /// about.
    pub docs_rs_targets: Vec<String>,
    /// Whether the manifest parsed at all.
    pub parsed: bool,
}

fn table_keys(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_table)
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default()
}

/// Reads the facts. `files` are the crate's paths relative to its root.
#[must_use]
pub fn parse(manifest: &str, files: &BTreeSet<String>) -> ManifestFacts {
    let Ok(value) = manifest.parse::<toml::Table>() else {
        return ManifestFacts::default();
    };
    let package = value.get("package");
    let build_script = match package.and_then(|p| p.get("build")) {
        Some(toml::Value::String(path)) => Some(path.clone()),
        Some(toml::Value::Boolean(false)) => None,
        _ => files.contains("build.rs").then(|| "build.rs".to_owned()),
    };
    let lib = value.get("lib");
    let proc_macro = ["proc-macro", "proc_macro"]
        .iter()
        .any(|k| lib.and_then(|l| l.get(*k)).and_then(toml::Value::as_bool) == Some(true));
    let mut target_dependencies = BTreeMap::new();
    if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
        for (target, table) in targets {
            let mut deps = Vec::new();
            for key in ["dependencies", "build-dependencies", "build_dependencies"] {
                deps.extend(table_keys(table.get(key)));
            }
            if !deps.is_empty() {
                target_dependencies.insert(target.clone(), deps);
            }
        }
    }
    let docs_rs_targets = package
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("docs").or_else(|| m.get("docs.rs")))
        .and_then(|d| d.get("rs").unwrap_or(d).get("targets"))
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    ManifestFacts {
        build_script,
        proc_macro,
        links: package
            .and_then(|p| p.get("links"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned),
        edition: package
            .and_then(|p| p.get("edition"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned),
        target_dependencies,
        docs_rs_targets,
        parsed: true,
    }
}

impl ManifestFacts {
    /// The code context of a file, by its path relative to the crate root.
    #[must_use]
    pub fn context_of(&self, path: &str) -> CodeContext {
        let build_dir = self
            .build_script
            .as_deref()
            .and_then(|b| b.rsplit_once('/').map(|(dir, _)| format!("{dir}/")));
        if self.build_script.as_deref() == Some(path)
            || path.starts_with("build/")
            || build_dir.is_some_and(|d| !d.starts_with("src/") && path.starts_with(&d))
        {
            CodeContext::BuildScript
        } else if path.starts_with("tests/") {
            CodeContext::Test
        } else if path.starts_with("examples/")
            || path.starts_with("benches/")
            || path.starts_with("src/bin/")
            || path == "src/main.rs"
        {
            CodeContext::Binary
        } else if self.proc_macro {
            CodeContext::ProcMacro
        } else {
            CodeContext::Library
        }
    }

    /// Whether building the crate runs any of its own code.
    #[must_use]
    pub fn has_build_time_code(&self) -> bool {
        self.build_script.is_some() || self.proc_macro
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn implicit_build_script_and_proc_macro() {
        let facts = parse(
            "[package]\nname = \"x\"\nedition = \"2021\"\nlinks = \"z\"\n[lib]\nproc_macro = true\n",
            &files(&["build.rs", "src/lib.rs"]),
        );
        assert_eq!(facts.build_script.as_deref(), Some("build.rs"));
        assert!(facts.proc_macro);
        assert_eq!(facts.links.as_deref(), Some("z"));
        assert_eq!(facts.context_of("build.rs"), CodeContext::BuildScript);
        assert_eq!(facts.context_of("src/lib.rs"), CodeContext::ProcMacro);
    }

    #[test]
    fn build_false_disables_the_script_and_target_tables_are_read() {
        let facts = parse(
            "[package]\nname = \"x\"\nbuild = false\n\
             [target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n\
             [package.metadata.docs.rs]\ntargets = [\"x86_64-pc-windows-msvc\"]\n",
            &files(&["build.rs"]),
        );
        assert_eq!(facts.build_script, None);
        assert_eq!(
            facts.target_dependencies["cfg(windows)"],
            vec!["winapi".to_owned()]
        );
        assert_eq!(
            facts.docs_rs_targets,
            vec!["x86_64-pc-windows-msvc".to_owned()]
        );
        assert_eq!(facts.context_of("src/bin/tool.rs"), CodeContext::Binary);
        assert_eq!(facts.context_of("tests/it.rs"), CodeContext::Test);
    }

    #[test]
    fn garbage_manifest_is_not_parsed() {
        assert!(!parse("not toml [[[", &BTreeSet::new()).parsed);
    }
}
