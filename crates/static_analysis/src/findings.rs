//! Findings: what static analysis reports, with evidence.
//!
//! Every finding names the file and line it came from and the code context
//! (a build script runs at build time, a library only when used) and the
//! `cfg` predicate it sits under, so a verdict can always point at the code
//! that caused it, and platform specific behavior stays visible even though
//! Crateward only executes code on Linux.

use serde::{Deserialize, Serialize};

/// How much a finding matters on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context, no risk by itself.
    Info,
    /// Common in legitimate code, worth noting.
    Low,
    /// Unusual; relevant in combination.
    Medium,
    /// Rarely legitimate.
    High,
}

impl Severity {
    /// One level higher, for code that runs at build time.
    #[must_use]
    pub const fn raised(self) -> Self {
        match self {
            Self::Info => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium | Self::High => Self::High,
        }
    }
}

/// Where in a crate a file belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeContext {
    /// The build script: runs on the builder's machine during every build.
    BuildScript,
    /// A proc macro crate: runs inside the compiler during every build.
    ProcMacro,
    /// Library code: runs when a dependent calls it.
    Library,
    /// Binaries, examples and benchmarks.
    Binary,
    /// Tests.
    Test,
}

impl CodeContext {
    /// Whether code in this context runs during `cargo build` or `check`.
    #[must_use]
    pub const fn runs_at_build_time(self) -> bool {
        matches!(self, Self::BuildScript | Self::ProcMacro)
    }
}

/// The platform a `cfg` predicate selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Not platform specific.
    Any,
    /// Linux.
    Linux,
    /// Unix in general.
    Unix,
    /// Windows.
    Windows,
    /// macOS or another Apple platform.
    Apple,
}

impl Platform {
    /// Classifies a `cfg` predicate by the platform it names. Negations and
    /// combinations default to the first platform mentioned, which is enough
    /// to flag platform specific code for review.
    #[must_use]
    pub fn from_cfg(predicate: &str) -> Self {
        let p = predicate.replace(' ', "");
        if p.contains("not(") {
            return Self::Any;
        }
        if p.contains("windows") {
            Self::Windows
        } else if p.contains("target_os=\"macos\"")
            || p.contains("target_vendor=\"apple\"")
            || p.contains("target_os=\"ios\"")
        {
            Self::Apple
        } else if p.contains("target_os=\"linux\"") {
            Self::Linux
        } else if p.contains("unix") {
            Self::Unix
        } else {
            Self::Any
        }
    }
}

/// What a finding is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FindingKind {
    /// Network access through the standard library or an HTTP client.
    NetworkAccess,
    /// A URL in a string literal.
    UrlLiteral,
    /// Starting other programs.
    ProcessSpawn,
    /// Shell commands that download or run code (`curl`, `powershell`, ...).
    ShellCommand,
    /// Network access combined with running or writing code, in code that
    /// runs at build time: the shape of a downloader.
    DownloaderPattern,
    /// Paths or names of credentials: SSH keys, cargo tokens, cloud keys,
    /// browser and wallet data.
    CredentialAccess,
    /// Reading environment variables that hold secrets.
    SecretEnvironmentVariable,
    /// Enumerating the whole environment.
    EnvironmentEnumeration,
    /// Exfiltration endpoints such as chat webhooks.
    ExfiltrationEndpoint,
    /// Long high entropy strings or large literal byte arrays.
    ObfuscatedData,
    /// `include_bytes!` or `include_str!` of a file with binary content.
    IncludedBinary,
    /// `unsafe` blocks, functions or impls in a file.
    UnsafeCode {
        /// Occurrences in the file.
        count: u32,
    },
    /// Inline assembly.
    InlineAssembly,
    /// Foreign function declarations.
    ForeignFunctions,
    /// Windows APIs that run code, download or touch other processes.
    WindowsApi,
    /// The crate has a build script.
    BuildScript,
    /// The crate is a proc macro.
    ProcMacro,
    /// The crate links a native library (`links`).
    NativeLink,
    /// A YARA-X rule matched.
    YaraMatch {
        /// Rule name.
        rule: String,
    },
    /// A source file that does not parse as Rust.
    UnparsableSource,
}

/// One finding with its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Finding {
    /// What it is.
    #[serde(flatten)]
    pub kind: FindingKind,
    /// How much it matters.
    pub severity: Severity,
    /// File, relative to the crate root.
    pub file: String,
    /// Line, counting from 1, when known.
    pub line: Option<u32>,
    /// Code context of the file.
    pub context: CodeContext,
    /// The innermost `cfg` predicate around the code, if any.
    pub cfg: Option<String>,
    /// The platform that predicate selects.
    pub platform: Platform,
    /// The code or literal that triggered it, truncated.
    pub evidence: String,
}

/// Longest evidence text kept.
pub const MAX_EVIDENCE: usize = 200;

/// Whether a character must not appear literally in evidence: control
/// characters (Postgres `jsonb` rejects NUL), and bidirectional or invisible
/// characters that would make the dashboard show something other than the
/// code (Trojan Source).
fn must_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Makes evidence safe to store and display: escapes control, bidi and
/// invisible characters as `\u{..}` and truncates to [`MAX_EVIDENCE`]
/// bytes on a character boundary.
#[must_use]
pub fn evidence(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        let piece = if must_escape(c) {
            format!("\\u{{{:x}}}", u32::from(c))
        } else {
            c.to_string()
        };
        if out.len() + piece.len() > MAX_EVIDENCE {
            out.push('…');
            return out;
        }
        out.push_str(&piece);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_are_classified_from_cfg_predicates() {
        assert_eq!(Platform::from_cfg("windows"), Platform::Windows);
        assert_eq!(Platform::from_cfg("target_os = \"macos\""), Platform::Apple);
        assert_eq!(
            Platform::from_cfg("all(unix, target_os = \"linux\")"),
            Platform::Linux
        );
        assert_eq!(Platform::from_cfg("not(windows)"), Platform::Any);
        assert_eq!(Platform::from_cfg("feature = \"std\""), Platform::Any);
    }

    #[test]
    fn evidence_is_truncated_on_character_boundaries() {
        let long = "é".repeat(300);
        let e = evidence(&long);
        assert!(e.ends_with('…'));
        assert!(e.len() <= MAX_EVIDENCE + '…'.len_utf8());
    }

    #[test]
    fn evidence_escapes_invisible_and_control_characters() {
        assert_eq!(evidence("a\0b\u{202E}c"), "a\\u{0}b\\u{202e}c");
    }
}
