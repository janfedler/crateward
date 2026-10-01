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
    /// The lowercase name, as stored with a report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

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
    /// The lowercase name, as serialized.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BuildScript => "build_script",
            Self::ProcMacro => "proc_macro",
            Self::Library => "library",
            Self::Binary => "binary",
            Self::Test => "test",
        }
    }

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
    /// The lowercase name, as serialized.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Linux => "linux",
            Self::Unix => "unix",
            Self::Windows => "windows",
            Self::Apple => "apple",
        }
    }

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

impl FindingKind {
    /// The name of the kind, as serialized in the `kind` field.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::NetworkAccess => "network_access",
            Self::UrlLiteral => "url_literal",
            Self::ProcessSpawn => "process_spawn",
            Self::ShellCommand => "shell_command",
            Self::DownloaderPattern => "downloader_pattern",
            Self::CredentialAccess => "credential_access",
            Self::SecretEnvironmentVariable => "secret_environment_variable",
            Self::EnvironmentEnumeration => "environment_enumeration",
            Self::ExfiltrationEndpoint => "exfiltration_endpoint",
            Self::ObfuscatedData => "obfuscated_data",
            Self::IncludedBinary => "included_binary",
            Self::UnsafeCode { .. } => "unsafe_code",
            Self::InlineAssembly => "inline_assembly",
            Self::ForeignFunctions => "foreign_functions",
            Self::WindowsApi => "windows_api",
            Self::BuildScript => "build_script",
            Self::ProcMacro => "proc_macro",
            Self::NativeLink => "native_link",
            Self::YaraMatch { .. } => "yara_match",
            Self::UnparsableSource => "unparsable_source",
        }
    }
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
    /// The source lines around [`Finding::line`], for review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<Snippet>,
}

/// A few lines of a text file around a finding, made safe like
/// [`evidence`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Snippet {
    /// Number of the first line, counting from 1.
    pub start: u32,
    /// The lines, each escaped and truncated.
    pub lines: Vec<String>,
}

/// Lines shown before and after the finding's line.
pub const SNIPPET_CONTEXT: usize = 3;

impl Snippet {
    /// The lines around `line` of `text`, or `None` when the file has no
    /// such line.
    #[must_use]
    pub fn around(text: &str, line: u32) -> Option<Self> {
        let at = usize::try_from(line).ok().filter(|&l| l > 0)?;
        let first = at.saturating_sub(SNIPPET_CONTEXT).max(1);
        let lines: Vec<String> = text
            .lines()
            .skip(first - 1)
            .take(at - first + SNIPPET_CONTEXT + 1)
            .map(|l| evidence(&l.replace('\t', "    ")))
            .collect();
        let start = u32::try_from(first).ok()?;
        (lines.len() > at - first).then_some(Self { start, lines })
    }
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
    fn snippets_hold_the_lines_around_a_finding() {
        let text = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
        let mid = Snippet::around(text, 5).unwrap();
        assert_eq!((mid.start, mid.lines.join("")), (2, "2345678".into()));
        let top = Snippet::around(text, 1).unwrap();
        assert_eq!((top.start, top.lines.join("")), (1, "1234".into()));
        let end = Snippet::around(text, 9).unwrap();
        assert_eq!((end.start, end.lines.join("")), (6, "6789".into()));
        assert_eq!(Snippet::around(text, 10), None);
        assert_eq!(Snippet::around(text, 0), None);
        let bidi = Snippet::around("let a = \"\u{202E}x\";\n", 1).unwrap();
        assert_eq!(bidi.lines, ["let a = \"\\u{202e}x\";"]);
        let tab = Snippet::around("\tlet a = 1;\r\n", 1).unwrap();
        assert_eq!(tab.lines, ["    let a = 1;"]);
    }

    #[test]
    fn severity_names_are_the_serialized_names() {
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
        ] {
            let value = serde_json::to_value(severity).unwrap();
            assert_eq!(value.as_str(), Some(severity.name()));
        }
    }

    #[test]
    fn platform_and_context_names_are_the_serialized_names() {
        use CodeContext::*;
        use Platform::*;
        for platform in [Any, Linux, Unix, Windows, Apple] {
            assert_eq!(serde_json::to_value(platform).unwrap(), platform.name());
        }
        for context in [BuildScript, ProcMacro, Library, Binary, Test] {
            assert_eq!(serde_json::to_value(context).unwrap(), context.name());
        }
    }

    #[test]
    fn kind_names_are_the_serialized_kinds() {
        use FindingKind::*;
        let kinds = [
            NetworkAccess,
            UrlLiteral,
            ProcessSpawn,
            ShellCommand,
            DownloaderPattern,
            CredentialAccess,
            SecretEnvironmentVariable,
            EnvironmentEnumeration,
            ExfiltrationEndpoint,
            ObfuscatedData,
            IncludedBinary,
            UnsafeCode { count: 2 },
            InlineAssembly,
            ForeignFunctions,
            WindowsApi,
            BuildScript,
            ProcMacro,
            NativeLink,
            YaraMatch { rule: "r".into() },
            UnparsableSource,
        ];
        for kind in kinds {
            let value = serde_json::to_value(&kind).unwrap();
            assert_eq!(value["kind"], kind.name());
        }
    }

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
