//! Enforces the project's writing style mechanically.
//!
//! The style asks for short, precise English sentences with no em dashes, no
//! hyphenated compounds and no semicolons in prose. Reviewers miss these. A check does not.
//! The rules apply to prose only: code blocks, inline code, URLs and HTML
//! comments are skipped. Names that contain hyphens (crates, tools, flags,
//! targets) belong in inline code, which is good style anyway.
//!
//! Checked files: Markdown in the repository root, `docs/` and `deploy/`, Rust
//! comments in `crates/`, and comments in `config/*.toml`.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::TaskError;

/// Hyphenated words that are proper names and cannot be rewritten.
const ALLOWED_HYPHENATED: &[&str] = &["YARA-X"];

/// One style problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// File, relative to the workspace root.
    pub path: PathBuf,
    /// Line number, counting from 1.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.path.display(), self.line, self.message)
    }
}

/// How lines of a file are turned into prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Markdown,
    RustComments,
    TomlComments,
}

/// Lints every documentation source of the workspace.
///
/// # Errors
///
/// Fails if a directory or file cannot be read.
pub fn lint_workspace(root: &Path) -> Result<Vec<Violation>, TaskError> {
    let mut files = Vec::new();
    collect(root, &mut files, false)?;
    let mut violations = Vec::new();
    for (path, kind) in files {
        let text = std::fs::read_to_string(&path).map_err(|e| TaskError::Io(path.clone(), e))?;
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        violations.extend(lint_text(&relative, &text, kind));
    }
    Ok(violations)
}

fn collect(dir: &Path, out: &mut Vec<(PathBuf, Kind)>, nested: bool) -> Result<(), TaskError> {
    let entries = std::fs::read_dir(dir).map_err(|e| TaskError::Io(dir.to_path_buf(), e))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            let descend = if nested {
                !matches!(name, "target" | "fixtures")
            } else {
                matches!(name, "docs" | "crates" | "config" | "deploy")
            };
            if descend && !name.starts_with('.') {
                collect(&path, out, true)?;
            }
            continue;
        }
        let in_config = path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|parent| parent == "config");
        let kind = match path.extension().and_then(|e| e.to_str()) {
            Some("md") => Some(Kind::Markdown),
            Some("rs") if nested => Some(Kind::RustComments),
            Some("toml") if in_config => Some(Kind::TomlComments),
            _ => None,
        };
        if let Some(kind) = kind {
            out.push((path, kind));
        }
    }
    Ok(())
}

/// Lints one file.
fn lint_text(path: &Path, text: &str, kind: Kind) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut fence: Option<String> = None;
    let mut in_comment = false;
    for (index, raw) in text.lines().enumerate() {
        let Some(line) = prose_source(raw, kind) else {
            continue;
        };
        let trimmed = line.trim_start();
        if let Some(marker) = &fence {
            if trimmed.starts_with(marker.as_str()) {
                fence = None;
            }
            continue;
        }
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            let marker: String = trimmed
                .chars()
                .take_while(|c| *c == '`' || *c == '~')
                .collect();
            fence = Some(marker);
            continue;
        }
        let without_comments = strip_html_comments(line, &mut in_comment);
        let prose = strip_non_prose(&without_comments);
        for message in check_prose(&prose) {
            violations.push(Violation {
                path: path.to_path_buf(),
                line: index + 1,
                message,
            });
        }
    }
    violations
}

/// Extracts the documentation part of a line, if it has one.
fn prose_source(line: &str, kind: Kind) -> Option<&str> {
    match kind {
        Kind::Markdown => Some(line),
        Kind::RustComments => {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix("//!")
                .or_else(|| trimmed.strip_prefix("///"))
                .or_else(|| trimmed.strip_prefix("//"))
        }
        Kind::TomlComments => line.trim_start().strip_prefix('#'),
    }
}

fn strip_html_comments(line: &str, in_comment: &mut bool) -> String {
    let mut out = String::new();
    let mut rest = line;
    loop {
        if *in_comment {
            match rest.find("-->") {
                Some(end) => {
                    rest = rest.get(end + 3..).unwrap_or_default();
                    *in_comment = false;
                }
                None => return out,
            }
        } else {
            match rest.find("<!--") {
                Some(start) => {
                    out.push_str(rest.get(..start).unwrap_or_default());
                    rest = rest.get(start + 4..).unwrap_or_default();
                    *in_comment = true;
                }
                None => {
                    out.push_str(rest);
                    return out;
                }
            }
        }
    }
}

/// Removes inline code, link targets, autolinks and bare URLs.
fn strip_non_prose(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c == '`' {
            // An unclosed code span runs to the end of the line.
            let Some(end) = code_span_end(&chars, i) else {
                break;
            };
            out.push(' ');
            i = end;
        } else if c == ']' && chars.get(i + 1) == Some(&'(') {
            out.push(' ');
            i = link_destination_end(&chars, i);
        } else if c == '<'
            && let Some(end) = autolink_end(&chars, i)
        {
            out.push(' ');
            i = end;
        } else {
            out.push(c);
            i += 1;
        }
    }
    // Quotations are someone else's words, for example a cited document.
    let out = strip_quotations(&out);
    // Bare URLs and reference link definitions.
    out.split(' ')
        .filter(|word| !(word.contains("://") || word.starts_with("www.")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The index after the code span that starts at `start`: a run of backticks
/// closed by a run of the same length.
fn code_span_end(chars: &[char], start: usize) -> Option<usize> {
    let run = backticks(chars, start);
    let mut at = start + run;
    while at < chars.len() {
        let here = backticks(chars, at);
        if here == run {
            return Some(at + run);
        }
        at += here.max(1);
    }
    None
}

/// The length of the run of backticks at `at`.
fn backticks(chars: &[char], at: usize) -> usize {
    chars
        .get(at..)
        .map_or(0, |rest| rest.iter().take_while(|&&c| c == '`').count())
}

/// The index after the link destination that follows the `]` at `start`.
fn link_destination_end(chars: &[char], start: usize) -> usize {
    chars
        .get(start + 2..)
        .and_then(|rest| rest.iter().position(|&c| c == ')'))
        .map_or(chars.len(), |p| start + 2 + p + 1)
}

/// The index after the autolink (`<https://...>`, `<mailto:...>`) at `start`.
fn autolink_end(chars: &[char], start: usize) -> Option<usize> {
    let head: String = chars.get(start + 1..)?.iter().take(7).collect();
    if !(head.starts_with("http") || head.starts_with("mailto:")) {
        return None;
    }
    let close = chars.get(start..)?.iter().position(|&c| c == '>');
    Some(close.map_or(chars.len(), |p| start + p + 1))
}

/// Removes text between pairs of straight double quotes.
fn strip_quotations(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut parts = line.split('"');
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    let rest: Vec<&str> = parts.collect();
    // With an odd number of quotes the last one is unmatched. Keep its text.
    let pairs = rest.len() / 2;
    for (index, part) in rest.iter().enumerate() {
        if index % 2 == 1 || index >= pairs * 2 {
            out.push(' ');
            out.push_str(part);
        }
    }
    out
}

fn check_prose(prose: &str) -> Vec<String> {
    let mut messages = Vec::new();
    if prose.contains('\u{2014}') {
        messages.push("em dash in prose: use a period, comma or colon".to_owned());
    }
    if has_semicolon(prose) {
        messages.push("semicolon in prose: end the sentence with a period".to_owned());
    }
    for word in prose.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
        // Command line flags such as `--no-deps` are names, not prose.
        if word.starts_with('-') {
            continue;
        }
        if is_hyphenated_compound(word) && !ALLOWED_HYPHENATED.contains(&word) {
            messages.push(format!(
                "hyphenated compound {word:?}: write it as separate words, as one word, or in inline code if it is a name"
            ));
        }
    }
    messages
}

/// Whether a semicolon ends a clause. The one of an HTML character reference
/// such as `&amp;` does not.
fn has_semicolon(prose: &str) -> bool {
    prose.match_indices(';').any(|(at, _)| {
        let name = prose[..at]
            .rsplit_once('&')
            .map_or("", |(_, name)| name)
            .trim_start_matches('#');
        name.is_empty() || !name.chars().all(char::is_alphanumeric)
    })
}

/// A letter, a hyphen and a letter: `read-only`, `pre-warmed`. Hyphens next
/// to digits (`SHA-256`, `x86-64`) and leading hyphens (`--flag`) are fine.
fn is_hyphenated_compound(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    chars
        .windows(3)
        .any(|w| matches!(w, [a, '-', b] if a.is_alphabetic() && b.is_alphabetic()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lint(text: &str, kind: Kind) -> Vec<String> {
        lint_text(Path::new("t"), text, kind)
            .into_iter()
            .map(|v| v.message)
            .collect()
    }

    #[test]
    fn flags_em_dashes_and_compounds_in_prose() {
        let found = lint("A read-only disk \u{2014} always.", Kind::Markdown);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn ignores_code_urls_comments_and_numbers() {
        let text = "Use `cargo-deny` and <https://a-b.example/x-y>.\n\
                    See [docs](https://x.org/a-b) or https://c-d.org.\n\
                    <!-- generated-marker -->\n\
                    SHA-256 on x86-64 with --no-deps.\n\
                    ```\nlet read-only = 1;\n```\n";
        assert_eq!(lint(text, Kind::Markdown), Vec::<String>::new());
    }

    #[test]
    fn quotations_are_skipped_but_unmatched_quotes_are_not() {
        assert!(lint("The docs say \"a queue-like table\" here.", Kind::Markdown).is_empty());
        assert_eq!(
            lint("An \"odd quote with read-only text", Kind::Markdown).len(),
            1
        );
    }

    #[test]
    fn semicolons_are_flagged_outside_code_and_entities() {
        assert_eq!(lint("One clause; another.", Kind::Markdown).len(), 1);
        assert_eq!(
            lint("A list:\n* first;\n* second.", Kind::Markdown).len(),
            1
        );
        let fine = "Run `a; b`, see <https://x.org/a;b>, \"quoted; text\".\n\
                    MITRE ATT&amp;CK and &#38; are entities.\n\
                    ```\nlet x = 1;\n```\n";
        assert_eq!(lint(fine, Kind::Markdown), Vec::<String>::new());
    }

    #[test]
    fn rust_comments_are_checked_and_code_is_not() {
        let text = "//! A well-known fact.\nlet x = a-b;\n/// Fine text.\n// One; two.\n";
        assert_eq!(lint(text, Kind::RustComments).len(), 2);
    }

    #[test]
    fn toml_comments_are_checked_and_values_are_not() {
        let text = "# a user-agent string\nurl = \"https://ntfy.sh\"\n";
        assert_eq!(lint(text, Kind::TomlComments).len(), 1);
    }

    /// What is left of a line after the parts that are not prose are removed.
    #[test]
    fn non_prose_is_replaced_by_a_space() {
        let cases = [
            ("", ""),
            ("plain words", "plain words"),
            ("Use `cargo-deny` now", "Use   now"),
            ("`` a ` b `` tail", "  tail"),
            ("unclosed `code span with read-only", "unclosed "),
            ("See [docs](https://x.org/a-b) now", "See [docs  now"),
            ("A link [x](unclosed destination", "A link [x "),
            (
                "<https://a-b.example/x-y> and <mailto:a@b.c> ok",
                "  and   ok",
            ),
            ("a < b and <html> tag", "a < b and <html> tag"),
            ("unclosed <https://x.org", "unclosed  "),
            ("trailing <", "trailing <"),
            (
                "go to https://c-d.org now and www.x-y.org too",
                "go to now and too",
            ),
            ("say \"a b-c\" done", "say   done"),
            ("An \"odd quote", "An  odd quote"),
            ("`a \"b` c\" d", "  c  d"),
        ];
        for (input, expected) in cases {
            assert_eq!(strip_non_prose(input), expected, "{input}");
        }
    }

    #[test]
    fn the_repository_follows_its_own_style() {
        let violations = lint_workspace(&crate::workspace_root()).unwrap();
        let rendered: Vec<String> = violations.iter().map(ToString::to_string).collect();
        assert!(rendered.is_empty(), "{}", rendered.join("\n"));
    }
}
