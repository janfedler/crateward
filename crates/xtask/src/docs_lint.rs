//! Enforces the project's writing style mechanically.
//!
//! The style asks for short, precise English sentences with no em dashes and
//! no hyphenated compounds in prose. Reviewers miss these; a check does not.
//! The rules apply to prose only: code blocks, inline code, URLs and HTML
//! comments are skipped. Names that contain hyphens (crates, tools, flags,
//! targets) belong in inline code, which is good style anyway.
//!
//! Checked files: Markdown in the repository root and `docs/`, Rust doc
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
    RustDoc,
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
                matches!(name, "docs" | "crates" | "config")
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
            Some("rs") if nested => Some(Kind::RustDoc),
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
        Kind::RustDoc => {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix("//!")
                .or_else(|| trimmed.strip_prefix("///"))
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
            // Skip a code span delimited by a run of the same length.
            let run = chars
                .get(i..)
                .map_or(0, |s| s.iter().take_while(|&&x| x == '`').count());
            let body_start = i + run;
            let mut j = body_start;
            let mut closed = None;
            while j < chars.len() {
                let here = chars
                    .get(j..)
                    .map_or(0, |s| s.iter().take_while(|&&x| x == '`').count());
                if here == run {
                    closed = Some(j + run);
                    break;
                }
                j += here.max(1);
            }
            match closed {
                Some(end) => {
                    out.push(' ');
                    i = end;
                }
                None => i = chars.len(),
            }
            continue;
        }
        if c == ']' && chars.get(i + 1) == Some(&'(') {
            // Skip a link destination.
            let end = chars
                .get(i + 2..)
                .and_then(|s| s.iter().position(|&x| x == ')'))
                .map_or(chars.len(), |p| i + 2 + p + 1);
            out.push(' ');
            i = end;
            continue;
        }
        if c == '<' {
            let rest: String = chars
                .get(i + 1..)
                .map(|s| s.iter().collect())
                .unwrap_or_default();
            if rest.starts_with("http") || rest.starts_with("mailto:") {
                let end = chars
                    .get(i..)
                    .and_then(|s| s.iter().position(|&x| x == '>'))
                    .map_or(chars.len(), |p| i + p + 1);
                out.push(' ');
                i = end;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    // Quotations are someone else's words, for example a cited document.
    let out = strip_quotations(&out);
    // Bare URLs and reference link definitions.
    out.split(' ')
        .filter(|word| !(word.contains("://") || word.starts_with("www.")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Removes text between pairs of straight double quotes.
fn strip_quotations(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut parts = line.split('"');
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    let rest: Vec<&str> = parts.collect();
    // With an odd number of quotes the last one is unmatched; keep its text.
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
        messages.push("em dash in prose; use a period, comma or colon".to_owned());
    }
    for word in prose.split_whitespace() {
        let word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
        // Command line flags such as `--no-deps` are names, not prose.
        if word.starts_with('-') {
            continue;
        }
        if is_hyphenated_compound(word) && !ALLOWED_HYPHENATED.contains(&word) {
            messages.push(format!(
                "hyphenated compound {word:?}; write it as separate words, as one word, or in inline code if it is a name"
            ));
        }
    }
    messages
}

/// A letter, a hyphen and a letter: `read-only`, `pre-warmed`. Hyphens next
/// to digits (`SHA-256`, `i7-7700`) and leading hyphens (`--flag`) are fine.
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
                    SHA-256 on an i7-7700 with --no-deps.\n\
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
    fn rust_doc_comments_are_checked_and_code_is_not() {
        let text = "//! A well-known fact.\nlet x = a-b;\n/// Fine text.\n";
        assert_eq!(lint(text, Kind::RustDoc).len(), 1);
    }

    #[test]
    fn toml_comments_are_checked_and_values_are_not() {
        let text = "# a user-agent string\nurl = \"https://hc-ping.com\"\n";
        assert_eq!(lint(text, Kind::TomlComments).len(), 1);
    }

    #[test]
    fn the_repository_follows_its_own_style() {
        let violations = lint_workspace(&crate::workspace_root()).unwrap();
        let rendered: Vec<String> = violations.iter().map(ToString::to_string).collect();
        assert!(rendered.is_empty(), "{}", rendered.join("\n"));
    }
}
