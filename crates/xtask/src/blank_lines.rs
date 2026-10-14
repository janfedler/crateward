//! Checks the blank line rules of `CONTRIBUTING.md` in Rust code. `rustfmt`
//! keeps blank lines but never adds them, so without a check they drift.
//!
//! Each file is read as lines with their bracket depth, and with strings and
//! comments masked. A statement starts on a line after `;`, `{` or `}` and
//! ends where its depth is reached again with `;`, `}` or `,`, unless a
//! method chain continues on the next line. A blank line is missing
//!
//! * after a `let` that spans several lines, unless the next block or
//!   assertion uses its binding,
//! * before a `for`, `if`, `match`, `loop` or `while` that follows a
//!   statement, unless that statement is a `let` whose binding the block
//!   uses,
//! * after such a block when another statement follows,
//! * before a `//` comment that follows a statement,
//! * before a function's tail value that follows a statement.
//!
//! The checked files are the Rust sources in `crates/` and `fuzz/`, without
//! fuzz corpora and test fixtures, which are other people's code.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::TaskError;

/// How a line starts: in code, or inside a string or block comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Code,
    Str,
    /// A raw string closed by `"` and this many `#`.
    Raw(usize),
    /// Nested block comments.
    Comment(usize),
}

/// One line as the rules see it.
#[derive(Debug, Clone)]
struct Line<'a> {
    /// The line as written.
    raw: &'a str,
    /// Open brackets at its start.
    depth: i32,
    /// It starts inside a string or block comment.
    literal: bool,
    /// The code with strings and comments masked, trimmed.
    code: String,
}

/// Lines that open a block statement.
const BLOCKS: [&str; 6] = ["for ", "if ", "match ", "loop ", "while ", "unsafe {"];

/// Starts of lines that continue the statement above.
const CONTINUATIONS: [&str; 15] = [
    "}", ")", "]", ".", "#", "?", "else", "=>", "|", "&", "+", "-", "*", ",", "=",
];

fn lex(text: &str) -> Vec<Line<'_>> {
    let mut state = State::Code;
    let mut depth = 0;

    text.split('\n')
        .map(|raw| {
            let start = (depth, state != State::Code);
            let code = mask(raw, &mut state, &mut depth);

            Line {
                raw,
                depth: start.0,
                literal: start.1,
                code: code.trim().to_owned(),
            }
        })
        .collect()
}

/// The code of one line with strings, characters and comments masked.
/// Updates the state and the bracket depth for the next line.
fn mask(raw: &str, state: &mut State, depth: &mut i32) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut out = String::new();
    let mut i = 0;

    while let Some(c) = at(i) {
        i += 1;

        match *state {
            State::Str if c == '\\' => i += 1,
            State::Str if c == '"' => *state = State::Code,
            State::Raw(hashes) if c == '"' && (i..i + hashes).all(|k| at(k) == Some('#')) => {
                i += hashes;
                *state = State::Code;
            }
            State::Comment(n) if c == '*' && at(i) == Some('/') => {
                i += 1;
                *state = if n == 1 {
                    State::Code
                } else {
                    State::Comment(n - 1)
                };
            }
            State::Comment(n) if c == '/' && at(i) == Some('*') => {
                i += 1;
                *state = State::Comment(n + 1);
            }
            State::Str | State::Raw(_) | State::Comment(_) => {}
            State::Code => match c {
                '/' if at(i) == Some('/') => break,
                '/' if at(i) == Some('*') => {
                    i += 1;
                    *state = State::Comment(1);
                }
                '"' => *state = raw_string(&chars, i - 1).map_or(State::Str, State::Raw),
                '\'' => i += char_literal(&chars, i),
                '(' | '[' | '{' => *depth += 1,
                ')' | ']' | '}' => *depth -= 1,
                _ => {}
            },
        }

        if *state == State::Code || c == '"' {
            out.push(c);
        }
    }

    out
}

/// The number of `#` if the quote at `quote` opens a raw string.
fn raw_string(chars: &[char], quote: usize) -> Option<usize> {
    let before_quote = chars.get(..quote)?;
    let hashes = before_quote.iter().rev().take_while(|&&c| c == '#').count();
    let r = quote.checked_sub(hashes + 1)?;
    let before = r.checked_sub(1).and_then(|b| chars.get(b));
    let prefix = match before {
        Some('b') => r.checked_sub(2).and_then(|b| chars.get(b)),
        other => other,
    };

    (chars.get(r) == Some(&'r') && !prefix.is_some_and(|c| c.is_alphanumeric() || *c == '_'))
        .then_some(hashes)
}

/// How many characters after an opening `'` belong to a character literal,
/// or 0 for a lifetime.
fn char_literal(chars: &[char], start: usize) -> usize {
    if chars.get(start) == Some(&'\\') {
        let rest = chars.get(start + 2..).unwrap_or_default();
        return rest.iter().position(|&c| c == '\'').map_or(0, |p| p + 3);
    }

    if chars.get(start + 1) == Some(&'\'') {
        2
    } else {
        0
    }
}

/// Where a statement starting at `start` ends.
fn end_of(lines: &[Line<'_>], start: usize) -> usize {
    let depth = lines.get(start).map_or(0, |l| l.depth);
    let mut end = start;

    while let Some(next) = lines.get(end + 1) {
        let chained = next.code.starts_with('.') || next.code.starts_with('?');
        let ends = lines
            .get(end)
            .is_some_and(|l| l.code.ends_with([';', '}', ',']));

        let closed = next.code.starts_with('}');
        if next.depth < depth || (next.depth == depth && (closed || (ends && !chained))) {
            break;
        }

        end += 1;
    }

    end
}

/// The binding of a `let`, if it is a plain or tuple name.
fn binding(code: &str) -> Option<&str> {
    let mut rest = code.strip_prefix("let ")?;
    for prefix in ["mut ", "Some(", "(", "mut "] {
        rest = rest.strip_prefix(prefix).unwrap_or(rest);
    }

    let len = rest
        .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
        .unwrap_or(rest.len());

    rest.get(..len).filter(|name| !name.is_empty())
}

/// Whether `text` contains `word` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');

    text.match_indices(word).any(|(i, _)| {
        let before = text.get(..i).and_then(|t| t.chars().next_back());
        let after = text.get(i + word.len()..).and_then(|t| t.chars().next());

        !ident(before) && !ident(after)
    })
}

/// A file's lines and statements.
struct File<'a> {
    lines: Vec<Line<'a>>,
    statements: Vec<(usize, usize)>,
    /// The outermost statement ending on each line.
    by_end: HashMap<usize, usize>,
    by_start: HashMap<usize, usize>,
}

impl<'a> File<'a> {
    fn new(text: &'a str) -> Self {
        let lines = lex(text);
        let mut statements = Vec::new();
        let mut previous = "{".to_owned();

        for (i, line) in lines.iter().enumerate() {
            if line.literal || line.code.is_empty() {
                continue;
            }

            let starts = previous.ends_with([';', '{', '}'])
                && !CONTINUATIONS.iter().any(|c| line.code.starts_with(c));
            if starts {
                statements.push((i, end_of(&lines, i)));
            }

            previous.clone_from(&line.code);
        }

        let mut by_end = HashMap::new();
        for &(a, b) in &statements {
            by_end.entry(b).or_insert(a);
        }

        let by_start = statements.iter().copied().collect();

        Self {
            lines,
            statements,
            by_end,
            by_start,
        }
    }

    fn code(&self, k: usize) -> &str {
        self.lines.get(k).map_or("", |l| l.code.as_str())
    }

    fn blank(&self, k: usize) -> bool {
        self.lines
            .get(k)
            .is_none_or(|l| !l.literal && l.raw.trim().is_empty())
    }

    fn comment(&self, k: usize) -> bool {
        self.lines
            .get(k)
            .is_some_and(|l| !l.literal && l.raw.trim().starts_with("//"))
    }

    fn depth(&self, k: usize) -> i32 {
        self.lines.get(k).map_or(0, |l| l.depth)
    }

    fn block(&self, k: usize) -> bool {
        let code = self.code(k);

        BLOCKS.iter().any(|b| code.starts_with(b)) || code == "loop {"
    }

    /// The statement that ends right above line `k` at its depth.
    fn previous(&self, k: usize) -> Option<usize> {
        let p = k.checked_sub(1)?;
        if self.blank(p) || self.comment(p) {
            return None;
        }

        self.by_end
            .get(&p)
            .copied()
            .filter(|&start| self.depth(start) == self.depth(k))
    }

    /// Whether lines `a` to `b` use the binding of the `let` at `k`.
    fn uses(&self, k: usize, a: usize, b: usize) -> bool {
        let lines = self.lines.get(a..=b).unwrap_or_default();

        binding(self.code(k)).is_some_and(|name| lines.iter().any(|l| has_word(l.raw, name)))
    }

    /// Lines after which a blank line is missing, and the rule.
    fn missing(&self) -> BTreeMap<usize, &'static str> {
        let mut missing = BTreeMap::new();

        for &(a, b) in &self.statements {
            if let Some(rule) = self.after(a, b) {
                missing.insert(b, rule);
            }

            if self.missing_before_block(a, b) {
                missing.insert(a - 1, "before a block");
            }

            if self.missing_before_tail(a, b) {
                missing.insert(a - 1, "before the tail value");
            }
        }

        for k in 1..self.lines.len() {
            if self.missing_before_comment(k) {
                missing.insert(k - 1, "before a comment that opens a group");
            }
        }

        missing.retain(|&k, _| !self.blank(k + 1));

        missing
    }

    /// The rule that asks for a blank line after the statement `a` to `b`.
    fn after(&self, a: usize, b: usize) -> Option<&'static str> {
        let next = b + 1;
        let closes = self.code(next).starts_with(['}', ')', ']']) || self.code(next).is_empty();
        if self.blank(next) || closes || self.depth(next) != self.depth(a) {
            return None;
        }

        if self.code(a).starts_with("let ") && b > a {
            let next_end = self.by_start.get(&next).copied().unwrap_or(next);
            let feeds = (self.block(next) || self.code(next).starts_with("assert"))
                && self.uses(a, next, next_end);

            return (!feeds).then_some("after a let over several lines");
        }

        let ends_block = self.block(a) && self.code(b).ends_with('}');

        (ends_block && !self.code(next).starts_with("else")).then_some("after a block")
    }

    fn missing_before_block(&self, a: usize, b: usize) -> bool {
        let Some(p) = self.previous(a).filter(|_| self.block(a)) else {
            return false;
        };

        let opens = self.code(a - 1).ends_with(['{', '=', '(', ',']);
        let feeds = self.code(p).starts_with("let ") && self.uses(p, a, b);

        !opens && !feeds
    }

    fn missing_before_comment(&self, k: usize) -> bool {
        let raw = self.lines.get(k).map_or("", |l| l.raw.trim());
        let after_statement = self
            .by_end
            .get(&(k - 1))
            .is_some_and(|&s| self.depth(s) == self.depth(k));

        self.comment(k)
            && !raw.starts_with("///")
            && !self.comment(k - 1)
            && after_statement
            && self.code(k - 1).ends_with(';')
    }

    /// Whether the statement `a` to `b` is a function's tail value right
    /// after another statement.
    fn missing_before_tail(&self, a: usize, b: usize) -> bool {
        let next = b + 1;
        let is_tail = !self.block(a)
            && !self.code(a).starts_with("let ")
            && !self.code(a).starts_with("return")
            && !self.code(b).ends_with(';')
            && self.code(next) == "}"
            && self.depth(next) == self.depth(a);

        is_tail && self.previous(a).is_some() && self.in_function_body(a)
    }

    /// Whether line `a` is directly in a function body.
    fn in_function_body(&self, a: usize) -> bool {
        let Some(opener) = (0..a).rev().find(|&o| self.depth(o) < self.depth(a)) else {
            return false;
        };

        let header = (0..=opener)
            .rev()
            .take(8)
            .take_while(|&o| o == opener || !self.code(o).ends_with([';', '{', '}']))
            .any(|o| has_word(self.code(o), "fn"));

        self.code(opener).ends_with('{') && header
    }
}

/// The text with every missing blank line added, and where they were.
fn fix(text: &str) -> (String, BTreeMap<usize, &'static str>) {
    let missing = File::new(text).missing();
    let mut out = Vec::new();

    for (k, line) in text.split('\n').enumerate() {
        out.push(line);

        if missing.contains_key(&k) {
            out.push("");
        }
    }

    (out.join("\n"), missing)
}

/// The Rust sources the rules apply to, without fuzz corpora and test
/// fixtures.
pub fn sources(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), TaskError> {
    let entries = std::fs::read_dir(dir).map_err(|e| TaskError::Io(dir.to_path_buf(), e))?;

    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name();
        let skipped = matches!(name.to_str(), Some("target" | "corpus" | "fixtures"));
        if path.is_dir() && !skipped && !name.to_string_lossy().starts_with('.') {
            sources(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }

    Ok(())
}

/// The Rust sources in `crates/` and `fuzz/`, sorted.
///
/// # Errors
///
/// Fails if a directory cannot be read.
pub fn rust_files(root: &Path) -> Result<Vec<PathBuf>, TaskError> {
    let mut files = Vec::new();
    for dir in ["crates", "fuzz"] {
        sources(&root.join(dir), &mut files)?;
    }

    files.sort();

    Ok(files)
}

/// Checks every Rust source, or adds the missing blank lines with `write`.
///
/// # Errors
///
/// Fails if a file cannot be read or written, or when a check finds a
/// missing blank line.
pub fn run(root: &Path, write: bool) -> Result<(), TaskError> {
    let mut count = 0;
    for path in rust_files(root)? {
        let text = std::fs::read_to_string(&path).map_err(|e| TaskError::Io(path.clone(), e))?;
        let (fixed, missing) = fix(&text);
        count += missing.len();

        if write && !missing.is_empty() {
            std::fs::write(&path, fixed).map_err(|e| TaskError::Io(path.clone(), e))?;
        }

        for (k, rule) in &missing {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            eprintln!(
                "{}:{}: blank line missing {rule}",
                relative.display(),
                k + 1
            );
        }
    }

    match (count, write) {
        (0, _) => {
            eprintln!("xtask: blank lines follow the rules");
            Ok(())
        }
        (n, true) => {
            eprintln!("xtask: added {n} blank line(s)");
            Ok(())
        }
        (n, false) => Err(TaskError::Check(format!(
            "{n} missing blank line(s), see CONTRIBUTING.md, or run cargo xtask blank-lines --write"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn added(text: &str) -> Vec<&'static str> {
        fix(text).1.into_values().collect()
    }

    #[test]
    fn each_rule_adds_its_blank_line() {
        let text = "fn f() -> u32 {
    let a = foo
        .bar();
    let b = 2;
    for x in y {
        z(x);
    }
    let c = 3;
    // why
    c
}";

        let expected = "fn f() -> u32 {
    let a = foo
        .bar();

    let b = 2;

    for x in y {
        z(x);
    }

    let c = 3;

    // why
    c
}";

        assert_eq!(fix(text).0, expected);
        assert!(added(expected).is_empty());
    }

    #[test]
    fn a_binding_stays_with_the_block_that_uses_it() {
        let text = "fn f() {
    let name = finding(
        x,
    );
    if bad {
        warn(format!(\"{name}\"));
    }
}";

        assert!(added(text).is_empty());
    }

    #[test]
    fn strings_chains_and_tails_are_left_alone() {
        let text = "fn f() -> String {
    let sql = \"SELECT 1;
         FROM t\";
    Page {
        a: 1,
    }
    .render()
}";

        assert_eq!(added(text), ["after a let over several lines"]);
        assert!(!fix(text).0.contains("FROM t\"\n\n"));
    }

    #[test]
    fn a_function_of_one_statement_needs_no_blank_line() {
        assert_eq!(
            added("fn f() -> u32 {\n    let a = 1;\n    a\n}"),
            ["before the tail value"]
        );
        assert!(added("fn f() -> u32 {\n    1\n}").is_empty());
        assert!(added("let f = |x| {\n    g(x);\n    x\n};").is_empty());
    }

    #[test]
    fn masking_knows_raw_strings_and_characters() {
        let lines = lex("let a = r#\"{\"#; let b = '{'; let c: &'a str = \"}\"; // {\nx");

        assert_eq!(lines[1].depth, 0);
        assert!(!lines[1].literal);
    }

    #[test]
    fn the_repository_follows_the_rules() {
        assert!(run(&crate::workspace_root(), false).is_ok());
    }
}
