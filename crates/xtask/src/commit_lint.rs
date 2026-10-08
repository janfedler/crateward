//! Checks that commit messages follow Conventional Commits 1.0
//! (<https://www.conventionalcommits.org/en/v1.0.0/>): a subject
//! `type(scope)!: description` and a blank line before any body. The
//! project adds that the description starts in lowercase and does not end
//! with a full stop. Merge commits, which GitHub writes for pull requests,
//! are skipped.

use std::path::Path;

use crate::{TaskError, output};

/// The allowed types.
const TYPES: [&str; 11] = [
    "build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style", "test",
];

/// Why a commit message breaks the convention, if it does.
fn problem(message: &str) -> Option<String> {
    let mut lines = message.lines();
    let subject = lines.next().unwrap_or_default();
    let Some((head, description)) = subject.split_once(": ") else {
        return Some("the subject is not `type(scope): description`".to_owned());
    };

    let head = head.strip_suffix('!').unwrap_or(head);
    let (kind, scope) = head
        .split_once('(')
        .map_or((head, None), |(kind, rest)| (kind, Some(rest)));

    if !TYPES.contains(&kind) {
        return Some(format!("`{kind}` is not one of {}", TYPES.join(", ")));
    }

    if !scope.is_none_or(valid_scope) {
        return Some("the scope is not a lowercase name in parentheses".to_owned());
    }

    if description.is_empty() || description.starts_with([' ', '.']) {
        return Some("the description is missing".to_owned());
    }

    if description.starts_with(char::is_uppercase) || description.ends_with('.') {
        return Some("the description starts in uppercase or ends with a full stop".to_owned());
    }

    if lines.next().is_some_and(|line| !line.is_empty()) {
        return Some("the body does not start after a blank line".to_owned());
    }

    None
}

/// Whether `scope)` holds a lowercase name.
fn valid_scope(scope: &str) -> bool {
    scope.strip_suffix(')').is_some_and(|name| {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    })
}

/// Checks every commit reachable from `HEAD`, without merge commits.
///
/// # Errors
///
/// Fails if `git` fails, or names each commit that breaks the convention.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let log = output(
        root,
        "git",
        &["log", "--no-merges", "--format=%h %s%x00%B%x01"],
    )?;

    let mut broken = 0;
    for entry in log.split('\x01').map(str::trim).filter(|e| !e.is_empty()) {
        let (line, message) = entry.split_once('\0').unwrap_or((entry, ""));
        if let Some(problem) = problem(message) {
            eprintln!("{line}: {problem}");
            broken += 1;
        }
    }

    if broken > 0 {
        return Err(TaskError::Check(format!(
            "{broken} commit message(s) do not follow Conventional Commits, see CONTRIBUTING.md"
        )));
    }

    eprintln!("xtask: commit messages follow Conventional Commits");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conventional_messages_pass() {
        for message in [
            "feat: initial public release",
            "fix(api): fetch the stylesheet again\n\nBody.\n\nCo-Authored-By: A <a@example.com>",
            "refactor!: name the binaries in kebab case",
            "docs(threat-model): describe warm images",
            "style(static_analysis): group statements",
            "fix(deploy): turn ProtectHostname off",
        ] {
            assert_eq!(problem(message), None, "{message}");
        }
    }

    #[test]
    fn other_messages_are_named() {
        for message in [
            "Add cargo xtask coverage",
            "feature: add coverage",
            "feat(API): add coverage",
            "feat(): add coverage",
            "feat(api: add coverage",
            "feat:add coverage",
            "feat: ",
            "feat: Add coverage",
            "feat: add coverage.",
            "feat: add coverage\nno blank line",
        ] {
            assert!(problem(message).is_some(), "{message}");
        }
    }
}
