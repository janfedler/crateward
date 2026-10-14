# Contributing

Issues and pull requests are welcome. Larger design changes start with an
[architecture decision record](docs/adr/README.md). Security issues are
reported privately, as [`docs/SECURITY.md`](docs/SECURITY.md) describes.

Before a pull request, run

```sh
cargo xtask ci
```

It runs the checks of CI. They are listed in
[`docs/TESTING.md`](docs/TESTING.md#running-the-checks), with the
differences to CI. Crate code never runs outside
a microVM, not even in tests.

The rules below keep the code and the documentation easy to read. The
checks enforce some of them. Reviewers ask for the rest.

## Code

### Shape

* Write short, imperative Rust: straight line code, early returns and `?`
  instead of `and_then` chains.
* Keep functions at 100 lines or less, as clippy's `too_many_lines`
  checks. Split a longer function into steps with names where the steps
  stand on their own, not just to get under the limit.
* Keep files at 1000 lines or less, tests included, as
  `cargo xtask file-length` checks. Move a long unit test module into a
  `tests.rs` next to its file (`mod tests;`), split long code into modules
  by topic, and turn a long integration test into a directory with a
  `main.rs`.
* Add an abstraction only once it has a second user.

### Errors

Production code never panics. The workspace lints deny `unwrap`, `expect`,
`panic!`, `todo!`, indexing and `dbg!`. Errors are typed and propagated.

* A service stops with [`app::fatal`](crates/core/src/app.rs) and leaves
  the exit code and the log line to `run_component`.
* A job's failure is a [`Failure`](crates/core/src/failure.rs) with a class
  (transient, infrastructure, permanent or suspected compromise). Do not
  add a failure type per stage.

Tests may unwrap, with an `#![allow]` at the top of the test file.

### Unsafe code

`unsafe` is denied everywhere. The only exception is
`crateward_core::sandbox`, which documents its one unsafe block. Packages
without unsafe code `#![forbid]` it at the crate root.

### Fixed paths

Every fixed path lives in [`crateward_core::paths`](crates/core/src/paths.rs),
in the section it is relative to: `host`, `guest`, `repo`, `build` or
`bundle`. Import the constant and use it in place:

```rust
let pins: RustPins = read_toml(&root.join(repo::RUST_PIN))?;
```

Do not spell a path out, and do not bind a constant to a local only to
name it. Test fixtures that assert a contract value may keep the literal.

### Shared code

Shared code lives in one place. Before writing a helper, look for an
existing one:

| Need | Where |
|------|-------|
| Startup, logging, exit codes, the stop signal | `crateward_core::app` |
| Failure classes | `crateward_core::failure` |
| The clock | `crateward_core::protocol::WallClock::now` |
| Integers in untrusted bytes, hex encoding | `crateward_core::bytes` |
| Escaping text from hostile input | `crateward_core::text` |
| A PostgreSQL schema for a test | `crateward_core::testing` (feature `testing`) |
| Commands, copies, downloads in `xtask` | `crates/xtask/src/main.rs`, `images.rs` and `testing.rs` |
| The microVM tests' root and kernel | `crates/orchestrator/tests/common` |

### Blank lines

Blank lines split a function into its steps, so the reader sees the
structure before the details. `rustfmt` keeps blank lines but does not add
them. `cargo xtask blank-lines` checks the rules below that a program can
see, and `--write` adds the missing lines. Ordering the steps is up to the
author:

* Definitions come first, then the actions that use them, then loops, then
  the result.
* Put a blank line after a `let` that spans several lines, and after a
  `let … else { return; };` setup.
* Put a blank line before and after a `for`, `if`, `match` or `loop` block
  that stands between statements.
* In a test, separate the setup, the action, the assertions and the
  teardown.
* Separate a function's return value from the code above it. Functions of
  a single statement are excluded.
* A binding that only feeds the next block or assertion stays directly
  above it.
* A comment that opens a new group of statements gets a blank line above
  it.

```rust
pub fn run(root: &Path) -> Result<(), TaskError> {
    let dir = root.join(build::DEPLOY_CHECK);
    let vars = dir.join("nftables-vars.nft");

    std::fs::create_dir_all(&dir).map_err(io(&dir))?;
    std::fs::write(&vars, SAMPLE_VARS).map_err(io(&vars))?;

    let mut checked = Vec::new();
    for unit in units(root)? {
        verify(&unit)?;
        checked.push(unit);
    }

    eprintln!("xtask: {} units verify", checked.len());

    Ok(())
}
```

### Comments

Every public item has a doc comment (`missing_docs` is denied). Comments
say why the code does something, not what it does. A comment that no longer
matches the code is a bug. Comments follow the [writing style](#writing).

### Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
a subject `type(scope): description`, then a blank line and the body.

* The type is one of `feat`, `fix`, `docs`, `refactor`, `style`, `test`,
  `build`, `ci`, `chore`, `perf` and `revert`. A `!` after the type or
  scope marks a breaking change.
* The scope is the crate directory (`api`, `orchestrator`, `xtask`), or
  `deploy`, `config`, `deps` or the name of a document. Leave it out when
  a commit spans several areas.
* The description is imperative, starts in lowercase and has no full stop.

`cargo xtask commit-lint` checks every commit.

## Writing

### Style

Documentation, code comments, configuration comments, messages, commit
messages and pull request descriptions are English, in short and precise
sentences, with no em dashes, no hyphenated compounds and no semicolons.
`cargo xtask docs-lint` enforces the last three rules in the Markdown files,
the Rust comments and `config/*.toml`:

* Write "read only", "content addressed", "build time" instead of joining
  words with hyphens.
* Put names that contain hyphens (crates, tools, flags, targets) and code
  in inline code, for example `cargo-deny`.
* End every sentence with a full stop, never with a semicolon, and never
  join two sentences with one. List items that are sentences end with a
  full stop too, not with a semicolon. In a lowercase log or error
  message, use a colon, "so" or "and" instead.
* Text inside double quotes is a quotation of a source and is not checked.

Use the precise computer science term where one applies. The job state
machine, for example, is a deterministic finite automaton with a partial
transition function, not "a set of allowed moves".

### One place for each fact

Each fact is stated in one place. Other documents link to it instead of
repeating it, so an update cannot miss a copy. When you change or remove a
fact, search for other copies and fix them too.

Documentation describes the system as it is. Dated status, pending
decisions and the setup of one particular server do not belong in it.

Break long text into short paragraphs, lists and tables.
