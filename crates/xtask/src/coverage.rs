//! Measures the line coverage of the workspace tests with `cargo llvm-cov`.
//!
//! It runs the same tests as `cargo test --workspace`, so the database tests
//! count when `CRATEWARD_TEST_DATABASE_URL` is set, and the ignored microVM
//! tests do not. Test files, the fuzz targets and the eBPF programs are not
//! measured. The report per line lands in `target/llvm-cov/html`.

use std::collections::BTreeMap;
use std::path::Path;

use crateward_core::paths::build;
use serde::Deserialize;

use crate::{TaskError, io, read, run};

/// Files whose coverage is not reported: tests and code outside `src`.
const IGNORED: &str = r"(/tests/|/benches/|/fuzz/|/\.cargo/|/rustc/)";

/// Runs the tests instrumented and prints the line coverage per crate.
///
/// # Errors
///
/// Fails if `cargo llvm-cov` is missing, a test fails or the summary cannot
/// be read.
pub fn run_coverage(root: &Path) -> Result<(), TaskError> {
    let summary = root.join(build::COVERAGE_SUMMARY);
    let html = root.join(build::COVERAGE_HTML);
    let summary_arg = summary.display().to_string();
    let html_arg = html.display().to_string();
    std::fs::create_dir_all(&html).map_err(io(&html))?;

    run("cargo", &["llvm-cov", "clean", "--workspace"], &[])?;
    run(
        "cargo",
        &[
            "llvm-cov",
            "--workspace",
            "--locked",
            "--no-report",
            "--ignore-filename-regex",
            IGNORED,
        ],
        &[],
    )?;
    run(
        "cargo",
        &[
            "llvm-cov",
            "report",
            "--json",
            "--summary-only",
            "--ignore-filename-regex",
            IGNORED,
            "--output-path",
            &summary_arg,
        ],
        &[],
    )?;
    run(
        "cargo",
        &[
            "llvm-cov",
            "report",
            "--html",
            "--ignore-filename-regex",
            IGNORED,
            "--output-dir",
            &html_arg,
        ],
        &[],
    )?;

    let export: Export = serde_json::from_str(&read(&summary)?)
        .map_err(|e| TaskError::Check(format!("{}: {e}", summary.display())))?;

    print!("{}", table(&per_crate(&export)));
    eprintln!("xtask: report per line in {}/index.html", html.display());

    Ok(())
}

/// `llvm-cov export --summary-only`, reduced to what the table needs.
#[derive(Debug, Deserialize)]
struct Export {
    data: Vec<ExportData>,
}

#[derive(Debug, Deserialize)]
struct ExportData {
    files: Vec<FileSummary>,
}

#[derive(Debug, Deserialize)]
struct FileSummary {
    filename: String,
    summary: Summary,
}

#[derive(Debug, Deserialize)]
struct Summary {
    lines: Lines,
}

/// Instrumented and covered lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
struct Lines {
    count: u64,
    covered: u64,
}

/// Sums the lines of each crate under `crates/`.
fn per_crate(export: &Export) -> BTreeMap<String, Lines> {
    let mut crates: BTreeMap<String, Lines> = BTreeMap::new();

    for file in export.data.iter().flat_map(|d| &d.files) {
        let Some((_, rest)) = file.filename.split_once("/crates/") else {
            continue;
        };

        let Some((name, _)) = rest.split_once('/') else {
            continue;
        };

        let total = crates.entry(name.to_owned()).or_default();
        total.count += file.summary.lines.count;
        total.covered += file.summary.lines.covered;
    }

    crates
}

/// The table, one crate per line and the total last.
fn table(crates: &BTreeMap<String, Lines>) -> String {
    let mut out = format!(
        "{:<20} {:>8} {:>8} {:>7}\n",
        "crate", "lines", "covered", "percent"
    );

    let mut total = Lines::default();

    for (name, lines) in crates {
        out.push_str(&row(name, *lines));
        total.count += lines.count;
        total.covered += lines.covered;
    }

    out.push_str(&row("total", total));

    out
}

fn row(name: &str, lines: Lines) -> String {
    let tenths = (lines.covered * 1000).checked_div(lines.count).unwrap_or(0);

    format!(
        "{name:<20} {:>8} {:>8} {:>5}.{}%\n",
        lines.count,
        lines.covered,
        tenths / 10,
        tenths % 10
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const SAMPLE: &str = r#"{"data": [{"files": [
        {"filename": "/w/crates/core/src/job.rs", "summary": {"lines": {"count": 100, "covered": 90, "percent": 90.0}}},
        {"filename": "/w/crates/core/src/store.rs", "summary": {"lines": {"count": 100, "covered": 60, "percent": 60.0}}},
        {"filename": "/w/crates/api/src/lib.rs", "summary": {"lines": {"count": 3, "covered": 1, "percent": 33.3}}},
        {"filename": "/elsewhere/src/lib.rs", "summary": {"lines": {"count": 5, "covered": 5, "percent": 100.0}}}
    ]}]}"#;

    #[test]
    fn lines_are_summed_per_crate_and_in_total() {
        let export: Export = serde_json::from_str(SAMPLE).unwrap();
        let crates = per_crate(&export);

        assert_eq!(
            table(&crates),
            "crate                   lines  covered percent\n\
             api                         3        1    33.3%\n\
             core                      200      150    75.0%\n\
             total                     203      151    74.3%\n"
        );
    }

    #[test]
    fn a_crate_without_instrumented_lines_reads_zero() {
        assert_eq!(
            row("empty", Lines::default()),
            "empty                       0        0     0.0%\n"
        );
    }
}
