//! Recall on the inert samples in `tests/fixtures/recall`: each rebuilds a
//! known malicious technique or a legitimate pattern. Static analysis reads
//! the sample's sources, its `sample.json` says what a VM run of it records,
//! and the verdict must reach or stay below the level the sample names.
//! Nothing here compiles or runs a sample.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use crateward_analyzer::score::{Inputs, score};
use crateward_core::report::run::RunReport;
use crateward_core::report::trace::TraceSummary;
use crateward_core::verdict::{Coverage, RiskLevel, Verdict};
use crateward_static_analysis::analyze::{AnalyzeLimits, analyze};
use crateward_static_analysis::yara::Rules;
use serde_json::{Value, json};

/// What a sample promises.
struct Sample {
    name: String,
    technique: String,
    min: Option<RiskLevel>,
    max: Option<RiskLevel>,
    /// Why the verdict stays below what the technique deserves.
    gap: Option<String>,
    run: Value,
}

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recall")
}

fn level(value: &Value) -> Option<RiskLevel> {
    value
        .as_str()
        .map(|_| serde_json::from_value(value.clone()).unwrap())
}

fn sample(dir: &Path) -> Sample {
    let text = std::fs::read_to_string(dir.join("sample.json")).unwrap();
    let json: Value = serde_json::from_str(&text).unwrap();

    Sample {
        name: dir.file_name().unwrap().to_string_lossy().into_owned(),
        technique: json["technique"].as_str().unwrap().to_owned(),
        min: level(&json["min"]),
        max: level(&json["max"]),
        gap: json["gap"].as_str().map(str::to_owned),
        run: json["run"].clone(),
    }
}

/// The sample's files except `sample.json`, packed like a `.crate`.
fn archive(dir: &Path, package: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut files = Vec::new();
    for sub in ["", "src"] {
        let Ok(entries) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };

        for path in entries.map(|e| e.unwrap().path()) {
            if path.is_file() && path.file_name().unwrap() != "sample.json" {
                files.push(path);
            }
        }
    }

    for path in files {
        let data = std::fs::read(&path).unwrap();
        let relative = path.strip_prefix(dir).unwrap().display().to_string();
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, format!("{package}-0.1.0/{relative}"), &*data)
            .unwrap();
    }

    builder.into_inner().unwrap()
}

/// An empty run report of `package`'s build with the sample's observations.
fn run(package: &str, observed: &Value) -> RunReport {
    let script = format!("/work/target/debug/build/{package}-0123456789abcdef/build-script-build");
    let observed: Value =
        serde_json::from_str(&observed.to_string().replace("$SCRIPT", &script)).unwrap();

    let mut trace = serde_json::to_value(TraceSummary::default()).unwrap();
    trace["complete"] = json!(true);
    trace["processes"] = json!([
        {"pid": 1, "ppid": null, "exe": "/usr/local/bin/cargo", "argv": ["cargo", "check"],
         "role": "cargo", "started_ms": 0, "became_root": false},
        {"pid": 2, "ppid": 1, "exe": script, "argv": [script],
         "role": "build_script", "started_ms": 1, "became_root": false},
    ]);

    let mut report = json!({
        "outcome": "succeeded", "end": "agent reported the end", "exit": null,
        "restore_ms": 60, "run_ms": 1000, "stdout_tail": "", "stderr_tail": "",
        "truncated": false, "payload_files": 3, "payload_bytes": 1024,
        "missing_packages": [],
        "network": {"dns": [], "connections": [], "udp_datagrams": 0, "refused": 0,
                    "truncated": false},
        "leaked": [],
    });

    for (key, value) in observed.as_object().unwrap() {
        if key == "trace" {
            for (field, items) in value.as_object().unwrap() {
                match (field.as_str(), trace[field].as_array_mut()) {
                    ("processes", Some(list)) => list.extend(items.as_array().unwrap().clone()),
                    _ => trace[field] = items.clone(),
                }
            }
        } else {
            report[key] = value.clone();
        }
    }

    report["trace"] = trace;

    serde_json::from_value(report).unwrap()
}

fn verdict(dir: &Path, sample: &Sample, rules: &Rules) -> Verdict {
    let package = format!("recall-{}", sample.name);
    let report = analyze(&archive(dir, &package), rules, &AnalyzeLimits::default()).unwrap();
    let runs = [run(&package, &sample.run)];

    score(&Inputs {
        name: &package,
        coverage: Coverage::DynamicLinux,
        report: Some(&report),
        diff: None,
        runs: &runs,
        previous_profile: None,
        dismissed: &[],
    })
}

#[test]
fn every_sample_reaches_its_level() {
    let rules = Rules::builtin().unwrap();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(corpus())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();

    dirs.sort();
    assert!(dirs.len() >= 8, "the corpus is incomplete");

    let mut misses = Vec::new();
    for dir in &dirs {
        let sample = sample(dir);
        let v = verdict(dir, &sample, &rules);
        let found = v.level;
        eprintln!(
            "{:<22} {:>3} {:<8} {}",
            sample.name,
            v.score,
            found.name(),
            sample.technique
        );

        if let Some(gap) = &sample.gap {
            eprintln!("{:<35} gap: {gap}", "");
        }

        let low = sample.min.is_some_and(|min| found < min);
        let high = sample.max.is_some_and(|max| found > max);
        if low || high {
            let signals: Vec<String> = v
                .evidence
                .iter()
                .map(|e| format!("{} {}", e.signal, e.points))
                .collect();

            misses.push(format!(
                "{}: {} ({}): {}",
                sample.name,
                found.name(),
                v.score,
                signals.join(", ")
            ));
        }
    }

    assert!(misses.is_empty(), "{}", misses.join("\n"));
}
