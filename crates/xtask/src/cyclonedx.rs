//! Validates a sample SBOM and findings document (ADR 0012). The documents
//! must pass the CycloneDX 1.6 schema in `cyclonedx-cli`, and the SBOM must
//! meet BSI TR-03183-2 v2.1.0 in `sbomqs`. Both tools are pinned release
//! binaries, downloaded once into `target/check-tools`.

use std::path::Path;

use crateward_core::paths::build;
use serde::Deserialize;

use crate::images::download;
use crate::{TaskError, io, output, run_in};

const CYCLONEDX_CLI_URL: &str =
    "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.33.1/cyclonedx-linux-x64";
const CYCLONEDX_CLI_SHA256: &str =
    "bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746";
const SBOMQS_URL: &str = "https://github.com/interlynk-io/sbomqs/releases/download/v2.1.2/sbomqs_2.1.2_Linux_x86_64.tar.gz";
const SBOMQS_SHA256: &str = "451c800019c81059f86eac2c1344c57572b3436e7e0ffeaa076459d195a39ab8";

/// The fields left out of the BSI gate. CycloneDX 1.6 holds one licence
/// expression, so a compound one cannot be both concluded and declared,
/// and `sbomqs` rejects `WITH` exceptions (ADR 0012).
const LICENCE_FIELDS: [&str; 2] = [
    "original licence (declared)",
    "distribution licence (concluded)",
];

/// One requirement in the `sbomqs` compliance report.
#[derive(Debug, Deserialize)]
struct Section {
    required: bool,
    score: f64,
    element_id: String,
    section_data_field: String,
    element_result: String,
}

/// The `sbomqs` compliance report.
#[derive(Debug, Deserialize)]
struct Report {
    sections: Vec<Section>,
}

/// Writes the samples and checks them with both tools.
///
/// # Errors
///
/// Fails if a tool cannot be downloaded or run, a document breaks the
/// schema, or the SBOM misses a required TR-03183-2 field.
pub fn run(root: &Path) -> Result<(), TaskError> {
    let tools = root.join(build::CHECK_TOOLS);
    let samples = root.join(build::CYCLONEDX_SAMPLES);
    let samples_env = samples.to_string_lossy();

    run_in(
        root,
        "cargo",
        &[
            "test",
            "-p",
            "crateward_core",
            "--features",
            "sbom",
            "--test",
            "cyclonedx_samples",
            "--locked",
        ],
        &[("CRATEWARD_CYCLONEDX_SAMPLES", &samples_env)],
    )?;

    validate_schema(&tools, &samples)?;

    check_bsi(&tools, &samples)
}

/// Validates both documents against the CycloneDX 1.6 schema.
fn validate_schema(tools: &Path, samples: &Path) -> Result<(), TaskError> {
    let cli = download(
        tools,
        "cyclonedx-cli",
        CYCLONEDX_CLI_URL,
        CYCLONEDX_CLI_SHA256,
    )?;

    make_executable(&cli)?;

    for name in ["sample.cdx.json", "sample.vex.cdx.json"] {
        let file = samples.join(name).to_string_lossy().into_owned();
        run_in(
            samples,
            &cli.to_string_lossy(),
            &[
                "validate",
                "--input-file",
                &file,
                "--input-format",
                "json",
                "--input-version",
                "v1_6",
                "--fail-on-errors",
            ],
            // The binary needs ICU for cultures unless told to do without.
            &[("DOTNET_SYSTEM_GLOBALIZATION_INVARIANT", "1")],
        )?;
    }

    Ok(())
}

/// Scores the SBOM against TR-03183-2 and fails on any required field below
/// full marks, except the licence fields.
fn check_bsi(tools: &Path, samples: &Path) -> Result<(), TaskError> {
    let archive = download(tools, "sbomqs.tar.gz", SBOMQS_URL, SBOMQS_SHA256)?;
    run_in(
        tools,
        "tar",
        &["-xzf", &archive.to_string_lossy(), "sbomqs"],
        &[],
    )?;

    let sbomqs = tools.join("sbomqs").to_string_lossy().into_owned();
    let sbom = samples
        .join("sample.cdx.json")
        .to_string_lossy()
        .into_owned();

    let json = output(
        samples,
        &sbomqs,
        &["compliance", "--bsi-v21", "--json", &sbom],
    )?;

    let report: Report =
        serde_json::from_str(&json).map_err(|e| TaskError::Check(format!("sbomqs report: {e}")))?;

    let failed: Vec<String> = report
        .sections
        .iter()
        .filter(|s| s.required && s.score < 10.0)
        .filter(|s| !LICENCE_FIELDS.contains(&s.section_data_field.as_str()))
        .map(|s| {
            format!(
                "{}: {}: {}",
                s.element_id, s.section_data_field, s.element_result
            )
        })
        .collect();

    if !failed.is_empty() {
        return Err(TaskError::Check(format!(
            "the sample SBOM misses TR-03183-2 fields:\n{}",
            failed.join("\n")
        )));
    }

    eprintln!("xtask: the samples pass CycloneDX 1.6 and TR-03183-2");

    Ok(())
}

fn make_executable(file: &Path) -> Result<(), TaskError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).map_err(io(file))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn reads_the_sbomqs_report() {
        let report: Report = serde_json::from_str(
            r#"{"sections": [{"required": true, "score": 10, "element_id": "4",
                 "section_data_field": "creator", "element_result": "ok",
                 "extra": 1}]}"#,
        )
        .unwrap();

        assert_eq!(report.sections.len(), 1);
    }
}
