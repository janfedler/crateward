//! Coverage labels that qualify every verdict.
//!
//! A low risk score means little unless the reader knows what was examined.
//! Every verdict therefore carries a [`Coverage`] label, and the labels are
//! chosen so that no wording ever claims a crate is "clean": a crate whose
//! code never compiles on Linux is "not applicable", and a crate that was
//! only parsed is "static only", with the reason.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What the analysis of one version actually covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "reason")]
pub enum Coverage {
    /// The version was built inside a Linux microVM and its behavior was
    /// traced, in addition to static analysis.
    DynamicLinux,
    /// Only static analysis ran.
    StaticOnly(StaticOnlyReason),
    /// The version has no code that compiles on Linux, so dynamic analysis
    /// on Linux cannot say anything about it.
    NotApplicableOnLinux,
}

/// Why a version was not analyzed dynamically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticOnlyReason {
    /// The version has no build script, is not a proc macro and adds no
    /// build time dependency, so building it executes none of its own code.
    NoBuildTimeCode,
    /// The version qualified for dynamic analysis but waited longer than the
    /// configured deadline for a free VM slot.
    CapacityDeadline,
    /// The archive failed validation and was never unpacked, so there is
    /// nothing to parse or build. The archive findings are the evidence.
    ArchiveRejected,
    /// Cargo could not resolve the dependencies, so the version cannot be
    /// built anywhere and none of its code runs at build time.
    UnresolvedDependencies,
}

impl Coverage {
    /// The label shown next to every verdict.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DynamicLinux => "dynamic on Linux",
            Self::StaticOnly(_) => "static only",
            Self::NotApplicableOnLinux => "not applicable",
        }
    }
}

impl fmt::Display for Coverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Outcome of the cross target `cargo check` for one foreign target.
/// Foreign code is only type checked, never executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "reason")]
pub enum TargetCoverage {
    /// `cargo check` ran for the target (whether or not it succeeded).
    Checked,
    /// The target could not be checked. This is logged, never treated as an
    /// infrastructure error.
    NotApplicable(TargetNotApplicable),
}

/// Why a foreign target could not be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetNotApplicable {
    /// The version has no code specific to this target.
    NoPlatformSpecificCode,
    /// The Rust standard library for the target is not in the guest image.
    MissingToolchain,
    /// The check needs a platform SDK the guest image cannot contain.
    MissingSdk,
}

/// How risky a version looks. Ordered from `None` to `Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Nothing counted.
    None,
    /// Below 20 points.
    Low,
    /// 20 to 49 points.
    Medium,
    /// 50 to 79 points: a human looks at it.
    High,
    /// 80 points or more: a human looks at it first.
    Critical,
}

impl RiskLevel {
    /// The level of a score from 0 to 100.
    #[must_use]
    pub const fn from_score(score: u32) -> Self {
        match score {
            0 => Self::None,
            1..=19 => Self::Low,
            20..=49 => Self::Medium,
            50..=79 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Whether the verdict goes to the "needs you" inbox.
    #[must_use]
    pub const fn needs_review(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }

    /// Name for labels.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Where a piece of evidence comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Static analysis of the crate's own files.
    Static,
    /// The change against the previous version.
    Diff,
    /// The eBPF trace from inside the guest.
    Trace,
    /// The fake internet on the host.
    Network,
    /// The host's scan of the scratch disk.
    Disk,
    /// How the run ended.
    Run,
}

impl EvidenceSource {
    /// Name for labels, the same as in the stored JSON.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Diff => "diff",
            Self::Trace => "trace",
            Self::Network => "network",
            Self::Disk => "disk",
            Self::Run => "run",
        }
    }
}

/// One reason behind a score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Stable name of the signal, for example `honeytoken_left_vm`.
    pub signal: String,
    /// Points it adds.
    pub points: u32,
    /// Where it comes from.
    pub source: EvidenceSource,
    /// One sentence for a human, with guest supplied text escaped.
    pub summary: String,
    /// The package responsible, when it can be told: the crate itself or a
    /// dependency whose build script did it.
    pub package: Option<String>,
    /// File and line, process, path or destination.
    pub location: Option<String>,
}

/// The version of the analyzer's scoring (`crateward_analyzer::score`).
/// Bumped whenever scoring changes, so old verdicts are recomputed. The
/// dashboard reads it to show which verdicts wait for that.
pub const ANALYZER_VERSION: u32 = 4;

/// The analyzer's judgment of one version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// 0 to 100.
    pub score: u32,
    /// The level of the score.
    pub level: RiskLevel,
    /// What the analysis covered.
    pub coverage: Coverage,
    /// Every point of the score, highest first.
    pub evidence: Vec<Evidence>,
    /// The version's behavior, as normalized entries such as `exec:curl`.
    pub profile: Vec<String>,
    /// Profile entries the previous analyzed version did not have.
    pub new_behavior: Vec<String>,
    /// The analyzer version that produced it.
    pub analyzer_version: u32,
}

#[cfg(test)]
mod tests {
    #[test]
    fn levels_follow_the_score() {
        use super::RiskLevel;

        assert_eq!(RiskLevel::from_score(0), RiskLevel::None);
        assert_eq!(RiskLevel::from_score(19), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(20), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
        assert!(RiskLevel::High.needs_review() && !RiskLevel::Medium.needs_review());
    }

    use super::*;

    #[test]
    fn no_label_claims_a_crate_is_clean() {
        let all = [
            Coverage::DynamicLinux,
            Coverage::StaticOnly(StaticOnlyReason::NoBuildTimeCode),
            Coverage::StaticOnly(StaticOnlyReason::CapacityDeadline),
            Coverage::NotApplicableOnLinux,
        ];

        for coverage in all {
            assert!(!coverage.label().contains("clean"), "{coverage:?}");
        }
    }

    #[test]
    fn source_names_are_the_stored_names() {
        use EvidenceSource::{Diff, Disk, Network, Run, Static, Trace};

        for source in [Static, Diff, Trace, Network, Disk, Run] {
            assert_eq!(serde_json::to_value(source).unwrap(), source.name());
        }
    }
}
