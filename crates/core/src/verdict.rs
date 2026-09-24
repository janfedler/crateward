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

#[cfg(test)]
mod tests {
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
}
