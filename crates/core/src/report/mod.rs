//! What the stages store about a version and the analyzer scores: the
//! static report and version diff, the VM run report with its network log,
//! eBPF trace and scratch disk, and the findings in them.
//!
//! The types live here so that every reader (the analyzer, the dashboard)
//! shares them without linking the stages that produce them.

pub mod findings;
pub mod network;
pub mod run;
pub mod scratch;
pub mod static_report;
pub mod trace;
