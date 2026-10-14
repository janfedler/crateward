//! The report of one VM run.

use serde::{Deserialize, Serialize};

use crate::job::BuildOutcome;
use crate::protocol::ExitStatus;
use crate::report::network::{Leak, NetworkSummary};
use crate::report::scratch::ScratchReport;
use crate::report::trace::TraceSummary;

/// What one VM run produced, as stored in `job_runs.report`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    /// How the build ended.
    pub outcome: BuildOutcome,
    /// How the run ended from the host's view.
    pub end: String,
    /// The guest's exit status, when the agent reported one.
    pub exit: Option<ExitStatus>,
    /// Restore to ready agent, in milliseconds.
    pub restore_ms: u64,
    /// The run itself, in milliseconds.
    pub run_ms: u64,
    /// The last bytes of stdout.
    pub stdout_tail: String,
    /// The last bytes of stderr.
    pub stderr_tail: String,
    /// Output beyond the limit was dropped.
    pub truncated: bool,
    /// Files and bytes in the payload.
    pub payload_files: u64,
    /// Bytes of file contents in the payload.
    pub payload_bytes: u64,
    /// Locked crates missing from the payload (not stored by the fetcher).
    pub missing_packages: Vec<String>,
    /// What the guest tried to reach, from the fake internet's log.
    pub network: NetworkSummary,
    /// Honeytokens that left the VM.
    pub leaked: Vec<Leak>,
    /// The guest's eBPF trace. Absent when the run ended without a report.
    #[serde(default)]
    pub trace: TraceSummary,
    /// Honeytokens the trace shows inside the VM, for example in a
    /// program's arguments. `via` names the process or path.
    #[serde(default)]
    pub tokens_in_trace: Vec<Leak>,
    /// What the job left on its scratch disk, read by the host. `None` if
    /// the scanner itself failed.
    #[serde(default)]
    pub scratch: Option<ScratchReport>,
    /// Honeytokens copied into files on the scratch disk. `via` is the path.
    #[serde(default)]
    pub tokens_on_disk: Vec<Leak>,
}
