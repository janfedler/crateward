//! Integration tests of the job store against a real PostgreSQL.
//!
//! The database setup is [`crateward_core::testing`].

#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod autonomy;
mod findings;
mod queue;
mod reports;

use std::time::Duration;

use crateward_core::breaker::{BreakerState, Counts};
use crateward_core::digest::Sha256Digest;
use crateward_core::escalation::HumanEscalation;
use crateward_core::failure::FailureClass;
use crateward_core::job::{JobEvent, JobId, JobState, Stage, Triage};
use crateward_core::name::CrateName;
use crateward_core::store::{
    AlertOutcome, CrateFile, DisclosureKind, DisclosureRefusal, JobFilter, NewJob, PauseReason,
    Review, Store, StoreError,
};
use crateward_core::testing::{TestDb, policies};
use crateward_core::verdict::{
    ANALYZER_VERSION, Coverage, RiskLevel, STATIC_ANALYZER_VERSION, Verdict,
};

fn new_job(name: &str, version: &str, priority: i16) -> NewJob {
    NewJob {
        name: CrateName::parse(name).unwrap(),
        version: version.parse().unwrap(),
        cksum: "ab".repeat(32).parse().unwrap(),
        published_at: None,
        priority,
        index_entry: serde_json::json!({"name": name, "vers": version}),
    }
}

const LEASE: Duration = Duration::from_secs(30);
