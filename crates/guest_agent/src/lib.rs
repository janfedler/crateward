//! Agent inside the microVM.
//!
//! Zone: guest. Everything in the guest, this agent included, is assumed to
//! be under the control of the crate being analyzed once its code runs. The
//! host therefore treats every byte from the agent as hostile input: frames
//! are length limited, schema validated and parsed by fuzzed code.
//!
//! Why it looks the way it does:
//!
//! * It ships as a static musl binary so that it does not depend on the
//!   guest's C library, which a crate could tamper with.
//! * It waits on one vsock port. The host initiates the single connection
//!   after restoring the snapshot, sends the job specification (including
//!   the per job honeytokens and the wall clock), and receives a stream of
//!   length prefixed event frames. The host never listens for guest
//!   initiated vsock connections.
//! * It runs cargo offline against the vendored dependencies with
//!   `CARGO_INCREMENTAL=0` and debuginfo off, as an unprivileged user.
//! * It traces processes, files, network and selected syscalls with eBPF
//!   (see ADR 0006). The eBPF programs live in a separate package because
//!   they build for a different target with a pinned nightly toolchain.
//! * It never holds host secrets. The honeytokens it plants are fake and
//!   unique per job, so any sighting attributes to exactly one run.

#![forbid(unsafe_code)]

use crateward_core::component::Component;

/// The component this package implements.
pub const COMPONENT: Component = Component::GuestAgent;

/// Milestone that delivers the agent.
pub const MILESTONE: &str = "M4";
