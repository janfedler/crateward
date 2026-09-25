//! Shared vocabulary of Crateward.
//!
//! Every other package depends on this one, so it holds exactly the things
//! that must mean the same in every process: validated identifiers
//! ([`name`], [`digest`]), the components and their trust zones
//! ([`component`]), the pipeline state machine ([`job`]), the failure
//! taxonomy ([`failure`]) and retry policy ([`retry`]), verdict coverage
//! labels ([`verdict`]), the closed list of human escalations
//! ([`escalation`]), the typed configuration ([`config`]) and the wire
//! protocol between host and guest ([`protocol`]).
//!
//! By default the package is pure: no I/O besides reading the configuration
//! file, no async runtime and no database. That keeps it cheap to test
//! exhaustively and safe to link into the guest agent. Host services opt
//! into the process harness (`app`) and the Postgres job store (`store`).

// Unsafe code is denied everywhere except `sandbox`, which wraps one system
// call and documents why it is sound.
#![deny(unsafe_code)]

#[cfg(feature = "app")]
pub mod app;
#[cfg(feature = "blobs")]
pub mod blobs;
pub mod breaker;
pub mod component;
pub mod config;
#[cfg(feature = "cratesio")]
pub mod cratesio;
pub mod digest;
pub mod elf;
pub mod escalation;
pub mod failure;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "integrity")]
pub mod integrity;
pub mod job;
pub mod name;
pub mod protocol;
pub mod retry;
#[cfg(feature = "sandbox")]
pub mod sandbox;
#[cfg(feature = "store")]
pub mod store;
pub mod verdict;
