//! Shared vocabulary of Crateward.
//!
//! Every other package depends on this one, so it holds exactly the things
//! that must mean the same in every process: validated identifiers
//! ([`name`], [`digest`]), the components and their trust zones
//! ([`component`]), the pipeline state machine ([`job`]), the failure
//! taxonomy ([`failure`]) and retry policy ([`retry`]), verdict coverage
//! labels ([`verdict`]), the closed list of human escalations
//! ([`escalation`]) and the typed configuration ([`config`]).
//!
//! The package is pure: no I/O besides reading the configuration file, no
//! async runtime and no database. That keeps it cheap to test exhaustively
//! and safe to link into the guest agent.

#![forbid(unsafe_code)]

#[cfg(feature = "app")]
pub mod app;
pub mod component;
pub mod config;
pub mod digest;
pub mod escalation;
pub mod failure;
pub mod job;
pub mod name;
pub mod retry;
pub mod verdict;
