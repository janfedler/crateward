# Testing

## The one rule

**Crate code is never executed outside a microVM.** That includes tests and
CI. Fixture crates are inert, stored as archives, and never workspace
members, so `cargo test` at the root can never build them. CI tests the
orchestrator against a fake Firecracker backend; real VMs run only on the
server.

## Layers

| Layer | What | Where |
|-------|------|-------|
| Unit tests | Pure logic: names, digests, config validation, state machine paths | `#[cfg(test)]` modules |
| Property tests | Parsers and the state machine under arbitrary input | `proptest`, for example `crates/core/tests/state_machine.rs` |
| Documentation checks | Writing style, generated diagram up to date | `cargo xtask docs-lint`, `cargo xtask state-diagram` |
| Integration tests | Feed and fetcher against a mock crates.io; Postgres job store | M2 |
| End to end tests | Canary crates through the whole pipeline with the fake VM backend | M5 |
| Fuzz targets | Extraction, event decoding, DNS and HTTP sinks | M7 (`cargo fuzz`) |
| Soak test | 50 sequential real VM jobs without leaked resources | M1, on the server |

## State machine properties

`crates/core/tests/state_machine.rs` drives the job state machine with
arbitrary event sequences and checks:

* rejected events leave the job unchanged;
* terminal states accept no event;
* every sequence of valid events reaches a terminal state within a fixed
  bound, so there is no infinite path;
* transient failures end in `Failed` after at most `max_attempts`;
* escalation to a full build happens at most once;
* the coverage label is "dynamic on Linux" exactly when a VM run completed.

## Running the checks

```sh
cargo xtask ci
```

runs formatting, clippy with warnings denied, all tests, rustdoc with
warnings denied, the static musl build of the guest agent, the
documentation checks, `cargo deny`, `cargo audit` and `cargo vet`, in the
same order as CI.

## Writing style

Documentation, rustdoc comments and configuration comments are English, in
short and precise sentences, with no em dashes and no hyphenated compounds.
`cargo xtask docs-lint` enforces the last two rules:

* write "read only", "content addressed", "build time" instead of joining
  words with hyphens;
* put names that contain hyphens (crates, tools, flags, targets) in inline
  code, for example `cargo-deny`;
* text inside double quotes is a quotation of a source and is not checked.
