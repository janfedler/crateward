# Security checklist

What to check before a release, after every deploy, and every week. Each
item names the command or file that proves it. The threat model says why
each control exists; this page says how to see that it still holds.

## Before a release

| Check | How |
|-------|-----|
| Formatting, clippy, tests, rustdoc, guest agent, eBPF programs, documentation, `cargo deny`, `cargo audit`, `cargo vet` | `cargo xtask ci` passes; CI is green for the commit |
| Every fuzz target runs from the seed corpus without a finding | `cargo xtask fuzz --seconds 150`; `fuzz/artifacts` stays empty |
| Real microVM tests, the soak test and the canary pass on the server | `cargo test -p crateward_orchestrator --test firecracker -- --ignored`, `cargo xtask soak --jobs 50`, `cargo xtask canary` |
| No new `unsafe` outside `crateward_core::sandbox` | `unsafe_code` is denied workspace wide; `grep -rn "allow(unsafe_code)" crates` lists only that module |
| New or updated dependencies are audited | `cargo vet` passes without new exemptions, or each exemption is explained in the commit |
| The threat model matches the code | every row marked Built or Tested points at code that exists |
| The release bundle is complete and signed | `cargo xtask release` on a clean tree (no `-dirty` in the name); `sha256sum -c SHA256SUMS`; the signature over `SHA256SUMS` verifies with `ssh-keygen -Y verify`, which `install.sh` also checks |

## After every deploy

| Check | How |
|-------|-----|
| The integrity manifest covers the new binaries | `crateward integrity --config <file> record`, then `check` prints nothing |
| The configuration is valid | `crateward config check --config <file>` |
| The dashboard listens on loopback only | `ss -ltn` shows `127.0.0.1:8080` and no other address for it |
| No inbound service except WireGuard and SSH | `ss -ltun` |
| Secrets are readable by their service user only | the secret files are mode 0600 |
| Access times work where jails live | the orchestrator starts (it refuses to when a read does not change a file's access time) |
| Nothing is paused unexpectedly | `crateward status` shows no quarantine and closed breakers |

## Every week

| Check | How |
|-------|-----|
| SMT is off | `/sys/devices/system/cpu/smt/control` reads `off` or `forceoff` |
| KSM is off and there is no swap | `/sys/kernel/mm/ksm/run` reads `0`; `/proc/swaps` lists nothing |
| PostgreSQL data checksums are on | `SHOW data_checksums` returns `on` |
| The RAID is healthy and the last scrub found nothing | `/proc/mdstat`, `mismatch_cnt` of each array |
| Canaries pass | `crateward status` |
| Decoys are in place and excluded from backups | the paths in `supervisor.decoys` exist; the backup configuration excludes them |
| Storage stays within the budget | `du` of the data directory and `pg_database_size`, compared with OPERATIONS.md |
| Security advisories for the kernel, Firecracker and KVM are read | the Debian security tracker and the Firecracker releases |
