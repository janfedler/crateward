# 0009: Explainable scoring and a server rendered dashboard

* Status: Accepted
* Date: 2026-09-25

## Context

The stages store what they observed: static reports, the version diff, and
each VM run's trace, network log and scratch scan. That must become a
verdict a human can check, and a human sees only what needs them: crates.io
publishes about 7,400 versions a day, so even one percent in an inbox would
bury the real findings. The dashboard shows text that attackers control to
the one person who can act on it.

## Decision

1. **A sum of evidence, capped per group** and at 100 in total. Levels:
   none (0), low (1 to 19), medium (20 to 49), high (50 to 79), critical
   (80 and up).

   | Group | Cap | Signals and points |
   |-------|-----|--------------------|
   | Theft | 100 | honeytoken left the VM 100, copied inside the VM 60, network data the honeytoken search could not see 50 |
   | Integrity | 100 | became root 80, tamper attempt 60, guest stopped 50, set ID file 40 |
   | Dropper | 100 | the build ran a program from a writable location 60, build time code embeds an executable and starts programs 40 |
   | Credentials | 60 | a non cargo process read credentials 50, another process's memory or environment 30, the crate's own build script wrote the whole environment with a honeytoken into its build directory 15 (a dependency's 0) |
   | Persistence | 60 | write to a persistence location 40, elsewhere outside the build 15, left on disk (persistence 40, executable 20, other 10 per top directory) |
   | Network | 40 | name looked up 10, connection without lookup 20, raw frame 30 |
   | Static | 30 | per finding kind, its strongest instance: high at build time 30, high elsewhere or medium at build time 10, medium elsewhere 2, low at build time 1. A downloader shape whose download the run saw 10 |
   | Execution | 20 | a build script ran a network or privilege tool 15, an encoder 8, a downloader 5, a shell 3 |
   | Change | 20 | build script added 10, new high finding 10 per kind, proc macro added 5, each new dynamic behavior 5 |

2. **Attribution.** Dynamic evidence names the package whose code acted,
   through the process tree (a build script's directory, or `rustc`
   compiling a crate whose proc macros run inside it).
3. **Behavior profiles** (`exec:downloader`, `read:cargo-credentials`, ...)
   per verdict. Behavior the previous version did not have counts in the
   change group.
4. **Review inbox.** High and critical verdicts wait for a human, who marks
   them confirmed or a false positive. A high verdict from `cargo check`
   gets one confirmation run with `cargo build` and fresh honeytokens.
5. **Dashboard:** server rendered HTML (askama, escaping at compile time)
   with vendored htmx and server sent events, on loopback only, reached
   through an SSH tunnel. A `Host` check, same origin checks for writes, a
   strict Content Security Policy and read only page queries. The only
   write is a review decision.
6. **Public site:** a static export of counts only. Findings reach it by
   hand, after disclosure.
7. **MITRE ATT&CK tags.** A fixed table in `crates/core/src/attack.rs`
   maps each signal, and its path or program where that decides, to the
   techniques it is consistent with, checked against the named ATT&CK
   release. The job page and the evidence pack show them. They add no
   points, since the score already weighs the same signals. T1195.001 is
   claimed for the crate only after a human confirmed the verdict.

## Alternatives

* **Count every honeytoken copy as theft:** `cc` 1.6 sets the whole
  environment on the commands it builds, and `libz-sys` prints its command,
  so every crate depending on it copied the token into its build output.
  That was 44 of the first 104 high and critical verdicts. A copy that
  comes with the rest of the environment counts as a dump, and what such a
  build does next (running a program it wrote, sending the token) decides.
* **Count every finding instance:** large crates reached medium by volume
  alone (108 medium verdicts in the first live run).
* **A single page app with a JSON API:** an npm dependency tree in the
  supply chain of a supply chain security tool, and escaping spread over
  the client.
* **Passkeys for the dashboard:** need a secure context and a domain, and
  would add a second login without a second boundary behind SSH.

## Consequences

* Every point of a score links to its evidence and its package, so a
  malicious dependency is named as such.
* Library code weighs little: code that runs only when a library is called
  is out of reach of build time analysis, though static analysis lists it.
* Verdicts carry the analyzer version and are recomputed when it changes.
  The canaries pin the extremes: the known bad one is critical, the known
  good one scores nothing.

## Sources

* askama `https://askama.rs/` and htmx `www/content/docs.md` ("Security",
  "Configuring htmx"), `https://github.com/bigskysoftware/htmx`
* W3C Web Authentication Level 2, "Relying Party Identifier"
* DISCLOSURE.md, steps 1 to 3
