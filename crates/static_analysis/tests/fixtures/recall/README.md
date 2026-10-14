# Recall corpus

Inert crates that rebuild the techniques of known malicious crates, and two
that do what legitimate crates do. None of them is malware: every host is
under `.invalid`, every payload only prints, and nothing here is ever
compiled or run outside a microVM. `tests/recall` only parses them.

Each sample has its sources and a `sample.json`:

* `technique` and `after`: what it rebuilds, and from which public case.
* `run`: what a VM run of it records, merged into an empty run report.
  `trace.processes` are added to `cargo` (pid 1) and the build script
  (pid 2), whose path `$SCRIPT` stands for.
* `min` or `max`: the lowest level a malicious sample must reach, or the
  highest a legitimate one may.

* `gap`: why a malicious sample stays below the level its technique
  deserves. Its `min` pins what Crateward reaches today, so an improvement
  shows up as a failing test that raises it.
