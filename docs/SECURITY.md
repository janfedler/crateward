# Security policy

This page covers two different things: vulnerabilities in Crateward itself,
and what Crateward does when it finds something in a crate.

## Reporting a vulnerability in Crateward

Crateward runs hostile code for a living, so reports about sandbox escapes,
parser bugs, cache poisoning, or anything that lets a crate influence the
host or other jobs are especially welcome.

* Report privately through GitHub's private vulnerability reporting on
  `janfedler/crateward` (Security tab, "Report a vulnerability").
* Once the mailbox exists (milestone M8), `security@crateward.com` works
  too.
* Please do not open a public issue for a security problem.

Crateward is maintained by one person. Expect an acknowledgement within 7
days and a first assessment within 14 days. Fixes are released as soon as
they are ready; the report is published with credit (unless you prefer
otherwise) once a fix is deployed.

### Scope

In scope: the code in this repository, the deployment it describes, and the
public site at crateward.com.

Out of scope: denial of service by volume, reports from automated scanners
without a demonstrated impact, and the third party services Crateward uses
(crates.io, GitHub, healthchecks.io, ntfy.sh). Report those to their
operators.

### Safe harbor

Good faith research that respects the scope above, avoids privacy violations
and service disruption, and gives reasonable time to fix before disclosure
will not be pursued.

## Findings about crates

Crateward never publishes a finding about a crate before it has been
reported and handled. Malicious crates go to the crates.io team; ordinary
vulnerabilities go to the crate's maintainers first. The full workflow is in
[DISCLOSURE.md](DISCLOSURE.md).

If you believe Crateward reported one of your crates by mistake, open an
issue or use the contact above. False positives are treated as bugs.
