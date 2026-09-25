# 0022: The dashboard and the public export

* Status: Accepted
* Date: 2026-09-25

## Context

ADR 0005 chose server rendered HTML with htmx; ADR 0009 chose a static
public site on GitHub Pages. M6 builds both. The dashboard shows text that
attackers control (crate names, file names, strings from source code,
paths from traces) to the maintainer, who can act on it; the public site
must never reveal an undisclosed finding.

Facts verified on 2026-09-25:

* askama 0.16 generates templates at compile time and escapes HTML by
  default.
* htmx 2.0.11 and its server sent events extension 2.2.4 are 0BSD. Their npm
  tarballs matched the SHA-512 integrity the registry publishes.
* WebAuthn works only in a secure context (HTTPS, or `localhost`), and a
  relying party ID must be a domain, not an IP address. A dashboard served
  over plain HTTP at the WireGuard address therefore cannot use passkeys,
  which the threat model had planned.
* The server has no WireGuard interface yet and the site repository does
  not exist yet; both are M8 work.

## Decision

0. **Access.** The dashboard listens on loopback only; configuration
   rejects any other address. The maintainer reaches it through WireGuard
   and an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 <server>`), so the SSH
   key authenticates them. Passkeys are not a requirement (maintainer
   decision, 2026-09-25): with loopback and SSH they would add a second
   login without a second boundary, and without them no domain or
   certificate is needed.
1. **Dashboard.** `crateward_api` serves an overview (pipeline state,
   breakers, canaries, queues, verdict levels; live through server sent
   events), the "needs you" inbox, a filterable job list and a job page
   (evidence with points and packages, behavior profile and what is new,
   static findings, timeline, raw run reports). The only write is a review
   decision: confirmed or false positive.
2. **Protections**, for every request:
   * a `Host` check against the listen address, so a site that rebinds its
     name to the dashboard's address gets nothing (DNS rebinding);
   * requests other than `GET` and `HEAD` must be same origin
     (`Sec-Fetch-Site`, or `Origin`), against cross site form posts;
   * a Content Security Policy that allows only the dashboard's own
     scripts and styles, no inline code, no framing; htmx runs with eval,
     script tags and indicator styles disabled;
   * page queries run on a read only session; a second connection makes
     the review write.
3. **Vendored scripts.** htmx and the extension are compiled into the
   binary; a test checks their SHA-256 against the pins.
4. **Public export.** Next to the dashboard, a task renders the site every
   `export.interval_hours`: totals, coverage shares, verdict levels,
   finished versions per day, whether the canaries pass, and `stats.json`.
   It holds counts only. It is always written below `instance.run_dir`;
   with `[export]` configured, it is pushed from a fresh shallow clone with
   a deploy key for the site repository only, in one commit, only when
   something changed.

## Consequences

* Every local process on the server can reach the loopback port. They are
  all Crateward's own services or the maintainer's; crate code never runs
  on the host, and the VMs' network namespaces have no route to it.
* Through the tunnel the browser sends `Host: localhost:<port>`, so the
  Host check accepts `localhost` and `127.0.0.1` with the configured port.

* Crate supplied text is escaped everywhere; a test renders hostile names
  and evidence and checks nothing executes.
* Findings reach the public site only by hand, after disclosure.

## Sources

* askama `README.md` and book, `https://askama.rs/`
* htmx `www/content/docs.md` ("Security", "Configuring htmx"),
  `https://github.com/bigskysoftware/htmx`; npm registry metadata for
  `htmx.org` 2.0.11 and `htmx-ext-sse` 2.2.4
* W3C Web Authentication Level 2, "Relying Party Identifier" and "Secure
  Contexts"; W3C Secure Contexts, "Is origin potentially trustworthy?"
