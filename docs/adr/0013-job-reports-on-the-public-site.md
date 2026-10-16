# 0013: Job reports on the public site

* Status: Accepted
* Date: 2026-10-16

## Context

The public site held counts and disclosed findings only (ADR 0001). The
reports behind them stayed on the dashboard, which listens on loopback
behind SSH (ADR 0009). `crateward archive` already writes chosen reports
as static pages that may be published: it refuses verdicts that wait for
review and confirmed findings before their publication (DISCLOSURE.md), and
it redacts honeytokens. The maintainer wants those reports on the public
site without closing the server, and kept current.

A report that once was public must be removable. Git keeps every version
of a file in its history, and the site repository is public.

## Decision

1. `crateward archive --publish` writes the chosen reports into `reports/`
   of the site repository, replacing the ones there, and links them from
   the site's front page. The selection is saved in
   `/etc/crateward/report-selection.json`, not in the repository, since it
   names the jobs left out by hand.
2. With `export.reports`, every scheduled export refreshes `reports/` from
   that selection. A job the archive would now refuse, such as a verdict a
   reviewer reopened, leaves the site with the next export. `install.sh`
   asks for it on the first install.
3. Every push replaces the branch with a single commit of the whole tree, so
   a removed report leaves no history. The force push is leased on the
   commit that was cloned, so a page the maintainer pushed meanwhile fails
   the push instead of being lost, and the next export keeps it.
4. The dashboard's service user pushes, as before, with the deploy key that
   can write to the site repository only. `--publish` uses the same key and
   therefore runs as root.

## Alternatives

* **Reports on a separate site or repository:** a second deploy key and a
  second domain for the same audience.
* **Normal commits:** a removed report would stay readable in the public
  history.
* **Removing reports by rewriting the history only when needed:** the
  maintainer would have to notice every report that must go. The refresh
  removes them by the same rules that keep them out.

## Consequences

* The site now carries evidence, within the archive's refusals. Every rule
  that keeps a report out of an archive keeps it off the site.
* The site repository has no history. The finding pages written by hand
  keep their content but lose their past versions.
* The deploy key must be allowed to force push, so a stolen key can also
  replace the site's history. Branch protection that forbids force pushes
  breaks the export.
* GitHub may serve a replaced commit by its hash for a while, and forks or
  clones keep what they fetched. Taking a report down removes it from the
  site, not from every copy.
* Each refresh commits the whole report set. GitHub Pages recommends
  repositories under 1 GB, which bounds how many reports the selection may
  take.

## Sources

* ADR 0001 (the public site), ADR 0009 (the dashboard), DISCLOSURE.md.
* `crates/api/src/export.rs` and `crates/api/src/archive.rs`.
* GitHub Pages limits: <https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits>.
