# 0001: Record architecture decisions

* Status: Accepted
* Date: 2026-09-24

## Context

Crateward is a security project. A reviewer has to understand why a design
looks the way it does before trusting it, and the maintainer has to be able
to revisit a decision when a fact changes, for example when Firecracker adds
a host kernel to its support matrix.

## Options

1. Explain decisions in pull request descriptions only.
2. Keep one design document and edit it over time.
3. Keep numbered, immutable decision records.

## Decision

Option 3. Every decision with real alternatives gets a record in `docs/adr/`
using [the template](0000-template.md). Records cite the documents they rely
on. A changed decision gets a new record that supersedes the old one.

## Consequences

The history of the reasoning stays readable. Records cost a little time per
decision, and they must cite sources, which forces checking facts instead of
recalling them.

## Sources

* The ADR format described by Michael Nygard, "Documenting Architecture
  Decisions" (2011), used here in a shortened form.
