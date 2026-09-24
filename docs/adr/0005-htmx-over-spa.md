# 0005: Server rendered HTML with htmx, not a single page app

* Status: Accepted
* Date: 2026-09-24

## Context

The dashboard shows health lights, queues, verdicts, evidence and a "needs
you" inbox. It displays text that attackers control (crate names,
descriptions, file names, strings from source code) and it is the
maintainer's control panel, so cross site scripting is the main web risk.
The project rules forbid a JavaScript build chain.

## Options

1. **Server rendered HTML with htmx** for partial updates and server sent
   events for live data.
2. **A single page app** (React, Svelte or similar) with a JSON API.
3. **A Rust frontend compiled to WebAssembly.**

## Decision

Option 1, with axum on the server and a template engine that escapes by
default. htmx is vendored as a static file served from the same origin.

## Rationale

* No JavaScript build chain means no npm dependency tree in the supply
  chain of a supply chain security tool.
* Escaping happens on the server in one place: the templates.
* htmx can run under a strict Content Security Policy. Its documentation
  lists `htmx.config.allowEval` (can be set to false to disable features that
  rely on eval), `htmx.config.allowScriptTags`, `htmx.config.includeIndicatorStyles`
  (which otherwise injects inline styles) and `htmx.config.selfRequestsOnly`
  (defaults to true). Crateward sets the first three to false, which allows a
  policy such as `default-src 'none'; script-src 'self'; style-src 'self'`.
* Server sent events fit one way live updates (queue depth, new verdicts)
  and need no extra protocol.

## Consequences

* Interactive features that would need custom JavaScript are avoided or
  built from htmx attributes.
* The template engine is chosen in M6; the requirement is escaping by
  default at compile time.

## Sources

* htmx `www/content/docs.md` and `www/content/reference.md`, sections
  "Security" and "Configuring htmx", `https://github.com/bigskysoftware/htmx`
