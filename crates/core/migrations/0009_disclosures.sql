-- Disclosure records (M8, DISCLOSURE.md).

-- One report per confirmed finding: to whom, when, under which reference,
-- when the recipient acted, and when the finding was published. Only a
-- published row may appear on the public site.
CREATE TABLE disclosures (
    job_id       bigint      PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    kind         text        NOT NULL CHECK (kind IN ('malicious', 'vulnerability')),
    reported_to  text        NOT NULL,
    reported_at  timestamptz NOT NULL DEFAULT now(),
    reference    text,
    resolved_at  timestamptz,
    published_at timestamptz,
    slug         text        UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    note         text,
    CHECK (published_at IS NULL OR (resolved_at IS NOT NULL AND slug IS NOT NULL))
);
