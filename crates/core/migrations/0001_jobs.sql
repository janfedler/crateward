-- One row per crate version, from discovery to verdict (ADR 0001).
-- The pipeline state machine lives in crateward_core::job; the row stores
-- its value as JSON next to the columns the queue needs for claiming.

CREATE TABLE jobs (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    crate_name       text        NOT NULL,
    -- Lowercase with '-' folded to '_': crates.io rejects names that
    -- collide in this form, so it identifies a crate.
    canonical_name   text        NOT NULL,
    version          text        NOT NULL,
    cksum            bytea       NOT NULL CHECK (octet_length(cksum) = 32),
    published_at     timestamptz,
    discovered_at    timestamptz NOT NULL DEFAULT now(),
    priority         smallint    NOT NULL,
    state            text        NOT NULL,
    job              jsonb       NOT NULL,
    -- The version's line from the sparse index, as served.
    index_entry      jsonb       NOT NULL,
    lease_owner      text,
    lease_expires_at timestamptz,
    not_before       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (canonical_name, version),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);

-- Claiming: unleased rows of one state, highest priority first.
CREATE INDEX jobs_claim ON jobs (state, priority DESC, id) WHERE lease_owner IS NULL;
-- Reaping expired leases.
CREATE INDEX jobs_leases ON jobs (lease_expires_at) WHERE lease_owner IS NOT NULL;

-- Every transition, for the timeline on the dashboard and for audits.
CREATE TABLE job_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id     bigint      NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    from_state text        NOT NULL,
    to_state   text        NOT NULL,
    event      jsonb       NOT NULL,
    effect     jsonb       NOT NULL,
    worker     text        NOT NULL
);
CREATE INDEX job_events_job ON job_events (job_id, id);
