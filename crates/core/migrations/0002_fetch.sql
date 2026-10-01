-- Crate files the fetcher has downloaded and validated (ADR 0004). Keyed by
-- the SHA-256 that the crates.io index publishes, so a crate shared by many
-- jobs is fetched and validated once.
CREATE TABLE crate_files (
    sha256           bytea       PRIMARY KEY CHECK (octet_length(sha256) = 32),
    crate_name       text        NOT NULL,
    version          text        NOT NULL,
    -- BLAKE3 of the unpacked tar, naming its blob; NULL when validation
    -- aborted and the archive was not stored.
    blake3           text,
    compressed_bytes bigint      NOT NULL,
    unpacked_bytes   bigint      NOT NULL,
    stored_bytes     bigint,
    report           jsonb       NOT NULL,
    fetched_at       timestamptz NOT NULL DEFAULT now()
);

-- What the fetch stage produced for a job: the lockfile of its consumer
-- probe, or why resolution failed, and the locked packages.
CREATE TABLE job_fetches (
    job_id           bigint      PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    lockfile         text,
    resolution_error text,
    packages         jsonb       NOT NULL,
    fetched_at       timestamptz NOT NULL DEFAULT now()
);
