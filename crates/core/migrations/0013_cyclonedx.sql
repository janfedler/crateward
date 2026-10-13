-- CycloneDX documents (ADR 0012).

-- SHA-512 of the `.crate` file, which TR-03183-2 asks for. NULL for files
-- fetched before it was computed, until the fetcher hashes them again.
ALTER TABLE crate_files ADD COLUMN sha512 text CHECK (sha512 ~ '^[0-9a-f]{128}$');
CREATE INDEX crate_files_without_sha512 ON crate_files (fetched_at) WHERE sha512 IS NULL;

-- The SHA-256 of a job's lockfile, or of nothing without one: with the
-- crate's SHA-256 the key of its SBOM.
-- `Store::record_fetch` sets it.
ALTER TABLE job_fetches ADD COLUMN lockfile_key bytea;
UPDATE job_fetches SET lockfile_key = sha256(convert_to(coalesce(lockfile, ''), 'UTF8'));
ALTER TABLE job_fetches ALTER COLUMN lockfile_key SET NOT NULL;

-- The SBOM of a crate file and the lockfile it was resolved with, keyed by
-- the crate's SHA-256 and the lockfile's SHA-256. It is stored so that a
-- document others may hold does not change under the same serial number
-- and version. `gaps` counts what TR-03183-2 asks for and the data
-- lacked. Only a document with gaps is replaced, with a higher version.
-- `checked_at` is when the data was last looked at for fewer gaps.
CREATE TABLE sboms (
    crate_sha256 bytea       NOT NULL CHECK (octet_length(crate_sha256) = 32),
    lockfile_key bytea       NOT NULL CHECK (octet_length(lockfile_key) = 32),
    serial       text        NOT NULL,
    version      integer     NOT NULL CHECK (version >= 1),
    gaps         integer     NOT NULL CHECK (gaps >= 0),
    document     jsonb       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    checked_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (crate_sha256, lockfile_key)
);
CREATE INDEX sboms_with_gaps ON sboms (checked_at) WHERE gaps > 0;

-- How often a verdict or its review changed: the version of the job's
-- findings document.
ALTER TABLE verdicts ADD COLUMN revision integer NOT NULL DEFAULT 1;
