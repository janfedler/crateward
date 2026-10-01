-- Static analysis results (ADR 0005).
--
-- A report belongs to crate file content, not to a job: analysis of the
-- same bytes gives the same report, and shared dependencies are analyzed
-- once. A report from an older analyzer version is recomputed on demand.
CREATE TABLE static_reports (
    sha256           bytea       PRIMARY KEY REFERENCES crate_files (sha256) ON DELETE CASCADE,
    analyzer_version integer     NOT NULL,
    build_time_code  boolean     NOT NULL,
    -- Highest finding severity, NULL without findings.
    max_severity     text,
    report           jsonb       NOT NULL,
    analyzed_at      timestamptz NOT NULL DEFAULT now()
);

-- What static analysis decided for a job, and why.
CREATE TABLE job_static (
    job_id      bigint      PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    triage      jsonb       NOT NULL,
    reasons     jsonb       NOT NULL,
    -- Changes against the previous analyzed version; NULL for the first.
    diff        jsonb,
    analyzed_at timestamptz NOT NULL DEFAULT now()
);
