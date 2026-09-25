-- Dynamic analysis results (M4).

-- One row per VM run of a job: `check` first, `full` after escalation.
CREATE TABLE job_runs (
    job_id      bigint      NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    run_kind    text        NOT NULL,
    outcome     text        NOT NULL,
    report      jsonb       NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, run_kind)
);

-- The honeytokens planted for a job. Each value is unique to its job, so
-- finding one anywhere (fake internet, scratch disk) names the job that
-- took it.
CREATE TABLE job_honeytokens (
    job_id bigint NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    kind   text   NOT NULL,
    value  text   NOT NULL UNIQUE,
    PRIMARY KEY (job_id, kind)
);
