-- Retention (M7).

-- When the supervisor trimmed the raw parts of a run report (process list,
-- output tails). NULL while the report is complete.
ALTER TABLE job_runs ADD COLUMN trimmed_at timestamptz;
CREATE INDEX job_runs_untrimmed ON job_runs (recorded_at) WHERE trimmed_at IS NULL;
