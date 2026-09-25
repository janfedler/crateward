-- Autonomy (M5, ADR 0020): breakers, pauses, alerts, canaries.

-- One circuit breaker per stage. A missing row means closed.
CREATE TABLE stage_breakers (
    stage      text        PRIMARY KEY,
    state      text        NOT NULL CHECK (state IN ('closed', 'open', 'half_open')),
    since      timestamptz NOT NULL DEFAULT now(),
    reopened   integer     NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Reasons the pipeline, or some stages of it, stop claiming jobs. Each
-- reason is set and lifted on its own: quarantine only by a human, the
-- others automatically.
CREATE TABLE pipeline_pauses (
    reason text        PRIMARY KEY CHECK (reason IN ('quarantine', 'canary', 'disk')),
    stages text[]      NOT NULL,
    since  timestamptz NOT NULL DEFAULT now(),
    job_id bigint,
    detail text        NOT NULL
);

-- Alerts from the closed list in crateward_core::escalation, waiting for
-- the notifier (an outbox) and afterwards as a record.
CREATE TABLE alerts (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dedup_key  text        NOT NULL,
    escalation jsonb       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at    timestamptz,
    -- Not sent because the same alert went out recently.
    suppressed boolean     NOT NULL DEFAULT false,
    attempts   integer     NOT NULL DEFAULT 0,
    last_error text
);
CREATE INDEX alerts_pending ON alerts (id) WHERE sent_at IS NULL AND NOT suppressed;
CREATE INDEX alerts_sent ON alerts (dedup_key, sent_at) WHERE sent_at IS NOT NULL;

-- Results of the canaries the orchestrator runs.
CREATE TABLE canary_runs (
    id      bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    canary  text        NOT NULL,
    passed  boolean     NOT NULL,
    detail  jsonb       NOT NULL
);
CREATE INDEX canary_runs_latest ON canary_runs (canary, id DESC);
