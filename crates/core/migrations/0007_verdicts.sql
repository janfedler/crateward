-- Verdicts (M6, ADR 0009).

-- One verdict per job: the score, the evidence behind every point, and the
-- version's behavior profile. `review` tracks the "needs you" inbox.
CREATE TABLE verdicts (
    job_id           bigint      PRIMARY KEY REFERENCES jobs (id) ON DELETE CASCADE,
    score            integer     NOT NULL CHECK (score BETWEEN 0 AND 100),
    level            text        NOT NULL,
    verdict          jsonb       NOT NULL,
    analyzer_version integer     NOT NULL,
    review           text        NOT NULL DEFAULT 'none'
                     CHECK (review IN ('none', 'pending', 'confirmed', 'false_positive')),
    review_note      text,
    reviewed_at      timestamptz,
    scored_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX verdicts_inbox ON verdicts (scored_at) WHERE review = 'pending';
CREATE INDEX verdicts_level ON verdicts (level, scored_at DESC);
