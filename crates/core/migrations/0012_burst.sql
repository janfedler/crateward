-- Burst mode: the maintainer pauses VM runs so that reprocessing after an
-- analyzer version bump gets their cores.
ALTER TABLE pipeline_pauses DROP CONSTRAINT pipeline_pauses_reason_check;
ALTER TABLE pipeline_pauses ADD CONSTRAINT pipeline_pauses_reason_check
    CHECK (reason IN ('quarantine', 'canary', 'disk', 'burst'));
