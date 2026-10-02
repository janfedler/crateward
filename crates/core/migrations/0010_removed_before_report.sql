-- A malicious crate that crates.io removed before Crateward reported it
-- (DISCLOSURE.md): no report is sent and the record says so. The removal
-- is its resolution, so only a resolved malicious finding may lack a
-- report.
ALTER TABLE disclosures
    ALTER COLUMN reported_to DROP NOT NULL,
    ALTER COLUMN reported_at DROP NOT NULL,
    ADD CHECK ((reported_to IS NULL) = (reported_at IS NULL)),
    ADD CHECK (reported_to IS NOT NULL OR (kind = 'malicious' AND resolved_at IS NOT NULL));
