-- Versions of one crate may share a finding page. The store refuses a page
-- that a finding about another crate uses.
ALTER TABLE disclosures DROP CONSTRAINT disclosures_slug_key;
CREATE INDEX disclosures_slug ON disclosures (slug);
