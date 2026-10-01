-- TODO.sota/05 — the ROR id on the organization registry
-- (the member-domains pipeline's enrichment; additive).
ALTER TABLE org_registry ADD COLUMN ror_id TEXT;
