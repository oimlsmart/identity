-- Migration 0015 — the register's holder-org attribution (TODO.register/02:
-- "my organization's certificates"). The certificate's holder becomes the
-- OP-minted ORG id end to end: the application binds the applicant account's
-- active org (applicant_org_id), the issued certificate carries it as the
-- holder-org descriptor (json_data.holder_org — additive entity content, no
-- schema change), the federation registration package transports it, and the
-- HUB stores the descriptor on the registered certificate as an ATTRIBUTION
-- ROW here — the hub's own record, never a write into the sender's imported
-- artifact.
--
-- THE NUMBERING: 0013_org_registry is merged; the notify-03 inbox wave holds
-- 0014; THIS wave (TODO.register/02) holds 0015; the serial-registration wave
-- (TODO.register/03) takes 0016. Expand-only: two new tables, no alterations.
-- The identity repo (oimlsmart/identity) mirrors this migration set
-- byte-identical (552's precedent) — the coordinator carries the mirror.
--
-- certificate_holder_orgs: ONE row per certificate (the primary key) — the
-- first attribution wins; the claim act's confirmation is the only other
-- writer (a claimed row is deliberate, never silently overwritten). The org
-- display name is DENORMALIZED at attribution time: the register reads
-- correctly even when the org later renames (the register's permanence rule).
--
-- certificate_holder_claims: the legacy-row CLAIM act's state machine. A
-- certificate registered before this program (or arriving via records mode /
-- CSV) carries a free-text holder and no descriptor; the manufacturer org's
-- administrator claims the row by holder-name match (the matched name is
-- snapshotted as the claim's evidence), an estate admin confirms or refuses
-- (atomic on 'pending'), and the audit chain (auditEvents) carries both acts.
-- A refused claim never blocks a fresh claim; a confirmed claim is terminal.

CREATE TABLE IF NOT EXISTS certificate_holder_orgs (
  certificate_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  -- The org's display name at attribution time (denormalized — the
  -- register's permanence; never a join).
  org_name TEXT NOT NULL,
  -- 'registration' (the chain's carried descriptor, extracted by the
  -- registrar's act) | 'claim' (the confirmed legacy-row claim).
  source TEXT NOT NULL,
  attributed_at TEXT NOT NULL,
  attributed_by TEXT,
  -- The confirming claim (source 'claim' only).
  claim_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_certificate_holder_orgs_org ON certificate_holder_orgs (org_id);

CREATE TABLE IF NOT EXISTS certificate_holder_claims (
  id TEXT PRIMARY KEY,
  certificate_id TEXT NOT NULL,
  claimant_org_id TEXT NOT NULL,
  claimant_org_name TEXT NOT NULL,
  -- The certificate's free-text holder name the claim matched (snapshot).
  matched_holder_name TEXT NOT NULL,
  claimed_by TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  decided_by TEXT,
  decided_at TEXT,
  refusal_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_certificate_holder_claims_cert ON certificate_holder_claims (certificate_id);
CREATE INDEX IF NOT EXISTS idx_certificate_holder_claims_state ON certificate_holder_claims (state);
CREATE INDEX IF NOT EXISTS idx_certificate_holder_claims_org ON certificate_holder_claims (claimant_org_id);
