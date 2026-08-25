-- Migration 0016 — the instrument register (TODO.register/03: the
-- serial-number registration interface). One row per REGISTERED
-- instrument: the serial number riding under a type certificate, the
-- holder organization (the manufacturer), the Recommendation the
-- certificate belongs to, the manufacture date, the per-serial
-- designations (the concrete scope parameters the scope check evaluated
-- — accuracy class, capacity, …), the scope verdict recorded AT
-- REGISTRATION (in_scope, or scope_unverified when the certificate's
-- scope block is not structured — the records-mode honest-degradation
-- posture), and the lifecycle (registered / out_of_service / withdrawn).
--
-- The scope REFUSAL never lands a row: an out-of-scope declaration is
-- refused with the reason by the route (the executing-scope doctrine at
-- the instrument level), so every row here is a registration that stood.
-- The batch import's per-row verdicts are answered to the caller, never
-- persisted; the committed rows are the valid ones (never a partial
-- SILENT import — the refusal report is the caller's record).
--
-- Uniqueness: one serial number per certificate (the register's whole
-- point — the same physical unit never registers twice under one type
-- certificate). The route turns the conflict into the honest 409.
--
-- NOT mirrored into the identity service's migration set: the byte-
-- identity rule covers the OP's tables, and the instrument register is
-- platform-side (the identity deploy never shares it — TODO.register/03
-- §The model). The holder_org_id references the identity plane's
-- organization by id WITHOUT a foreign key, deliberately — the same
-- posture org_memberships practices (migration 0011): the identity-side
-- registry and this platform-side register never merge, and a
-- registration row's honesty never depends on a join.
--
-- No backfill: the register starts empty and fills through the
-- registration acts (the UI, the CSV batch, the API). schema.sql
-- carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS instrument_registrations (
  id TEXT PRIMARY KEY,
  -- The certificate the serial rides under (the entity store's
  -- certificates row id — a platform reference, never a key into the
  -- identity plane).
  certificate_id TEXT NOT NULL,
  -- The holder organization (the manufacturer org id; the identity
  -- plane's org, referenced by id without a foreign key).
  holder_org_id TEXT NOT NULL,
  -- The Recommendation the certificate belongs to (the kind of
  -- measuring instrument — certificates.standard_id).
  standard_id TEXT NOT NULL,
  serial_number TEXT NOT NULL,
  -- The manufacture date (ISO date text; NULL when the declaration
  -- did not carry it).
  manufacture_date TEXT,
  -- The per-serial designations the scope check evaluated (a JSON
  -- object; e.g. { "accuracy_class": "C", "e_max": { "value": 2.2,
  -- "unit": "t" } }).
  designations TEXT NOT NULL DEFAULT '{}',
  -- The scope verdict AT REGISTRATION: 'in_scope' (the structured
  -- scope block covered the designations) or 'scope_unverified' (the
  -- certificate carries no structured scope block — the records-mode
  -- honest degradation; the IA's oversight surface sees exactly this
  -- mark). The refused declaration never lands a row.
  scope_status TEXT NOT NULL,
  -- The verdict's record: the matched classification label (in_scope)
  -- or the unverified note (scope_unverified).
  scope_detail TEXT,
  lifecycle TEXT NOT NULL DEFAULT 'registered',
  -- The lifecycle act's provenance (the last act's actor + moment; the
  -- registration itself stamps registered_at/by).
  registered_at TEXT NOT NULL DEFAULT (datetime('now')),
  registered_by TEXT,
  updated_at TEXT,
  updated_by TEXT,
  UNIQUE (certificate_id, serial_number)
);
CREATE INDEX IF NOT EXISTS idx_instrument_registrations_certificate ON instrument_registrations (certificate_id);
CREATE INDEX IF NOT EXISTS idx_instrument_registrations_holder ON instrument_registrations (holder_org_id);
CREATE INDEX IF NOT EXISTS idx_instrument_registrations_lifecycle ON instrument_registrations (lifecycle);
