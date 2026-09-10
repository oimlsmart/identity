CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  avatar_url TEXT,
  provider TEXT NOT NULL DEFAULT 'demo',
  provider_account_id TEXT,
  role TEXT NOT NULL DEFAULT 'user',
  -- Organization linkage: manufacturer id (applicant), IA oiml_code (ia_officer),
  -- TL oiml_id (tl_operator); NULL for cs_admin/admin/viewer.
  org_id TEXT,
  -- TODO.federation/12 (RBAC): the FULL assigned role set as a JSON array
  -- (role stays the section-gating primary; roles drives permissions).
  -- NULL = the single primary role only. active=0 deactivates the account
  -- (sessions stop resolving, demo sign-in refuses).
  roles TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  -- TODO.identity/06: the primary address's verification state. Set by the
  -- enrollment ceremony (the administrator-delivered setup link) and by an
  -- email change whose token was DELIVERED BY THE MAILER to the new
  -- address; NULL when nothing ever proved the mailbox (a change confirmed
  -- through an on-screen link stays unverified, honestly).
  email_verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_login TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  token TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  -- TODO.federation/10: the SSO sign-in's id_token, kept for
  -- RP-initiated logout (id_token_hint). NULL for demo/GitHub sessions.
  id_token_hint TEXT,
  -- TODO.identity/06 (the account console's sessions section): the sign-in
  -- context. user_agent/ip are stamped at creation (NULL when the request
  -- carried none); last_seen_at is touched by session resolution, throttled
  -- to one write per minute per session.
  user_agent TEXT,
  ip TEXT,
  last_seen_at TEXT,
  -- TODO.identity/11 (the multi-org membership model): the session's
  -- ACTIVE-ORG context — the account acts AS this org (the org_memberships
  -- row's per-org role set applies). NULL = the primary context (the
  -- account's org_id binding — the pre-memberships behavior).
  active_org TEXT,
  -- TODO.identity-sso/02+03 (the strong-authentication wave): the sign-in
  -- provenance as a JSON array of RFC 8176 amr values ('pwd', 'otp',
  -- 'webauthn', 'hwk', the OP-private 'recovery'). NULL = no OP-side
  -- credential event recorded (an upstream-provider sign-in).
  amr TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- TODO.federation/10 — the SSO approval queue: an authenticated OIDC
-- user no claim-mapping rule matched (and no defaultRole declared) gets
-- NO account and NO session until an administrator approves with a role
-- (+ org) or rejects. One row per (issuer, sub); repeat sign-ins
-- refresh last_seen.
CREATE TABLE IF NOT EXISTS identity_approvals (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  sub TEXT NOT NULL,
  claims_json TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  decided_role TEXT,
  decided_org TEXT,
  decided_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT,
  decided_at TEXT,
  UNIQUE (issuer, sub)
);

-- TODO.federation/04 — the federation peer registry: a pinned
-- counterparty instance (descriptor fetched + validated, or pasted
-- out-of-band). The intake verifies signatures against ACTIVE peers'
-- published keys; a revoked peer's keys never verify (the row stays —
-- the audit trail + the revocations list carry the history).
CREATE TABLE IF NOT EXISTS federation_peers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  roles TEXT NOT NULL,
  descriptor_url TEXT,
  descriptor_json TEXT NOT NULL,
  pinned_via TEXT NOT NULL DEFAULT 'url',
  connectivity TEXT NOT NULL DEFAULT 'verified',
  status TEXT NOT NULL DEFAULT 'active',
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  added_by TEXT,
  refreshed_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT
);

-- The workflow entity store (TODO.ops/07 — server-side persistence):
-- one JSON document per entity, keyed by (store, id) — the same shape
-- the browser's IndexedDB stores hold, so the two repository backends
-- are contract-identical. org_id carries the scoping column when the
-- entity declares one (server-side enforcement for org-bound roles).
CREATE TABLE IF NOT EXISTS entities (
  store TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (store, id)
);
CREATE INDEX IF NOT EXISTS idx_entities_store_org ON entities (store, org_id);
-- The audit chain's typed legs (the 2026-09-06 audit's sign-in recency
-- read — migration 0023): (store, action, entity_id, timestamp) out of
-- the data JSON, so the per-account last-sign-in read walks the
-- sign-in slice instead of string-matching the journal. The json_valid
-- guard keeps a corrupt entities row writable (an unguarded
-- json_extract index expression would raise on the INSERT).
CREATE INDEX IF NOT EXISTS idx_entities_store_action ON entities (
  store,
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.action'),
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.entity_id'),
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.timestamp')
);
-- The public register's certificate-number lookup (migration 0028, the
-- seam's findCertificatesByNumber): (store, certificate_number) out of
-- the data JSON, COLLATE NOCASE for the register's case-insensitive
-- number match, so the keyed read is an index walk instead of a
-- listEntities scan + per-row JSON parse. The same json_valid guard.
CREATE INDEX IF NOT EXISTS idx_entities_store_certificate_number ON entities (
  store,
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.certificate_number') COLLATE NOCASE
);

-- The change journal: every write appends (seq, store, type, id) —
-- the SSE stream tails it (each client filters its stores).
CREATE TABLE IF NOT EXISTS entity_changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  store TEXT NOT NULL,
  type TEXT NOT NULL,
  id TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- The per-store high-water's walk (migration 0026, the seam's
-- latestChangeSeqFor(store)): MAX(seq) over one store's slice of the
-- one global journal costs a single indexed probe, never a journal
-- scan. The seq stays global and monotone — a projection, never a
-- second sequence.
CREATE INDEX IF NOT EXISTS idx_entity_changes_store_seq ON entity_changes (store, seq);

-- TODO.notify/01 — the platform event store (the notification system's
-- source of truth): one row per DECLARED notifiable act (the catalog,
-- browser/src/notify/catalog.ts, is deliberate — not every write is an
-- event). The hierarchical key <domain>/<entity-id>/<action> is SPLIT
-- into columns so the subscription grammar's prefixes resolve in SQL
-- (WHERE domain = ? AND entity_id = ?), never a string scan; the
-- composed key is derived at read. payload is the catalog row's JSON
-- envelope (the summary line, the deep link, the actors, the entity's
-- store for the read-time visibility gate). seq is the feed cursor;
-- written inside the acting request's envelope, never blocking the
-- triggering flow (the mailer doctrine). mentions (migration 0027,
-- TODO.notify/05's remainders) is the act's @user mentions as a JSON
-- array of user ids, resolved by the comment surfaces' parse at event
-- time and recorded ON THE ROW — a mention is a fact of the act, never
-- re-derivable from the entity at the feed's read-time computation.
-- NULL = none.
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  domain TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  payload TEXT NOT NULL,
  mentions TEXT,
  at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_domain_entity ON events (domain, entity_id);
CREATE INDEX IF NOT EXISTS idx_events_domain_action ON events (domain, action);

-- TODO.notify/02 — the subscriptions store (the notification system's
-- per-user rules, the GitHub shape). Three tables:
--
--   notify_rules: the per-user rule rows (mode subscribe|mute) on a key
--   pattern in the catalog's grammar (application/**, certificate/**/
--   issued, test-run/asg-…-001/**, or an exact key). The pattern's
--   pinned legs are SPLIT into columns (domain is always pinned;
--   entity_id/action NULL = the wild leg) so the recipient
--   resolution's REVERSE match — every user's rules covering one event —
--   resolves in SQL (WHERE domain = ? AND (entity_id IS NULL OR
--   entity_id = ?) AND (action IS NULL OR action = ?)), never a string
--   scan. channel_overrides is the subscribe row's per-rule email
--   override (JSON; NULL = the category preference rules on); a mute
--   row never carries one.
CREATE TABLE IF NOT EXISTS notify_rules (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  pattern TEXT NOT NULL,
  domain TEXT NOT NULL,
  entity_id TEXT,
  action TEXT,
  mode TEXT NOT NULL,
  channel_overrides TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, pattern)
);
CREATE INDEX IF NOT EXISTS idx_notify_rules_user ON notify_rules (user_id);
CREATE INDEX IF NOT EXISTS idx_notify_rules_event ON notify_rules (domain, entity_id, action);

--   notify_entity_mutes: the thread-level mutes (the entity-page bell's
--   Muted state; the email footer's one-click unsubscribe — TODO.notify/
--   04 — sets the same row). A mute wins over every candidate class,
--   subscriptions included; the access is unchanged.
CREATE TABLE IF NOT EXISTS notify_entity_mutes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  domain TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, domain, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_notify_entity_mutes_entity ON notify_entity_mutes (domain, entity_id);

--   notify_preferences: one row per user — the per-category (the event
--   catalog's domains) email posture as a JSON map { "<domain>":
--   "immediate"|"digest"|"off" }. A domain ABSENT falls back to the
--   catalog row's own email default; the inbox always carries the
--   event. No row at all = every category on its catalog default.
CREATE TABLE IF NOT EXISTS notify_preferences (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  channels TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- TODO.notify/03 — the inbox state: the per-user per-event read markers
-- (migration 0014). One row per (user, event), written lazily at the
-- first act on the inbox row: read_at stamps the mark-read, done_at the
-- archive (a done row leaves the feed; the marker keeps the state),
-- saved_at the per-event saved flag (migration 0027, TODO.notify/05's
-- remainders — the GitHub Save, independent of read/done: a saved row
-- that is done stays saved in the archive). The
-- feed itself is COMPUTED at read (events × the user's rules × the
-- visibility gate) — this table is the state the computation joins, and
-- a marker on a wiped event simply never joins (the user's state is
-- their own, never the workflow's). NO foreign keys, deliberately: the
-- event store's wipe (the demo reset) and its retention sweep must never
-- FK-block on the user's own markers; the write path's guard is the
-- integrity (a marker lands only on an event that exists, is visible and
-- is the caller's).
CREATE TABLE IF NOT EXISTS notify_inbox_state (
  user_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  read_at TEXT,
  done_at TEXT,
  saved_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_notify_inbox_state_user ON notify_inbox_state (user_id);

-- TODO.notify/04 — the email channel's delivery store (migration 0018):
-- one row per (event, recipient), the fan-out's record of who the event
-- reached and on which channel mark. reason is the resolution's
-- strongest reason; email the resolved posture (immediate | digest |
-- off — the inbox is the constant, never a column); email_status the
-- email leg's state (NULL when off; sent | failed | rate_limited;
-- digest_pending → digest_sent | digest_failed | digest_dropped;
-- 'unavailable' on a mailer-less instance — nothing queues there).
-- NO foreign keys (the subscriptions store's posture): a wiped event
-- simply never joins. UNIQUE (event_id, user_id) keeps the fan-out
-- idempotent. The mailer's per-SEND audit (entity_type 'email') stands
-- alongside — this table is the PER-RECIPIENT record.
CREATE TABLE IF NOT EXISTS notify_deliveries (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  email TEXT NOT NULL,
  email_status TEXT,
  email_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (event_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_event ON notify_deliveries (event_id);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_user ON notify_deliveries (user_id);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_status ON notify_deliveries (email_status);

-- The evidence store (TODO.ops/09 — the monitor daemon's durable
-- streams): append-only records across restarts. The adapter contract
-- (src/evidence-store/adapter.ts) is tiny: append, query, getByIds,
-- counts.
CREATE TABLE IF NOT EXISTS evidence_records (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  twin_id TEXT,
  monitor_id TEXT,
  at TEXT NOT NULL,
  data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_kind_at ON evidence_records (kind, at);
CREATE INDEX IF NOT EXISTS idx_evidence_twin ON evidence_records (twin_id, at);
CREATE INDEX IF NOT EXISTS idx_evidence_monitor ON evidence_records (monitor_id, at);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity/01 — the OIDC Provider (id.oimlsmart.org). Everything
-- below must survive Worker isolates, so it lives in the database —
-- NEVER a per-process Map (the GitHub-flow lesson, auth/github.ts).
-- ═══════════════════════════════════════════════════════════════════

-- The client registry: the relying parties (platform instances) allowed
-- to request tokens. secret_hash NULL = a public client (PKCE carries
-- the proof); claims_policy JSON names the claims the ID token carries
-- for this client (the instances' fed-10 claim mapping consumes them).
CREATE TABLE IF NOT EXISTS oidc_clients (
  client_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret_hash TEXT,
  redirect_uris TEXT NOT NULL,
  claims_policy TEXT,
  -- The SSO home's launch metadata (migration 0011): launch_url NULL =
  -- the client never appears on the post-login launcher; visibility is
  -- the not-admitted posture ('roles' hide, 'request' the request-access
  -- state, 'open' never gated).
  launch_url TEXT,
  launch_icon TEXT,
  launch_description TEXT,
  launch_visibility TEXT NOT NULL DEFAULT 'roles',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT
);

-- A pending authorization between /op/authorize's validation and the
-- consent decision (the decision POST may land on another isolate).
-- user_id is stamped when the signed-in session resolves.
CREATE TABLE IF NOT EXISTS oidc_authorizations (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  state TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  user_id TEXT,
  decision TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

-- The one-time authorization codes. consumed_at flips atomically at the
-- exchange (UPDATE … WHERE consumed_at IS NULL) — a replayed code loses
-- the race and gets invalid_grant.
CREATE TABLE IF NOT EXISTS oidc_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  user_id TEXT NOT NULL,
  -- TODO.identity/11: the active-org context the consent decision was made
  -- under (NULL = the primary context); the token endpoint re-judges it
  -- against the live membership before emitting the claims.
  context_org TEXT,
  -- TODO.identity-sso/02+03: the consenting session's amr provenance (a
  -- JSON array; NULL = none recorded), carried into the ID token.
  amr TEXT,
  -- TODO.identity-sso (the wave-A tail): the consenting session's
  -- authentication instant (sessions.created_at, verbatim; NULL = none
  -- recorded), carried into the ID token's auth_time.
  auth_time TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

-- The issued access tokens (the userinfo endpoint resolves them).
CREATE TABLE IF NOT EXISTS oidc_access_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  -- TODO.identity/11: the granting code's context — userinfo answers the
  -- SAME claims the ID token carried.
  context_org TEXT,
  -- TODO.identity-sso/02+03: the authorizing authentication's amr
  -- provenance — userinfo answers the same truth the ID token carried.
  amr TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The refresh tokens (migration 0025 — the SSO wave-C token surface): the
-- offline half of the remembered consent. One-time, atomically consumed
-- (WHERE consumed_at IS NULL); every rotation inherits the first mint's
-- family_id, and a presented CONSUMED token is the theft signal that kills
-- the whole family. The row carries the granting code's provenance
-- (canonical scope, context_org, amr, the ORIGINAL auth_time — a refresh
-- never advances it). Consumed rows STAY for the reuse detector;
-- revocation (client-bound, per family), the consent's revocation, the
-- deactivation sweep and the erasure remove rows outright.
CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  context_org TEXT,
  amr TEXT,
  auth_time TEXT,
  family_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_user ON oidc_refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_family ON oidc_refresh_tokens (family_id);

-- The OP's signing-key rotation history: the PUBLIC halves. JWKS serves
-- every row not retired beyond the token lifetime, so a rotation never
-- strands an in-flight ID token. The private half rides the
-- OP_SIGNING_KEY secret, never the database.
CREATE TABLE IF NOT EXISTS oidc_keys (
  kid TEXT PRIMARY KEY,
  public_jwk TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  retired_at TEXT
);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity/08 — the upstream provider registry (the OP's sign-in
-- methods: GitHub + Google + Apple + Entra + generic OIDC). Adding a
-- provider is a ROW, never a code fork.
-- ═══════════════════════════════════════════════════════════════════

-- The upstream registry. kind: 'github' (the OAuth web flow) or 'oidc'
-- (discovery + code + PKCE against the issuer — Google, Entra, Apple,
-- a generic Keycloak; Apple's documented quirks key on the issuer host,
-- auth/upstream/registry.ts). The client SECRET is never stored:
-- client_secret_ref names an environment variable ('env:<NAME>'), the
-- same discipline as OIDC_CLIENT_SECRET_REF. enabled=0 rows stay
-- invisible to the login page and refuse flows.
CREATE TABLE IF NOT EXISTS identity_providers (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  display_name TEXT NOT NULL,
  brand_mark TEXT,
  issuer TEXT,
  client_id TEXT NOT NULL,
  client_secret_ref TEXT,
  scopes TEXT,
  enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT,
  updated_at TEXT
);

-- The linked identities (TODO.identity/02's spec shape: user, provider,
-- provider_account_id, linked_at, linked_by). THE MATCH RULE: an
-- upstream sign-in resolves by (provider, provider_account_id) — NEVER
-- by email alone. UNIQUE(provider, provider_account_id): one upstream
-- account links to exactly one OIML SMART account.
CREATE TABLE IF NOT EXISTS identity_links (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  provider TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  linked_at TEXT NOT NULL DEFAULT (datetime('now')),
  linked_by TEXT,
  UNIQUE (provider, provider_account_id)
);
CREATE INDEX IF NOT EXISTS idx_identity_links_user ON identity_links (user_id);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity/02 — the OP's account model: real password accounts
-- (invite-only) and the enrollment links. Same rule as item 01:
-- everything survives Worker isolates in the database.
-- ═══════════════════════════════════════════════════════════════════

-- The password credentials, APART from the users row: only OP accounts
-- (provider='password') carry a row, and no SELECT * on users ever reads
-- credential material. hash is self-describing (pbkdf2:<iters>:<salt>:
-- <digest>, auth/passwords.ts) so a cost change never strands an account.
CREATE TABLE IF NOT EXISTS passwords (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  hash TEXT NOT NULL,
  set_at TEXT NOT NULL DEFAULT (datetime('now')),
  set_by TEXT
);

-- The invite-only enrollment links: an admin creates the account, the
-- user receives this one-time setup link (24 h) and sets their password.
-- consumed_at flips atomically at completion (UPDATE … WHERE consumed_at
-- IS NULL — the oidc_codes pattern), so a presented link works exactly
-- once; an expired one is burned on presentation, never redeemed later.
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_user ON enrollment_tokens (user_id);

-- TODO.identity/06 — the account console's email change ceremony. Same
-- doctrine as the enrollment links: a 256-bit random token backed by this
-- row (one-time, 24 h, atomically consumed). delivered_by records HOW the
-- link reached the user: 'mailer' (TODO.identity/09's send path; completing
-- it verifies the new address) or 'shown' (no mailer configured, the link
-- was displayed to the signed-in holder; completing it applies the change
-- but the address stays unverified, honestly). A fresh request voids the
-- account's earlier pending rows: only the newest link works.
-- TODO.identity-features/01: kind names the ceremony — 'change' (the
-- primary replacement above) or 'add' (the per-address verification of an
-- account_emails row; completion stamps the row's verified_at).
-- The 0.2.4 kind: 'verify' — the re-verification of the account's CURRENT
-- primary (new_email carries it as requested; a mailer-delivered
-- completion stamps users.email_verified_at while the address still IS
-- the primary). A value, never a column: the kind TEXT carries it, so no
-- migration rides the 0.2.4 seam change.
CREATE TABLE IF NOT EXISTS email_change_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  new_email TEXT NOT NULL,
  delivered_by TEXT NOT NULL DEFAULT 'shown',
  kind TEXT NOT NULL DEFAULT 'change',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_email_change_tokens_user ON email_change_tokens (user_id);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity/10 — delegated organization administration: the
-- self-service join requests. A staff member asks for an account naming
-- their organization FROM THE PARTICIPANTS REGISTER (org_id set — the
-- request lands with the ORG's admin); the "my organization is not
-- listed" path leaves org_id NULL and carries the free-text name in
-- org_name_text — those land with BIML (the new-organizations queue).
-- The decision is atomic on status='pending' (a double decide loses);
-- approval records the invited account (invited_user_id).
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS org_join_requests (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  -- The selected REGISTERED participant org (NULL = the not-listed path).
  org_id TEXT,
  -- The free-text organization name when org_id is NULL (BIML's queue).
  org_name_text TEXT,
  -- The role asked for (bounded by the org's kind at submit AND at
  -- approval; 'org_admin' on the not-listed path — the requester becomes
  -- the org's administrator after BIML's verification).
  requested_role TEXT NOT NULL,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  decided_by TEXT,
  decided_at TEXT,
  refusal_reason TEXT,
  invited_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_org_join_requests_org ON org_join_requests (org_id, status);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity/03 — the central user registry: the PER-CLIENT role
-- assignments. The account's OP-side role set (users.role/roles) is its
-- federation-wide default; a row here overrides it for ONE relying
-- party (an oidc_clients row): the ID token issued to that client
-- carries these roles, filtered by the client's claims-policy role
-- allowlist (oidc_clients.claims_policy.roles). roles='[]' is the
-- explicit "no roles on this client" (the instance's approval-queue
-- posture) — distinct from NO ROW, which restores the account default.
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS op_client_roles (
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  roles TEXT NOT NULL,
  assigned_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT,
  PRIMARY KEY (user_id, client_id)
);

-- TODO.identity/04 — the relying party's OIDC sign-in state jar (the
-- /signin/oidc → /callback/oidc round trip's one-time state: the nonce +
-- the PKCE verifier). STORE-BACKED so the Worker's isolates share it —
-- the per-process Map intermittently failed the state check across
-- isolates (the GitHub-flow lesson, retired for SSO too).
CREATE TABLE IF NOT EXISTS sso_states (
  state TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity/11 — the multi-organization membership model. One row
-- per (account, org): the PER-ORG role set + the lifecycle state
-- (invited → active ⇄ disabled). The account acts AS one org at a time
-- (the session's active_org stamp); the OP's claims carry the active
-- org's role set, and a relying party never learns the other
-- memberships.
--
-- THE DUAL-READ DOCTRINE: the users row's org_id/roles columns stay the
-- backward-compatible read — the PRIMARY membership's mirror
-- (is_primary=1) — until every consumer reads the memberships. The
-- store mirrors every legacy write into the primary row, and every
-- membership write on the primary row back into the columns.
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS org_memberships (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  org_id TEXT NOT NULL,
  -- The per-org role set (JSON array); the claims the account's tokens
  -- carry when acting AS this org.
  roles TEXT NOT NULL DEFAULT '[]',
  state TEXT NOT NULL DEFAULT 'active',
  is_primary INTEGER NOT NULL DEFAULT 0,
  invited_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  activated_at TEXT,
  disabled_at TEXT,
  disabled_by TEXT,
  -- TODO.identity-features/09 wave A — the org-member DATA CONE
  -- (migration 0017): NULL (org-wide, the default) | 'assigned' |
  -- 'read-only' | 'assigned+read-only'; the kernel's
  -- parseOrgMemberCone owns the grammar; a malformed cell fails
  -- CLOSED to the narrowest cone.
  cone TEXT,
  UNIQUE (user_id, org_id)
);
CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON org_memberships (org_id, state);
CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON org_memberships (user_id, state);
-- TODO.identity-sso/02 + /03 — the strong-authentication wave: the
-- factor registry (passkeys, TOTP authenticator apps, recovery codes),
-- the one-time ceremony state, and the provenance columns above. The
-- D1 migration set carries the identical end state (0012_strong_auth.sql).
-- ═══════════════════════════════════════════════════════════════════

-- The passkeys. credential_id is the authenticator's own (base64url);
-- public_key the COSE key bytes (base64url) as the attestation carried
-- them; sign_count the signature counter — a REGRESSED count on an
-- assertion is the clone signal (the advance is a guarded UPDATE, the
-- regression refuses + audits). aaguid + transports record what the
-- browser declared (attestation is 'none' at this assurance level —
-- display hints for the console, never proof).
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  aaguid TEXT,
  transports TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  last_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials (user_id);

-- The TOTP authenticator apps (RFC 6238: 30 s step, 6 digits, HMAC-SHA-1).
-- verified_at NULL = the PENDING enrollment — it activates ONLY on the
-- first valid code; the enrollment verify is throttled hard (fail_count +
-- last_failure_at: the six-digit window invites brute force). The secret
-- is base32 and never leaves the server after the enrollment answer.
CREATE TABLE IF NOT EXISTS totp_secrets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  secret TEXT NOT NULL,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_failure_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  verified_at TEXT,
  last_used_at TEXT,
  last_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_totp_secrets_user ON totp_secrets (user_id);

-- The recovery codes: generated at the first factor's enrollment, shown
-- once, stored HASHED (SHA-256 of the normalized code — 80 bits of random
-- per code, so the unsalted hash resists the offline attack), one time
-- each (consumed_at flips atomically). Regeneration REPLACES the account's
-- set (batch marks the generation; the old set goes with the audit event).
CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  batch TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes (user_id);

-- The one-time WebAuthn ceremony challenges (the database-is-the-proof
-- doctrine — the sso_states/enrollment_tokens pattern): short TTL,
-- consumed atomically. user_id binds the registration + the second-factor
-- assertion to the account; the PASSWORDLESS assertion's row carries NULL
-- (the asserted credential id resolves the account).
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id),
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges (user_id);

-- The pending second-factor sign-in: the password verified, the account
-- holds factors, the session waits on the factor. One-time (consumed at
-- completion), short TTL; the per-account throttle rides the row
-- (fail_count + last_failure_at give the backoff ladder; the cap burns
-- the attempt — the audit event + the account's lockout email).
CREATE TABLE IF NOT EXISTS mfa_pending (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  amr TEXT NOT NULL,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_failure_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_mfa_pending_user ON mfa_pending (user_id);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity-features/05 — the organization registry: organizations
-- as first-class citizens of the identity plane. One row per org: the
-- stable SLUG id (for a participant org the OIML code IS the id — the
-- platform resolves the org claim against its own participant registry
-- directly, the mapping is identity), the display data, the OPTIONAL
-- participant_ref annotation (the link's documentation, never a key),
-- and the lifecycle state (active ⇄ disabled — the honest removal; the
-- erasure-adjacent hard delete is the route's guarded act).
--
-- The membership graph (org_memberships above) references the org by
-- its id — deliberately WITHOUT a foreign key: the scheme-side
-- participants register (the entity store) and this identity-side
-- registry never merge (the spec's §4), and a membership row's honesty
-- (its lifecycle state) never depends on a join.
-- The D1 migration set carries the identical end state
-- (0013_org_registry.sql + 0019_org_member_category.sql).
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS org_registry (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  short_name TEXT,
  -- The participant kind (the OIML-CS program's four); NULL = a
  -- non-participant org (the estate operator's own org, a consumer).
  kind TEXT,
  country TEXT,
  -- The contacts (a JSON array of { name, email }; a malformed entry is
  -- skipped on read, never trusted).
  contacts TEXT NOT NULL DEFAULT '[]',
  -- The participant-link annotation (which participant record the org
  -- mirrors); documentation only.
  participant_ref TEXT,
  -- The designation links + the CS status facet (0019_org_member_category.sql,
  -- TODO.identity-features/10): a Utilizer's designated_by is its MEMBER
  -- STATE, an Associate's its CORRESPONDING MEMBER, a Test Laboratory's
  -- its associated ISSUING AUTHORITY; an Issuing Authority's proposed_by
  -- is its proposing MEMBER STATE; cs_status is the designated bodies'
  -- Declaration standing (signed-active / suspended / withdrawn). All
  -- NULL = not recorded; the kind enforcement is the program's write
  -- path, the store keeps the columns opaque.
  designated_by TEXT,
  proposed_by TEXT,
  cs_status TEXT,
  state TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT,
  updated_at TEXT,
  updated_by TEXT,
  disabled_at TEXT,
  disabled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_org_registry_state ON org_registry (state);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.register/02 — the register's holder-org attribution: the
-- certificate's holder as the OP-minted ORG id. The hub stores the
-- descriptor the federation registration package carried (or the
-- confirmed legacy-row claim) as its OWN row — never a write into the
-- sender's imported artifact. One row per certificate: the first
-- attribution wins. The org display name is denormalized (the register
-- reads correctly across a later rename).
--
-- The claim act's state machine sits beside it: a pre-program (or
-- records-mode / CSV) registered certificate carries a free-text holder
-- and no descriptor; the manufacturer org's administrator claims by
-- holder-name match (the matched name snapshots as the evidence), an
-- estate admin confirms or refuses (atomic on 'pending'), and the audit
-- chain carries both acts. A refused claim never blocks a fresh one; a
-- confirmed claim is terminal.
-- The D1 migration set carries the identical end state
-- (0015_certificate_holder_attribution.sql).
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS certificate_holder_orgs (
  certificate_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  org_name TEXT NOT NULL,
  source TEXT NOT NULL,
  attributed_at TEXT NOT NULL,
  attributed_by TEXT,
  claim_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_certificate_holder_orgs_org ON certificate_holder_orgs (org_id);

CREATE TABLE IF NOT EXISTS certificate_holder_claims (
  id TEXT PRIMARY KEY,
  certificate_id TEXT NOT NULL,
  claimant_org_id TEXT NOT NULL,
  claimant_org_name TEXT NOT NULL,
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
-- TODO.register/03 — the instrument register: the per-serial
-- registration of individual instruments under a type certificate's
-- scope. One row per registered instrument: the certificate it rides
-- under, the holder organization (the manufacturer org id, referenced
-- WITHOUT a foreign key — the identity plane and this platform-side
-- register never merge, the org_memberships posture), the
-- Recommendation, the manufacture date, the per-serial designations the
-- scope check evaluated (JSON), the scope verdict recorded AT
-- REGISTRATION (in_scope / scope_unverified — the records-mode honest
-- degradation; a REFUSED declaration never lands a row), and the
-- lifecycle (registered / out_of_service / withdrawn). One serial
-- number per certificate (the UNIQUE) — the same physical unit never
-- registers twice under one type certificate.
-- The D1 migration set carries the identical end state
-- (0016_instrument_registrations.sql).
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS instrument_registrations (
  id TEXT PRIMARY KEY,
  certificate_id TEXT NOT NULL,
  holder_org_id TEXT NOT NULL,
  standard_id TEXT NOT NULL,
  serial_number TEXT NOT NULL,
  manufacture_date TEXT,
  designations TEXT NOT NULL DEFAULT '{}',
  scope_status TEXT NOT NULL,
  scope_detail TEXT,
  lifecycle TEXT NOT NULL DEFAULT 'registered',
  registered_at TEXT NOT NULL DEFAULT (datetime('now')),
  registered_by TEXT,
  updated_at TEXT,
  updated_by TEXT,
  UNIQUE (certificate_id, serial_number)
);
CREATE INDEX IF NOT EXISTS idx_instrument_registrations_certificate ON instrument_registrations (certificate_id);
CREATE INDEX IF NOT EXISTS idx_instrument_registrations_holder ON instrument_registrations (holder_org_id);
CREATE INDEX IF NOT EXISTS idx_instrument_registrations_lifecycle ON instrument_registrations (lifecycle);

-- ═══════════════════════════════════════════════════════════════════
-- TODO.identity-features/08 — the personal access tokens (the developer
-- surface, the GitHub fine-grained pattern): an ACCOUNT-minted
-- credential that NEVER rides a request directly — it exchanges at the
-- OP's token endpoint (the RFC 8693 grant) for a short-lived OP JWT.
-- The plaintext shows ONCE at mint; the row holds only the SHA-256
-- (token_hash, the exchange's UNIQUE lookup key) + the display prefix.
-- Expiration is MANDATORY (expires_at NOT NULL — no permanent tokens).
-- scopes is the pinned JSON set ('<service>:<action-class>' — the
-- store.ts grammar; narrowing-only against the holder's standing);
-- org_context pins the mint's active-org context (NULL = the primary).
-- last_used_at + last_exchange_audit_at carry the exchange path's
-- THROTTLED heartbeat (never a write per exchange); expiry_notified_at
-- is the expiry-soon mailer's one-shot mark. Revocation flips
-- revoked_at/revoked_by and the row STAYS (the audit + the org
-- inventory carry the history); the account erasure removes the rows.
-- The D1 migration set carries the identical end state
-- (0020_personal_access_tokens.sql).
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS personal_access_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT '[]',
  org_context TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  last_used_at TEXT,
  last_exchange_audit_at TEXT,
  expiry_notified_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  UNIQUE (token_hash)
);
CREATE INDEX IF NOT EXISTS idx_personal_access_tokens_user ON personal_access_tokens (user_id);

-- ═══════════════════════════════════════════════════════════════════
-- The remembered consent grants (TODO.identity-features/12): the OP
-- remembers the account holder's "Allow" per (user, client, scope set) —
-- a repeat authorization the grant COVERS skips the consent page (unless
-- the request carries prompt=consent). scope is the canonical space-joined
-- set spelling (normalizeOidcScopeSet); the partial unique index keys ONE
-- LIVE grant per (user_id, client_id, scope) — revocation flips
-- revoked_at (the row stays for the audit + the history), a revoked
-- triple's re-allow lands a fresh row, and the account erasure removes
-- the rows outright. The D1 migration set carries the identical end state
-- (0021_oidc_consent_grants.sql).
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS oidc_consent_grants (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_consent_grants_live
  ON oidc_consent_grants (user_id, client_id, scope) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_oidc_consent_grants_user ON oidc_consent_grants (user_id);

-- ═══════════════════════════════════════════════════════════════════
-- Multiple emails per account (TODO.identity-features/01): the account
-- carries a primary + additional addresses. The PRIMARY stays users.email
-- (the OIDC `email` claim never changes shape); account_emails carries
-- the ADDITIONAL addresses, one row per (account, address), verified_at
-- NULL until the per-address ceremony (email_change_tokens kind 'add')
-- proves the mailbox. The unique index makes an additional address name
-- at most one account; the store's writes check across BOTH tables, and
-- the sign-in/recovery resolutions prefer the primary owner
-- deterministically. The D1 migration set carries the identical end
-- state (0022_account_emails.sql).
-- ═══════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS account_emails (
  user_id TEXT NOT NULL REFERENCES users(id),
  email TEXT NOT NULL,
  verified_at TEXT,
  added_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, email)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_emails_email ON account_emails (email);
