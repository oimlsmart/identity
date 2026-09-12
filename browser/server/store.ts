// ═══════════════════════════════════════════════════════════════════
// The server-store seam (TODO.cs-e2e/14 — the Cloudflare deployment).
//
// The routes never talk to a database driver directly: they go through
// the ServerStore, an ASYNC contract with two implementations:
//
//   - SQLite (node, self-hosted): sqlite-server-store.ts wraps the
//     pre-existing sync modules (store.ts / entities.ts) — better-sqlite3
//     stays behind this interface, so the Worker bundle never imports
//     it;
//   - D1 (Cloudflare Workers): d1-store.ts implements the same surface
//     against the D1 binding.
//
// The store is chosen by BINDING PRESENCE at the composition root: the
// Worker entry installs the D1 store when env.DB is bound (the same
// profile pattern ENTITY_BACKEND uses for the client); the node entry
// (server/index.ts) and the node scripts/tests install the SQLite one.
//
// This module is WORKER-SAFE: no node built-ins, no driver imports —
// every platform carries it.
// ═══════════════════════════════════════════════════════════════════

import { timedStore } from './store-timing'

/** The INITIAL role/org for an OAuth-provisioned account
 *  (findOrCreateOAuthUser): applied ONLY when the account is created —
 *  an existing account keeps its locally assigned role/org (the
 *  admin's users-section decisions stand, TODO.federation/12). Absent:
 *  the historical defaults (role 'user', org null). */
export interface OAuthInitialAssignment {
  role?: string
  orgId?: string | null
}

export interface AuthUserPayload {
  id: string
  email: string
  name: string
  role: string
  /** The FULL assigned role set (TODO.federation/12 RBAC) — `role` stays
   *  the section-gating primary; permissions resolve over this set
   *  (absent = the primary role only). */
  roles?: string[]
  orgId: string | null
  /** TODO.identity-features/09 — the ACTIVE org context's data cone (the
   *  membership's posture, resolved by the session-backed read; the OP's
   *  `cone` claim carries the same value). ABSENT on constructors that
   *  never resolve a membership (the row-backed reads); NULL = the
   *  context resolved no membership (an org-free account — the cone
   *  never applies to it). The cone only ever NARROWS: the enforcement
   *  reads it at the two choke points (the entity API's read/write
   *  gates), never as a grant. */
  cone?: OrgMemberCone | null
  avatarUrl?: string
  /** TODO.identity/04: the account's sign-in provider family ('demo',
   *  'github', 'oidc', the OP's account provider) — projected from the
   *  row by the row-backed reads (undefined where a constructor does not
   *  know it). The SSO cutover's moved-account guard reads it. */
  provider?: string
  /** TODO.identity/06: the primary address's verification state
   *  (users.email_verified_at; undefined on stores that do not project
   *  it, null = never verified). The account console shows it honestly. */
  emailVerifiedAt?: string | null
  /** TODO.identity-sso/02+03: the SESSION's authentication provenance
   *  (sessions.amr — the RFC 8176 values: 'pwd', 'otp', 'webauthn', 'hwk',
   *  plus the OP-private 'recovery'). Projected by the session-backed
   *  read (getSessionUser) only; ABSENT = no OP-side credential event
   *  recorded (an upstream-provider sign-in, a legacy row). */
  amr?: string[]
  /** TODO.identity-sso (the wave-A tail): the SESSION's authentication
   *  instant (sessions.created_at, the column verbatim — the sign-in's
   *  wall-clock stamp). Projected by the session-backed read
   *  (getSessionUser) only. The ID token's auth_time derives from it (the
   *  OIDC NumericDate conversion is the consumer's — the column's storage
   *  format is the store's own). */
  sessionCreatedAt?: string
}

// ── identity federation (TODO.federation/10) ─────────────────────────

/** The admin approval queue's row: an SSO-authenticated user no claim
 *  mapping rule matched (and no defaultRole is declared) — no account,
 *  no session, until an administrator approves with a role (+ org) or
 *  rejects. UNIQUE per (issuer, sub): a repeat sign-in refreshes
 *  last_seen, never duplicates. */
export interface IdentityApproval {
  id: string
  email: string
  name: string
  /** The issuing IdP (the configured issuer URL). */
  issuer: string
  /** The IdP's subject id. */
  sub: string
  /** The claims snapshot shown to the deciding admin (JSON). */
  claimsJson: string | null
  status: 'pending' | 'approved' | 'rejected'
  decidedRole: string | null
  decidedOrg: string | null
  decidedBy: string | null
  createdAt: string
  lastSeen: string
  decidedAt: string | null
}

/** The RP's one-time OIDC sign-in state (TODO.identity/04): the nonce +
 *  the PKCE verifier for one /signin/oidc → /callback/oidc round trip,
 *  store-backed (the sso_states table) so the Worker's isolates share
 *  it. Consumed atomically — a replay answers null. */
export interface SsoSignInState {
  state: string
  nonce: string
  verifier: string
  expiresAt: string
}

/** The admin view of a user (TODO.federation/12 — the instance settings
 *  users section + the users API). */
export interface UserAdminRow {
  id: string
  email: string
  name: string
  /** The section-gating primary role. */
  role: string
  /** The full assigned role set (drives permissions). */
  roles: string[]
  orgId: string | null
  active: boolean
  provider: string
  lastLogin: string | null
  /** TODO.identity/06: the primary address's verification state
   *  (users.email_verified_at; null = never verified). */
  emailVerifiedAt?: string | null
}

export interface EntityRow {
  store: string
  id: string
  org_id: string | null
  data: string
  updated_at: string
}

/** listEntities' candidate narrowing (the 2026-09-01 portal-load audit,
 *  R3-fix3): the entities table carries an indexed org_id column
 *  (idx_entities_store_org, migration 0001) that reads never used —
 *  every list scanned the whole store and left the org cone to the
 *  consumer's per-row gate. */
export interface EntityListOptions {
  /** Narrow the CANDIDATE set to the rows stamped under this org (org_id
   *  = the value — orgIdOf's first-org-field stamp, or the writer's own
   *  org on the stamping write paths) PLUS the unstamped rows (org_id IS
   *  NULL — a stamp-less row is never excluded: the stamp's absence says
   *  nothing about the row's cone). A candidate filter, NEVER a
   *  visibility decision: which rows of the narrowed set answer is the
   *  consumer's in-memory gate, authoritative as before. The consumer
   *  enables the filter only where its gate provably denies every row
   *  the filter drops (the per-store verification rides the consumer's
   *  change — org_id stamps the FIRST org field, so multi-org-field
   *  stores are never narrowed). The answer keeps the seam's declared
   *  order: (org_id, rowid) over the kept rows — the unfiltered order's
   *  restriction to the candidate set, so a gate-driven projection of
   *  either answer is byte-identical. */
  orgId?: string
}

// ── federation peers (TODO.federation/04) ────────────────────────────

/** A pinned federation peer: the counterparty instance's descriptor,
 *  fetched + validated + pinned (or pasted out-of-band). The registry
 *  is the intake's trust base beyond locally-registered org keys — a
 *  REVOKED peer's keys never verify. Revocation flips status (the row
 *  stays: the audit + the revocations list carry the history). */
export interface FederationPeer {
  /** The peer's descriptor instance.id (globally stable). */
  id: string
  name: string
  /** JSON array of 'hub' | 'ia' | 'tl'. */
  roles: string
  /** Where the descriptor was pinned from (null for a pure manual paste). */
  descriptorUrl: string | null
  /** The pinned descriptor, whole (JSON). */
  descriptorJson: string
  pinnedVia: 'url' | 'manual' | 'directory'
  /** 'verified' = the pin path probed a live endpoint; 'unverified' = the
   *  out-of-band paste (documented honestly in the UI). */
  connectivity: 'verified' | 'unverified'
  status: 'active' | 'revoked'
  addedAt: string
  addedBy: string | null
  refreshedAt: string | null
  revokedAt: string | null
  revokedBy: string | null
}

export interface EntityChange {
  seq: number
  store: string
  type: 'persist' | 'remove'
  id: string
  at: string
}

/** The journal fan-out's payload (onJournalAppend): the (store, type,
 *  id) triple one entity_changes row carries. seq/at are the
 *  database's (the write path never reads them back) — the consumer
 *  re-reads via changesAfter from its own cursor. */
export interface JournalAppend {
  store: string
  type: 'persist' | 'remove'
  id: string
}

/** One row of the multi-row write (putEntities): putEntity's (id,
 *  orgId, data) legs — the store is the call's, once for the whole
 *  batch. */
export interface EntityWriteInput {
  id: string
  orgId: string | null
  data: string
}

/** The multi-row write's batch chunk, in ROWS (putEntities): each row
 *  contributes two statements (the upsert + its journal entry), so a
 *  chunk is one db.batch of 2 × PUT_ENTITIES_CHUNK statements — the
 *  same conservative order as EVENTS_BULK_KEY_CHUNK. The chunk bounds
 *  the ATOMIC unit (a D1 batch is all-or-nothing; the SQLite half's
 *  per-chunk transaction matches it) and keeps one batch's latency
 *  well inside the write budget at demo-hub latency. Chunks issue
 *  SERIALLY, in input order — the journal's seq order IS the input
 *  order, and parallel chunks would forfeit it. */
export const PUT_ENTITIES_CHUNK = 50

// ── the platform event store (TODO.notify/01) ────────────────────────

/** A notifiable platform event (TODO.notify/00's event model): one row
 *  per DECLARED act (the catalog is deliberate — not every write is an
 *  event). The hierarchical key `<domain>/<entity-id>/<action>`
 *  (`certificate/crt-acme-lc/issued`) is SPLIT into columns so the
 *  subscription grammar's prefixes resolve in SQL
 *  (`WHERE domain = ? AND entity_id = ?`), never a string scan; the
 *  composed key is derived at read, never stored. `payload` is the JSON
 *  envelope the catalog row declares (the summary line, the deep link,
 *  the actors, the entity's store for the read-time visibility gate).
 *  `mentions` (migration 0027, TODO.notify/05's remainders) is the act's
 *  @user mentions as a JSON array of user ids — the comment surfaces'
 *  parse resolves them at event time and records them ON THE ROW (a
 *  mention is a fact of the act; the feed's read-time reason computation
 *  could never re-derive it from the entity). NULL = none. `seq` is the
 *  feed cursor (the entity_changes journal's pattern). */
export interface PlatformEvent {
  seq: number
  id: string
  domain: string
  entityId: string
  action: string
  payload: string
  /** The mentioned user ids' JSON array (raw, the payload/channelOverrides
   *  posture — the consumer parses); NULL = no mentions. */
  mentions: string | null
  at: string
}

/** One row of the bulk append (appendEvents): appendEvent's legs — the
 *  same fields, so each event lands exactly as the single-row verb
 *  would land it (the EntityWriteInput pattern). */
export interface EventWriteInput {
  id: string
  domain: string
  entityId: string
  action: string
  payload: string
  /** The act's mentioned user ids (JSON array; TODO.notify/05's
   *  remainders) — absent/NULL lands NULL (no mentions). */
  mentions?: string | null
}

/** The key pattern's SQL legs: a subscription pattern (`application/**`,
 *  `certificate` + `issued` across the domain, one entity's
 *  `test-run/asg-…-001/**`) compiles to the columns it pins; absent legs
 *  stay free. */
export interface EventKeyFilter {
  domain?: string
  entityId?: string
  action?: string
}

/** One pinned (domain, entityId) pair of the bulk history read — the
 *  participant-history shape (an entity's own event journal), never a
 *  partial pattern: both legs are pinned, so every key resolves against
 *  idx_events_domain_entity. */
export interface EventEntityKey {
  domain: string
  entityId: string
}

/** The bulk read's statement chunk: D1 caps a statement at 100 bound
 *  parameters (two per key + the limit), so a bulk call issues
 *  ceil(keys / 49) statements — ONE for any realistic inbox window —
 *  never one per key. The SQLite half chunks identically so the two
 *  backends stay answer-identical. */
export const EVENTS_BULK_KEY_CHUNK = 49

/** The bulk by-id read's statement chunk (getEvents): D1 caps a
 *  statement at 100 bound parameters and the IN list binds ONE per id
 *  (no limit parameter — the answer size is the matched-id count), so
 *  a bulk call issues ceil(ids / 99) statements — ONE for any
 *  realistic digest window — never one per id. The SQLite half chunks
 *  identically so the two backends stay answer-identical. */
export const EVENTS_ID_CHUNK = 99

/** The bulk append's chunk, in ROWS (appendEvents): each event
 *  contributes ONE statement (the INSERT … RETURNING * answers the
 *  stored row off the write itself, the appendEvent halving), so a
 *  chunk is one db.batch of APPEND_EVENTS_CHUNK statements — the
 *  INSTRUMENT_REGISTRATIONS_CHUNK order. The chunk bounds the ATOMIC
 *  unit (a D1 batch is all-or-nothing; the SQLite half's per-chunk
 *  transaction matches it). Chunks issue SERIALLY, in input order —
 *  the events' seq order IS the input order, and parallel chunks would
 *  forfeit it. */
export const APPEND_EVENTS_CHUNK = 50

// ── the notification subscriptions store (TODO.notify/02) ────────────

/** The rule row's mode: 'subscribe' adds the user to the candidates of
 *  every event the pattern covers; 'mute' removes them (the pattern-level
 *  "unwatch" — the per-entity mute rows carry the thread-level one). */
export type NotifyRuleMode = 'subscribe' | 'mute'

/** A per-user subscription rule (TODO.notify/00's GitHub shape): the
 *  authored `pattern` in the catalog's grammar (`application/**`,
 *  `certificate` + `issued` across the domain, one entity's
 *  `test-run/asg-…-001/**`, or an exact key)
 *  with its pinned legs SPLIT into columns (domain always pinned;
 *  entity_id/action NULL = the wild leg) so the recipient resolution's
 *  reverse match — EVERY user's rules covering one event — resolves in
 *  SQL (`WHERE domain = ? AND (entity_id IS NULL OR entity_id = ?) …`),
 *  never a string scan. channel_overrides is the subscribe row's
 *  per-rule email override (JSON `{ "email": "immediate"|"digest"|"off"
 *  }`; NULL = the category preference rules on); a mute row never
 *  carries one. UNIQUE (user_id, pattern). */
export interface NotifyRule {
  id: string
  userId: string
  pattern: string
  domain: string
  entityId: string | null
  action: string | null
  mode: NotifyRuleMode
  channelOverrides: string | null
  createdAt: string
}

/** The thread-level mute (TODO.notify/00: the "unwatch this thread" of
 *  the model — the entity-page bell's Muted state and the email
 *  footer's one-click unsubscribe both set it). Wins over every
 *  candidate class, subscriptions included; the access is unchanged. */
export interface NotifyEntityMute {
  id: string
  userId: string
  domain: string
  entityId: string
  createdAt: string
}

/** The per-category email posture (TODO.notify/00's channel split): the
 *  inbox always carries the event; 'immediate' emails at once, 'digest'
 *  holds for the daily digest, 'off' stays in-app. */
export type NotifyChannelPreference = 'immediate' | 'digest' | 'off'

/** The user's preferences row: `channels` is the JSON map
 *  { "<domain>": "immediate"|"digest"|"off" } over the catalog's
 *  domains; a domain ABSENT falls back to the catalog row's own email
 *  default. One row per user, written at first preference write. */
export interface NotifyPreferences {
  userId: string
  channels: string
  updatedAt: string
}

// ── the inbox state (TODO.notify/03) ─────────────────────────────────

/** The per-user per-event inbox marker (TODO.notify/00's "the inbox
 *  state (D1): per-user per-event state (read / done / saved) written
 *  lazily at read"): one row per (user, event), created at the first act
 *  on the inbox row. `readAt` stamps the mark-read (NULL = unread);
 *  `doneAt` stamps the archive (NULL = in the inbox — a done row leaves
 *  the feed, the marker keeps the state); `savedAt` (migration 0027,
 *  TODO.notify/05's remainders) stamps the per-event saved flag — the
 *  GitHub Save, independent of read/done (a saved row that is done stays
 *  saved in the archive).
 *  The feed is COMPUTED at read (events × the user's rules × the
 *  visibility gate); this table is the state that computation joins. A
 *  marker on a wiped event never joins (the user's state is their own,
 *  never the workflow's — the subscriptions store's posture). */
export interface NotifyInboxState {
  userId: string
  eventId: string
  readAt: string | null
  doneAt: string | null
  savedAt: string | null
  createdAt: string
}

// ── the email channel's delivery store (TODO.notify/04) ──────────────

/** The email leg's state on a delivery row: NULL when the resolved
 *  posture is 'off' (the inbox carries the event, the mailbox never
 *  does); 'sent' / 'failed' / 'rate_limited' for the immediate leg (the
 *  retry sweep re-attempts 'failed'); 'digest_pending' → 'digest_sent' /
 *  'digest_failed' for the daily rollup ('digest_dropped' when the event
 *  left the store before the rollup ran); 'unavailable' when the
 *  instance carries NO mailer (the honest degradation: nothing queues —
 *  a console-posture instance marks the row at event time and the digest
 *  never accumulates). */
export type NotifyDeliveryStatus =
  | 'sent' | 'failed' | 'rate_limited' | 'unavailable'
  | 'digest_pending' | 'digest_sent' | 'digest_failed' | 'digest_dropped'

/** One delivery row (TODO.notify/00: "a notification row per recipient
 *  with the channel marks"): the fan-out's record that the event reached
 *  this user — the resolution's STRONGEST reason, the resolved email
 *  posture, and the email leg's state. The inbox is the constant, never
 *  a column. UNIQUE (event_id, user_id): a re-driven event updates, never
 *  duplicates. NO foreign keys (the subscriptions store's posture) — a
 *  wiped event simply never joins. The mailer's per-SEND audit
 *  (entity_type 'email') stands alongside; this table is the
 *  PER-RECIPIENT record. */
export interface NotifyDelivery {
  id: string
  eventId: string
  userId: string
  /** The resolution's strongest reason (NOTIFY_REASON_PRECEDENCE's first). */
  reason: string
  /** The resolved email posture (the channel split's outcome). */
  email: NotifyChannelPreference
  emailStatus: NotifyDeliveryStatus | null
  /** The terminal stamp (the send / the drop); NULL while pending. */
  emailAt: string | null
  createdAt: string
}

// ── the OIDC Provider (TODO.identity/01) ─────────────────────────────

/** A registered relying party (an instance allowed to request tokens).
 *  secretHash NULL = a public client (PKCE carries the proof);
 *  claimsPolicy is the parsed claims-policy JSON — `claims` names which
 *  claims the ID token carries for this client, and the OPTIONAL
 *  `roles` allowlist (TODO.identity/03) bounds WHICH roles those claims
 *  may carry: the OP never emits a role the client is not configured
 *  to receive (absent = the policy does not bound the role set). */
export interface OidcClient {
  clientId: string
  name: string
  secretHash: string | null
  /** The exact redirect URIs (string equality — no pattern matching). */
  redirectUris: string[]
  /** Parsed claims policy (null = profile+email claims only — no role
   *  claims leave the OP). */
  claimsPolicy: OidcClientClaimsPolicy | null
  /** The SSO-home launch metadata (null = the client never appears on
   *  the launcher). Managed through setOidcClientLaunch — the registry
   *  upsert never touches it, so a re-seed keeps the admin's edits. */
  launch: OidcClientLaunch | null
  status: 'active' | 'disabled'
  createdAt: string
  createdBy: string | null
}

/** The client registry's claims policy (TODO.identity/01 + /03). */
export interface OidcClientClaimsPolicy {
  /** The claims the ID token carries for this client (roles, groups,
   *  org — profile+email ride the scopes). */
  claims: string[]
  /** OPTIONAL (TODO.identity/03): the closed allowlist of roles the
   *  role claims may carry for this client. ABSENT = no policy bound
   *  (the assignment set carries as-is). */
  roles?: string[]
}

/** The client registry's launch metadata (the SSO home, the post-login
 *  launcher on the identity service): how a signed-in account meets the
 *  service. A client with NO launch row (launch_url NULL) never appears
 *  on the launcher — the machine-only clients stay off it. */
export interface OidcClientLaunch {
  /** The service's sign-in start (an absolute http(s) URL): the card
   *  launches it, the live OP session lets the user straight in. */
  url: string
  /** The card's glyph: a name from the identity service's small icon
   *  set (null = the default launch glyph). */
  icon: string | null
  /** The card's one-line description (null = the name alone carries it). */
  description: string | null
  /** The visibility rule for an account the computed role set does NOT
   *  admit: 'roles' hides the card (the default), 'request' shows it
   *  with a plain request-access state, 'open' never gates (every
   *  signed-in account may launch — the service admits them all). */
  visibility: 'roles' | 'request' | 'open'
}

/** A pending authorization between /op/authorize's validation and the
 *  consent decision. */
export interface OidcAuthorization {
  id: string
  clientId: string
  redirectUri: string
  scope: string
  state: string
  nonce: string | null
  codeChallenge: string
  userId: string | null
  decision: 'allow' | 'deny' | null
  createdAt: string
  expiresAt: string
}

/** The one-time authorization code (consumed atomically at the token
 *  endpoint). */
export interface OidcCode {
  code: string
  clientId: string
  redirectUri: string
  scope: string
  nonce: string | null
  codeChallenge: string
  userId: string
  /** TODO.identity/11 — the ACTIVE-ORG CONTEXT the consent decision was
   *  made under (the session's stamped context at decide time; NULL =
   *  the account's primary context). The token endpoint re-judges it
   *  against the LIVE membership (a membership disabled mid-flow falls
   *  back to the primary context, never emits a dead org's claims). */
  contextOrg: string | null
  /** TODO.identity-sso/02+03: the consenting session's amr provenance
   *  (parsed from the row's JSON; null = none recorded). */
  amr: string[] | null
  /** TODO.identity-sso (the wave-A tail): the consenting session's
   *  authentication instant (sessions.created_at, verbatim; null = none
   *  recorded) — the token endpoint emits it as the ID token's auth_time. */
  authTime: string | null
  expiresAt: string
}

/** An issued access token (the userinfo endpoint resolves it). */
export interface OidcAccessToken {
  token: string
  userId: string
  clientId: string
  scope: string
  /** The context the granting code carried (userinfo answers the SAME
   *  claims the ID token did). */
  contextOrg: string | null
  /** TODO.identity-sso/02+03: the authorizing authentication's amr
   *  provenance — userinfo answers the same truth the ID token carried. */
  amr: string[] | null
  expiresAt: string
}

/** An issued refresh token (migration 0025 — the SSO wave-C token
 *  surface): the offline half of the remembered consent. The row carries
 *  the granting code's full provenance — the canonical scope spelling, the
 *  context_org, the amr, and the ORIGINAL authentication instant (authTime
 *  never advances on a refresh: the refreshed ID token proves the original
 *  authentication). familyId is the rotation lineage: every rotation
 *  inherits the first mint's id. consumedAt flips atomically at the
 *  exchange; the consumed row STAYS so a re-present detects the reuse. */
export interface OidcRefreshToken {
  token: string
  userId: string
  clientId: string
  scope: string
  contextOrg: string | null
  amr: string[] | null
  authTime: string | null
  familyId: string
  createdAt: string
  expiresAt: string
  consumedAt: string | null
}

/** The refresh exchange's honest outcomes. 'ok' carries the freshly
 *  consumed row (the route rotates from its provenance). 'reuse' is the
 *  theft signal (RFC 6819 §5.2.2.3): a presented CONSUMED token — the
 *  store already killed the whole family (the attacker's copy and the
 *  legitimate chain both end); a concurrent double-present loses the
 *  atomic race to the same verdict, the fail-toward-invalidation posture.
 *  'invalid' covers the never-existed, the revoked (the row is gone), and
 *  the expired (consumed anyway — never a second chance). */
export type ConsumeOidcRefreshTokenResult =
  | { kind: 'ok'; token: OidcRefreshToken }
  | { kind: 'reuse'; familyId: string; userId: string; clientId: string }
  | { kind: 'invalid' }

/** The OP key rotation history — the PUBLIC half only. */
export interface OidcKeyRow {
  kid: string
  publicJwk: string
  status: 'active' | 'retired'
  createdAt: string
  retiredAt: string | null
}

// ── the remembered consent grants (TODO.identity-features/12) ────────

/** A remembered consent grant (the oidc_consent_grants row): the account
 *  holder's "Allow", remembered per (user, client, scope set) so a repeat
 *  authorization the grant COVERS skips the consent page. A LIVE grant
 *  carries revoked_at NULL — revocation flips the stamp and the row stays
 *  (the audit chain's resolvable record); the account erasure removes the
 *  rows outright (the PAT doctrine). scope is the CANONICAL set spelling
 *  (normalizeOidcScopeSet) — the partial unique index keys one live row
 *  per (user, client, scope) triple. */
export interface OidcConsentGrant {
  id: string
  userId: string
  clientId: string
  /** The granted scope set, space-joined in the canonical spelling. */
  scope: string
  createdAt: string
  revokedAt: string | null
}

/** The scope set's canonical spelling: split on whitespace, drop empties
 *  and duplicates, sort — 'profile openid' and 'openid profile' are the
 *  SAME set, so the (user, client, scope) triple's uniqueness holds
 *  honestly. */
export function normalizeOidcScopeSet(scope: string): string {
  return [...new Set(scope.split(/\s+/).filter(Boolean))].sort().join(' ')
}

/** The skip check's coverage math (the authorize endpoint's rule): a live
 *  grant covers the request when EVERY requested scope is in the granted
 *  set. Both sides normalize first, so a hand-edited row still reads as a
 *  set — never trusted as a string match. */
export function consentGrantCovers(grantScope: string, requestedScope: string): boolean {
  const granted = new Set(normalizeOidcScopeSet(grantScope).split(' ').filter(Boolean))
  const requested = normalizeOidcScopeSet(requestedScope).split(' ').filter(Boolean)
  return requested.length > 0 && requested.every(s => granted.has(s))
}

// ── the upstream providers (TODO.identity/08) ────────────────────────

/** An upstream identity provider the OP links + accepts (a registry
 *  row — adding a provider is never a code fork). kind 'github' runs
 *  the OAuth web flow; kind 'oidc' runs discovery + code + PKCE against
 *  the issuer (Google/Entra/Apple/generic — Apple's documented quirks
 *  key on the issuer host, auth/upstream/registry.ts). The client
 *  SECRET is never stored: clientSecretRef names an env variable
 *  ('env:<NAME>'). */
export interface IdentityProvider {
  id: string
  kind: 'github' | 'oidc'
  displayName: string
  /** The brand-mark key the login/account pages map to an icon
   *  (github | google | apple | microsoft | oidc; null = generic). */
  brandMark: string | null
  /** The OIDC issuer URL (kind 'oidc'; NULL for github — its endpoints
   *  ride the GITHUB_*_BASE_URL env seam, auth/github.ts). */
  issuer: string | null
  clientId: string
  /** 'env:<NAME>' — resolved per request, never stored resolved. */
  clientSecretRef: string | null
  /** The scope override (NULL = the kind's default: github 'read:user
   *  user:email'; oidc 'openid profile email'; Apple 'openid name
   *  email'). */
  scopes: string | null
  enabled: boolean
  createdAt: string
  createdBy: string | null
  updatedAt: string | null
}

/** A linked upstream identity (TODO.identity/02's table shape, landed
 *  additively with 08's flows): THE match rule for an upstream sign-in
 *  — resolve by (provider, providerAccountId), NEVER by email alone. */
export interface IdentityLink {
  id: string
  userId: string
  /** The identity_providers row id. */
  provider: string
  providerAccountId: string
  linkedAt: string
  /** Who performed the link (the account holder's email, or the admin's). */
  linkedBy: string | null
}

// ── the OP's account model (TODO.identity/02) ────────────────────────

/** The invite-only enrollment link's row. One-time (consumed_at flips
 *  atomically at completion), 24 h TTL. */
export interface EnrollmentToken {
  token: string
  userId: string
  createdBy: string | null
  createdAt: string
  expiresAt: string
  consumedAt: string | null
}

/** The account page's session row — NEVER the token itself. `current`
 *  marks the row the presenting cookie resolves to (computed in SQL, so
 *  the token never leaves the store). TODO.identity/06 adds the sign-in
 *  context (user agent / IP at creation, last-active on resolution);
 *  NULLs render as "not recorded" on older rows. */
export interface SessionView {
  id: string
  createdAt: string
  expiresAt: string
  lastSeenAt: string | null
  userAgent: string | null
  ip: string | null
  current: boolean
}

/** The aggregate live-session row (TODO.identity-sso/01 — the admin
 *  dashboard's "who is signed in NOW"): a SessionView plus the account
 *  it belongs to. The SessionView rule stands: NEVER the token itself;
 *  `current` marks the presenting administrator's own row (computed in
 *  SQL, so the token never leaves the store). */
export interface OpLiveSession extends SessionView {
  userId: string
}

/** The enrollment completion's honest outcomes. */
export type CompleteEnrollmentResult =
  | { kind: 'ok'; userId: string }
  /** Never existed or already consumed (one-time means one-time — the
   *  two classes are deliberately indistinguishable). */
  | { kind: 'unknown' }
  /** Past the TTL: burned on presentation, never redeemable later. */
  | { kind: 'expired' }

// ── the central user registry (TODO.identity/03) ─────────────────────

/** A PER-CLIENT role assignment (the op_client_roles row): the roles
 *  the account holds on ONE relying party. An empty `roles` is the
 *  explicit "no roles on this client" — distinct from NO ROW, which
 *  leaves the account's OP-side role set as that client's default. */
export interface OpClientRoleAssignment {
  userId: string
  clientId: string
  roles: string[]
  assignedBy: string | null
  createdAt: string
  updatedAt: string | null
}

/** The erasure act's removal counts (the audit event's metadata):
 *  revokeOpUserCredentials' five plus the links, the per-client
 *  assignments, the org memberships (TODO.identity/11), and the
 *  credential/token rows (passwords, enrollment tokens, email-change
 *  tokens). TODO.identity-sso/02+03 adds `factors`: the factor-registry
 *  rows removed (passkeys, TOTP secrets, recovery codes, and the
 *  account's pending ceremony state). TODO.identity-features/08 adds
 *  `personalAccessTokens`: the developer-token rows (a dead account's
 *  tokens die with it). TODO.identity-features/12 adds `consentGrants`:
 *  the remembered consent rows (a dead account's grants die with it).
 *  TODO.identity-features/01 adds `emails`: the additional-address rows
 *  (every address of the account goes — the tombstone's primary is the
 *  anonymized users.email). */
export interface OpAccountErasure {
  sessions: number
  accessTokens: number
  refreshTokens: number
  codes: number
  authorizations: number
  links: number
  clientRoles: number
  memberships: number
  tokens: number
  factors: number
  personalAccessTokens: number
  consentGrants: number
  emails: number
}

// ── the account console (TODO.identity/06) ───────────────────────────

/** The verify-an-address ceremony's row (the enrollment link's doctrine:
 *  a 256-bit random token backed by the D1 row; one-time, 24 h).
 *  deliveredBy records the channel the link traveled: 'mailer' (sent to
 *  the NEW address; completing verifies it) or 'shown' (no mailer
 *  configured, the link was displayed to the signed-in holder; the change
 *  applies but the address stays unverified, honestly).
 *  TODO.identity-features/01: kind names the ceremony — 'change' (the
 *  primary-address replacement; completion moves users.email) or 'add'
 *  (the per-address verification of an account_emails row; completion
 *  stamps the row's verified_at). Rows predating the kind column read
 *  'change' (the migration's default).
 *  The 0.2.4 kind: 'verify' — the re-verification of the address the
 *  account ALREADY holds as its primary (the invited-not-yet-set-up and
 *  the admin-re-addressed postures, whose primary never went through a
 *  mailbox proof). new_email carries the primary AS REQUESTED;
 *  completion stamps users.email_verified_at when the address is STILL
 *  the account's primary and the link traveled by mailer. */
export interface EmailChangeToken {
  token: string
  userId: string
  newEmail: string
  deliveredBy: 'mailer' | 'shown'
  kind: 'change' | 'add' | 'verify'
  createdAt: string
  expiresAt: string
  consumedAt: string | null
}

/** The email change completion's honest outcomes. */
export type CompleteEmailChangeResult =
  | { kind: 'ok'; userId: string; newEmail: string; verified: boolean }
  /** Never existed or already consumed (indistinguishable, the
   *  enrollment rule) — or the ceremony's target vanished between
   *  request and completion: the 'add' row removed, the 'verify'
   *  primary moved (the link burns the same, honestly). */
  | { kind: 'unknown' }
  /** Past the TTL: burned on presentation, never redeemable later. */
  | { kind: 'expired' }
  /** Another account took the address between request and completion
   *  (the token is burned; the change must start over). */
  | { kind: 'conflict' }

// ── multiple emails per account (TODO.identity-features/01) ──────────

/** One of the account's addresses. The PRIMARY is the users row's email
 *  (isPrimary — the OIDC `email` claim's source, never an
 *  account_emails row); the ADDITIONAL addresses are the account_emails
 *  rows. verifiedAt NULL = the mailbox is unproven: an unverified
 *  additional NEVER names the account (not to sign-in, not to recovery,
 *  never a notification's target). */
export interface AccountEmail {
  userId: string
  email: string
  verifiedAt: string | null
  isPrimary: boolean
  /** Who added the row (the holder's session email, an admin's); NULL on
   *  the primary line (the users row carries no such provenance). */
  addedBy: string | null
  createdAt: string
}

/** The additional-address add's honest outcomes. */
export type AddAccountEmailResult =
  /** The row landed (unverified — the verification ceremony follows). */
  | 'added'
  /** The account ALREADY carries the address as an additional (the add
   *  is an idempotent no-op; the route re-sends the verification for an
   *  unverified row). */
  | 'present'
  /** Another account holds the address (as its primary or an
   *  additional), or it IS this account's primary — an address names at
   *  most one account across the estate. */
  | 'conflict'

// ── strong authentication: the factor registry (TODO.identity-sso/02 + /03)

/** A registered passkey (the webauthn_credentials row). publicKeyCose is
 *  the COSE key bytes (base64url) exactly as the attestation carried
 *  them; aaguid + transports record what the browser DECLARED at
 *  registration (attestation is 'none' — the console's display hints,
 *  never proof). signCount is the authenticator's signature counter. */
export interface WebauthnCredential {
  credentialId: string
  userId: string
  name: string
  publicKeyCose: string
  signCount: number
  aaguid: string | null
  transports: string[]
  createdAt: string
  lastUsedAt: string | null
  lastIp: string | null
}

/** The counter advance's honest outcomes (the clone rule): the guarded
 *  UPDATE either lands ('ok'), refuses a REGRESSED counter ('regressed'
 *  — the audit event's signal), or names a credential that is not there
 *  ('unknown'). A (0 → 0) pair is a software authenticator that never
 *  counts and passes; a zeroed-or-behind count against a started one
 *  regresses. */
export type AdvanceCounterResult = 'ok' | 'regressed' | 'unknown'

/** A TOTP authenticator app's row (RFC 6238). verifiedAt NULL = the
 *  PENDING enrollment (activates on the first valid code only);
 *  failCount + lastFailureAt carry the enrollment verify's throttle
 *  (the six-digit window invites brute force). `secret` is the base32
 *  seed — the store answers it, the ROUTES never return it after the
 *  enrollment answer. */
export interface TotpSecret {
  id: string
  userId: string
  name: string
  secret: string
  failCount: number
  lastFailureAt: string | null
  createdAt: string
  verifiedAt: string | null
  lastUsedAt: string | null
  lastIp: string | null
}

/** The recovery-code set's console state (never a hash, never a code):
 *  the generation's size, the unconsumed remainder, and when the current
 *  batch was minted. */
export interface RecoveryCodeState {
  total: number
  remaining: number
  createdAt: string | null
}

/** The one-time WebAuthn ceremony challenge (the database-is-the-proof
 *  doctrine): userId binds the registration + the second-factor
 *  assertion; the passwordless assertion's row carries null (the
 *  asserted credential id resolves the account). */
export interface WebauthnChallenge {
  challenge: string
  userId: string | null
  kind: 'register' | 'assert'
  createdAt: string
  expiresAt: string
  consumedAt: string | null
}

/** The pending second-factor sign-in: the password verified, the session
 *  waits on the factor. amr carries the methods proven so far (parsed
 *  JSON, e.g. ['pwd']); failCount + lastFailureAt ride the per-account
 *  throttle ladder. */
export interface MfaPending {
  token: string
  userId: string
  amr: string[]
  failCount: number
  lastFailureAt: string | null
  createdAt: string
  expiresAt: string
  consumedAt: string | null
}

// ── the personal access tokens (TODO.identity-features/08) ───────────
// The developer surface: an ACCOUNT-minted credential for programmatic
// access (the lab CLI, scripts, the agent pipelines). The GitHub
// fine-grained pattern mapped to the estate:
//
//   - the PAT NEVER rides a request directly — it exchanges at the OP's
//     token endpoint (the RFC 8693 grant, subject_token_type
//     urn:oimlsmart:params:oauth:token-type:pat) for a short-lived OP
//     JWT, so every relying party keeps validating the ONE token shape;
//   - the plaintext shows ONCE at mint; the row holds only the SHA-256
//     (256 bits of random — the recovery codes' unsalted-hash posture),
//     and token_hash IS the exchange's lookup key;
//   - expiration is MANDATORY (90 days default, 1 year the ceiling);
//   - a token only ever NARROWS the account: its scopes are a subset of
//     the holder's standing, enforced at mint AND re-judged at exchange;
//   - never an ORG credential: org-level automation speaks the org's
//     registered clients (the machine cone), never a person's token.

/** The PAT wire prefix (the GitHub `github_pat_` convention): the
 *  minted token is `${PAT_TOKEN_PREFIX}${43 base64url chars}` (32 random
 *  bytes). The prefix lets the exchange path recognize the cone and lets
 *  leak scanners catch a committed token. */
export const PAT_TOKEN_PREFIX = 'ospt_'

/** The action class's ordinality: admin ⊃ write ⊃ read. The RP's at-use
 *  check (patScopeCovers) reads it — a write token never mints admin
 *  acts, an admin token covers the read. */
export const PAT_ACTION_CLASSES = ['read', 'write', 'admin'] as const
export type PatActionClass = (typeof PAT_ACTION_CLASSES)[number]

/** One parsed scope: the service (a registered application-class OIDC
 *  client id — the estate's service registry IS the OP's client
 *  registry) × the action class. */
export interface PatScope {
  service: string
  action: PatActionClass
}

/** Parse one scope spelling ('<service>:<action-class>'). Total, never
 *  throws: a malformed spelling answers null (the mint refuses it, a
 *  stored row's malformed cell is skipped on read — never trusted). */
export function parsePatScope(raw: unknown): PatScope | null {
  if (typeof raw !== 'string') return null
  const m = /^([a-z0-9][a-z0-9._-]{0,127}):(read|write|admin)$/.exec(raw.trim())
  if (!m) return null
  return { service: m[1]!, action: m[2] as PatActionClass }
}

/** The canonical spelling (the store column's cell, the JWT's scope
 *  claim's word). */
export function encodePatScope(scope: PatScope): string {
  return `${scope.service}:${scope.action}`
}

/** Normalize a scope set: parse every cell (a malformed cell refuses the
 *  WHOLE set at mint — null), drop duplicates, and fold a service's
 *  classes to the WIDEST (hub:read + hub:write is hub:write — the
 *  ordinal subsumes). The answer sorts for a stable wire/claim shape. */
export function normalizePatScopes(raw: unknown): PatScope[] | null {
  if (!Array.isArray(raw) || raw.length === 0) return null
  const widest = new Map<string, PatActionClass>()
  for (const cell of raw) {
    const scope = parsePatScope(cell)
    if (!scope) return null
    const held = widest.get(scope.service)
    if (!held || PAT_ACTION_CLASSES.indexOf(scope.action) > PAT_ACTION_CLASSES.indexOf(held)) {
      widest.set(scope.service, scope.action)
    }
  }
  return [...widest.entries()]
    .map(([service, action]) => ({ service, action }))
    .sort((a, b) => a.service.localeCompare(b.service))
}

/** THE NARROWING INVARIANT (the spec's core: scopes ≤ the holder's,
 *  enforced at exchange AND at use): every granted scope must be covered
 *  by the ceiling set — the account's current standing at mint/exchange,
 *  the token's own pinned set when a caller narrows per exchange. */
export function patScopesWithin(granted: readonly PatScope[], ceiling: readonly PatScope[]): boolean {
  return granted.every(g => patScopeCovers(ceiling, g.service, g.action))
}

/** The at-use check (the RP's bearer gate — the RBAC map's token-scope
 *  cone): does the granted set cover this service at this action class?
 *  Ordinal: a wider class covers the narrower. */
export function patScopeCovers(granted: readonly PatScope[], service: string, action: PatActionClass): boolean {
  const need = PAT_ACTION_CLASSES.indexOf(action)
  return granted.some(g => g.service === service && PAT_ACTION_CLASSES.indexOf(g.action) >= need)
}

/** A personal access token's row (the personal_access_tokens table).
 *  NEVER the plaintext, never reversible material: tokenHash is the
 *  SHA-256 lookup key, tokenPrefix the console's display fragment.
 *  orgContext pins the mint's active-org context (null = the account's
 *  primary); lastUsedAt / lastExchangeAuditAt carry the exchange path's
 *  throttled heartbeat; expiryNotifiedAt the expiry-soon mailer's
 *  one-shot mark. */
export interface PersonalAccessToken {
  id: string
  userId: string
  name: string
  tokenHash: string
  tokenPrefix: string
  /** The pinned scope set (the encoded spellings, normalized at mint). */
  scopes: string[]
  orgContext: string | null
  createdAt: string
  expiresAt: string
  lastUsedAt: string | null
  lastExchangeAuditAt: string | null
  expiryNotifiedAt: string | null
  revokedAt: string | null
  revokedBy: string | null
}


// ── organization administration (TODO.identity/10) ───────────────────

/** A self-service join request (the "Request an account" page). The
 *  queue routing is on the row: `orgId` set → the named ORG's admin
 *  decides (the org must be a REGISTERED participant org at submit and
 *  again at approval); `orgId` NULL + `orgNameText` → the "my
 *  organization is not listed" path — BIML's new-organizations queue
 *  (BIML verifies the participation, then the requester becomes the
 *  org's administrator). The decision is atomic on 'pending'; approval
 *  records the invited account in `invitedUserId`. */
export interface OrgJoinRequest {
  id: string
  name: string
  email: string
  /** The selected registry org (NULL = the not-listed path). */
  orgId: string | null
  /** The free-text organization name (the not-listed path only). */
  orgNameText: string | null
  /** The role asked for — bounded by the org's kind (the submit route
   *  and the approval both validate; 'org_admin' on the not-listed path). */
  requestedRole: string
  note: string | null
  status: 'pending' | 'approved' | 'refused'
  decidedBy: string | null
  decidedAt: string | null
  refusalReason: string | null
  invitedUserId: string | null
  createdAt: string
}

// ── the multi-organization membership model (TODO.identity/11) ───────

/** The membership lifecycle: INVITED (the org's admin added the account,
 *  the holder has not accepted yet — the account does not act for the
 *  org) → ACTIVE (the account holds the org's context: the per-org role
 *  set applies) → DISABLED (the org's admin or the scheme operator
 *  suspended the membership; reversible — re-activation is a deliberate
 *  act, never an automatic one). */
export type OrgMembershipState = 'invited' | 'active' | 'disabled'

// ── the per-member data cone (TODO.identity-features/09) ─────────────
// Every org membership carries a CONE — the org administrator's answer
// to "what can this member see and do" (the design: the org-wide default
// keeps today's behavior; 'assigned' narrows the member to the org's
// rows that NAME them; 'read-only' is the orthogonal modifier that
// refuses the member's writes). The cone lives on the membership row
// (org_memberships.cone, a nullable TEXT column — NULL is org-wide, so
// existing memberships keep their posture silently), rides the OP's
// claims in the active-org context, and is enforced at the platform's
// two choke points ONLY (the read gate and the write gate). THE
// INVARIANT: the cone only ever NARROWS — nothing in this machinery can
// grant.

/** The cone's scope: org-wide (the default — every row the org sees) or
 *  assigned (only the org's rows that NAME the member — the operator on
 *  the test run, the assignment's performer, the engagement's inquirer). */
export type OrgMemberConeScope = 'org-wide' | 'assigned'

/** The parsed cone (the payload shape every consumer reads). */
export interface OrgMemberCone {
  scope: OrgMemberConeScope
  /** The orthogonal modifier: the member reads per the scope but the
   *  write gate refuses them (a reviewer's posture). */
  readOnly: boolean
}

/** The DEFAULT cone (a NULL column): org-wide, writable — today's
 *  behavior, kept silently by every pre-existing membership. */
export const ORG_MEMBER_CONE_DEFAULT: OrgMemberCone = { scope: 'org-wide', readOnly: false }

/** The FAIL-CLOSED cone: a stored value the parser cannot read narrows
 *  to the tightest posture (never a silent re-widen — the platform's
 *  standing doctrine: a malformed permission input never grants). */
export const ORG_MEMBER_CONE_FAIL_CLOSED: OrgMemberCone = { scope: 'assigned', readOnly: true }

/** The canonical column spellings (NULL is the default — the column
 *  stays NULL for org-wide+writable, keeping the expand-only posture
 *  clean). 'org-wide' parses but never encodes (it IS the default). */
export function encodeOrgMemberCone(cone: OrgMemberCone): string | null {
  if (cone.scope === 'assigned') return cone.readOnly ? 'assigned+read-only' : 'assigned'
  return cone.readOnly ? 'read-only' : null
}

/** Parse the stored cone (total, never throws): NULL/empty/'org-wide'
 *  answer the default; a recognized composition parses; ANYTHING else
 *  fails CLOSED (the narrowest cone) — a hand-edited or corrupt row
 *  narrows the member, it never widens them. */
export function parseOrgMemberCone(raw: string | null | undefined): OrgMemberCone {
  if (raw === null || raw === undefined) return { ...ORG_MEMBER_CONE_DEFAULT }
  const tokens = raw.split('+').map(t => t.trim()).filter(Boolean)
  if (tokens.length === 0) return { ...ORG_MEMBER_CONE_DEFAULT }
  let scopeSeen: OrgMemberConeScope | null = null
  let readOnly = false
  for (const token of tokens) {
    if (token === 'read-only') {
      if (readOnly) return { ...ORG_MEMBER_CONE_FAIL_CLOSED } // a doubled modifier is not a spelling
      readOnly = true
    } else if (token === 'org-wide' || token === 'assigned') {
      if (scopeSeen !== null) return { ...ORG_MEMBER_CONE_FAIL_CLOSED } // two scopes is not a spelling
      scopeSeen = token
    } else {
      return { ...ORG_MEMBER_CONE_FAIL_CLOSED } // an unknown token
    }
  }
  return { scope: scopeSeen ?? 'org-wide', readOnly }
}

/** An account's membership in ONE organization (the org_memberships
 *  row): the per-org role set + the lifecycle state. The PRIMARY
 *  membership (isPrimary) is the backward-compatible one: the users
 *  row's org_id/roles columns mirror it, so every consumer that still
 *  reads the legacy columns sees exactly the primary context (the
 *  dual-read doctrine — the columns stay until every consumer reads the
 *  memberships). */
export interface OrgMembership {
  id: string
  userId: string
  orgId: string
  /** The PER-ORG role set (JSON on the row): the roles the account holds
   *  when acting AS this org. */
  roles: string[]
  /** The membership's data cone (TODO.identity-features/09), parsed from
   *  the row's nullable column — the DEFAULT object when the column is
   *  NULL (org-wide, writable); never null on the payload. */
  cone: OrgMemberCone
  state: OrgMembershipState
  isPrimary: boolean
  invitedBy: string | null
  createdAt: string
  activatedAt: string | null
  disabledAt: string | null
  disabledBy: string | null
}

/** The effective org context: the org the account acts AS, the role
 *  set that context carries, and the context membership's data cone
 *  (TODO.identity-features/09 — NULL when NO membership row resolved:
 *  the pre-memberships dual-read and the org-free account carry no
 *  cone). The session payloads and the OP's token claims both resolve
 *  through resolveOrgContext, so the two never drift. */
export interface OrgContextResolution {
  orgId: string | null
  roles: string[]
  cone: OrgMemberCone | null
}

/**
 * THE CONTEXT RULE (TODO.identity/11 — the GitHub context-switch
 * pattern, one pure function every reader shares). Given the account's
 * legacy columns (role/roles/orgId), the session's stamped active org
 * (NULL = the primary context), and the membership rows it names:
 *
 *   - an ACTIVE-ORG context whose membership is ACTIVE resolves to that
 *     org + its per-org role set. An ORG-FREE account's account-level
 *     roles (the scheme's own staff: admin, cs_admin, …) ride EVERY
 *     context honestly; an org-bound account's legacy set is the
 *     primary membership's mirror and rides ONLY the primary context —
 *     a relying party never learns the other memberships.
 *   - a context whose membership is missing or no longer active (the
 *     org's admin disabled it mid-session) falls through to the primary
 *     rule — the stale context never emits a dead org's claims.
 *   - the PRIMARY context: no membership row at all answers the
 *     pre-memberships read (the dual-read fallback — a store predating
 *     the backfill behaves exactly as before); an ACTIVE primary carries
 *     the mirrored set (byte-identical with the legacy columns); an
 *     invited/disabled primary means the account does NOT act for the
 *     org — no org, no org roles.
 */
export function resolveOrgContext(
  user: { role: string; roles?: string[] | null; orgId: string | null },
  context: { activeOrg: string | null; active: OrgMembership | null; primary: OrgMembership | null },
): OrgContextResolution {
  const accountRoles = user.roles?.length ? [...user.roles] : [user.role]
  if (context.activeOrg) {
    const m = context.active
    if (m && m.orgId === context.activeOrg && m.state === 'active') {
      const global = user.orgId ? [] : accountRoles
      return { orgId: context.activeOrg, roles: [...new Set([...m.roles, ...global])], cone: m.cone }
    }
  }
  if (!user.orgId) return { orgId: null, roles: accountRoles, cone: null }
  const p = context.primary
  // The pre-memberships dual-read (no primary row) carries NO cone — the
  // org-wide default the enforcement reads for a cone-less context.
  if (!p) return { orgId: user.orgId, roles: accountRoles, cone: null }
  if (p.state !== 'active') return { orgId: null, roles: [], cone: null }
  return { orgId: user.orgId, roles: [...new Set([...accountRoles, ...p.roles])], cone: p.cone }
}

// ── the organization registry (TODO.identity-features/05) ────────────

/** The registry organization's lifecycle: ACTIVE (the membership graph
 *  admits it — memberships, assignments, and the join selector where it
 *  carries a participant kind) → DISABLED (the identity administrator's
 *  honest removal: the org's memberships disable, its members' per-org
 *  roles stop carrying; the row and the audit trail keep the history).
 *  The erasure-adjacent hard delete exists only for an org that never
 *  held a membership (the routes enforce it; the store removes rows). */
export type OrgRegistryState = 'active' | 'disabled'

/** One contact on the registry organization (the row's contacts JSON
 *  array; a malformed entry is skipped on read, never trusted). */
export interface OrgRegistryContact {
  name: string | null
  email: string
}

/** One organization on the identity service's OWN registry (the
 *  org_registry row) — the identity plane's membership graph as a
 *  first-class entity with its lifecycle (the identity administrator's
 *  add/edit/disable/remove).
 *
 *  The id is the stable SLUG; for a participant organization the OIML
 *  code IS the id (TODO.identity-features/05 §4 — the platform resolves
 *  the org claim's value against its own participant registry directly:
 *  the same string on both sides, so the mapping is identity, never a
 *  lookup table). `kind` names the participant kind for a participant
 *  org (NULL = a non-participant org — the estate operator's own org, a
 *  scheme consumer); the program side bounds the assignable per-org
 *  roles by it. `participantRef` is the OPTIONAL annotation documenting
 *  which participant record the org mirrors (the link's documentation,
 *  never a key the store resolves).
 *
 *  TODO.identity-features/10 (the OIML Member category, the taxonomy
 *  correction): the designation links + the CS status facet (migration
 *  0019). `designatedBy` is the designating body (a Utilizer's member
 *  state, an Associate's corresponding member, a Test Laboratory's
 *  associated issuing authority); `proposedBy` is an Issuing
 *  Authority's proposing member state; `csStatus` is the designated
 *  bodies' Declaration standing ('signed-active' | 'suspended' |
 *  'withdrawn'). All three are opaque strings to the store — the
 *  per-kind link enforcement (which kind may point at which) is the
 *  program's write path; NULL reads "not recorded", honestly. */
export interface OrgRegistryOrg {
  id: string
  /** The display name. */
  name: string
  shortName: string | null
  /** The participant kind ('issuing-authority' | 'test-laboratory' |
   *  'utilizer' | 'associate' on the OIML-CS program, 'member-state' |
   *  'corresponding-member' on the OIML Member category), NULL for a
   *  non-participant org. Opaque to the store. */
  kind: string | null
  country: string | null
  contacts: OrgRegistryContact[]
  participantRef: string | null
  /** The designating body's org id (TODO.identity-features/10) — the
   *  designated-body kinds carry it; NULL = not recorded. */
  designatedBy: string | null
  /** The proposing member state's org id (the issuing-authority kind). */
  proposedBy: string | null
  /** The Declaration's standing on the designated bodies
   *  ('signed-active' | 'suspended' | 'withdrawn'); NULL = not
   *  recorded. */
  csStatus: string | null
  state: OrgRegistryState
  createdAt: string
  createdBy: string | null
  updatedAt: string | null
  updatedBy: string | null
  disabledAt: string | null
  disabledBy: string | null
}

// ── the register's holder-org attribution (TODO.register/02) ─────────

/** The hub-side attribution of a REGISTERED certificate to its holder
 *  organization — the OP-minted org id, never an instance-minted one.
 *  The hub's OWN row (the certificate_holder_orgs table): the registrar's
 *  act extracts the descriptor the federation registration package carried
 *  (source 'registration'), or the estate admin's claim confirmation writes
 *  it for a legacy row (source 'claim'). ONE row per certificate — the
 *  first attribution wins, a later writer never overwrites silently.
 *
 *  The org display name is DENORMALIZED at attribution time: the register
 *  reads correctly even when the organization later renames (the
 *  register's permanence rule — the descriptor is the register's record,
 *  never a join against a live registry). */
export interface CertificateHolderOrg {
  certificateId: string
  orgId: string
  orgName: string
  source: 'registration' | 'claim'
  attributedAt: string
  /** The registrar / the confirming estate admin (the actor's name). */
  attributedBy: string | null
  /** The confirming claim (source 'claim' only). */
  claimId: string | null
}

/** The legacy-row claim act's lifecycle: PENDING (the manufacturer org's
 *  administrator claimed the row by holder-name match — a claim is a
 *  claim until confirmed) → CONFIRMED (the estate admin's act; the
 *  attribution row lands) / REFUSED (terminal for THAT claim, with the
 *  written reason; a fresh claim may follow). */
export type CertificateHolderClaimState = 'pending' | 'confirmed' | 'refused'

export interface CertificateHolderClaim {
  id: string
  certificateId: string
  claimantOrgId: string
  /** The claiming org's display name at claim time (denormalized — the
   *  confirmed attribution's org_name comes from here). */
  claimantOrgName: string
  /** The certificate's free-text holder name the claim matched — the
   *  snapshot, the claim's evidence. */
  matchedHolderName: string
  /** The claiming account (the org admin's name). */
  claimedBy: string
  state: CertificateHolderClaimState
  decidedBy: string | null
  decidedAt: string | null
  refusalReason: string | null
  createdAt: string
}

// ── the instrument register (TODO.register/03) ──────────────────────

/** The registered instrument's lifecycle: REGISTERED (the declaration
 *  stood) ⇄ OUT_OF_SERVICE (the holder's mark — the instrument is out
 *  of service, the registration stands; a return to service re-marks
 *  it registered) → WITHDRAWN (terminal — the holder withdrew the
 *  instrument from the register; a withdrawn row never reopens). The
 *  route owns the transition rule; the store keeps the rows. */
export type InstrumentRegistrationLifecycle = 'registered' | 'out_of_service' | 'withdrawn'

/** The scope verdict recorded AT REGISTRATION (the executing-scope
 *  doctrine at the instrument level):
 *  - in_scope — the certificate's structured scope block (its
 *    classifications) covered the declared designations;
 *  - scope_unverified — the certificate carries NO structured scope
 *    block (the records-mode import's honest degradation): the check
 *    was unavailable, the registration is marked, and the issuing IA's
 *    oversight surface sees exactly this mark.
 * The third verdict — refused — never lands a row: the route refuses
 * the out-of-scope declaration with the reason. */
export type InstrumentRegistrationScopeStatus = 'in_scope' | 'scope_unverified'

/** One registered instrument (the instrument_registrations row): the
 *  serial number riding under a type certificate. The certificate's
 *  holder organization is referenced by id WITHOUT a foreign key (the
 *  identity plane and this platform-side register never merge — the
 *  org_memberships posture); a registration row's honesty never depends
 *  on a join. */
export interface InstrumentRegistration {
  id: string
  /** The certificate the serial rides under (the entity store's
   *  certificates row id). */
  certificateId: string
  /** The holder organization (the manufacturer org id). */
  holderOrgId: string
  /** The Recommendation the certificate belongs to. */
  standardId: string
  serialNumber: string
  /** The ISO manufacture date, null when the declaration omitted it. */
  manufactureDate: string | null
  /** The per-serial designations the scope check evaluated (the JSON
   *  object; a malformed cell reads as the empty object, never
   *  trusted). */
  designations: Record<string, unknown>
  scopeStatus: InstrumentRegistrationScopeStatus
  /** The verdict's record: the matched classification label
   *  (in_scope) or the unverified note (scope_unverified). */
  scopeDetail: string | null
  lifecycle: InstrumentRegistrationLifecycle
  registeredAt: string
  registeredBy: string | null
  updatedAt: string | null
  updatedBy: string | null
}

/** One row of the batch register write (createInstrumentRegistrations):
 *  createInstrumentRegistration's legs — the same fields, so each row
 *  lands exactly as the single-row verb would land it (the
 *  EntityWriteInput pattern). */
export interface InstrumentRegistrationWriteInput {
  id: string
  certificateId: string
  holderOrgId: string
  standardId: string
  serialNumber: string
  manufactureDate?: string | null
  designations?: Record<string, unknown>
  scopeStatus: InstrumentRegistrationScopeStatus
  scopeDetail?: string | null
  registeredBy?: string | null
}

/** The batch register write's chunk, in ROWS (createInstrumentRegistrations):
 *  each row contributes ONE statement (the INSERT OR IGNORE … RETURNING *
 *  answers the stored row off the write itself), so a chunk is one
 *  db.batch of INSTRUMENT_REGISTRATIONS_CHUNK statements — half the
 *  PUT_ENTITIES_CHUNK statement load, the same conservative order. The
 *  chunk bounds the ATOMIC unit (a D1 batch is all-or-nothing; the
 *  SQLite half's per-chunk transaction matches it). Chunks issue
 *  SERIALLY, in input order — the register's insertion order IS the
 *  input's row order (the CSV commit's chain events sequence after it,
 *  same order), and parallel chunks would forfeit it. */
export const INSTRUMENT_REGISTRATIONS_CHUNK = 50

/** Per-store org fields for the READ visibility (the multi-party
 *  model: a row is visible when ANY named field equals the user's
 *  org). The field names are the entities' REAL ones (verified against
 *  the data model, 2026-08-03 — a guessed name hides everything).
 *
 *  The instrument CATALOG (families/groups/models/samples) is NOT here
 *  on purpose: it is shared reference data — the IA evaluates against
 *  the model, the TL tests the sample (the 2026-08-03 zero-verdicts
 *  diagnosis: manufacturer-only catalog reads left the IA's verdict
 *  engine with no subject chain). Catalog WRITES are gated in
 *  writeAllowed. */
export const ORG_FIELDS: Record<string, string[]> = {
  applications: ['manufacturer_id', 'issuing_authority_id'],
  testRequests: ['requesting_authority_id', 'assigned_laboratory_id'],
  testReports: ['laboratory_id'],
  testAssignments: ['laboratory_id'],
  testRuns: ['laboratory_id'],
  evaluationReports: ['authority_id'],
  modelEvaluations: ['laboratory_id'],
  certificates: ['issuing_authority_id', 'model_family_id'],
  acceptanceReviews: ['participant_id'],
  // TODO.federation/02 — the engagement module, generalized by
  // TODO.adoption/07 into the negotiation primitive: the two parties of
  // the pair see the negotiation and its quotation/agreement — the
  // applicant org and the IA on ia_applicant, the IA and the laboratory
  // on ia_tl, the applicant org and the laboratory on tl_applicant; on
  // the test-request quote leg the quotation carries the dispatching IA
  // and the quoting laboratory (the Quotation/ConsultingAgreement
  // records denormalize the party ids from their parent — the org fields
  // are the entities' REAL fields, no parent-resolution leg).
  engagements: ['manufacturer_id', 'issuing_authority_id', 'test_laboratory_id'],
  quotations: ['manufacturer_id', 'issuing_authority_id', 'test_laboratory_id'],
  consultingAgreements: ['manufacturer_id', 'issuing_authority_id', 'test_laboratory_id'],
  // TODO.adoption/09 — the payment records: the two parties of the
  // invoice pair both see (and upload evidence to) the record; the hub's
  // platform roles (not org-bound) see the whole store. Never public.
  paymentRecords: ['payer_id', 'payee_id'],
}

/** The instrument catalog stores (shared reference data on read;
 *  org-gated on write). */
export const CATALOG_STORES = new Set([
  'measuringInstrumentModelFamilies',
  'measuringInstrumentModelGroups',
  'measuringInstrumentModels',
  'measuringInstrumentSamples',
])

/** The org a row is indexed under (the first declared org field's
 *  value; null when the entity declares none — shared reference data). */
export function orgIdOf(store: string, data: unknown): string | null {
  const fields = ORG_FIELDS[store] ?? []
  const rec = data as Record<string, unknown>
  for (const f of fields) {
    if (typeof rec[f] === 'string' && rec[f]) return rec[f] as string
  }
  return null
}

// Role model per TODO.new-paradigm/01: applicant | ia_officer | tl_operator |
// cs_admin, plus the pre-existing admin/viewer accounts. org_id links the user
// to their organization record in the browser-side entity graph:
//   applicant  → manufacturer id (sample data: mfr-acme, the ACME fictional manufacturer)
//   ia_officer → issuing-authority oiml_code (EX1; XX1 = the pre-signature
//                demo IA of the task-44 participant registry — its Declaration
//                is unsigned, so the PD-08 cl. 5 issuance gate blocks it)
//   tl_operator → test-laboratory oiml_id (21 = the example TL)
//   mc_member / rc_member / executive_secretary → the OIML-CS organ roles of
//                TODO.roadmap/44 (approval pipeline + participant registry)
//   cs_admin/admin/viewer → null (no org)
export const DEMO_ACCOUNTS = [
  { email: 'admin@oiml.org', name: 'OIML Admin', role: 'admin', orgId: null as string | null },
  // TODO.register/02 — the ACME applicant also holds its org's org_admin
  // (the OP-side manufacturer-org role, simulated on the demo cast until
  // the identity wave lands it): the register's legacy-row claim act is
  // the org administrator's. `roles` is the optional full role set (the
  // users.roles column; absent = the primary role only).
  { email: 'applicant@oiml.org', name: 'ACME Applicant', role: 'applicant', orgId: 'mfr-acme' as string | null, roles: ['applicant', 'org_admin'] },
  { email: 'ia@oiml.org', name: 'IA Officer', role: 'ia_officer', orgId: 'EX1' as string | null },
  { email: 'ia2@oiml.org', name: 'IA Officer (XX1)', role: 'ia_officer', orgId: 'XX1' as string | null },
  { email: 'tl@oiml.org', name: 'TL Operator', role: 'tl_operator', orgId: '21' as string | null },
  // The test operators hold their OWN accounts (the demonstration cast,
  // docs/demo-personas.md): every run, evidence sign-off and report
  // attributes to a person, never to a shared laboratory login.
  { email: 'petra.horvat@etl.example.org', name: 'Ms. Petra Horvat', role: 'tl_operator', orgId: '21' as string | null },
  { email: 'martin.berger@etl.example.org', name: 'Mr. Martin Berger', role: 'tl_operator', orgId: '21' as string | null },
  { email: 'biml@oiml.org', name: 'BIML Officer', role: 'biml_officer', orgId: null as string | null },
  { email: 'cs@oiml.org', name: 'CS Administrator', role: 'cs_admin', orgId: null as string | null },
  { email: 'mc@oiml.org', name: 'MC Member', role: 'mc_member', orgId: null as string | null },
  { email: 'rc@oiml.org', name: 'RC Member', role: 'rc_member', orgId: null as string | null },
  { email: 'secretariat@oiml.org', name: 'Executive Secretary', role: 'executive_secretary', orgId: null as string | null },
  // TODO.adoption/11 — the Utilizer's staff member (scheme_participant):
  // declares Additional National Requirements for their country on the ANR
  // registry console; the declaration records the participant it acts for
  // (the CS registry's approval is the moderation gate).
  // TODO.adoption/10 — the ORG BINDING (ut-nmi-nl, the seeded NL Utilizer)
  // is the account's link into the participants register: the register's
  // participant depth resolves from it (the role alone never upgrades a
  // viewer — the org-registry's bounds keep the link assignable).
  { email: 'utilizer@oiml.org', name: 'Utilizer Officer (NL)', role: 'scheme_participant', orgId: 'ut-nmi-nl' as string | null },
  { email: 'viewer@oiml.org', name: 'Viewer', role: 'viewer', orgId: null as string | null },
  { email: 'developer@ribose.com', name: 'Ribose Developer', role: 'admin', orgId: null as string | null },
]

export const DEMO_PASSWORD = 'demo2026'

/** The store's honest unavailable answer (the 2026-09-01 lesson — a
 *  hung store write must answer in seconds, never spin the caller
 *  forever): a bounded WRITE's confirmation did not arrive within its
 *  budget. The route surface maps it to a 503 naming the store's
 *  TEMPORARY unavailability + the retryability.
 *
 *  The timed-out write may STILL land — the store accepted the
 *  statement and it was the confirmation path that hung, so the error
 *  never claims the write was lost. `retrySafe` names the statement's
 *  own idempotency posture: true (an upsert, a keyed UPDATE/DELETE, an
 *  IF NOT EXISTS heal) — a retry converges; false (a plain INSERT) —
 *  reconcile before retrying. The reads are NOT bounded by this
 *  discipline (the read-path latency story is read replication); only
 *  write/batch/DDL statements throw this. */
export class StoreUnavailable extends Error {
  constructor(
    /** The write's label — the verb + the target (e.g.
     *  'UPDATE sessions', 'batch (6 statements)'); never row data. */
    readonly operation: string,
    /** The confirmation budget the write exceeded, in ms. */
    readonly budgetMs: number,
    /** The statement's idempotency posture (the class note). */
    readonly retrySafe: boolean,
  ) {
    super(
      `the store write did not confirm within ${budgetMs} ms (${operation}) — the store is briefly unavailable; `
      + `the write may have landed — retry is safe for idempotent operations${retrySafe ? ' (this one is)' : ''}`,
    )
    this.name = 'StoreUnavailable'
  }
}

/** The async store contract the routes consume. Every method mirrors a
 *  sync counterpart in store.ts / entities.ts — same SQL, same
 *  semantics, awaited. */
export interface ServerStore {
  // ── users / sessions (schema.sql's auth half) ──
  seedDemoAccounts(): Promise<void>
  authenticateDemo(email: string, password: string): Promise<AuthUserPayload | null>
  /** TODO.identity/06: the sign-in context (the account console's
   *  sessions section): the user agent + the client IP, stamped at
   *  creation (server/auth/client-info.ts). TODO.identity-sso/02+03:
   *  `amr` records the sign-in's provenance (the RFC 8176 list the ID
   *  token later carries); absent = no OP-side credential event. */
  createSession(
    userId: string,
    opts?: { idTokenHint?: string | null; userAgent?: string | null; ip?: string | null; amr?: string[] | null },
  ): Promise<string>
  /** Stamp the account's last sign-in (TODO.identity/07 — the registry's
   *  last-sign-in column). The OP's own sign-in paths call this on a
   *  completed sign-in; the demo/OAuth paths bump it inline already. */
  touchLastLogin(userId: string): Promise<void>
  getSessionUser(token: string): Promise<AuthUserPayload | null>
  deleteSession(token: string): Promise<void>
  cleanExpiredSessions(): Promise<void>
  listDemoAccounts(): Promise<Array<{ email: string; name: string; role: string }>>

  // ── identity federation (TODO.federation/10) ──
  findUserByEmail(email: string): Promise<AuthUserPayload | null>
  /** The account by its id (TODO.identity/01 — the OP's token endpoint
   *  resolves the code's user_id). */
  getUserById(id: string): Promise<AuthUserPayload | null>
  findUserByProvider(provider: string, providerAccountId: string): Promise<AuthUserPayload | null>
  /** Provision a NEW account from a validated SSO sign-in (the claim
   *  mapping's mapped/default outcome). */
  provisionSsoUser(input: {
    email: string
    name: string
    provider: string
    providerAccountId: string
    role: string
    orgId: string | null
  }): Promise<AuthUserPayload>
  /** The approval decision's write: the account's role (+ org). */
  updateUserRoleOrg(userId: string, role: string, orgId: string | null): Promise<void>
  // ── the SSO sign-in state jar (TODO.identity/04) ──
  // ── federation peers (TODO.federation/04) ──
  // ── user administration (TODO.federation/12 — multi-user instances) ──
  listUsers(): Promise<UserAdminRow[]>
  createLocalUser(input: {
    email: string
    name: string
    role: string
    roles?: string[]
    orgId?: string | null
  }): Promise<UserAdminRow>
  setUserRoles(id: string, role: string, roles: string[]): Promise<boolean>
  setUserActive(id: string, active: boolean): Promise<boolean>

  // ── the OIDC Provider (TODO.identity/01) ──
  /** The client registry (admin-managed; the bootstrap seed upserts). */
  getOidcClient(clientId: string): Promise<OidcClient | null>
  listOidcClients(): Promise<OidcClient[]>
  upsertOidcClient(input: {
    clientId: string
    name: string
    secretHash: string | null
    redirectUris: string[]
    claimsPolicy: OidcClientClaimsPolicy | null
    createdBy?: string | null
  }): Promise<OidcClient>
  setOidcClientStatus(clientId: string, status: OidcClient['status']): Promise<OidcClient | null>
  /** The SSO-home launch metadata write (the registry API + the
   *  bootstrap seed): set the card, or null to take the client off the
   *  launcher. Answers null when the client does not exist. */
  setOidcClientLaunch(clientId: string, launch: OidcClientLaunch | null): Promise<OidcClient | null>
  /** The pending authorizations (consent round trip). */
  createOidcAuthorization(input: {
    id: string
    clientId: string
    redirectUri: string
    scope: string
    state: string
    nonce: string | null
    codeChallenge: string
    userId: string | null
    ttlMs: number
  }): Promise<OidcAuthorization>
  getOidcAuthorization(id: string): Promise<OidcAuthorization | null>
  /** The consent decision: binds the row's OWN account (userId must
   *  equal the row's stamped user) and flips the decision atomically —
   *  a pending row that already carries a decision, or belongs to a
   *  different account, answers null (the double-submit / cross-account
   *  case fails honestly). */
  decideOidcAuthorization(
    id: string,
    decision: { userId: string; decision: 'allow' | 'deny' },
  ): Promise<OidcAuthorization | null>
  /** The one-time codes. */
  createOidcCode(input: {
    code: string
    clientId: string
    redirectUri: string
    scope: string
    nonce: string | null
    codeChallenge: string
    userId: string
    /** TODO.identity/11: the session's stamped active-org context at the
     *  consent decision (NULL = the primary context). */
    contextOrg?: string | null
    /** TODO.identity-sso/02+03: the consenting session's amr provenance
     *  (stored as JSON; the token endpoint emits it as the ID token's
     *  amr). Absent = no provenance recorded. */
    amr?: string[] | null
    /** TODO.identity-sso (the wave-A tail): the consenting session's
     *  authentication instant (sessions.created_at, verbatim; absent =
     *  none recorded) — the token endpoint emits it as the ID token's
     *  auth_time. */
    authTime?: string | null
    ttlMs: number
  }): Promise<void>
  /** Atomically consume the code: answers the row exactly once (a
   *  replay/concurrent double-exchange loses the consumed_at race and
   *  gets null → invalid_grant). An EXPIRED code also answers null. */
  consumeOidcCode(code: string): Promise<OidcCode | null>
  /** The access tokens (userinfo). */
  createOidcAccessToken(input: {
    token: string
    userId: string
    clientId: string
    scope: string
    /** The granting code's context (userinfo answers the ID token's
     *  claims). */
    contextOrg?: string | null
    /** TODO.identity-sso/02+03: the authorizing authentication's amr —
     *  userinfo answers the same truth the ID token carried. */
    amr?: string[] | null
    ttlMs: number
  }): Promise<void>
  getOidcAccessToken(token: string): Promise<OidcAccessToken | null>
  /** The RFC 7009 access-token revocation: delete the row, client-bound —
   *  a client revokes only its OWN tokens (a token minted for another
   *  client answers false). An absent row answers false too (the endpoint
   *  masks both behind its 200). */
  deleteOidcAccessToken(token: string, clientId: string): Promise<boolean>
  /** The client-registry governance view's population read: the count of
   *  the client's LIVE access tokens (unexpired — the row's absence IS the
   *  revocation, so presence + liveness is standing). A count, never the
   *  rows: the governance console answers "how many sessions stand behind
   *  this client", never a token value. */
  countOidcAccessTokensForClient(clientId: string): Promise<number>
  /** The refresh tokens (migration 0025 — the SSO wave-C token surface).
   *  The mint: token is the opaque value the route generated, familyId the
   *  rotation lineage (a fresh id at the code exchange's first mint, the
   *  consumed row's familyId at every rotation). scope is the CANONICAL
   *  spelling of the granted set (a refresh never widens it). authTime is
   *  the ORIGINAL authentication instant — it never advances. */
  createOidcRefreshToken(input: {
    token: string
    userId: string
    clientId: string
    scope: string
    contextOrg?: string | null
    amr?: string[] | null
    authTime?: string | null
    familyId: string
    ttlMs: number
  }): Promise<OidcRefreshToken>
  /** The refresh exchange's consume: the UPDATE … WHERE consumed_at IS
   *  NULL flips exactly once (the oidc_codes doctrine). A presented
   *  CONSUMED token is the reuse signal — the whole family is deleted
   *  before the verdict answers. An expired live row is consumed anyway
   *  and answers 'invalid'. */
  consumeOidcRefreshToken(token: string): Promise<ConsumeOidcRefreshTokenResult>
  /** The RFC 7009 refresh-token revocation, client-bound: the presented
   *  token's WHOLE FAMILY goes (the grant lineage ends), never another
   *  client's rows. Answers false when the token never existed, was
   *  already gone, or belongs to another client (the endpoint masks all
   *  three behind its 200). */
  revokeOidcRefreshToken(token: string, clientId: string): Promise<boolean>
  /** The consent revocation's companion: every refresh row of the
   *  (account, client) pair goes — the "Revoke access" act ends the
   *  offline half with the remembered consent. Answers the count. */
  deleteOidcRefreshTokensForUserClient(userId: string, clientId: string): Promise<number>
  /** The client-registry governance view's population read: the count of
   *  the client's LIVE refresh tokens (unconsumed AND unexpired — a
   *  revoked family is DELETED wholesale, so a live row's presence is the
   *  grant's standing). A count, never the rows: the console answers "how
   *  many offline grants stand", never a token value. */
  countOidcRefreshTokensForClient(clientId: string): Promise<number>
  /** The key rotation history (public halves). */
  listOidcKeys(): Promise<OidcKeyRow[]>
  upsertOidcKey(input: { kid: string; publicJwk: string }): Promise<void>
  // ── the remembered consent grants (TODO.identity-features/12) ──
  /** The authorize endpoint's remembered-consent read: the account's
   *  LIVE grant for this client whose scope set COVERS the requested set
   *  (the consentGrantCovers math over the live rows), or null — the
   *  consent page shows. Both scope spellings normalize before the math. */
  getConsentGrant(userId: string, clientId: string, scope: string): Promise<OidcConsentGrant | null>
  /** The consent decision's remember (the allow): the upsert per
   *  (user, client, scope) — a live triple's row refreshes its stamp (the
   *  re-affirmed consent); a REVOKED triple's re-allow lands a FRESH live
   *  row (the partial unique index keeps the revoked rows out of the
   *  collision, so the history survives). The scope cell stores the
   *  canonical spelling (normalizeOidcScopeSet). Answers the live row. */
  recordConsentGrant(input: { userId: string; clientId: string; scope: string }): Promise<OidcConsentGrant>
  /** The account console's "apps they can access": the account's LIVE
   *  grants, newest first (the revoked rows never list — the audit chain
   *  carries them). */
  listConsentGrants(userId: string): Promise<OidcConsentGrant[]>
  /** The console's "Revoke access": flips revoked_at on the account's OWN
   *  live row — a second revoke or another account's row answers false
   *  (the PAT guard's posture). The row STAYS. */
  revokeConsentGrant(id: string, userId: string): Promise<boolean>
  /** The client-registry governance view's per-client read: EVERY grant
   *  row the client holds — live AND revoked (the account console's
   *  listConsentGrants hides the revoked half; the governance view shows
   *  the history the audit chain would otherwise carry alone), newest
   *  first. Read-only: the acts stay on the account console and the
   *  dashboard's revoke routes. */
  listOidcConsentGrantsForClient(clientId: string): Promise<OidcConsentGrant[]>

  // ── the upstream providers (TODO.identity/08) ──
  /** The upstream registry (admin-managed; OP_UPSTREAM_SEED bootstraps).
   *  Secrets are NEVER in these rows — clientSecretRef is an env name. */
  listIdentityProviders(): Promise<IdentityProvider[]>
  getIdentityProvider(id: string): Promise<IdentityProvider | null>
  upsertIdentityProvider(input: {
    id: string
    kind: IdentityProvider['kind']
    displayName: string
    brandMark?: string | null
    issuer?: string | null
    clientId: string
    clientSecretRef?: string | null
    scopes?: string | null
    enabled?: boolean
    createdBy?: string | null
  }): Promise<IdentityProvider>
  setIdentityProviderEnabled(id: string, enabled: boolean): Promise<IdentityProvider | null>
  deleteIdentityProvider(id: string): Promise<boolean>

  // ── the linked identities (TODO.identity/02's shape, 08's flows) ──
  /** The account's linked upstream identities (the account surface). */
  listIdentityLinks(userId: string): Promise<IdentityLink[]>
  /** The bulk list-endpoint variant (identity's TODO.restructure/06):
   *  the same rows as listIdentityLinks for every id, ONE read for the
   *  whole set — the per-row loop's O(rows) store-call disease's
   *  kernel-side answer. Every requested id answers (an unknown id
   *  honestly as the empty array, the per-id read's own posture); an
   *  empty array answers an empty map. */
  listIdentityLinksBulk(userIds: string[]): Promise<Map<string, IdentityLink[]>>
  /** THE match rule's read: resolve (provider, providerAccountId) → the
   *  link (and thereby the account). NEVER match by email alone. */
  findIdentityLink(provider: string, providerAccountId: string): Promise<IdentityLink | null>
  /** Create the link; answers NULL when (provider, providerAccountId)
   *  is already linked (to any account — the UNIQUE constraint), the
   *  honest conflict the route maps to a refusal. */
  createIdentityLink(input: {
    userId: string
    provider: string
    providerAccountId: string
    linkedBy?: string | null
  }): Promise<IdentityLink | null>
  /** Remove the account's link for a provider (the unlink action). */
  deleteIdentityLink(userId: string, provider: string): Promise<boolean>

  // ── the OP's account model (TODO.identity/02) ──
  /** Create an OP password account (provider 'password', email
   *  normalized lowercase). Answers null when the email is taken (the
   *  invite route's 409; the UNIQUE constraint is the backstop). */
  createOpAccount(input: {
    email: string
    name: string
    role: string
    createdBy?: string | null
  }): Promise<UserAdminRow | null>
  /** The password sign-in's lookup: the credential + the account's
   *  active flag by email (normalized). Null = no such credential — the
   *  route still runs one full-cost verify (the timing-shape rule,
   *  auth/passwords.ts). The hash never leaves the server.
   *  TODO.identity-features/01: the address resolves by ANY of the
   *  account's VERIFIED addresses — the primary (users.email) or a
   *  proven account_emails row. An unverified additional never resolves
   *  (the mailbox is unproven), and a primary owner always wins over an
   *  additional row (the deterministic rule — a stray duplicate shadows,
   *  never ambiguates). */
  getPasswordLogin(email: string): Promise<{ userId: string; hash: string; active: boolean } | null>
  /** Set/replace the account's password credential (enrollment
   *  completion, the account page's change). */
  setPasswordHash(userId: string, hash: string, setBy?: string | null): Promise<void>
  /** The sign-in methods the account holds (the account page's
   *  password-set state + the admin list's posture). TODO.identity-sso/02:
   *  `passkeys` counts the registered passkeys — a passkey is a PRIMARY
   *  sign-in method (passwordless), so the at-least-one-way-in guard
   *  reads it alongside the password and the links. */
  countSignInMethods(userId: string): Promise<{ password: boolean; links: number; passkeys: number }>
  /** The bulk list-endpoint variant (identity's TODO.restructure/06):
   *  the same counts for every id, one grouped read per underlying
   *  table (the D1 leg rides them in ONE batch) instead of three reads
   *  per account. Every requested id answers; an absent row reads as
   *  zero (the per-id read's posture); an empty array answers an empty
   *  map. */
  countSignInMethodsBulk(userIds: string[]): Promise<Map<string, { password: boolean; links: number; passkeys: number }>>
  /** The enrollment links (invite-only). The token arrives from the
   *  caller (auth/op/accounts.ts's mint); expires_at = now + ttlMs. */
  createEnrollmentToken(input: {
    token: string
    userId: string
    createdBy?: string | null
    ttlMs: number
  }): Promise<EnrollmentToken>
  getEnrollmentToken(token: string): Promise<EnrollmentToken | null>
  /** Complete the enrollment: consume the token ATOMICALLY (a presented
   *  link works exactly once, expired or not), then set the password.
   *  The tagged result lets the route answer honestly. */
  completeEnrollment(token: string, passwordHash: string, setBy?: string | null): Promise<CompleteEnrollmentResult>
  /** The account's live sessions (expired ones excluded), `current`
   *  computed against the presenting token — never exposed. */
  listUserSessions(userId: string, currentToken?: string): Promise<SessionView[]>
  /** Revoke ONE of the account's own sessions (the user_id clause makes
   *  another account's session id a no-op). */
  deleteSessionById(userId: string, sessionId: string): Promise<boolean>
  /** The aggregate "who is signed in NOW" read across accounts
   *  (TODO.identity-sso/01's live-sessions surface): every live session
   *  (expired excluded), `current` computed against the presenting
   *  administrator's token. The account name/email join stays with the
   *  caller (listUsers) — this read carries the session rows only. */
  listOpLiveSessions(currentToken?: string): Promise<OpLiveSession[]>
  /** The administrator's revoke-ALL of an account's sessions (the
   *  dashboard's light act): EVERY session deleted, no kept exception
   *  (the self-service's deleteOtherSessions keeps the presenting one;
   *  this keeps none). Answers the revoked count (the audit event's
   *  metadata). */
  deleteAllUserSessions(userId: string): Promise<number>

  // ── the central user registry (TODO.identity/03) ──
  /** The account's per-client role assignments (the registry console's
   *  per-client view), one row per client that carries an override. */
  listOpClientRoles(userId: string): Promise<OpClientRoleAssignment[]>
  /** EVERY per-client assignment across accounts (TODO.identity-sso/01's
   *  live access review reads the privileged per-client grants without a
   *  per-account loop). */
  listAllOpClientRoles(): Promise<OpClientRoleAssignment[]>
  /** The assignment for ONE client: the roles the ID token issued to
   *  that client carries (pre-allowlist). NULL = no row — the account's
   *  OP-side role set is that client's default (the pre-03 behavior).
   *  An EMPTY array is the explicit "no roles on this client". */
  getOpClientRoles(userId: string, clientId: string): Promise<string[] | null>
  /** Upsert the per-client assignment (roles may be empty — the explicit
   *  none). The route validates the set against the client's policy. */
  setOpClientRoles(userId: string, clientId: string, roles: string[], assignedBy: string | null): Promise<void>
  /** Clear the per-client assignment (the account default is restored). */
  deleteOpClientRoles(userId: string, clientId: string): Promise<boolean>
  /** The deactivation's revocation half: delete EVERY live session, every
   *  issued OIDC access token, every refresh token (consumed or not — the
   *  reuse detector has no more verdicts to give), every unconsumed
   *  authorization code and every pending authorization of the account.
   *  Answers the counts (the audit event's metadata). The user row STAYS
   *  (the history). */
  revokeOpUserCredentials(userId: string): Promise<{ sessions: number; accessTokens: number; refreshTokens: number; codes: number; authorizations: number }>
  /** The offboarding runbook's DELETE path (the erasure): every credential,
   *  token, link and per-client assignment removed, the user row anonymized
   *  in place (provider 'erased' — it drops out of every account surface;
   *  the tombstone keeps the audit chain's entity_id resolvable). Answers
   *  the counts, or null when the account does not exist. */
  eraseOpAccount(userId: string): Promise<OpAccountErasure | null>
  /** Edit the account row's name/email (the registry's edit act).
   *  Answers false when the account does not exist; the email UNIQUE
   *  conflict surfaces as the 'unique' error (the route's 409). */
  updateOpAccount(id: string, input: { name?: string; email?: string }): Promise<boolean>
  /** The last OP-side sign-in per account, read FROM THE AUDIT CHAIN:
   *  the latest auditEvents row whose action is a sign-in
   *  ('account.sign_in' — the password login; 'upstream_sign_in' — a
   *  linked-provider sign-in) per entity_id. Answers userId → ISO
   *  timestamp; accounts that never signed in are absent. The typed
   *  read: json_extract legs (json_valid-guarded, the index's exact
   *  spelling) against idx_entities_store_action (migration 0023) — an
   *  index walk over the sign-in slice, never a data-LIKE scan of the
   *  journal. The action match stays exact (the retired LIKE's closing
   *  quote made it so too) and becomes spelling-proof: the legs parse
   *  the JSON. */
  lastAccountSignIns(): Promise<Record<string, string>>

  // ── the account console (TODO.identity/06) ──
  /** The profile edit's write (the display name). Answers false when the
   *  account is gone. */
  updateUserName(userId: string, name: string): Promise<boolean>
  /** The avatar write (users.avatar_url: the upload's serving URL, the
   *  linked provider's picture, NULL for the initials). Answers false when
   *  the account is gone. */
  setUserAvatar(userId: string, avatarUrl: string | null): Promise<boolean>
  /** Remove the account's password credential (the sign-in METHODS
   *  section's remove action; the route holds the at-least-one-method
   *  guard). Answers false when no credential was set. */
  deletePasswordHash(userId: string): Promise<boolean>
  /** Revoke every session of the account EXCEPT the presenting one (the
   *  "sign out everywhere else" action + the password change's
   *  best-practice revocation). Answers the revoked count. */
  deleteOtherSessions(userId: string, keepToken: string): Promise<number>
  /** Mint the verify-an-address ceremony's token. The void rule keeps
   *  one live link per ceremony target: a 'change' request VOIDS the
   *  account's earlier pending 'change' rows (only the newest change
   *  link works — the pre-01 doctrine); an 'add' request voids the
   *  account's earlier pending 'add' rows FOR THE SAME address (other
   *  addresses' links stand); a 'verify' request voids the account's
   *  earlier pending 'verify' rows (the target is the CURRENT primary —
   *  one per account, the change doctrine's scoping; cross-kind links
   *  never touch each other). deliveredBy is stamped at request time and
   *  decides whether completion may verify the address. kind defaults
   *  'change'. */
  createEmailChangeToken(input: {
    token: string
    userId: string
    newEmail: string
    deliveredBy: 'mailer' | 'shown'
    kind?: 'change' | 'add' | 'verify'
    ttlMs: number
  }): Promise<EmailChangeToken>
  getEmailChangeToken(token: string): Promise<EmailChangeToken | null>
  /** The account's pending change (the newest unconsumed, unexpired row),
   *  so the console can show it. 'verify' rows have NO pending read: the
   *  waiting state IS users.email_verified_at NULL (the 'add' doctrine —
   *  the account_emails rows carry their own). */
  getPendingEmailChange(userId: string): Promise<EmailChangeToken | null>
  /** Complete the ceremony: consume the token ATOMICALLY (a presented
   *  link works exactly once, expired or not), judge the expiry, then
   *  act on the kind: 'change' re-checks the address's uniqueness across
   *  BOTH address tables (a conflict burns the token honestly) and moves
   *  the account's primary (users.email); 'add' stamps the
   *  account_emails row's verified_at (a row removed between request and
   *  completion answers 'unknown'); 'verify' (the 0.2.4 kind, the
   *  resend-verification act for the CURRENT primary) stamps
   *  users.email_verified_at when the token's new_email IS STILL the
   *  account's primary — a primary moved meanwhile (a completed 'change',
   *  an admin re-address, the erasure) burns the link as 'unknown', and
   *  'conflict' never applies (no address changes hands). verified = the
   *  token traveled by mailer (mailbox proven); a shown link never
   *  verifies. The answer carries { userId, newEmail, verified } for
   *  every kind, so the consumer's completion route audits a proven
   *  'verify' exactly as it audits an 'add' (its account.email_verified). */
  completeEmailChange(token: string): Promise<CompleteEmailChangeResult>

  // ── multiple emails per account (TODO.identity-features/01) ──
  /** The account's addresses, the PRIMARY first (the users row's email +
   *  its verification stamp), then the additional account_emails rows
   *  (oldest first). The console's emails section and the security-mail
   *  fan-out read this. */
  listAccountEmails(userId: string): Promise<AccountEmail[]>
  /** Resolve the account by ANY of its addresses (normalized): the
   *  primary always names it; an additional ONLY when verified (an
   *  unproven address never names the account — not to sign-in, not to
   *  recovery). The primary owner wins over an additional row (the
   *  deterministic rule). */
  findUserByAnyEmail(email: string): Promise<AuthUserPayload | null>
  /** Add an ADDITIONAL address (normalized lowercase; the row lands
   *  UNVERIFIED — the verify-an-address ceremony's kind 'add' token
   *  proves the mailbox). The tagged result names the outcome; the
   *  unique index + the cross-table check make an address name at most
   *  one account. */
  addAccountEmail(userId: string, email: string, addedBy?: string | null): Promise<AddAccountEmailResult>
  /** The verification ceremony's stamp on the account's OWN additional
   *  row (the kind 'add' completion): verified_at flips, once (the
   *  guarded update). Answers false when no such row stands. */
  markAccountEmailVerified(userId: string, email: string): Promise<boolean>
  /** Promote a VERIFIED additional to primary: the promoted address
   *  becomes users.email (its verification stamp travels, so the claims
   *  stay verified), and the previous primary takes the row's place in
   *  account_emails with ITS stamp (it stays a verified additional —
   *  sign-in by it keeps working). 'unknown' = no such additional row;
   *  'unverified' = the row stands unproven (a primary is always
   *  proven). */
  setPrimaryAccountEmail(userId: string, email: string): Promise<'ok' | 'unknown' | 'unverified'>
  /** Remove an ADDITIONAL address. 'primary' = the address IS the
   *  account's primary (promote another first — the primary is never
   *  removed from under the holder); 'unknown' = no such additional
   *  row. */
  removeAccountEmail(userId: string, email: string): Promise<'ok' | 'primary' | 'unknown'>

  // ── strong authentication: the factor registry (TODO.identity-sso/02 + /03) ──
  /** The one-time WebAuthn ceremony challenge. The challenge value IS the
   *  key (the clientDataJSON binds it); expires_at = now + ttlMs. */
  createWebauthnChallenge(input: {
    challenge: string
    userId: string | null
    kind: WebauthnChallenge['kind']
    ttlMs: number
  }): Promise<void>
  /** Atomically consume the challenge: answers the row exactly once (a
   *  replay loses the consumed_at race); an EXPIRED row is consumed too
   *  and answers null — never a second chance. */
  consumeWebauthnChallenge(challenge: string): Promise<WebauthnChallenge | null>
  /** Register the passkey. Answers NULL when the credential id is already
   *  registered (to any account — the PRIMARY KEY is the race backstop;
   *  the route maps it to the honest conflict). */
  createWebauthnCredential(input: {
    credentialId: string
    userId: string
    name: string
    publicKeyCose: string
    signCount: number
    aaguid: string | null
    transports: string[]
    ip?: string | null
  }): Promise<WebauthnCredential | null>
  /** The account's passkeys (the console's factors section), oldest first. */
  listWebauthnCredentials(userId: string): Promise<WebauthnCredential[]>
  /** The assertion's lookup by the authenticator's credential id. */
  getWebauthnCredential(credentialId: string): Promise<WebauthnCredential | null>
  /** Revoke the account's own passkey (the user_id clause makes another
   *  account's credential id a no-op). */
  deleteWebauthnCredential(userId: string, credentialId: string): Promise<boolean>
  /** The signature counter's advance, GUARDED (the clone rule): the
   *  UPDATE lands only when the presented count legitimately follows the
   *  stored one (both zero = the authenticator never counts; otherwise
   *  strictly greater). 'regressed' is the clone signal — the route
   *  fails the assertion and audits. A landed advance stamps
   *  last_used_at/last_ip. */
  advanceWebauthnCounter(credentialId: string, newCount: number, opts?: { ip?: string | null }): Promise<AdvanceCounterResult>

  /** Start the TOTP enrollment (the PENDING row — verified_at NULL; it
   *  activates at markTotpSecretVerified, never before). */
  createTotpSecret(input: { id: string; userId: string; name: string; secret: string }): Promise<TotpSecret>
  /** The account's TOTP rows, pending ones included (the route filters;
   *  the console lists the verified only). */
  listTotpSecrets(userId: string): Promise<TotpSecret[]>
  getTotpSecret(id: string): Promise<TotpSecret | null>
  /** Activate the enrollment: verified_at (+ the final name) set where
   *  the row is still pending and belongs to the account. */
  markTotpSecretVerified(id: string, userId: string, name: string): Promise<boolean>
  /** The enrollment verify's throttle: fail_count++ + last_failure_at,
   *  answering the fresh count (the route's backoff + cap read it). */
  recordTotpEnrollFailure(id: string, userId: string): Promise<number>
  /** A verified secret's sign-in use: last_used_at/last_ip stamped. */
  markTotpSecretUsed(id: string, opts?: { ip?: string | null }): Promise<void>
  /** Revoke the account's own TOTP factor (pending or verified). */
  deleteTotpSecret(userId: string, id: string): Promise<boolean>

  /** Replace the account's recovery-code set WHOLE (the regenerate: the
   *  old batch is deleted, the new hashes land, one transaction/batch).
   *  The hashes are SHA-256 of the normalized codes — the plaintext is
   *  shown once and never stored. */
  replaceRecoveryCodes(userId: string, batch: string, codeHashes: string[]): Promise<void>
  /** The console's honest state (counts + the batch's age — never a hash). */
  recoveryCodeState(userId: string): Promise<RecoveryCodeState>
  /** The one-time use: consumed_at flips atomically WHERE the hash matches
   *  an unconsumed row of the account — true exactly once per code. */
  consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean>

  /** The pending second-factor sign-in row (the password verified; the
   *  session waits on the factor). amr is the methods proven so far. */
  createMfaPending(input: { token: string; userId: string; amr: string[]; ttlMs: number }): Promise<void>
  /** The verify attempt's read (NOT consuming — failures keep it alive
   *  under the throttle ladder until the cap or the TTL). */
  getMfaPending(token: string): Promise<MfaPending | null>
  /** The completion: consumed ATOMICALLY (a concurrent completion loses
   *  the race and answers null); an EXPIRED row is consumed too, never
   *  redeemed later. */
  consumeMfaPending(token: string): Promise<MfaPending | null>
  /** The failure ladder: fail_count++ + last_failure_at, answering the
   *  fresh row (null when the token is gone). */
  recordMfaPendingFailure(token: string): Promise<MfaPending | null>

  // ── the personal access tokens (TODO.identity-features/08) ──
  /** The mint: one row per token. The plaintext NEVER crosses the seam —
   *  the caller hashes (SHA-256) and the row holds the hash + the
   *  display prefix. expiresAt is mandatory (the route enforces the
   *  1-year ceiling; the store trusts the route's arithmetic). */
  createPersonalAccessToken(input: {
    id: string
    userId: string
    name: string
    tokenHash: string
    tokenPrefix: string
    scopes: string[]
    orgContext: string | null
    expiresAt: string
  }): Promise<PersonalAccessToken>
  /** The console's own list (newest first) — metadata only, never the
   *  hash even (the list is a display surface). */
  listPersonalAccessTokens(userId: string): Promise<PersonalAccessToken[]>
  /** The org's token inventory (the org detail page's section): every
   *  token whose holder carries an org_memberships row for the org —
   *  ANY membership state (a disabled member's live token is exactly
   *  what the oversight surface hunts). Metadata only. */
  listOrgPersonalAccessTokens(orgId: string): Promise<PersonalAccessToken[]>
  getPersonalAccessToken(id: string): Promise<PersonalAccessToken | null>
  /** The exchange's lookup: by the presented token's SHA-256. */
  findPersonalAccessTokenByHash(tokenHash: string): Promise<PersonalAccessToken | null>
  /** The revoke act (the owner's console): flips revoked_at/revoked_by
   *  guarded on the LIVE row (a second revoke answers false; another
   *  account's row answers false). The row STAYS — the audit + the org
   *  inventory carry the history. */
  revokePersonalAccessToken(id: string, userId: string, revokedBy: string): Promise<boolean>
  /** The exchange path's throttled heartbeat: the caller decides the
   *  throttle from the row it already read; the store stamps. auditAt
   *  rides along when the heartbeat crossed the audit window; the
   *  expiry-soon mailer's one-shot mark lands through expiryNotifiedAt. */
  stampPersonalAccessTokenUse(
    id: string,
    stamps: { usedAt: string; auditAt?: string | null; expiryNotifiedAt?: string | null },
  ): Promise<void>

  // ── organization administration (TODO.identity/10) ──
  /** File a join request (the public "Request an account" page). */
  createOrgJoinRequest(input: {
    name: string
    email: string
    orgId: string | null
    orgNameText: string | null
    requestedRole: string
    note?: string | null
  }): Promise<OrgJoinRequest>
  getOrgJoinRequest(id: string): Promise<OrgJoinRequest | null>
  /** The queue reads. scope 'org' = one org's queue (orgId required);
   *  'unregistered' = BIML's new-organizations queue (org_id IS NULL);
   *  'all' = every request (BIML's oversight). Default: 'all'. */
  listOrgJoinRequests(filter?: {
    scope?: 'org' | 'unregistered' | 'all'
    orgId?: string
    status?: OrgJoinRequest['status']
  }): Promise<OrgJoinRequest[]>
  /** The decision — ATOMIC on 'pending': an already-decided row answers
   *  null (a double approve/refuse loses the race honestly). */
  decideOrgJoinRequest(
    id: string,
    decision: {
      status: 'approved' | 'refused'
      decidedBy: string
      refusalReason?: string | null
      invitedUserId?: string | null
    },
  ): Promise<OrgJoinRequest | null>
  /** A PENDING request from the same email exists (the duplicate guard —
   *  decided requests never block a fresh ask). */
  findPendingOrgJoinRequestByEmail(email: string): Promise<OrgJoinRequest | null>

  // ── the multi-organization membership model (TODO.identity/11) ──
  // The org_memberships table is the account × org × per-org role set
  // with the lifecycle state. THE DUAL-READ DOCTRINE: the users row's
  // org_id/roles columns stay the backward-compatible read (the PRIMARY
  // membership's mirror) until every consumer reads the memberships —
  // the store mirrors every legacy write into the primary membership
  // row, and resolveOrgContext falls back to the columns when no
  // membership row exists.
  /** The account's memberships, every state (the console's
   *  Organizations section, the admin's per-user page). */
  listOrgMemberships(userId: string): Promise<OrgMembership[]>
  /** One org's memberships (the per-org view), every state. */
  listOrgMembers(orgId: string): Promise<OrgMembership[]>
  /** EVERY membership across organizations, every state (the admin
   *  registry's org list groups it in memory — one read, never a
   *  per-org loop of listOrgMembers). Org- then creation-ordered, so a
   *  caller's group-by-org keeps listOrgMembers' per-org ordering. */
  listAllOrgMemberships(): Promise<OrgMembership[]>
  getOrgMembership(userId: string, orgId: string): Promise<OrgMembership | null>
  /** Create the membership — the org's admin inviting an EXISTING
   *  account (state 'invited': the holder accepts from the account
   *  console), or the join-request approval's grant (state 'active':
   *  both consents are on record). NULL on the (user, org) conflict —
   *  the honest "already a member". */
  createOrgMembership(input: {
    userId: string
    orgId: string
    roles: string[]
    state: OrgMembershipState
    invitedBy?: string | null
  }): Promise<OrgMembership | null>
  /** Replace the per-org role set. A PRIMARY membership's write mirrors
   *  into the users row's roles (and the section-gating primary role
   *  when it fell out of the set) — the dual-write keeps the legacy
   *  read identical. Answers false when no membership exists. */
  setOrgMembershipRoles(userId: string, orgId: string, roles: string[]): Promise<boolean>
  /** The lifecycle act: invited → active (the holder's accept, or the
   *  approval), active ⇄ disabled (the org's admin / the scheme
   *  operator). Stamps activated_at / disabled_at(+by); disabling also
   *  clears the account's sessions' active-org stamps pointing at the
   *  org (the context ends honestly). Answers null when no membership
   *  exists. */
  setOrgMembershipState(
    userId: string,
    orgId: string,
    state: OrgMembershipState,
    actor?: string | null,
  ): Promise<OrgMembership | null>
  /** Set the membership's data cone (TODO.identity-features/09): the
   *  CANONICAL column spelling (encodeOrgMemberCone's answer — NULL is
   *  the org-wide default) or NULL to clear. The input's validation is
   *  the ROUTE's (parse + re-encode; the store writes what it is given,
   *  the parser's fail-closed posture backstops a bad cell). Answers
   *  null when no membership exists. */
  setOrgMembershipCone(userId: string, orgId: string, cone: string | null): Promise<OrgMembership | null>
  /** Remove the row — the holder declining an invitation, and the
   *  erasure's cleanup. (The routes refuse the PRIMARY membership: the
   *  primary binding moves through the account's role/org assignment,
   *  never through a delete.) */
  deleteOrgMembership(userId: string, orgId: string): Promise<boolean>
  /** The session's stamped active-org context (NULL = the primary
   *  context; also NULL for an unknown/expired token). */
  getSessionActiveOrg(token: string): Promise<string | null>
  /** Stamp the session's active-org context (the account console's
   *  switcher; the route validates the membership first). NULL clears
   *  to the primary context. */
  setSessionActiveOrg(token: string, orgId: string | null): Promise<boolean>

  // ── the organization registry (TODO.identity-features/05) ──
  // The identity service's OWN org registry (the org_registry table):
  // the first-class organizations the membership graph above references
  // by id (the slug; the participant orgs' OIML codes). The lifecycle
  // acts are the routes' — the disable CASCADE (every active membership
  // of the org disabling honestly) is the route's loop over
  // setOrgMembershipState; the store keeps the rows.
  /** Every registry organization, every state, name-ordered. */
  listOrgRegistryOrgs(): Promise<OrgRegistryOrg[]>
  getOrgRegistryOrg(id: string): Promise<OrgRegistryOrg | null>
  /** Add the organization. NULL on the id conflict (the slug is taken —
   *  the route's honest 409). */
  createOrgRegistryOrg(input: {
    id: string
    name: string
    shortName?: string | null
    kind?: string | null
    country?: string | null
    contacts?: OrgRegistryContact[]
    participantRef?: string | null
    designatedBy?: string | null
    proposedBy?: string | null
    csStatus?: string | null
    createdBy?: string | null
  }): Promise<OrgRegistryOrg | null>
  /** Edit the display data (the id is the stable slug — never editable);
   *  stamps updated_at/by. NULL when the registry does not carry the
   *  org. */
  updateOrgRegistryOrg(
    id: string,
    patch: {
      name?: string
      shortName?: string | null
      kind?: string | null
      country?: string | null
      contacts?: OrgRegistryContact[]
      participantRef?: string | null
      designatedBy?: string | null
      proposedBy?: string | null
      csStatus?: string | null
    },
    actor?: string | null,
  ): Promise<OrgRegistryOrg | null>
  /** The lifecycle act: disable (the honest removal — stamps
   *  disabled_at/by) / re-enable (the disable stamps clear; the org's
   *  memberships stay as they are — re-activation is the per-membership
   *  deliberate act, never an automatic one). NULL when the registry
   *  does not carry the org. */
  setOrgRegistryOrgState(id: string, state: OrgRegistryState, actor?: string | null): Promise<OrgRegistryOrg | null>
  /** The erasure-adjacent hard delete — the ROUTE refuses it while any
   *  membership or join request references the org (the honest 409:
   *  disable it instead); this removes the row only. */
  deleteOrgRegistryOrg(id: string): Promise<boolean>

  // ── the register's holder-org attribution (TODO.register/02) ──
  // The certificate_holder_orgs / certificate_holder_claims tables (the
  // 0015 migration): the hub's record of WHICH OP org a registered
  // certificate belongs to, and the legacy-row claim act's state machine.
  // ── the instrument register (TODO.register/03) ──
  // The platform-side serial register (the instrument_registrations
  // table): one row per registered instrument under a type certificate.
  // The scope check + the cones are the ROUTE's (browser/server/routes/
  // registrations.ts); the store keeps the rows. Every row the store
  // returns is a registration that STOOD — the refused declaration never
  // lands (the route answers it with the reason).
  // ── the workflow entity store + change journal ──
  /** The store's rows, in the seam's declared order: (org_id, rowid) —
   *  the read's observable order since migration 0001 (NULL org ids
   *  first, then by org id, then by insertion). Both backends spell the
   *  ORDER BY explicitly — a list read's order is a consumer-visible
   *  contract, never the planner's pick (the 0.2.3 pin, after
   *  migration 0023's expression index flipped the unnamed walk).
   *  `options.orgId` narrows the candidate set in SQL (EntityListOptions
   *  — the portal-load audit's R3-fix3); the narrowed answer is the same
   *  order's restriction to the candidates. */
  listEntities(store: string, options?: EntityListOptions): Promise<EntityRow[]>
  getEntity(store: string, id: string): Promise<EntityRow | undefined>
  putEntity(store: string, id: string, orgId: string | null, data: string): Promise<void>
  deleteEntity(store: string, id: string): Promise<boolean>
  // ── the platform event store (TODO.notify/01) ──
  // ── the notification subscriptions store (TODO.notify/02) ──
  // ── the inbox state (TODO.notify/03) ──
  // ── the email channel's delivery store (TODO.notify/04) ──
  // ── provisioning / dev support ──
}

let current: ServerStore | null = null

/** The composition roots install the store exactly once per process /
 *  per binding. The stores are stateless facades over a connection or a
 *  binding, so a per-isolate memoized install is safe across concurrent
 *  requests. */
export function installStore(store: ServerStore): void {
  current = store
}

/** The installed store. Throws honestly when no composition root ran —
 *  a route hit without an installed store is a wiring bug, never a
 *  silent fallback. While a SERVER_TIMING-measured request is in
 *  flight, the store resolves through the counting proxy
 *  (server/store-timing.ts — the store phase of the Server-Timing
 *  header); at every other moment the installed store itself passes
 *  through, untouched. */
export function getStore(): ServerStore {
  if (!current) {
    throw new Error(
      'the server store is not installed — the composition root installs it '
      + '(server/index.ts installs SQLite on node; server/cloudflare.ts installs D1 on the Worker)',
    )
  }
  return timedStore(current)
}
