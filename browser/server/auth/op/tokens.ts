// ═══════════════════════════════════════════════════════════════════
// The personal access tokens (TODO.identity-features/08) — the developer
// surface's OP half. The GitHub fine-grained pattern mapped to the
// estate:
//
//   - a PAT is minted by an ACCOUNT from the console and NEVER rides a
//     request directly: it exchanges at /op/token (the RFC 8693 grant
//     PAT_EXCHANGE_GRANT, subject_token_type PAT_TOKEN_TYPE) for a
//     short-lived OP JWT — every relying party keeps validating the ONE
//     token shape (the OP's JWT against the JWKS, the device cone's
//     precedent);
//   - the plaintext shows ONCE at mint (the GitHub doctrine); the store
//     holds only the SHA-256 (the kernel's personal_access_tokens row);
//   - expiration is MANDATORY (PAT_DEFAULT_EXPIRY_DAYS default,
//     PAT_MAX_EXPIRY_DAYS the ceiling — the fine-grained lesson);
//   - a token only ever NARROWS the account: its scopes are a subset of
//     the holder's standing, validated at mint (the console route) and
//     RE-JUDGED at exchange against the live account (a role narrowing,
//     a disabled membership, a deactivated account — the exchange
//     answers the current truth, never the mint's memory);
//   - a PAT is never an ORG credential: org-level automation speaks the
//     org's registered clients (the device/machine cone), never a
//     person's token;
//   - the audit chain carries mint / exchange-use (the THROTTLED
//     heartbeat — never a per-request write) / revoke; the mailer
//     notifies on mint and on expiry-soon (the lazy sweep: the notice
//     rides the exchange path and the console read — no scheduler on
//     this deployment shape).
//
// THE SCOPE MODEL (the kernel's grammar, @oimlsmart/platform-server/
// store): '<service>:<action-class>' — the service is a REGISTERED,
// ACTIVE, application-class client id (the estate's service registry IS
// the OP's client registry; a device-class client is the machine cone's,
// never a PAT's); the action class is ordinal (admin ⊃ write ⊃ read).
// The account-side bound (resolvePatScopesForAccount):
//
//   read   — the account can ENTER the service with roles (the token
//            endpoint's own rule: the per-client assignment through the
//            client's policy allowlist, under the org context);
//   write  — and the effective roles hold at least one ACTION
//            PERMISSION (the deployment's effective RBAC map — a
//            read-only account (viewer) mints read scopes only);
//   admin  — and the roles hold an administration-class permission
//            (PAT_ADMIN_PERMISSIONS: the instance/org administration
//            family).
//
// The OP's bound reads the OP's OWN effective RBAC map — the honest
// approximation; the relying party's own map enforces at use (the
// exchanged token's scope claim is a claim, never a grant past the RP's
// gate — patScopeCovers is the RP's check).
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import {
  getStore,
  PAT_TOKEN_PREFIX,
  encodeOrgMemberCone,
  normalizePatScopes,
  patScopesWithin,
  type AuthUserPayload,
  type OrgContextResolution,
  type PatActionClass,
  type PatScope,
  type PersonalAccessToken,
  type ServerStore,
} from '@oimlsmart/platform-server/store'
import { permissionsForRoles, rolesCan, type ActionPermission } from '@oimlsmart/platform-server/vocab'
import { effectiveRbacMap } from '@oimlsmart/platform-server/rbac'
import { rolesForClient } from './claims'
import { deviceClassOf } from './device-clients'

// ── the wire constants ───────────────────────────────────────────────

/** The RFC 8693 grant the PAT speaks at /op/token. */
export const PAT_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
/** The subject_token_type naming a PAT (the estate's own URN). */
export const PAT_TOKEN_TYPE = 'urn:oimlsmart:params:oauth:token-type:pat'

/** The expiration bounds (the fine-grained doctrine): 90 days the
 *  default, one year the ceiling, never none. */
export const PAT_DEFAULT_EXPIRY_DAYS = 90
export const PAT_MAX_EXPIRY_DAYS = 366

/** The expiry-soon notice's window: a live, unrevoked token inside it
 *  mails the holder ONCE (the expiry_notified_at mark). */
export const PAT_EXPIRY_NOTICE_WINDOW_MS = 7 * 86_400_000

/** The exchange audit's heartbeat: the use stamps + the audit event fire
 *  at most once per window per token (never a per-request write). */
export const PAT_EXCHANGE_HEARTBEAT_MS = 3_600_000

/** The administration-class permissions (the admin action class's
 *  account-side bound): the instance + org administration family. */
export const PAT_ADMIN_PERMISSIONS: readonly ActionPermission[] = [
  'users.manage', 'instance.settings', 'org.users.manage', 'peers.manage',
]

// ── the credential itself ────────────────────────────────────────────

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Mint the plaintext: `ospt_` + 43 base64url chars (32 random bytes —
 *  the entropy that licenses the unsalted hash). The plaintext answers
 *  the mint response ONCE and never persists. */
export function mintPatSecret(): string {
  return `${PAT_TOKEN_PREFIX}${base64url(crypto.getRandomValues(new Uint8Array(32)))}`
}

/** The store's lookup key: SHA-256 hex of the full token. */
export async function hashPat(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** The console's display fragment ('ospt_' + 8 — enough to recognize
 *  the row, never enough to authenticate). */
export function patDisplayPrefix(token: string): string {
  return token.slice(0, PAT_TOKEN_PREFIX.length + 8)
}

/** The presented credential's plausible shape (before any store work). */
export function patPlausible(raw: unknown): raw is string {
  return typeof raw === 'string' && /^ospt_[A-Za-z0-9_-]{43}$/.test(raw)
}

/** The expiration picker's honest arithmetic: days 1..366 (default 90
 *  when the field is absent); the answer is the ISO expiry instant. */
export function resolvePatExpiry(raw: unknown, now = Date.now()): { days: number; expiresAt: string } | { error: string } {
  const days = raw === undefined || raw === null ? PAT_DEFAULT_EXPIRY_DAYS : Number(raw)
  if (!Number.isInteger(days) || days < 1 || days > PAT_MAX_EXPIRY_DAYS) {
    return { error: `the expiration is required and bounded: 1…${PAT_MAX_EXPIRY_DAYS} days (the default ${PAT_DEFAULT_EXPIRY_DAYS})` }
  }
  return { days, expiresAt: new Date(now + days * 86_400_000).toISOString() }
}

// ── the account-side narrowing bound ─────────────────────────────────

export type PatScopeVerdict =
  | { ok: true; granted: PatScope[]; serviceRoles: Record<string, string[]> }
  | { ok: false; error: string }

/** Validate the requested scopes against the account's CURRENT standing
 *  (the mint AND the exchange share this one computation — the exchange
 *  re-judges the pinned set against the live account):
 *
 *  - the service names a registered, ACTIVE, application-class client
 *    (a device client is the machine cone's, never a PAT's);
 *  - the account can ENTER the service with roles (rolesForClient — the
 *    per-client assignment through the policy allowlist, over the
 *    context's role set);
 *  - the action class bound (read ← the entry; write ← a workflow
 *    permission; admin ← an administration-class permission — the OP's
 *    effective RBAC map).
 *
 *  `account` is the RAW account row (never the context-shaped session
 *  payload); `context` is the resolved org context (the PAT's pinned
 *  one at exchange, the session's at mint). */
export async function resolvePatScopesForAccount(
  store: ServerStore,
  account: { id: string; role: string; roles?: string[] | null },
  context: OrgContextResolution,
  requested: readonly PatScope[],
  env?: Record<string, string | undefined>,
): Promise<PatScopeVerdict> {
  const map = effectiveRbacMap(env)
  const serviceRoles: Record<string, string[]> = {}
  for (const scope of requested) {
    const client = await store.getOidcClient(scope.service)
    if (!client || client.status !== 'active') {
      return { ok: false, error: `the service '${scope.service}' is not a registered, active relying party` }
    }
    if (deviceClassOf(client.claimsPolicy)) {
      return { ok: false, error: `the service '${scope.service}' is a device-class client — the machine cone speaks client_credentials, never a person's token` }
    }
    const assigned = await store.getOpClientRoles(account.id, client.clientId)
    const roles = rolesForClient(assigned, context.roles, client.claimsPolicy)
    if (!roles.length) {
      return { ok: false, error: `the account holds no role on '${scope.service}' — a token only ever narrows the account` }
    }
    if (scope.action !== 'read') {
      const held = permissionsForRoles(roles, map)
      if (!held.size) {
        return { ok: false, error: `the account's roles on '${scope.service}' hold no action permission — the write class refuses` }
      }
      if (scope.action === 'admin' && !rolesCan(roles, PAT_ADMIN_PERMISSIONS, map)) {
        return { ok: false, error: `the account's roles on '${scope.service}' hold no administration permission — the admin class refuses` }
      }
    }
    serviceRoles[client.clientId] = roles
  }
  return { ok: true, granted: [...requested], serviceRoles }
}

/** The picker's catalog (GET /api/op/account/tokens): the services the
 *  account may mint for — the ACTIVE, application-class clients the
 *  account enters with roles, each with the WIDEST action class the
 *  account-side bound admits (the picker's per-service select disables
 *  the rest honestly). A service the account never enters never shows. */
export interface PatServiceOption {
  id: string
  name: string
  maxAction: PatActionClass
}

export async function patServicesForAccount(
  store: ServerStore,
  account: { id: string },
  context: OrgContextResolution,
  env?: Record<string, string | undefined>,
): Promise<PatServiceOption[]> {
  const map = effectiveRbacMap(env)
  // The account's assignments load ONCE and group by client — the
  // per-client getOpClientRoles this replaces was one store round trip
  // per registered client (the endpoint-scaling doctrine). A client
  // without a row answers null exactly like getOpClientRoles (the
  // UNIQUE(user, client) key makes the Map's read a non-question).
  const [clients, assignments] = await Promise.all([
    store.listOidcClients(),
    store.listOpClientRoles(account.id),
  ])
  const assignedByClient = new Map(assignments.map(a => [a.clientId, a.roles]))
  const out: PatServiceOption[] = []
  for (const client of clients) {
    if (client.status !== 'active' || deviceClassOf(client.claimsPolicy)) continue
    const assigned = assignedByClient.get(client.clientId) ?? null
    const roles = rolesForClient(assigned, context.roles, client.claimsPolicy)
    if (!roles.length) continue
    let maxAction: PatActionClass = 'read'
    if (permissionsForRoles(roles, map).size) maxAction = 'write'
    if (rolesCan(roles, PAT_ADMIN_PERMISSIONS, map)) maxAction = 'admin'
    out.push({ id: client.clientId, name: client.name, maxAction })
  }
  return out.sort((a, b) => a.name.localeCompare(b.name))
}

// ── the exchanged token (the RFC 8693 answer's JWT) ──────────────────

/** The exchanged access token's claim set: the OP's ONE token shape (the
 *  device cone's precedent — a self-contained ES256 JWT the RPs validate
 *  against the JWKS, no call-back), carrying the scope set + the
 *  account's identity + the active-org context (the spec's exact list),
 *  plus the per-service role sets (service_roles) so the RP's RBAC gate
 *  never calls back. `pat` names the credential row (the revocation +
 *  the audit's correlation). */
export function patTokenClaims(
  pat: PersonalAccessToken,
  account: AuthUserPayload,
  context: OrgContextResolution,
  granted: readonly PatScope[],
  serviceRoles: Record<string, string[]>,
  config: { issuer: string; accessTokenTtlMs: number },
): Record<string, unknown> {
  const nowSec = Math.floor(Date.now() / 1000)
  const services = [...new Set(granted.map(s => s.service))].sort()
  const claims: Record<string, unknown> = {
    iss: config.issuer,
    sub: account.id,
    aud: services,
    iat: nowSec,
    exp: nowSec + Math.floor(config.accessTokenTtlMs / 1000),
    scope: granted.map(s => `${s.service}:${s.action}`).join(' '),
    name: account.name,
    email: account.email,
    service_roles: Object.fromEntries(
      services.map(s => [s, serviceRoles[s] ?? []]),
    ),
    pat: pat.id,
  }
  // The active-org context (never a dead org's claims — the exchange
  // re-judged the pinned context against the live membership). The cone
  // claim rides the context's canonical spelling (the claims.ts rule).
  if (context.orgId) claims.org = context.orgId
  if (context.orgId && context.cone) {
    claims.cone = encodeOrgMemberCone(context.cone) ?? 'org-wide'
  }
  return claims
}

// ── the audit chain (entity_type 'account' — the account's own
//    activity feed shows them, the factors' auditFactor discipline) ───

export async function auditPat(
  action: string,
  entityId: string,
  actor: { userId?: string; userName?: string },
  metadata: Record<string, unknown>,
): Promise<void> {
  try {
    const id = crypto.randomUUID()
    await getStore().putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'account',
      entity_id: entityId,
      action,
      user_id: actor.userId,
      user_name: actor.userName,
      metadata,
    }))
  } catch (err) {
    console.error(`[op] PAT audit event ${action} failed to persist:`, (err as Error).message)
  }
}

// ── the display projection (the console's list + the org inventory
//    share it — metadata only, the hash never leaves a read) ──────────

/** The list row's honest state: revoked > expired > active. */
export function patStateOf(pat: PersonalAccessToken, now = Date.now()): 'active' | 'expired' | 'revoked' {
  if (pat.revokedAt) return 'revoked'
  if (new Date(pat.expiresAt).getTime() <= now) return 'expired'
  return 'active'
}

/** The metadata-only projection (NEVER the hash: every read surface is
 *  a display surface). */
export function patListRow(pat: PersonalAccessToken, now = Date.now()) {
  return {
    id: pat.id,
    name: pat.name,
    prefix: pat.tokenPrefix,
    scopes: pat.scopes,
    orgContext: pat.orgContext,
    createdAt: pat.createdAt,
    expiresAt: pat.expiresAt,
    lastUsedAt: pat.lastUsedAt,
    revokedAt: pat.revokedAt,
    state: patStateOf(pat, now),
  }
}

// ── the exchange path's shared pieces (the route in routes/op.ts) ────

/** The exchange's lazy expiry-soon notice (the mailer's one-shot): the
 *  token is live and inside the window and never notified → true (the
 *  route sends + stamps). The console read runs the same check. */
export function patExpiryNoticeDue(pat: PersonalAccessToken, now = Date.now()): boolean {
  if (pat.revokedAt || pat.expiryNotifiedAt) return false
  const expires = new Date(pat.expiresAt).getTime()
  return expires > now && expires - now <= PAT_EXPIRY_NOTICE_WINDOW_MS
}

/** The heartbeat decision (the exchange's throttled use-stamp + audit):
 *  true when the row's last audit beat is older than the window. */
export function patExchangeBeatDue(pat: PersonalAccessToken, now = Date.now()): boolean {
  if (!pat.lastExchangeAuditAt) return true
  return now - new Date(pat.lastExchangeAuditAt).getTime() >= PAT_EXCHANGE_HEARTBEAT_MS
}

/** The per-exchange narrowing (RFC 8693's `scope` parameter): the caller
 *  may ask for a SUBSET of the PAT's pinned set, never wider. Answers
 *  the normalized request, or the refusal's reason. */
export function narrowPatScopesParam(raw: string | null, pinned: readonly PatScope[]): { scopes: PatScope[] | null; error: string | null } {
  if (raw === null || !raw.trim()) return { scopes: null, error: null }
  const requested = normalizePatScopes(raw.trim().split(/\s+/))
  if (!requested) return { scopes: null, error: 'the scope parameter is not in the PAT grammar' }
  if (!patScopesWithin(requested, pinned)) {
    return { scopes: null, error: 'the requested scope widens the token — a token only ever narrows' }
  }
  return { scopes: requested, error: null }
}

// ── the session delegation (TODO.ai-platform/03) ─────────────────────
// A service acting ON THE USER'S behalf within the user's own session —
// the estate assistant's "my account" reads are the reference caller.
// Where the PAT cone's subject token is a long-lived developer
// credential, the delegation's subject token is the OP's OWN opaque
// access token, minted to the calling client by the authorization-code
// flow the sign-in just ran (so the window IS the session's: the
// subject dies with the sign-in's access-token TTL, and the retained
// credential never outlives it). The rules, all narrow-only:
//
//   - the caller AUTHENTICATES (the client credentials — the opaque
//     subject is a bearer artifact, so the exchange binds it to the
//     client it was ISSUED to: a service exchanges only its own
//     sign-ins' tokens, never another RP's);
//   - the `scope` parameter is REQUIRED — the delegation names its
//     narrowed target (the same <service>:<action-class> grammar), and
//     the standing re-judgment (resolvePatScopesForAccount) is shared
//     verbatim with the PAT cone: a role the account lost since the
//     sign-in narrows the answer, a set that fell away refuses;
//   - the answer is the OP's ONE token shape carrying the ACTOR claim
//     (RFC 8693 §4.1's `act`: the delegating service's client id) so the
//     relying party's audit names who ACTED, never just who was acted
//     for. Never an ID token, never a refresh, never `amr` (the
//     exchange is not an authentication ceremony — the PAT doctrine).

/** The RFC 8693 subject_token_type the delegation speaks — the
 *  standard's own access-token type; the OP accepts it for its OWN
 *  store-backed opaque access tokens only (a foreign-issuer JWT is
 *  unknown here by construction). */
export const DELEGATION_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'

/** The delegation's scope parameter (REQUIRED — unlike the PAT cone's
 *  optional narrowing): the normalized set, or the refusal's reason. */
export function delegationScopesParam(raw: string | null): { scopes: PatScope[] | null; error: string | null } {
  if (raw === null || !raw.trim()) {
    return { scopes: null, error: 'the delegation names its narrowed scope — the <service>:<action-class> grammar, never absent' }
  }
  const requested = normalizePatScopes(raw.trim().split(/\s+/))
  if (!requested) return { scopes: null, error: 'the scope parameter is not in the <service>:<action-class> grammar' }
  return { scopes: requested, error: null }
}

/** The delegated access token's claim set: the PAT cone's exact shape
 *  (the ONE token the RPs validate) with the actor claim in the
 *  credential row's place — `act.sub` names the delegating client (the
 *  audit's "the assistant read AS the user", never a silent person). */
export function delegationTokenClaims(
  account: AuthUserPayload,
  context: OrgContextResolution,
  granted: readonly PatScope[],
  serviceRoles: Record<string, string[]>,
  config: { issuer: string; accessTokenTtlMs: number },
  actorClientId: string,
): Record<string, unknown> {
  const nowSec = Math.floor(Date.now() / 1000)
  const services = [...new Set(granted.map(s => s.service))].sort()
  const claims: Record<string, unknown> = {
    iss: config.issuer,
    sub: account.id,
    aud: services,
    iat: nowSec,
    exp: nowSec + Math.floor(config.accessTokenTtlMs / 1000),
    scope: granted.map(s => `${s.service}:${s.action}`).join(' '),
    name: account.name,
    email: account.email,
    service_roles: Object.fromEntries(
      services.map(s => [s, serviceRoles[s] ?? []]),
    ),
    act: { sub: actorClientId },
  }
  if (context.orgId) claims.org = context.orgId
  if (context.orgId && context.cone) {
    claims.cone = encodeOrgMemberCone(context.cone) ?? 'org-wide'
  }
  return claims
}
