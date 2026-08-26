// ═══════════════════════════════════════════════════════════════════
// The org signing keys (TODO.trust-registry/01): the OP learns to hold
// an org's signing keys as the ORG ACCOUNT'S property — the OP is the
// root of trust for WHO signs; a verifier resolves signer → org →
// standing in ONE anonymous, cacheable, CORS-open request.
//
// THE MANAGEMENT ACTS (register / rotate / revoke) are gated on the
// org's `org_admin` in the ACTIVE context (the session acts AS the org)
// or the estate administrator — the OP never holds a key for an org
// that nobody administers. Every act lands on the audit chain
// (entity_type 'organization' — the per-org page's slice carries them).
//
// THE OVERLAP DOCTRINE (op-key-rotate.ts applied to org keys): the
// rotation registers the successor and stamps the predecessor
// (rotated_at/by + successor_kid) — BOTH rows keep resolving, so an
// artifact signed before the rotation still verifies. The revocation
// stamps revoked_at/by and KEEPS the row: the verify answer is "valid
// at the time; the key since revoked on DATE".
//
// THE PUBLIC ENDPOINT: GET /op/keys/<org-id>.json — the org's key set
// (the JWK Set shape; the rotated + revoked rows CARRY their stamps and
// stay in the set) + the org's standing projection (the same computed
// projection the registry renders — auth/org-registry.ts). Anonymous,
// cacheable (short max-age), CORS-open (the verifiers are everywhere),
// replayable offline (this wave: plain JWKS + standing over TLS; a
// signed key-set document is the later hardening). The actors' personal
// emails stay on the audit chain (the consoles show them); the public
// document carries the DATES — the time anchor is what verification
// needs.
//
// The routes mount on EVERY instance (app.ts) but answer 404 unless the
// deployment profile carries the identity module (the op.ts posture).
//
// WORKER-SAFE: the ServerStore seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { getStore, type AuthUserPayload } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { effectiveRolesOf } from '@oimlsmart/platform-server/vocab'
import { sessionUser } from '@oimlsmart/platform-server/session'
import { isActiveRegistryOrg, resolveRegistryOrg } from '../auth/org-registry'
import {
  listOrgSigningKeys,
  orgSigningJwkRefusal,
  registerOrgSigningKey,
  resolveOrgSigningKey,
  revokeOrgSigningKey,
  rotateOrgSigningKey,
  type OrgSigningKey,
} from '../auth/org-signing-keys'

/** The public document's cache posture: anonymous verifiers everywhere,
 *  a SHORT max-age (a registration/rotation/revocation propagates within
 *  the minute; the offline-tolerant replay is the cached copy). */
const PUBLIC_CACHE = 'public, max-age=60'

/** The management read's row (the consoles see the custody chain whole,
 *  actors included — the gated surface, never the public document). */
function managementRow(key: OrgSigningKey) {
  return {
    kid: key.kid,
    orgId: key.orgId,
    publicJwk: key.publicJwk,
    label: key.label,
    createdAt: key.createdAt,
    createdBy: key.createdBy,
    rotatedAt: key.rotatedAt,
    rotatedBy: key.rotatedBy,
    successorKid: key.successorKid,
    revokedAt: key.revokedAt,
    revokedBy: key.revokedBy,
  }
}

/** The public document's key entry: the JWK Set member (a verifier reads
 *  `keys` as plain JWKS and tolerates the extension members) + the
 *  custody DATES + the successor link. NEVER the actors' emails. */
function publicKeyEntry(key: OrgSigningKey) {
  return {
    ...key.publicJwk,
    label: key.label,
    created_at: key.createdAt,
    rotated_at: key.rotatedAt,
    successor_kid: key.successorKid,
    revoked_at: key.revokedAt,
  }
}

export function createOpKeysRouter(): Hono {
  const router = new Hono()

  // ── the profile gate (the op.ts posture: one build, the profile
  //    decides) ─────────────────────────────────────────────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  router.use('/api/op/org-keys', profileGate)
  router.use('/api/op/org-keys/*', profileGate)
  router.use('/op/keys/*', profileGate)

  /** The key-act grant against the named org: the org's `org_admin` in
   *  the ACTIVE context (the session's org IS the org — the account
   *  console's switcher stamps it; the primary binding counts) or the
   *  estate administrator. Answers the error response when the act may
   *  not run. */
  async function keyActGrant(c: Context, orgId: string): Promise<{ user: AuthUserPayload } | { error: Response }> {
    const user = await sessionUser(c)
    if (!user) return { error: c.json({ error: 'authentication required' }, 401) }
    if (user.role === 'admin' || user.role === 'cs_admin') return { user }
    const held = new Set(effectiveRolesOf(user))
    if (user.orgId === orgId && held.has('org_admin')) return { user }
    return {
      error: c.json({
        error: `the signing keys are the organization’s own — act as '${orgId}' with its org_admin role (switch the active organization on the account console), or ask the identity administrator`,
        permission: 'org.keys.manage',
      }, 403),
    }
  }

  /** The key journal (the org-registry lifecycle's audit slice —
   *  entity_type 'organization' naming the org; the per-org page's
   *  activity section carries the acts). */
  async function audit(actor: AuthUserPayload, orgId: string, action: string, metadata: Record<string, unknown>): Promise<void> {
    const id = crypto.randomUUID()
    await getStore().putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'organization',
      entity_id: orgId,
      action,
      user_id: actor.id,
      user_name: actor.name,
      metadata,
    }))
  }

  /** The act's org preconditions: the org is on the registry (404), and
   *  for the acts that ADD a key it is ACTIVE (a disabled org admits
   *  nothing new — the registry's lifecycle doctrine). The revocation
   *  never takes this second check: the terminal honesty act is always
   *  allowed. */
  async function activeOrgOrError(c: Context, orgId: string): Promise<Response | null> {
    const org = await resolveRegistryOrg(getStore(), orgId)
    if (!org) return c.json({ error: `organization '${orgId}' is not on the organization registry` }, 404)
    if (org.state !== 'active') {
      return c.json({ error: `organization '${orgId}' is disabled — a disabled organization registers no new signing key; re-enable it first (the existing keys keep resolving)` }, 400)
    }
    return null
  }

  // ── the management acts ────────────────────────────────────────────

  // GET /api/op/org-keys/:orgId — the org's key set for the consoles
  // (every row: active, rotated, revoked — the custody chain whole).
  router.get('/api/op/org-keys/:orgId', async (c) => {
    const orgId = c.req.param('orgId')
    const gate = await keyActGrant(c, orgId)
    if ('error' in gate) return gate.error
    const org = await resolveRegistryOrg(getStore(), orgId)
    if (!org) return c.json({ error: `organization '${orgId}' is not on the organization registry` }, 404)
    const keys = await listOrgSigningKeys(getStore(), orgId)
    return c.json({ keys: keys.map(managementRow) })
  })

  // POST /api/op/org-keys — the register act:
  // { org_id, label, public_jwk }. The PUBLIC half only — a body carrying
  // private material is refused at the door. The kid derives the OP's
  // own way; the duplicate coordinates are the honest 409.
  router.post('/api/op/org-keys', async (c) => {
    const body = await c.req.json<{ org_id?: string; label?: string; public_jwk?: JsonWebKey }>().catch(() => null)
    const orgId = typeof body?.org_id === 'string' ? body.org_id.trim() : ''
    const label = typeof body?.label === 'string' ? body.label.trim() : ''
    if (!body || !orgId || !label || body.public_jwk === undefined) {
      return c.json({ error: 'org_id, label (the key’s display name) and public_jwk (the PUBLIC half, ES256) are required' }, 400)
    }
    const jwkRefusal = orgSigningJwkRefusal(body.public_jwk)
    if (jwkRefusal) return c.json({ error: jwkRefusal }, 400)
    const gate = await keyActGrant(c, orgId)
    if ('error' in gate) return gate.error
    const { user } = gate
    const orgError = await activeOrgOrError(c, orgId)
    if (orgError) return orgError

    const key = await registerOrgSigningKey(getStore(), { orgId, publicJwk: body.public_jwk!, label, createdBy: user.email })
    if (!key) {
      return c.json({ error: 'these coordinates are already registered to this organization — the kid derives from the key itself; a re-registration is never a second row' }, 409)
    }
    await audit(user, orgId, 'organization.key_registered', { kid: key.kid, label })
    return c.json({ key: managementRow(key) }, 201)
  })

  // POST /api/op/org-keys/:orgId/:kid/rotate — the rotation: register
  // the successor ({ label, public_jwk }) and stamp the predecessor
  // (the overlap doctrine — BOTH rows keep resolving). Refusals: the
  // unknown predecessor (404), the revoked predecessor (400 — a revoked
  // key never rotates; register afresh), the already-rotated one (409 —
  // the chain never forks), the duplicate successor coordinates (409).
  router.post('/api/op/org-keys/:orgId/:kid/rotate', async (c) => {
    const orgId = c.req.param('orgId')
    const kid = c.req.param('kid')
    const body = await c.req.json<{ label?: string; public_jwk?: JsonWebKey }>().catch(() => null)
    const label = typeof body?.label === 'string' && body.label.trim() ? body.label.trim() : null
    if (!body || !label || body.public_jwk === undefined) {
      return c.json({ error: 'label (the successor’s display name) and public_jwk (the successor’s PUBLIC half, ES256) are required' }, 400)
    }
    const jwkRefusal = orgSigningJwkRefusal(body.public_jwk)
    if (jwkRefusal) return c.json({ error: jwkRefusal }, 400)
    const gate = await keyActGrant(c, orgId)
    if ('error' in gate) return gate.error
    const { user } = gate
    const orgError = await activeOrgOrError(c, orgId)
    if (orgError) return orgError

    const predecessor = await resolveOrgSigningKey(getStore(), orgId, kid)
    if (!predecessor) return c.json({ error: `organization '${orgId}' holds no signing key '${kid}'` }, 404)
    if (predecessor.revokedAt) {
      return c.json({ error: `key '${kid}' is revoked (${predecessor.revokedAt}) — a revoked key never rotates; register the successor as a new key` }, 400)
    }
    if (predecessor.rotatedAt) {
      return c.json({ error: `key '${kid}' already rotated to '${predecessor.successorKid}' (${predecessor.rotatedAt}) — the chain never forks; rotate the successor instead` }, 409)
    }
    const rotated = await rotateOrgSigningKey(getStore(), predecessor, { publicJwk: body.public_jwk!, label, actor: user.email })
    if (!rotated) {
      return c.json({ error: 'these coordinates are already registered to this organization — the successor must be a NEW key' }, 409)
    }
    await audit(user, orgId, 'organization.key_rotated', {
      kid: predecessor.kid,
      successor_kid: rotated.successor.kid,
      label: rotated.successor.label,
    })
    return c.json({ predecessor: managementRow(rotated.predecessor), successor: managementRow(rotated.successor) }, 201)
  })

  // POST /api/op/org-keys/:orgId/:kid/revoke — the revocation: the
  // terminal stamps land on the row (NEVER a delete — the at-the-time
  // honesty). A disabled org's key still revokes (the terminal act is
  // always allowed). The second revocation is the honest 409.
  router.post('/api/op/org-keys/:orgId/:kid/revoke', async (c) => {
    const orgId = c.req.param('orgId')
    const kid = c.req.param('kid')
    const gate = await keyActGrant(c, orgId)
    if ('error' in gate) return gate.error
    const { user } = gate
    if (!(await resolveRegistryOrg(getStore(), orgId))) {
      return c.json({ error: `organization '${orgId}' is not on the organization registry` }, 404)
    }
    const existing = await resolveOrgSigningKey(getStore(), orgId, kid)
    if (!existing) return c.json({ error: `organization '${orgId}' holds no signing key '${kid}'` }, 404)
    if (existing.revokedAt) {
      return c.json({ error: `key '${kid}' is already revoked (${existing.revokedAt} by ${existing.revokedBy ?? '—'}) — the revocations never rewrite the history` }, 409)
    }
    const revoked = await revokeOrgSigningKey(getStore(), orgId, kid, user.email)
    await audit(user, orgId, 'organization.key_revoked', { kid, label: existing.label, successor_kid: existing.successorKid })
    return c.json({ key: managementRow(revoked!) })
  })

  // ── the PUBLIC endpoint ────────────────────────────────────────────

  // GET /op/keys/<org-id>.json — the org's key set + its standing
  // projection, one request, anonymous, cacheable (short max-age),
  // CORS-open. The rotated + revoked rows CARRY their stamps and stay in
  // the set: the verify answer for an artifact signed before a
  // revocation resolves the key and names the revocation date ("valid at
  // the time; the key since revoked on DATE"). A DISABLED org still
  // resolves (org_state says so — the at-the-time artifacts keep their
  // answer); an unknown org is the honest 404.
  router.get('/op/keys/:file', async (c) => {
    const file = c.req.param('file')
    const orgId = file.endsWith('.json') ? file.slice(0, -'.json'.length) : ''
    const cors = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': PUBLIC_CACHE }
    if (!orgId) {
      return c.json({ error: 'the org key set resolves at /op/keys/<org-id>.json' }, 404, cors)
    }
    const org = await resolveRegistryOrg(getStore(), orgId)
    if (!org) {
      return c.json({ error: `organization '${orgId}' is not on the organization registry` }, 404, cors)
    }
    const keys = await listOrgSigningKeys(getStore(), orgId)
    return c.json({
      org_id: org.id,
      org_name: org.name,
      org_kind: org.kind,
      org_state: org.state,
      standing: org.standing,
      endorsed_by: org.endorsedBy,
      keys: keys.map(publicKeyEntry),
    }, 200, cors)
  })

  return router
}
