// ═══════════════════════════════════════════════════════════════════
// The IA endorsement acts (TODO.register/01 — the manufacturer org
// kind's standing semantics): an issuing authority CONFIRMS the
// relationship with a manufacturer org (the standing upgrades
// declared → ia-endorsed), and can withdraw the confirmation (the row
// keeps its revocation stamps; the standing falls back to declared).
//
// THE DOCTRINE (TODO.register/00): a manufacturer org is NOT a PD-03
// participant — the endorsement is a RELATIONSHIP record (the IA it
// applied to vouches for it), never a peer assessment and never a
// scope. The kind's honesty is the scheme's liability shield: the
// standing renders per kind and a manufacturer row never reads
// "participant".
//
// THE GRANT: the act is the issuing authority's own — the caller's
// ACTIVE org context must BE an active issuing-authority org and carry
// an officer-class role (ia_officer / certification_officer) or the
// IA's organization administrator. The identity administrator
// (admin/cs_admin, the registry operator) may record or withdraw an
// endorsement naming any active IA org (the curating act).
//
// The routes mount on EVERY instance (app.ts) but answer 404 unless the
// deployment profile carries the identity module (the op.ts posture).
// Every act lands on the audit chain (entity_type 'organization', the
// org-registry lifecycle's journal — the per-org page's slice carries
// them).
//
// WORKER-SAFE: the ServerStore seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { getStore, type AuthUserPayload } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { effectiveRolesOf } from '@oimlsmart/platform-server/vocab'
import { sessionUser } from '@oimlsmart/platform-server/session'
import {
  createOrgEndorsement,
  listOrgEndorsements,
  resolveRegistryOrg,
  revokeOrgEndorsement,
  type RegistryOrg,
} from '../auth/org-registry'

/** The roles that commit an issuing authority to a manufacturer
 *  relationship (the IA desk's officers + the IA's delegated
 *  administrator). */
const IA_CONFIRM_ROLES = new Set(['ia_officer', 'certification_officer', 'org_admin'])

export function createOpEndorsementsRouter(): Hono {
  const router = new Hono()

  // ── the profile gate (the op.ts posture: one build, the profile
  //    decides) ─────────────────────────────────────────────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  router.use('/api/op/org-endorsements', profileGate)
  router.use('/api/op/org-endorsements/*', profileGate)

  /** The endorsement grant against the named IA org: the confirming IA
   *  must be an ACTIVE issuing-authority registry org, and the caller
   *  either acts AS it (the active org context + an officer-class role)
   *  or is the registry operator. Answers the error response when the
   *  act may not run. */
  async function endorsementGrant(c: Context, iaOrgId: string): Promise<{ user: AuthUserPayload; iaOrg: RegistryOrg } | { error: Response }> {
    const user = await sessionUser(c)
    if (!user) return { error: c.json({ error: 'authentication required' }, 401) }
    const iaOrg = await resolveRegistryOrg(getStore(), iaOrgId)
    if (!iaOrg || iaOrg.kind !== 'issuing-authority' || iaOrg.state !== 'active') {
      return {
        error: c.json({
          error: `organization '${iaOrgId}' is not an active issuing authority on the organization registry — only an issuing authority confirms a manufacturer relationship`,
        }, 400),
      }
    }
    if (user.role === 'admin' || user.role === 'cs_admin') return { user, iaOrg }
    const held = new Set(effectiveRolesOf(user))
    if (user.orgId === iaOrgId && [...held].some(r => IA_CONFIRM_ROLES.has(r))) return { user, iaOrg }
    return {
      error: c.json({
        error: 'the endorsement is the issuing authority’s own act — act as the IA organization (an ia_officer / certification_officer / its organization administrator), or ask the identity administrator',
        permission: 'org.endorsements.manage',
      }, 403),
    }
  }

  /** The endorsement journal (the org-registry lifecycle's audit slice —
   *  entity_type 'organization' naming the MANUFACTURER org). */
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

  // POST /api/op/org-endorsements — the confirm act:
  // { org_id, ia_org_id, note? }. The target must be an ACTIVE
  // MANUFACTURER org (a participant kind's standing is the scheme's —
  // there is nothing to endorse); one ACTIVE endorsement per
  // (manufacturer, IA) pair.
  router.post('/api/op/org-endorsements', async (c) => {
    const body = await c.req.json<{ org_id?: string; ia_org_id?: string; note?: string | null }>().catch(() => null)
    const orgId = typeof body?.org_id === 'string' ? body.org_id.trim() : ''
    const iaOrgId = typeof body?.ia_org_id === 'string' ? body.ia_org_id.trim() : ''
    if (!body || !orgId || !iaOrgId) {
      return c.json({ error: 'org_id (the manufacturer organization) and ia_org_id (the confirming issuing authority) are required' }, 400)
    }
    const gate = await endorsementGrant(c, iaOrgId)
    if ('error' in gate) return gate.error
    const { user, iaOrg } = gate
    const store = getStore()

    const org = await resolveRegistryOrg(store, orgId)
    if (!org) return c.json({ error: `organization '${orgId}' is not on the organization registry` }, 404)
    if (org.kind !== 'manufacturer') {
      return c.json({
        error: `organization '${orgId}' is ${org.kind ? `a ${org.kind}` : 'a non-participant organization'} — the endorsement standing applies to MANUFACTURER organizations only (a participant's standing is the scheme's registration, PD-03; there is nothing to endorse)`,
      }, 400)
    }
    if (org.state !== 'active') {
      return c.json({ error: `organization '${orgId}' is disabled — re-enable it before an endorsement can land` }, 400)
    }
    const existing = (await listOrgEndorsements(store, orgId)).find(e => e.iaOrgId === iaOrgId && !e.revokedAt)
    if (existing) {
      return c.json({ error: `${iaOrg.name} already endorses ${org.name} (recorded ${existing.createdAt})` }, 409)
    }

    const note = typeof body.note === 'string' && body.note.trim() ? body.note.trim() : null
    const endorsement = await createOrgEndorsement(store, { orgId, iaOrgId, note, createdBy: user.email })
    await audit(user, orgId, 'organization.endorsed', {
      name: org.name,
      ia_org_id: iaOrgId,
      ia_org_name: iaOrg.name,
      note,
    })
    return c.json({ endorsement, standing: 'ia-endorsed' }, 201)
  })

  // DELETE /api/op/org-endorsements/:orgId/:iaOrgId — the withdrawal:
  // the ACTIVE endorsement for the pair keeps its row with the
  // revocation stamps (the audit trail is the history); the standing
  // falls back to 'declared' when no other IA's endorsement stands.
  router.delete('/api/op/org-endorsements/:orgId/:iaOrgId', async (c) => {
    const orgId = c.req.param('orgId')
    const iaOrgId = c.req.param('iaOrgId')
    const gate = await endorsementGrant(c, iaOrgId)
    if ('error' in gate) return gate.error
    const { user, iaOrg } = gate
    const store = getStore()

    const existing = (await listOrgEndorsements(store, orgId)).find(e => e.iaOrgId === iaOrgId && !e.revokedAt)
    if (!existing) {
      return c.json({ error: `no active endorsement of organization '${orgId}' by '${iaOrgId}' — the withdrawals never rewrite the history` }, 404)
    }
    const revoked = await revokeOrgEndorsement(store, existing.id, user.email)
    const remaining = (await listOrgEndorsements(store, orgId)).filter(e => !e.revokedAt)
    await audit(user, orgId, 'organization.endorsement_revoked', {
      ia_org_id: iaOrgId,
      ia_org_name: iaOrg.name,
      endorsements_remaining: remaining.length,
    })
    return c.json({ endorsement: revoked, standing: remaining.length ? 'ia-endorsed' : 'declared' })
  })

  return router
}
