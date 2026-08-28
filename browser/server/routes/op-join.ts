// ═══════════════════════════════════════════════════════════════════
// Delegated organization administration (TODO.identity/10) — the OP's
// join-request surface: the public "Request an account" intake and the
// two decision queues.
//
// The topology (B 18:2025 §10.2 / PD-03, TODO.identity-features/05):
// the identity administrator manages ORGANIZATIONS (the identity
// service's OWN organization registry is the membership graph's source
// of truth — an account naming an org is created only for an ACTIVE
// registry org; the PUBLIC intake's selector + submit stay the scheme's
// participation flow, gated to active orgs carrying a participant
// kind); each organization manages its OWN people through its org
// admin (the org-scoped `org.users.manage` grant, routes/users.ts).
// TODO.register/01 adds the MANUFACTURER path to the intake: a
// manufacturer org is NOT a PD-03 participant — its standing is
// declared on self-registration (the founder's work email declares the
// domain hint; an existing manufacturer org with a matching domain
// takes the join ask), upgradeable to IA-endorsed by an issuing
// authority's confirmation (routes/op-endorsements.ts), and NEVER the
// participant standing.
// This router carries the intake + the decisions:
//
//   GET  /api/op/organizations             — the PUBLIC selector feed:
//                                            the REGISTERED participant
//                                            orgs (the join page never
//                                            offers an unregistered one)
//                                            with the roles each org's
//                                            kind bounds;
//   POST /api/op/join-requests             — the PUBLIC submit: name,
//                                            work email, the org (from
//                                            the selector) + the role
//                                            asked for — or the "my
//                                            organization is not listed"
//                                            path (a free-text org name)
//                                            which lands with BIML;
//   GET  /api/op/join-requests[?scope=]    — the queues: an org admin
//                                            reads ONLY its own org's;
//                                            the scheme operator
//                                            (users.manage) reads all,
//                                            or scope=unregistered for
//                                            the new-organizations queue;
//   POST /api/op/join-requests/:id/approve — the invite is issued (the
//                                            TODO.identity/02 enrollment
//                                            seam, auth/op/enrollment.ts)
//                                            and the row decided —
//                                            atomically on 'pending';
//   POST /api/op/join-requests/:id/refuse  — the honest refusal with a
//                                            reason (the not-listed
//                                            queue's refusal carries the
//                                            participation pointer).
//
// The routes mount on EVERY instance (app.ts) but answer 404 unless the
// deployment profile carries the identity module (the op.ts posture —
// one build, the profile decides).
//
// WORKER-SAFE: the ServerStore seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload, type OrgJoinRequest } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { effectiveRbacMap } from '@oimlsmart/platform-server/rbac'
import { effectiveRolesOf } from '@oimlsmart/platform-server/vocab'
import {
  admitsJoinFlow,
  emailDomain,
  emailDomainHint,
  listRegistryOrganizations,
  mintManufacturerOrgId,
  onJoinSelector,
  orgAssignableRoles,
  resolveRegistryOrg,
} from '../auth/org-registry'
import { issueAccountInvite } from '../auth/op/enrollment'
import { OP_ENROLLMENT_TTL_MS } from '../auth/op/accounts'
import { sendOpMail } from '../auth/op/mail'
import type { MailEnv } from '@oimlsmart/platform-server/mailer'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { sessionUser } from '@oimlsmart/platform-server/session'

type EnvLike = Record<string, string | undefined>

/** The decision-queue grant: 'wide' (users.manage — BIML, every queue)
 *  or 'org' (org.users.manage — the org admin, its own org's queue). */
interface QueueGrant {
  kind: 'wide' | 'org'
  orgId: string | null
}

export function createOpJoinRouter(): Hono {
  const router = new Hono()

  // ── the profile gate (the op.ts posture: one build, the profile
  //    decides) ─────────────────────────────────────────────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  router.use('/api/op/organizations', profileGate)
  router.use('/api/op/join-requests', profileGate)
  router.use('/api/op/join-requests/*', profileGate)
  router.use('/api/op/org-invites', profileGate)

  /** The caller's queue grant, or the error response. */
  async function queueGrant(c: Context): Promise<{ user: AuthUserPayload; grant: QueueGrant } | { error: Response }> {
    const user = await sessionUser(c)
    if (!user) return { error: c.json({ error: 'authentication required' }, 401) }
    const map = effectiveRbacMap(runtimeEnv(c) as Record<string, string | undefined>)
    const held = new Set(effectiveRolesOf(user).flatMap(r => map[r] ?? []))
    if (held.has('users.manage')) return { user, grant: { kind: 'wide', orgId: user.orgId ?? null } }
    if (held.has('org.users.manage')) {
      if (!user.orgId) {
        return { error: c.json({ error: 'org.users.manage requires the account to be bound to an organization' }, 403) }
      }
      return { user, grant: { kind: 'org', orgId: user.orgId } }
    }
    return { error: c.json({ error: 'missing permission: org.users.manage', permission: 'org.users.manage' }, 403) }
  }

  /** The decision audit (actor + the request + the outcome). */
  async function audit(actor: AuthUserPayload, request: OrgJoinRequest, action: string, metadata: Record<string, unknown>): Promise<void> {
    const id = crypto.randomUUID()
    await getStore().putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'org_join_requests',
      entity_id: request.id,
      action,
      user_id: actor.id,
      user_name: actor.name,
      metadata: { email: request.email, org_id: request.orgId, requested_role: request.requestedRole, ...metadata },
    }))
  }

  // ── the public selector feed ───────────────────────────────────────

  // GET /api/op/organizations — the REGISTERED participant orgs plus the
  // active OIML MEMBER orgs (TODO.identity-features/10 — the member
  // state's / corresponding member's personnel ask against their member
  // org on this same intake), each with the account roles its kind
  // bounds (the join page's selector + role options; the member kinds
  // bound the read/access posture only — the plain member's viewer,
  // never a workflow role). The register is public scheme data (B 18
  // §10.2); an UNREGISTERED org is never offered (the not-listed path
  // covers it), and a manufacturer org neither (its self-registration
  // path declares it).
  router.get('/api/op/organizations', async (c) => {
    const orgs = await listRegistryOrganizations(getStore())
    return c.json(orgs.filter(onJoinSelector).map(o => ({
      id: o.id,
      name: o.name,
      shortName: o.shortName,
      kind: o.kind,
      country: o.country,
      roles: o.roles,
    })))
  })

  // ── the public submit ──────────────────────────────────────────────

  // POST /api/op/join-requests — file the request. Three shapes:
  //   { name, email, org_id, requested_role, note? }   — a registry org
  //   { name, email, org_name_text, note? }            — the not-listed
  //                                                      path (BIML's queue)
  //   { name, email, org_kind: 'manufacturer', org_name_text, country?,
  //     note? }                                        — the manufacturer
  //                                                      path (TODO.register/01)
  router.post('/api/op/join-requests', async (c) => {
    const body = await c.req.json<{
      name?: string
      email?: string
      org_id?: string | null
      org_kind?: string | null
      org_name_text?: string | null
      country?: string | null
      requested_role?: string
      note?: string | null
    }>().catch(() => null)
    const name = body?.name?.trim() ?? ''
    const email = body?.email?.trim().toLowerCase() ?? ''
    if (!body || !name || !email.includes('@')) {
      return c.json({ error: 'name and a work email are required' }, 400)
    }
    const note = typeof body.note === 'string' && body.note.trim() ? body.note.trim() : null

    // The duplicate guard: one PENDING request per email (a decided
    // request never blocks a fresh ask).
    if (await getStore().findPendingOrgJoinRequestByEmail(email)) {
      return c.json({ error: 'a request from this email address is already waiting for a decision' }, 409)
    }

    const orgId = typeof body.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : null
    if (orgId) {
      // The registry path: the org must admit the join flow (an ACTIVE
      // participant org — PD-03 — or an ACTIVE manufacturer org,
      // TODO.register/01) and the role asked for must be one its kind
      // bounds (the selector offers only valid pairs — the server
      // re-checks).
      const org = await resolveRegistryOrg(getStore(), orgId)
      if (!org || !admitsJoinFlow(org)) {
        return c.json({
          error: 'that organization is not an active participant on the identity service’s organization registry and not an active manufacturer or OIML member organization either — account requests file only for those; if your organization is not listed, use the "not listed" path so BIML can verify its participation',
        }, 400)
      }
      const role = body.requested_role ?? ''
      if (!orgAssignableRoles(org).includes(role)) {
        return c.json({
          error: `role '${role}' is not one a ${org.kind} organization's staff holds (assignable: ${orgAssignableRoles(org).join(', ')})`,
        }, 400)
      }
      const request = await getStore().createOrgJoinRequest({
        name, email, orgId, orgNameText: null, requestedRole: role, note,
      })
      return c.json(request, 201)
    }

    // ── the manufacturer path (TODO.register/01): "my organization
    //    manufactures measuring instruments". The org row is the
    //    SELF-REGISTRATION: an existing ACTIVE manufacturer org whose
    //    declared email-domain hint matches the requester's work-email
    //    domain takes the request (its own administrator decides, the
    //    member's 'applicant' role); otherwise the org is CREATED with
    //    the manufacturer kind and the DECLARED standing (the founder's
    //    work email declares the domain hint — the enrollment ceremony
    //    proves the mailbox), and the founder's ask (org_admin, fixed
    //    honestly) lands with BIML like the not-listed path's. A
    //    manufacturer org NEVER gains the participant standing — the
    //    kind's honesty is the scheme's liability shield.
    const orgKind = typeof body.org_kind === 'string' && body.org_kind.trim() ? body.org_kind.trim() : null
    if (orgKind) {
      if (orgKind !== 'manufacturer') {
        return c.json({
          error: `the self-service intake declares only the manufacturer kind ('${orgKind}' asked) — OIML-CS participation (an issuing authority, a test laboratory, a utilizer, an associate) is verified by BIML through the "not listed" path (PD-03/PD-09)`,
        }, 400)
      }
      const orgNameText = typeof body.org_name_text === 'string' && body.org_name_text.trim() ? body.org_name_text.trim() : null
      if (!orgNameText) {
        return c.json({ error: 'name your manufacturing organization' }, 400)
      }
      const country = typeof body.country === 'string' && body.country.trim() ? body.country.trim() : null
      const store = getStore()

      // Join on the declared email-domain hint (a hint, never the proof —
      // the org's administrator decides). A case-insensitive exact name
      // match wins among the domain's orgs; a single domain match stands
      // alone.
      const domain = emailDomain(email)
      const domainMatches = domain
        ? (await listRegistryOrganizations(store)).filter(o => o.kind === 'manufacturer' && o.state === 'active' && o.emailDomain === domain)
        : []
      const match = domainMatches.find(o => o.name.toLowerCase() === orgNameText.toLowerCase()) ?? domainMatches[0] ?? null
      if (match) {
        const request = await store.createOrgJoinRequest({
          name, email, orgId: match.id, orgNameText: null, requestedRole: 'applicant', note,
        })
        return c.json({ ...request, organization: { id: match.id, name: match.name, created: false } }, 201)
      }

      // Create the org with the declared standing. The audit row carries
      // the SELF-REGISTRATION act (no session yet — the founder's
      // name/email are the actor, the enrollment proves the mailbox).
      const id = await mintManufacturerOrgId(store, orgNameText)
      const org = await store.createOrgRegistryOrg({
        id, name: orgNameText, shortName: null, kind: 'manufacturer', country,
        contacts: [{ name, email }], participantRef: null, createdBy: email,
      })
      if (!org) {
        return c.json({ error: `the organization id '${id}' was taken while filing — file the request again` }, 409)
      }
      const auditId = crypto.randomUUID()
      await store.putEntity('auditEvents', auditId, null, JSON.stringify({
        id: auditId,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: 'organization',
        entity_id: id,
        action: 'organization.added',
        user_id: email,
        user_name: name,
        metadata: { name: orgNameText, kind: 'manufacturer', participant_ref: null, self_registered: true, email },
      }))
      const request = await store.createOrgJoinRequest({
        name, email, orgId: id, orgNameText: null, requestedRole: 'org_admin', note,
      })
      return c.json({ ...request, organization: { id, name: orgNameText, created: true } }, 201)
    }

    // The not-listed path: BIML's new-organizations queue. The requester
    // becomes the org's ADMINISTRATOR after BIML verifies the
    // participation (requested_role is fixed, honestly).
    const orgNameText = typeof body.org_name_text === 'string' && body.org_name_text.trim() ? body.org_name_text.trim() : null
    if (!orgNameText) {
      return c.json({ error: 'name your organization, or pick it from the register' }, 400)
    }
    const request = await getStore().createOrgJoinRequest({
      name, email, orgId: null, orgNameText, requestedRole: 'org_admin', note,
    })
    return c.json(request, 201)
  })

  // ── the queues ─────────────────────────────────────────────────────

  // GET /api/op/join-requests?scope=pending|all|unregistered — the org
  // admin reads its own org's queue (the scope query is IGNORED for the
  // org grant — the slice is the org's, never wider); the scheme
  // operator reads all (default), pending, or the unregistered queue.
  // The envelope carries the caller's GRANT so the console renders its
  // audience's sections without guessing from roles.
  router.get('/api/op/join-requests', async (c) => {
    const gate = await queueGrant(c)
    if ('error' in gate) return gate.error
    const { grant } = gate
    const store = getStore()

    const rows = grant.kind === 'org'
      ? await store.listOrgJoinRequests({ scope: 'org', orgId: grant.orgId! })
      : c.req.query('scope') === 'unregistered'
        ? await store.listOrgJoinRequests({ scope: 'unregistered' })
        : c.req.query('scope') === 'pending'
          ? await store.listOrgJoinRequests({ scope: 'all', status: 'pending' })
          : await store.listOrgJoinRequests({ scope: 'all' })

    // The email-domain HINT per org-bound row (a hint for the deciding
    // admin, never the proof) + the org's display name.
    const orgs = await listRegistryOrganizations(store)
    const byId = new Map(orgs.map(o => [o.id, o]))
    return c.json({
      grant: grant.kind,
      orgId: grant.kind === 'org' ? grant.orgId : null,
      orgName: grant.kind === 'org' ? byId.get(grant.orgId!)?.name ?? grant.orgId : null,
      requests: rows.map(r => ({
        ...r,
        orgName: r.orgId ? byId.get(r.orgId)?.name ?? r.orgId : null,
        orgKind: r.orgId ? byId.get(r.orgId)?.kind ?? null : null,
        emailDomainMatch: r.orgId && byId.has(r.orgId) ? emailDomainHint(byId.get(r.orgId)!, r.email) : null,
      })),
    })
  })

  /** Resolve the pending request + the scope check for a decision
   *  route. Answers the error response when the decision may not run. */
  async function decidable(c: Context, grant: QueueGrant): Promise<{ request: OrgJoinRequest } | { error: Response }> {
    const request = await getStore().getOrgJoinRequest(c.req.param('id')!)
    if (!request) return { error: c.json({ error: 'not found' }, 404) }
    // The org grant decides ONLY its own org's rows — a row of another
    // org (or BIML's unregistered queue) is not found, never wider.
    if (grant.kind === 'org' && request.orgId !== grant.orgId) {
      return { error: c.json({ error: 'not found' }, 404) }
    }
    if (request.status !== 'pending') {
      return { error: c.json({ error: `this request was already ${request.status}` }, 409) }
    }
    return { request }
  }

  // POST /api/op/join-requests/:id/approve — the invite is issued (the
  // 02 enrollment seam) and the row decided. For the UNREGISTERED queue
  // (BIML only) the body names the now-registered org ({ org_id }) — the
  // eligibility rule applies (a still-unregistered org is refused).
  router.post('/api/op/join-requests/:id/approve', async (c) => {
    const gate = await queueGrant(c)
    if ('error' in gate) return gate.error
    const { user, grant } = gate
    const found = await decidable(c, grant)
    if ('error' in found) return found.error
    const request = found.request
    const store = getStore()

    // The approval's org + role: org-bound rows approve as asked (the
    // role re-validated against the org's kind — the registry may have
    // moved since the ask); the unregistered queue approves onto the
    // body's org as its ADMINISTRATOR.
    let orgId = request.orgId
    let role = request.requestedRole
    if (!orgId) {
      const body = await c.req.json<{ org_id?: string }>().catch(() => null)
      orgId = typeof body?.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : null
      role = 'org_admin'
      if (!orgId) {
        return c.json({ error: 'approve with the organization’s registry id (org_id) once its organization is added and active' }, 400)
      }
    }
    const org = await resolveRegistryOrg(store, orgId)
    if (!org || !admitsJoinFlow(org)) {
      return c.json({
        error: `organization '${orgId}' is not an active participant on the organization registry and not an active manufacturer or OIML member organization either — accounts are created only for those (PD-03 / B 18:2025 §10.2 for the participant kinds; TODO.register/01 for the manufacturer; TODO.identity-features/10 for the member category); the identity administrator adds/activates it on the Organizations surface first`,
      }, 400)
    }
    if (role !== 'org_admin' && !orgAssignableRoles(org).includes(role)) {
      return c.json({
        error: `role '${role}' is not one a ${org.kind} organization's staff holds — refuse the request and ask the requester to re-apply`,
      }, 400)
    }

    // TODO.identity/11 — the EXISTING account joins the org (the
    // multi-org model): no second account, no enrollment link. The
    // membership lands directly ACTIVE — the holder asked, the org's
    // admin approved: both consents are on record. An existing
    // membership decides honestly: the ACTIVE one is the conflict; the
    // invited one settles (both consents now present); the disabled one
    // is the org's deliberate re-admission (the role set follows the
    // approval).
    const existingAccount = await store.findUserByEmail(request.email)
    if (existingAccount) {
      const existingMembership = await store.getOrgMembership(existingAccount.id, orgId)
      if (existingMembership?.state === 'active') {
        return c.json({ error: `${request.email} already holds an active membership in this organization` }, 409)
      }
      if (existingMembership) {
        await store.setOrgMembershipRoles(existingAccount.id, orgId, [role])
        await store.setOrgMembershipState(existingAccount.id, orgId, 'active', user.email)
      } else {
        const created = await store.createOrgMembership({
          userId: existingAccount.id, orgId, roles: [role], state: 'active', invitedBy: user.email,
        })
        if (!created) {
          // A concurrent approval created it first — settle honestly.
          await store.setOrgMembershipRoles(existingAccount.id, orgId, [role])
          await store.setOrgMembershipState(existingAccount.id, orgId, 'active', user.email)
        }
      }
      const decided = await store.decideOrgJoinRequest(request.id, {
        status: 'approved',
        decidedBy: user.email,
        invitedUserId: existingAccount.id,
      })
      if (!decided) return c.json({ error: 'this request was already decided' }, 409)
      await audit(user, request, 'org_join_request.approved', {
        invited_user_id: existingAccount.id,
        role,
        org_id: orgId,
        existing_account: true,
      })
      return c.json({
        ...decided,
        membership: { userId: existingAccount.id, orgId, roles: [role], state: 'active' },
      })
    }

    // The invite (the TODO.identity/02 enrollment seam, bound for real):
    // an OP password account with the role set + the org binding, and
    // the one-time 24 h setup link — EMAILED when a mail provider is
    // configured (TODO.identity/09), shown to the deciding admin ONCE
    // for the out-of-band handover when it is not (the response's mail
    // block says which happened). A known email is the honest conflict —
    // never a silent second account.
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    const invite = await issueAccountInvite(store, {
      email: request.email,
      name: request.name,
      role,
      roles: [role],
      orgId,
      invitedBy: user.email,
      issuer,
    })
    if (!invite) {
      return c.json({ error: `an account with email ${request.email} already exists` }, 409)
    }

    const decided = await store.decideOrgJoinRequest(request.id, {
      status: 'approved',
      decidedBy: user.email,
      invitedUserId: invite.user.id,
    })
    if (!decided) return c.json({ error: 'this request was already decided' }, 409)
    const mail = await sendOpMail(runtimeEnv<MailEnv>(c), {
      to: request.email,
      template: 'invite',
      issuer,
      params: { name: request.name, setupUrl: invite.setupUrl, hours: Math.round(OP_ENROLLMENT_TTL_MS / 3_600_000) },
    })
    await audit(user, request, 'org_join_request.approved', {
      invited_user_id: invite.user.id,
      role,
      org_id: orgId,
      invite_delivery: mail.sent ? 'email' : invite.delivery,
      mail_error: mail.error,
    })
    return c.json({
      ...decided,
      invite: {
        userId: invite.user.id,
        delivery: invite.delivery,
        setupUrl: invite.setupUrl,
        expiresAt: invite.expiresAt,
        mail: { posture: mail.posture, sent: mail.sent, error: mail.error },
      },
    })
  })

  // POST /api/op/join-requests/:id/refuse — the honest refusal, with a
  // reason the requester can act on (required — a reasonless refusal is
  // a dead letter).
  router.post('/api/op/join-requests/:id/refuse', async (c) => {
    const gate = await queueGrant(c)
    if ('error' in gate) return gate.error
    const { user, grant } = gate
    const found = await decidable(c, grant)
    if ('error' in found) return found.error
    const request = found.request
    const body = await c.req.json<{ reason?: string }>().catch(() => null)
    const reason = body?.reason?.trim() ?? ''
    if (!reason) return c.json({ error: 'a refusal reason is required — the requester sees it' }, 400)

    const decided = await getStore().decideOrgJoinRequest(request.id, {
      status: 'refused',
      decidedBy: user.email,
      refusalReason: reason,
    })
    if (!decided) return c.json({ error: 'this request was already decided' }, 409)
    await audit(user, request, 'org_join_request.refused', { reason })
    return c.json(decided)
  })

  // POST /api/op/org-invites — the console's direct invite (no join
  // request in flight): the org admin invites a colleague within its own
  // org (the role bounded by the org's kind, org_admin never); the
  // identity administrator creates an org admin for an ACTIVE registry
  // org (any kind — the non-participant org's delegated administrator
  // too, TODO.identity-features/05). Either way the invite is the 02
  // enrollment link — EMAILED when a provider is configured
  // (TODO.identity/09), shown once for the handover otherwise.
  router.post('/api/op/org-invites', async (c) => {
    const gate = await queueGrant(c)
    if ('error' in gate) return gate.error
    const { user, grant } = gate
    const body = await c.req.json<{ email?: string; name?: string; role?: string; org_id?: string | null }>().catch(() => null)
    const name = body?.name?.trim() ?? ''
    const email = body?.email?.trim().toLowerCase() ?? ''
    const role = body?.role ?? ''
    if (!body || !name || !email.includes('@') || !role) {
      return c.json({ error: 'name, a work email and the role are required' }, 400)
    }

    let orgId: string | null = typeof body.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : null
    if (grant.kind === 'org') {
      // The org scope pins the invite to the caller's org and bounds the
      // role by the org's kind; org_admin is never invitable here.
      if (orgId && orgId !== grant.orgId) {
        return c.json({ error: `the org-scoped grant invites only into your own organization ('${grant.orgId}')` }, 403)
      }
      orgId = grant.orgId
      if (role === 'org_admin') {
        return c.json({ error: 'the org_admin role is assigned by the scheme operator (BIML) only — one organization administrator per registered org' }, 403)
      }
    } else if (role !== 'org_admin' && !orgId) {
      // BIML inviting STAFF still names the org (an org-less staff
      // account is the account-console's own surface, not this one).
      return c.json({ error: 'org_id is required — the invite binds the account to its organization' }, 400)
    }

    const store = getStore()
    const org = orgId ? await resolveRegistryOrg(store, orgId) : null
    if (orgId && (!org || org.state !== 'active')) {
      return c.json({
        error: `organization '${orgId}' is not an active organization on the registry — accounts bind only to active registry orgs; the identity administrator adds/activates it on the Organizations surface first`,
      }, 400)
    }
    if (org && role !== 'org_admin' && !orgAssignableRoles(org).includes(role)) {
      return c.json({
        error: `role '${role}' is not one a ${org.kind ?? 'non-participant'} organization's staff holds (assignable: ${orgAssignableRoles(org).join(', ')})`,
      }, 400)
    }

    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    const invite = await issueAccountInvite(store, {
      email, name, role, roles: [role], orgId,
      invitedBy: user.email,
      issuer,
    })
    if (!invite) return c.json({ error: `an account with email ${email} already exists` }, 409)

    const mail = await sendOpMail(runtimeEnv<MailEnv>(c), {
      to: email,
      template: 'invite',
      issuer,
      params: { name, setupUrl: invite.setupUrl, hours: Math.round(OP_ENROLLMENT_TTL_MS / 3_600_000) },
    })

    // The audit rides the same journal the decisions use.
    const id = crypto.randomUUID()
    await store.putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'users',
      entity_id: invite.user.id,
      action: 'org_invite.issued',
      user_id: user.id,
      user_name: user.name,
      metadata: { email, role, org_id: orgId, invite_delivery: mail.sent ? 'email' : invite.delivery, mail_error: mail.error },
    }))
    return c.json({
      user: invite.user,
      invite: {
        delivery: invite.delivery,
        setupUrl: invite.setupUrl,
        expiresAt: invite.expiresAt,
        mail: { posture: mail.posture, sent: mail.sent, error: mail.error },
      },
    }, 201)
  })

  return router
}
