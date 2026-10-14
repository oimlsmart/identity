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
// The anonymous-intake bounds (the 2026-09-07 security cone audit's
// F10.5, smart#297 — VERIFIED, one bound added): the public submit is
// bounded by design, and each bound is deliberate —
//   - one PENDING request per email (the duplicate guard; a decided
//     request never blocks a fresh ask);
//   - the registry path admits only an ACTIVE join-flow org and a role
//     the org's kind bounds (the server re-checks what the selector
//     offers);
//   - the manufacturer path mints only the DECLARED standing — never
//     the participant standing (the kind's honesty is the scheme's
//     liability shield) — and the founder's ask lands with BIML like
//     the not-listed path's (the review gate);
//   - no account exists before the enrollment ceremony proves the
//     mailbox (the one-time 24 h setup link), so the intake can never
//     mint access;
//   - RATE-BOUND (added with this adjudication): the OP rate limiter
//     mounts on /api/op/join-requests* (app.ts) — without it the
//     anonymous submit could mint unbounded join-request and
//     manufacturer-org rows per caller. The per-caller token bucket
//     (default 120/min, honest 429 + the audit event) is the row-count
//     bound; the review gate above is the standing bound.
//
// WORKER-SAFE: the ServerStore seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload, type OrgJoinRequest } from '../store'
import { getInstanceProfile } from '../profile'
import { effectiveRbacMap } from '../rbac'
import { effectiveRolesOf } from '../vocab'
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
import { sendOpMail, sendOpSecurityMail } from '../auth/op/mail'
import type { MailEnv } from '../mailer'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { sessionUser } from '../session'

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

  /** The filing ack (the decision loop's first half, 2026-10-14): the
   *  requester learns by mail that the request stands and who decides —
   *  and a stranger whose address someone named learns it too, to
   *  ignore safely (nothing proceeds without the invitation that only
   *  their mailbox accepts). Never fails the filing (the mailer never
   *  throws); the BIML door files no ack — its setup link IS the
   *  receipt. */
  async function sendFilingAck(c: Context, input: { name: string; email: string; org: string; destination: string }): Promise<void> {
    await sendOpMail(runtimeEnv<MailEnv>(c), {
      to: input.email,
      template: 'join_received',
      issuer: opRequestOrigin(c.req.raw),
      params: {
        name: input.name,
        org: input.org,
        destination: input.destination,
        when: new Date().toISOString().slice(0, 16).replace('T', ' '),
      },
    })
  }

  /** The deciders' doorbell (the queue's other half, 2026-10-14): the
   *  people who can act learn by mail that a request waits — the org's
   *  org.users.manage holders for an org-bound request, the
   *  users.manage holders for the secretariat queues. Never fails the
   *  filing (each send is its own try; the mailer never throws). */
  async function notifyDeciders(c: Context, input: { orgId: string | null; orgName: string; requesterName: string; requesterEmail: string; role: string }): Promise<void> {
    const env = runtimeEnv<Record<string, string | undefined>>(c)
    const map = effectiveRbacMap(env)
    const users = await getStore().listUsers()
    const wanted = input.orgId
      ? users.filter(u => u.active && u.orgId === input.orgId && u.roles.some(r => (map[r] ?? []).includes('org.users.manage')))
      : users.filter(u => u.active && u.roles.some(r => (map[r] ?? []).includes('users.manage')))
    const reviewPath = input.orgId ? '/op/admin/organization' : '/op/admin/users'
    const issuer = opRequestOrigin(c.req.raw)
    for (const decider of wanted) {
      try {
        await sendOpMail(runtimeEnv<MailEnv>(c), {
          to: decider.email,
          template: 'join_admin_notice',
          issuer,
          params: {
            org: input.orgName,
            name: input.requesterName,
            from: input.requesterEmail,
            role: input.role,
            when: new Date().toISOString().slice(0, 16).replace('T', ' '),
            reviewUrl: `${issuer}${reviewPath}`,
          },
        })
      } catch {
        /* one decider's unreachable mailbox never blanks the others */
      }
    }
  }

  /** The decision audit (actor + the request + the outcome). */
  async function audit(actor: AuthUserPayload, request: OrgJoinRequest, action: string, metadata: Record<string, unknown>): Promise<void> {    const id = crypto.randomUUID()
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

  /** The door acts' audit (no request row behind them — the BIML
   *  self-invite mints an account, not a queue entry; the same
   *  auditEvents envelope, the account entity). Never throws (the
   *  admin-invite audit's posture). */
  async function auditEvent(action: string, entityId: string, userName: string, metadata: Record<string, unknown>): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: 'account',
        entity_id: entityId,
        action,
        user_id: null,
        user_name: userName,
        metadata,
      }))
    } catch (err) {
      console.error(`[op] join door audit event ${action} failed to persist:`, (err as Error).message)
    }
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
    // Public scheme data, ops-managed, rarely changed: minutes of
    // edge freshness are safe (the selector tolerates it; the submit
    // re-validates server-side), and Cloudflare's edge carries the
    // join page's repeat load.
    c.header('Cache-Control', 'public, max-age=300')
    return c.json(orgs.filter(onJoinSelector).map(o => ({
      id: o.id,
      name: o.name,
      shortName: o.shortName,
      kind: o.kind,
      country: o.country,
      roles: o.roles,
      // 0043: the org's VERIFIED email domains (the pre-approved domain
      // the join page shows and honestly compares) — public registry
      // data, ops-managed.
      email_domains: o.emailDomains,
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
      given_name?: string
      family_name?: string
      email?: string
      org_id?: string | null
      org_kind?: string | null
      org_name_text?: string | null
      country?: string | null
      requested_role?: string
      note?: string | null
    }>().catch(() => null)
    // 0043: the doors collect the structured names (the OIDC claims'
    // vocabulary); a bare `name` (the legacy/API shape) still works.
    const givenName = body?.given_name?.trim() || null
    const familyName = body?.family_name?.trim() || null
    const name = body?.name?.trim() || [givenName, familyName].filter(Boolean).join(' ').trim()
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
        name, givenName, familyName, email, orgId, orgNameText: null, requestedRole: role, note,
      })
      await sendFilingAck(c, { name, email, org: org.name, destination: "the organization's administrator" })
      await notifyDeciders(c, { orgId, orgName: org.name, requesterName: name, requesterEmail: email, role })
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
    // ── the BIML door (2026-10-13): "I work for the OIML/BIML" ─────────
    // BIML and OIML staff hold @oiml.org addresses — the domain IS the
    // claim, and the one-time enrollment link IS the mailbox proof (the
    // admin-invite ceremony, self-served). No queue row and no decision
    // wait: the account is minted UNREACHABLE (the invite posture — no
    // password until the link completes) into the operator's own org
    // with the floor role; the admins promote from there — a public
    // form never grants. The link rides the mail only, never the
    // answer. The bounds: the OP rate limiter (app.ts), Turnstile on
    // this POST, the critical mail lane's per-recipient budget, and one
    // account per address.
    if (orgKind === 'biml') {
      const declared = runtimeEnv<Record<string, string | undefined>>(c).OP_BIML_DOMAINS?.trim()
      const bimlDomains = (declared || 'oiml.org').split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
      const domain = emailDomain(email)
      if (!bimlDomains.includes(domain)) {
        return c.json({
          error: `BIML and OIML staff hold an @${bimlDomains[0] ?? 'oiml.org'} address — this door files only for those. If that is not you, go back and pick the description that matches your organization.`,
        }, 400)
      }
      if (await getStore().findUserByEmail(email)) {
        return c.json({
          error: 'you already hold an account on this service — sign in instead (the "Forgot your password?" link is on the sign-in page)',
        }, 409)
      }
      const profile = getInstanceProfile()
      const issuer = opRequestOrigin(c.req.raw)
      const invite = await issueAccountInvite(getStore(), {
        email,
        name,
        givenName,
        familyName,
        role: 'viewer',
        roles: ['viewer'],
        orgId: profile.identity.org_id,
        invitedBy: 'join-biml',
        issuer,
      })
      if (!invite) {
        return c.json({ error: 'you already hold an account on this service — sign in instead' }, 409)
      }
      // The setup link goes BY EMAIL (the admin invite's own posture —
      // the send never fails the ask; the holder retries if the mail
      // bounces). The link never rides the public answer.
      await sendOpMail(runtimeEnv<MailEnv>(c), {
        to: email,
        template: 'invite',
        issuer,
        params: {
          name,
          setupUrl: invite.setupUrl,
          hours: Math.round(OP_ENROLLMENT_TTL_MS / 3_600_000),
        },
      })
      await auditEvent('account.invite', invite.user.id, name, {
        email,
        role: 'viewer',
        roles: ['viewer'],
        org_id: profile.identity.org_id,
        invitedBy: 'join-biml',
        door: 'biml',
      })
      return c.json({ invited: true, org: profile.identity.org_name }, 201)
    }
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
          name, givenName, familyName, email, orgId: match.id, orgNameText: null, requestedRole: 'applicant', note,
        })
        await sendFilingAck(c, { name, email, org: match.name, destination: "the organization's administrator" })
        await notifyDeciders(c, { orgId: match.id, orgName: match.name, requesterName: name, requesterEmail: email, role: 'applicant' })
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
        name, givenName, familyName, email, orgId: id, orgNameText: null, requestedRole: 'org_admin', note,
      })
      await sendFilingAck(c, { name, email, org: orgNameText, destination: 'the BIML secretariat' })
      await notifyDeciders(c, { orgId: null, orgName: orgNameText, requesterName: name, requesterEmail: email, role: 'org_admin' })
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
      name, givenName, familyName, email, orgId: null, orgNameText, requestedRole: 'org_admin', note,
    })
    await sendFilingAck(c, { name, email, org: orgNameText, destination: 'the BIML secretariat' })
    await notifyDeciders(c, { orgId: null, orgName: orgNameText, requesterName: name, requesterEmail: email, role: 'org_admin' })
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
    // multi-org model): no second account, no enrollment link. THE
    // CONSENT MODEL (2026-10-13, the cold-eyes audit's finding): the
    // intake is ANONYMOUS — the filer's "the holder asked" proves
    // nothing, and an approval landing DIRECTLY ACTIVE would let an
    // org admin silently attach any account to their org. The
    // membership lands INVITED — the holder's yes is the activation
    // (the account console's Organizations section: accept / decline),
    // and the holder learns by mail. An existing ACTIVE membership is
    // the conflict; an invited or disabled one refreshes the role set
    // and waits for the holder's yes again.
    const existingAccount = await store.findUserByEmail(request.email)
    if (existingAccount) {
      const existingMembership = await store.getOrgMembership(existingAccount.id, orgId)
      if (existingMembership?.state === 'active') {
        return c.json({ error: `${request.email} already holds an active membership in this organization` }, 409)
      }
      if (existingMembership) {
        await store.setOrgMembershipRoles(existingAccount.id, orgId, [role])
        await store.setOrgMembershipState(existingAccount.id, orgId, 'invited', user.email)
      } else {
        const created = await store.createOrgMembership({
          userId: existingAccount.id, orgId, roles: [role], state: 'invited', invitedBy: user.email,
        })
        if (!created) {
          // A concurrent approval created it first — it waits for the
          // holder's yes exactly the same.
          await store.setOrgMembershipRoles(existingAccount.id, orgId, [role])
          await store.setOrgMembershipState(existingAccount.id, orgId, 'invited', user.email)
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
        consent: 'invited',
      })
      // The holder learns by mail (the account console holds the
      // accept/decline). Never blocks the act (the mailer doctrine).
      const approvedOrg = await resolveRegistryOrg(store, orgId)
      try {
        await sendOpSecurityMail(runtimeEnv<MailEnv>(c), store, {
          userId: existingAccount.id,
          template: 'membership_invited',
          issuer: resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer,
          params: {
            name: existingAccount.name,
            org: approvedOrg?.name ?? orgId,
            roles: role,
            when: new Date().toISOString().slice(0, 16).replace('T', ' '),
          },
        })
      } catch (err) {
        console.error('[op] the approval notice failed:', (err as Error).message)
      }
      return c.json({
        ...decided,
        membership: { userId: existingAccount.id, orgId, roles: [role], state: 'invited' },
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
      givenName: request.givenName,
      familyName: request.familyName,
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
    // The refusal notice (the decision loop's second half, 2026-10-14):
    // email is the only channel that reaches an account that does not
    // exist yet — the required reason travels by mail, never a silent
    // wait. Never fails the answer (the mailer never throws).
    const org = request.orgId ? await resolveRegistryOrg(getStore(), request.orgId) : null
    const refusalMail = await sendOpMail(runtimeEnv<MailEnv>(c), {
      to: request.email,
      template: 'join_refused',
      issuer: opRequestOrigin(c.req.raw),
      params: {
        name: request.name,
        org: org?.name ?? request.orgNameText ?? 'your organization',
        reason,
        when: new Date().toISOString().slice(0, 16).replace('T', ' '),
      },
    })
    await audit(user, request, 'org_join_request.refused', { reason, notice_delivery: refusalMail.sent ? 'email' : 'skipped' })
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
