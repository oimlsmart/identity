// ═══════════════════════════════════════════════════════════════════
// The OP's account model (TODO.identity/02) — the identity provider's
// OWN sign-in: real password accounts (invite-only) and the account
// self-service. This router is the account half of the OIDC Provider;
// routes/op.ts stays the protocol half (discovery, authorize, token,
// userinfo, the client registry), and routes/op-upstream.ts
// (TODO.identity/08) owns the linked sign-in METHODS (GitHub, OIDC
// upstreams) — the registry, the link/sign-in flows, and the account's
// links API (GET/DELETE /api/op/account/links).
//
// The surface (every path profile-gated like the OP's — a non-identity
// deployment answers 404):
//
//   POST /api/op/login                     — the password sign-in
//   POST /api/op/login/reset               — the SELF-SERVICE password
//                                            reset: emails the one-time
//                                            link when a mail provider is
//                                            configured (the answer never
//                                            reveals whether the account
//                                            exists); 503 honestly when no
//                                            mailer can carry it
//   POST /api/op/accounts                  — the invite (admin): create
//                                            the account + its one-time
//                                            24 h setup link (optionally
//                                            org-bound + per-client roles)
//   GET  /api/op/accounts                  — the registry list (admin):
//                                            EVERY sign-in account (the OP's
//                                            password accounts + the demo
//                                            cast — TODO.identity-features/06)
//                                            with the per-client roles + the
//                                            last sign-in; the erased
//                                            tombstones stay out
//   PUT  /api/op/accounts/:id              — the edit act (name, email)
//   DELETE /api/op/accounts/:id            — the ERASURE act (admin): the
//                                            offboarding runbook's delete
//                                            path — every credential, link
//                                            and token removed, the row
//                                            anonymized in place (the audit
//                                            chain's entity_id resolves to
//                                            the tombstone)
//   PUT  /api/op/accounts/:id/client-roles/:clientId   — assign the
//                                            account's roles for ONE
//                                            registered client ([] = the
//                                            explicit none)
//   DELETE /api/op/accounts/:id/client-roles/:clientId — clear the
//                                            per-client assignment (the
//                                            account default is restored)
//   POST /api/op/accounts/:id/status       — deactivate/reactivate:
//                                            honest (the row stays, sign-ins
//                                            refuse, sessions + issued
//                                            tokens are revoked)
//   POST /api/op/accounts/:id/enrollment   — a fresh setup link
//   GET  /api/op/enroll/:token             — the setup page's context
//   POST /api/op/enroll/:token             — set the password (consumes
//                                            the link atomically)
//   GET  /api/op/account                   — the account console's context
//                                            (account + verification state,
//                                            passwordSet, sessions, the
//                                            pending email change, the
//                                            avatar feature's availability)
//   POST /api/op/account/profile           — the display-name edit
//   PUT  /api/op/account/avatar            — the avatar upload (size-capped,
//                                            the four raster types, the
//                                            bytes sniffed against the
//                                            declaration)
//   GET  /api/op/account/avatar            — serve the session account's
//                                            avatar (the user menu, the
//                                            console, the consent page)
//   DELETE /api/op/account/avatar          — remove the uploaded avatar
//                                            (the initials stand in again)
//   POST /api/op/account/email             — request the email change
//                                            (mints the one-time link;
//                                            shown on screen until
//                                            TODO.identity/09's mailer)
//   GET  /api/op/email-change/:token       — the change page's context
//   POST /api/op/email-change/:token       — complete the change (consumes
//                                            the link atomically)
//   POST /api/op/account/emails            — TODO.identity-features/01:
//                                            ADD an additional address
//                                            (lands unverified; the
//                                            verification link travels by
//                                            mail only, honestly
//                                            'unavailable' with no mailer)
//   POST /api/op/account/emails/:email/verification
//                                          — resend the added address's
//                                            verification link
//   POST /api/op/account/emails/primary    — promote a VERIFIED
//                                            additional to primary (the
//                                            old primary stays a verified
//                                            additional)
//   DELETE /api/op/account/emails/:email   — remove an additional
//                                            address (the PRIMARY refuses
//                                            honestly: promote another
//                                            first)
//   POST /api/op/account/password          — set/change the password (every
//                                            OTHER session is revoked, the
//                                            best-practice rule)
//   DELETE /api/op/account/password        — remove the password (guarded:
//                                            one sign-in method must remain)
//   POST /api/op/account/sessions/revoke-others
//   POST /api/op/account/sessions/:id/revoke
//   GET  /api/op/account/activity          — the account's own sign-in +
//                                            security events (the OP's
//                                            audit chain, newest first)
//
// The rules that make it honest:
//   - enrollment is INVITE-ONLY (no open signup, ever — the admin or the
//     OP_ACCOUNT_SEED bootstrap mints the one-time links);
//   - the setup link is EMAILED to the account when a mail provider is
//     configured (TODO.identity/09, auth/op/mail.ts → @oimlsmart/platform-server/mailer),
//     and shown to the admin for the out-of-band handover when it is not
//     (the console posture — never a silent drop). Every sign-in
//     notifies the account holder by the same channel;
//   - passwords are policy-gated (≥ 12), PBKDF2-hashed, never logged;
//     the sign-in is timing-shaped (an unknown email pays one full-cost
//     verify — auth/passwords.ts);
//   - every state that must survive an isolate lives in D1 (the OP
//     doctrine — nothing in per-process Maps).
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { clientInfo } from '@oimlsmart/platform-server/client-info'
import { deliverEmailChangeLink, OP_EMAIL_CHANGE_TTL_MS } from '../auth/op/email-change'
import { deliverEmailVerificationLink, type EmailVerificationDelivery } from '../auth/op/emails'
import {
  mintEnrollmentToken,
  OP_ACCOUNT_PROVIDER,
  OP_ENROLLMENT_TTL_MS,
  seedOpAccountsFromEnv,
} from '../auth/op/accounts'
import { opRandomToken } from '../auth/op/keys'
import { factorCounts, MFA_PENDING_TTL_MS } from '../auth/op/factors'
import { issueAccountInvite } from '../auth/op/enrollment'
import { sendOpMail, sendOpSecurityMail, type OpMailResult } from '../auth/op/mail'
import { resolveMailerConfig, type MailEnv } from '@oimlsmart/platform-server/mailer'
import { isActiveRegistryOrg, listRegistryOrganizations, orgAssignableRoles, resolveRegistryOrg } from '../auth/org-registry'
import { seedOidcClientsFromEnv } from '../auth/op/registry'
import { hashPassword, passwordPolicy, verifyPasswordLogin } from '../auth/passwords'
import { isStatusProbe } from '../auth/op/probe'
import { avatarKey, avatarKeys, avatarMaxBytes, AVATAR_TYPES, sniffAvatar } from '../auth/op/avatars'
import { getBlobStore } from '../blobs'
import { APP_ROLES } from '@oimlsmart/platform-server/vocab'
import { SESSION_COOKIE, sessionCookieOpts, sessionUser } from '@oimlsmart/platform-server/session'

type EnvLike = Record<string, string | undefined>

export function createOpAccountsRouter(): Hono {
  const accounts = new Hono()

  // ── the profile gate (the same posture as routes/op.ts: the routes
  // exist in the ONE build, the identity module decides) ──────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  accounts.use('/api/op/*', profileGate)

  /** The admin gate (the same rule as routes/op.ts's registry surface:
   *  the platform admin and the scheme operator manage accounts). */
  async function requireAdmin(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    if (user.role !== 'admin' && user.role !== 'cs_admin') {
      return { user: null, error: c.json({ error: 'administrator role required' }, 403) }
    }
    return { user, error: null }
  }

  // The bootstrap account seed runs once per process/isolate (the first
  // administrator on a fresh OP; idempotent — auth/op/accounts.ts). The
  // CLIENT registry's bootstrap (op/registry.ts) rides the same seam:
  // the registry acts below read the client registry (the per-client
  // role policy) and must see a fresh isolate's declared clients.
  let seeded: Promise<void> | null = null
  function ensureSeeded(c: Context): Promise<void> {
    if (!seeded) {
      seeded = (async () => {
        const env = runtimeEnv<EnvLike>(c)
        const issuer = resolveOpConfig(env, opRequestOrigin(c.req.raw)).issuer
        const ids = await seedOpAccountsFromEnv(env, getStore(), issuer)
        if (ids.length) console.log(`[op] account bootstrap seeded: ${ids.join(', ')}`)
        const clientIds = await seedOidcClientsFromEnv(env, getStore())
        if (clientIds.length) console.log(`[op] client registry bootstrap seeded: ${clientIds.join(', ')}`)
      })()
      seeded.catch(() => { seeded = null }) // a failed seed retries next request
    }
    return seeded
  }
  accounts.use('/api/op/*', async (c, next) => {
    await ensureSeeded(c)
    await next()
  })

  /** The account mutations' audit trail (the same discipline as
   *  routes/auth.ts's SSO audit: the audit never blocks the path).
   *  entityType stays 'account' for the registry's acts; the sign-in
   *  path's events ride 'auth' (the same journal family the upstream
   *  sign-in writes, so the account holder's own feed sees them). */
  async function audit(
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
    entityType: 'account' | 'auth' = 'account',
  ): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: entityType,
        entity_id: entityId,
        action,
        user_id: actor.userId,
        user_name: actor.userName,
        metadata,
      }))
    } catch (err) {
      console.error(`[op] account audit event ${action} failed to persist:`, (err as Error).message)
    }
  }

  // ── TODO.identity/09 — the transactional email seam ────────────────

  /** The mail outcome the invite/reset responses carry (the console
   *  surfaces it: sent / the posture / why not). */
  function mailBlock(result: OpMailResult) {
    return { posture: result.posture, sent: result.sent, error: result.error }
  }

  /** The invite / password-reset send: the setup link by email when a
   *  provider is configured; the honest console posture otherwise (the
   *  link still answers in the response — never a silent drop). */
  function sendSetupLink(
    c: Context,
    template: 'invite' | 'reset',
    input: { to: string; name: string; setupUrl: string; issuer: string },
  ): Promise<OpMailResult> {
    return sendOpMail(runtimeEnv<MailEnv>(c), {
      to: input.to,
      template,
      issuer: input.issuer,
      params: {
        name: input.name,
        setupUrl: input.setupUrl,
        hours: Math.round(OP_ENROLLMENT_TTL_MS / 3_600_000),
      },
    })
  }

  /** The new-sign-in notification: every entry tells the account holder.
   *  Never blocks the path — a mail failure is audited, never a sign-in
   *  failure. TODO.identity-features/01: the notice fans out to the
   *  primary PLUS every verified additional (the "was this you?" must
   *  reach every proven mailbox — auth/op/mail.ts's sendOpSecurityMail). */
  async function notifySignIn(c: Context, user: { id: string; email: string; name: string }): Promise<void> {
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    await sendOpSecurityMail(runtimeEnv<MailEnv>(c), getStore(), {
      userId: user.id,
      template: 'signin',
      issuer,
      params: { name: user.name, when: new Date().toISOString().slice(0, 16).replace('T', ' ') },
    })
  }

  // ── the password sign-in ───────────────────────────────────────────

  // POST /api/op/login — email + password. The failure classes are
  // deliberately indistinguishable (unknown account / no credential /
  // wrong password) AND timing-uniform (verifyPasswordLogin always runs
  // one full-cost verify — auth/passwords.ts). A deactivated account
  // with the RIGHT password gets its own honest message. Every outcome
  // lands on the audit chain: the success as account.sign_in, the
  // failures as account.sign_in_failed (the dashboard's burst signal +
  // the holder's own feed — TODO.identity-sso/01).
  // The one re-label: the estate status probe (auth/op/probe.ts — the
  // recognized X-OIML-Probe token) lands its invalid-credentials
  // failure as account.sign_in_probe instead, the honest label the
  // feeds + the burst signal exclude (the raw chain retains it). The
  // recognition NEVER changes the answer: the same uniform 401, the
  // same timing, the same write through the exercised path.
  // TODO.identity-sso/03: when the account holds factors, the password
  // alone does NOT open the session — the answer is the pending
  // second-factor challenge (one-time, short-TTL, throttled), and the
  // completion lives in routes/op-mfa.ts.
  accounts.post('/api/op/login', async (c) => {
    const body = await c.req.json<{ email?: string; password?: string }>().catch(() => null)
    if (!body || typeof body.email !== 'string' || typeof body.password !== 'string' || !body.email || !body.password) {
      return c.json({ error: 'Email and password required' }, 400)
    }
    const store = getStore()
    const cred = await store.getPasswordLogin(body.email)
    const ok = await verifyPasswordLogin(body.password, cred?.hash ?? null)
    if (!cred || !ok) {
      // The failure lands on the audit chain too (TODO.identity-sso/01's
      // failed-login signal + the holder's own security feed). The
      // caller's answer stays uniform; the journal keys on the account
      // id when the address names one (the holder then sees the attempt
      // on their own feed), else on the normalized address itself.
      // The recognized status probe's row carries the honest
      // account.sign_in_probe label instead — the recognition is read
      // AFTER the outcome is decided, so it never shapes the answer,
      // the timing, or an error path (auth/op/probe.ts's doctrine).
      const action = isStatusProbe(c.req.raw, runtimeEnv<EnvLike>(c))
        ? 'account.sign_in_probe'
        : 'account.sign_in_failed'
      await audit(action, cred?.userId ?? body.email.trim().toLowerCase(), {}, {
        method: 'password',
        email: body.email.trim().toLowerCase(),
        reason: 'invalid_credentials',
      }, 'auth')
      return c.json({ error: 'Invalid email or password' }, 401)
    }
    if (!cred.active) {
      await audit('account.sign_in_failed', cred.userId, {}, {
        method: 'password',
        email: body.email.trim().toLowerCase(),
        reason: 'deactivated',
      }, 'auth')
      return c.json({ error: 'This account is deactivated — contact your administrator.' }, 403)
    }
    // The second-factor branch (the factor registry, TODO.identity-sso/02+03):
    // a verified TOTP app or a registered passkey turns the password into
    // the FIRST leg — the session waits on the factor. The pending row's
    // amr carries the provenance so far; the completion appends the
    // factor's own. The recovery remainder rides along so the page can
    // offer the recovery floor honestly.
    const counts = await factorCounts(store, cred.userId)
    if (counts.passkeys + counts.totp > 0) {
      const mfaToken = opRandomToken()
      await store.createMfaPending({ token: mfaToken, userId: cred.userId, amr: ['pwd'], ttlMs: MFA_PENDING_TTL_MS })
      return c.json({
        mfaRequired: true,
        mfaToken,
        methods: {
          totp: counts.totp > 0,
          passkey: counts.passkeys > 0,
          recovery: counts.recoveryRemaining > 0,
        },
      })
    }
    await store.touchLastLogin(cred.userId)
    const token = await store.createSession(cred.userId, { ...clientInfo(c), amr: ['pwd'] })
    setCookie(c, SESSION_COOKIE, token, sessionCookieOpts(c))
    // Every OP-side sign-in lands on the audit chain: TODO.identity/03's
    // registry reads it back for the last-sign-in column, and
    // TODO.identity/06's console shows it on the account's activity feed.
    await audit('account.sign_in', cred.userId, { userId: cred.userId }, { method: 'password', amr: ['pwd'] })
    const user = await store.getUserById(cred.userId)
    // TODO.identity/09 — the account holder learns of every entry. The
    // notification never blocks or fails the sign-in (sendOpMail's
    // results are honest; the console posture just logs).
    if (user) await notifySignIn(c, user)
    return c.json(user)
  })

  // ── the self-service password reset (the "forgot password" path) ─────

  // POST /api/op/login/reset — the account holder's own reset request
  // (the login page's "Forgot your password?"). The doctrine:
  //   - the answer NEVER reveals whether the address names an account
  //     (the same 200 for a known, an unknown, a deactivated, or a
  //     non-OP account — enumeration buys nothing);
  //   - the reset travels BY EMAIL ONLY: the link sets a password, so
  //     showing it on screen to an unauthenticated requester would be an
  //     account-takeover door. A deployment without a mail provider
  //     answers 503 honestly and points at the administrator (whose
  //     enrollment-link re-issue is the same link, handed over in
  //     person);
  //   - the send rides the mailer's per-recipient rate limit (a
  //     rate-limited send is swallowed into the same 200 — the limiter
  //     is never an oracle either);
  //   - the link itself is 02's enrollment machinery: one-time, 24 h,
  //     atomically consumed at /op/setup.
  accounts.post('/api/op/login/reset', async (c) => {
    const body = await c.req.json<{ email?: string }>().catch(() => null)
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : ''
    if (!email || !email.includes('@') || email.length > 254) {
      return c.json({ error: 'A valid email address is required.' }, 400)
    }
    const env = runtimeEnv<MailEnv>(c)
    if (resolveMailerConfig(env).posture === 'console') {
      return c.json({
        error: 'This deployment cannot send email, so the self-service reset is unavailable. Ask your administrator for a password-reset link — it is a click for them.',
        mailAvailable: false,
      }, 503)
    }
    const store = getStore()
    // TODO.identity-features/01: the reset answers to ANY of the
    // account's VERIFIED addresses (the primary or a proven additional —
    // an unverified address never names the account). The link travels
    // to the address the request NAMED: that mailbox is the proof
    // channel (the verify-an-address ceremonies' posture, never the
    // security notices' fan-out).
    const resolved = await store.findUserByAnyEmail(email)
    // The admin row carries the provider + the active flag (the
    // session-shaped payload does not — the same read registryAccount
    // runs).
    const account = resolved ? (await store.listUsers()).find(u => u.id === resolved.id) ?? null : null
    if (account && account.provider === OP_ACCOUNT_PROVIDER && account.active) {
      const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
      const token = mintEnrollmentToken()
      await store.createEnrollmentToken({
        token,
        userId: account.id,
        createdBy: 'self-service reset',
        ttlMs: OP_ENROLLMENT_TTL_MS,
      })
      const setupUrl = setupUrlFor(c, token)
      await sendOpMail(env, {
        to: email,
        template: 'reset',
        issuer,
        params: { name: account.name, setupUrl, hours: Math.round(OP_ENROLLMENT_TTL_MS / 3_600_000) },
      })
      // The account's own activity feed shows the request (the holder
      // learns of it, whoever asked); the send's own audit rides the
      // mailer's email.* chain either way.
      await audit('account.password_reset', account.id, { userName: email }, { delivery: 'email' })
    }
    return c.json({ ok: true, message: 'If an account exists for that address, a password reset email is on its way. The link works once and lives 24 hours.' })
  })

  // ── invite-only enrollment ─────────────────────────────────────────

  /** The setup link's public URL: the OP's issuer (the deployment's
   *  declared URL; the request origin in dev) + the one-time token. */
  function setupUrlFor(c: Context, token: string): string {
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    return `${issuer}/op/setup?token=${encodeURIComponent(token)}`
  }

  // POST /api/op/accounts — the invite: create the account (email +
  // name), mint its one-time 24 h setup link. The link is EMAILED when a
  // mail provider is configured (TODO.identity/09) and shown to the
  // admin for the out-of-band handover when it is not — the response's
  // `mail` block says which happened, honestly.
  // TODO.identity/03: the invite rides 02's issueAccountInvite seam (the
  // org binding + the full role set), and may carry the account's
  // PER-CLIENT role assignments (client_roles) — each validated against
  // the client registry's claims policy (a role the client is not
  // configured to receive is refused, naming the policy).
  accounts.post('/api/op/accounts', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<{
      email?: string
      name?: string
      role?: string
      roles?: string[]
      org_id?: string | null
      client_roles?: Array<{ client_id?: string; roles?: string[] }>
    }>().catch(() => null)
    if (!body || typeof body.email !== 'string' || !body.email.includes('@') || typeof body.name !== 'string' || !body.name.trim()) {
      return c.json({ error: 'email and name are required' }, 400)
    }
    const role = body.role ?? 'viewer' // the OP's default: no privileges beyond the account page
    if (!(APP_ROLES as readonly string[]).includes(role)) {
      return c.json({ error: `unknown role: ${role}`, knownRoles: [...APP_ROLES] }, 400)
    }
    const extras = (body.roles ?? []).filter(r => r !== role)
    for (const r of extras) {
      if (!(APP_ROLES as readonly string[]).includes(r)) {
        return c.json({ error: `unknown role: ${r}`, knownRoles: [...APP_ROLES] }, 400)
      }
    }
    const store = getStore()

    // The org binding (TODO.identity/10's topology,
    // TODO.identity-features/05's registry): a provided org must be an
    // ACTIVE organization on the identity service's own registry.
    const orgId = typeof body.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : null
    if (orgId && !(await isActiveRegistryOrg(store, orgId))) {
      return c.json({
        error: `organization '${orgId}' is not an active organization on the registry — accounts bind only to active registry orgs; the identity administrator adds/activates it on the Organizations surface first`,
      }, 400)
    }

    // The per-client assignments, validated BEFORE the account exists:
    // the client must be registered, the roles in the platform
    // vocabulary, and within the client's policy allowlist when it
    // declares one.
    const clientRoles = body.client_roles ?? []
    for (const [i, entry] of clientRoles.entries()) {
      const clientId = typeof entry?.client_id === 'string' ? entry.client_id.trim() : ''
      const entryRoles = Array.isArray(entry?.roles) ? entry.roles.filter((r): r is string => typeof r === 'string') : null
      if (!clientId || !entryRoles) {
        return c.json({ error: `client_roles[${i}] needs client_id + a roles list ([] = explicitly none)` }, 400)
      }
      const refusal = await clientRolesRefusal(store, clientId, entryRoles)
      if (refusal) return c.json({ error: refusal.error }, refusal.status)
    }

    const email = body.email.trim().toLowerCase()
    if (await store.findUserByEmail(email)) {
      return c.json({ error: `an account with email ${email} already exists` }, 409)
    }
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    const invite = await issueAccountInvite(store, {
      email,
      name: body.name.trim(),
      role,
      roles: [role, ...extras],
      orgId,
      invitedBy: gate.user.email,
      issuer,
    })
    if (!invite) return c.json({ error: `an account with email ${email} already exists` }, 409)
    for (const entry of clientRoles) {
      await store.setOpClientRoles(invite.user.id, entry.client_id!.trim(), entry.roles as string[], gate.user.email)
    }
    // TODO.identity/09 — the setup link goes BY EMAIL when a provider is
    // configured; the console posture (or a failed send) leaves the link
    // in the response for the out-of-band handover, with the outcome
    // named. The invite never fails over the mail.
    const mail = await sendSetupLink(c, 'invite', { to: email, name: invite.user.name, setupUrl: invite.setupUrl, issuer })
    await audit('account.invite', invite.user.id, { userId: gate.user.id, userName: gate.user.name }, {
      email: invite.user.email,
      role,
      roles: [role, ...extras],
      org_id: orgId,
      client_roles: clientRoles.map(r => ({ client_id: r.client_id, roles: r.roles })),
      invite_delivery: mail.sent ? 'email' : invite.delivery,
      mail_error: mail.error,
    })
    return c.json({
      account: { id: invite.user.id, email: invite.user.email, name: invite.user.name, role: invite.user.role, roles: invite.user.roles, orgId: invite.user.orgId },
      setupUrl: invite.setupUrl,
      expiresAt: invite.expiresAt,
      mail: mailBlock(mail),
    }, 201)
  })

  // GET /api/op/accounts — the registry list (TODO.identity/03): EVERY
  // sign-in account on the identity service with its sign-in posture, its
  // PER-CLIENT role assignments, and the last sign-in (never any
  // credential material). TODO.identity-features/06: the list is the
  // admin's "who can sign in" audit, so it answers the demo cast
  // (provider 'demo') alongside the OP's own password accounts — the demo
  // personas ARE sign-in accounts on a demo-postured deployment, and
  // filtering them out had the console declare "no accounts yet" over
  // accounts that exist. The erased tombstones (provider 'erased') never
  // resurface. The last sign-in prefers the audit chain; the demo
  // sign-in never journals there, so its rows fall back to the account's
  // own last-login stamp. The ACTS below stay scoped to the OP's own
  // accounts (registryAccount) — the demo cast is seed-managed.
  accounts.get('/api/op/accounts', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const rows = (await store.listUsers()).filter(u => u.provider !== 'erased')
    const signIns = await store.lastAccountSignIns()
    const out = []
    for (const row of rows) {
      const methods = await store.countSignInMethods(row.id)
      const links = await store.listIdentityLinks(row.id)
      const clientRoles = await store.listOpClientRoles(row.id)
      out.push({
        id: row.id,
        email: row.email,
        name: row.name,
        role: row.role,
        roles: row.roles,
        orgId: row.orgId,
        active: row.active,
        provider: row.provider,
        passwordSet: methods.password,
        links: links.map(l => ({ provider: l.provider, linkedAt: l.linkedAt, linkedBy: l.linkedBy })),
        lastSignIn: signIns[row.id] ?? row.lastLogin ?? null,
        clientRoles: clientRoles.map(a => ({ clientId: a.clientId, roles: a.roles, assignedBy: a.assignedBy, updatedAt: a.updatedAt })),
      })
    }
    return c.json(out)
  })

  // ── the registry acts (TODO.identity/03) ───────────────────────────
  // The central user registry's admin acts beyond the invite: the edit,
  // the per-client role assignments, and the honest deactivation. Every
  // one is the WIDE grant's (the OP's administrator / the scheme
  // operator) — the org-scoped org_admin keeps 10's /api/users slice and
  // never reaches these (the requireAdmin gate above refuses it).

  /** The registry ACTS' scope: the OP's own accounts only (provider
   *  'password'); any other account id is not found here. The LIST above
   *  is deliberately wider (every sign-in account — the "who can sign
   *  in" audit, TODO.identity-features/06), but the acts stay here: the
   *  demo cast is seed-managed (its rows re-align at every seed, so an
   *  edit/erasure would fight the seed), and an SSO-provisioned row's
   *  credential material is not the OP's. The provider flag lives on the
   *  admin row, so the read goes through listUsers. */
  async function registryAccount(id: string) {
    const user = (await getStore().listUsers()).find(u => u.id === id) ?? null
    if (!user || user.provider !== OP_ACCOUNT_PROVIDER) return null
    return user
  }

  /** Validate a per-client assignment's role set against the client
   *  registry: the client must EXIST, the roles must be platform roles,
   *  and when the client's claims policy declares its role allowlist the
   *  set must fit inside it (the OP never emits — so never assigns — a
   *  role the client is not configured to receive). Answers the refusal
   *  ({ error, status }) or null. */
  async function clientRolesRefusal(
    store: ReturnType<typeof getStore>,
    clientId: string,
    roles: string[],
  ): Promise<{ error: string; status: 400 | 404 } | null> {
    const client = await store.getOidcClient(clientId)
    if (!client) {
      return { error: `unknown client: ${clientId} — the client registry (the instance's relying-party row) names the assignable clients`, status: 404 }
    }
    const unknown = roles.filter(r => !(APP_ROLES as readonly string[]).includes(r))
    if (unknown.length) {
      return { error: `unknown role(s): ${unknown.join(', ')}`, status: 400 }
    }
    const allowlist = client.claimsPolicy?.roles
    if (allowlist) {
      const outside = roles.filter(r => !allowlist.includes(r))
      if (outside.length) {
        return {
          error: `role(s) ${outside.map(r => `'${r}'`).join(', ')} are not in ${clientId}'s claims-policy role allowlist — the client is not configured to receive them (allowed: ${allowlist.join(', ') || 'none'})`,
          status: 400,
        }
      }
    }
    return null
  }

  // PUT /api/op/accounts/:id — the edit act: { name?, email? }. An email
  // change re-normalizes and must stay unique (the credential rows ride
  // the account id, so sign-ins follow the edit).
  accounts.put('/api/op/accounts/:id', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const target = await registryAccount(c.req.param('id'))
    if (!target) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<{ name?: string; email?: string }>().catch(() => null)
    if (!body || (body.name === undefined && body.email === undefined)) {
      return c.json({ error: 'name and/or email are required' }, 400)
    }
    const edit: { name?: string; email?: string } = {}
    if (body.name !== undefined) {
      if (typeof body.name !== 'string' || !body.name.trim()) return c.json({ error: 'name must be a non-empty string' }, 400)
      edit.name = body.name.trim()
    }
    if (body.email !== undefined) {
      if (typeof body.email !== 'string' || !body.email.includes('@')) return c.json({ error: 'email must be a valid address' }, 400)
      const email = body.email.trim().toLowerCase()
      const taken = await getStore().findUserByEmail(email)
      if (taken && taken.id !== target.id) {
        return c.json({ error: `an account with email ${email} already exists` }, 409)
      }
      edit.email = email
    }
    try {
      await getStore().updateOpAccount(target.id, edit)
    } catch (e) {
      if (String((e as Error).message).startsWith('unique:')) {
        return c.json({ error: `an account with email ${edit.email} already exists` }, 409)
      }
      throw e
    }
    await audit('account.updated', target.id, { userId: gate.user.id, userName: gate.user.name }, {
      before: { name: target.name, email: target.email },
      after: { name: edit.name ?? target.name, email: edit.email ?? target.email },
    })
    const updated = await getStore().getUserById(target.id)
    return c.json({ id: updated!.id, email: updated!.email, name: updated!.name, role: updated!.role })
  })

  // PUT /api/op/accounts/:id/client-roles/:clientId — assign the
  // account's roles for ONE registered client: { roles: [...] }. An
  // EMPTY list is the explicit "no roles on this client" (the ID token
  // carries no role claim for it — the instance's viewer/approval-queue
  // posture); DELETE clears the assignment entirely (the account's
  // OP-side default set is restored for that client).
  accounts.put('/api/op/accounts/:id/client-roles/:clientId', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const target = await registryAccount(c.req.param('id'))
    if (!target) return c.json({ error: 'not found' }, 404)
    const clientId = c.req.param('clientId')
    const body = await c.req.json<{ roles?: unknown }>().catch(() => null)
    if (!body || !Array.isArray(body.roles) || body.roles.some(r => typeof r !== 'string')) {
      return c.json({ error: 'roles must be a list of role ids ([] = explicitly none on this client)' }, 400)
    }
    const roles = [...new Set(body.roles as string[])]
    const refusal = await clientRolesRefusal(store, clientId, roles)
    if (refusal) return c.json({ error: refusal.error }, refusal.status)
    const previous = await store.getOpClientRoles(target.id, clientId)
    await store.setOpClientRoles(target.id, clientId, roles, gate.user.email)
    await audit('account.client_roles', target.id, { userId: gate.user.id, userName: gate.user.name }, {
      client_id: clientId,
      roles,
      previous,
    })
    return c.json({ userId: target.id, clientId, roles })
  })

  // DELETE /api/op/accounts/:id/client-roles/:clientId — clear the
  // per-client assignment (the account default is restored).
  accounts.delete('/api/op/accounts/:id/client-roles/:clientId', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const target = await registryAccount(c.req.param('id'))
    if (!target) return c.json({ error: 'not found' }, 404)
    const removed = await store.deleteOpClientRoles(target.id, c.req.param('clientId'))
    if (!removed) return c.json({ error: 'no assignment for this client' }, 404)
    await audit('account.client_roles_cleared', target.id, { userId: gate.user.id, userName: gate.user.name }, {
      client_id: c.req.param('clientId'),
    })
    return c.json({ ok: true })
  })

  // POST /api/op/accounts/:id/status — deactivate/reactivate: { active }.
  // The HONEST deactivation: the row stays (the history), sign-ins refuse
  // (the credential check + the session join), and the live credentials
  // are REVOKED — every session, every issued access token, every
  // unconsumed code (the counts ride the audit event). You cannot
  // deactivate your own account (the lockout guard).
  accounts.post('/api/op/accounts/:id/status', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const target = await registryAccount(c.req.param('id'))
    if (!target) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<{ active?: boolean }>().catch(() => null)
    if (!body || typeof body.active !== 'boolean') {
      return c.json({ error: 'active (boolean) is required' }, 400)
    }
    if (target.id === gate.user.id && !body.active) {
      return c.json({ error: 'you cannot deactivate your own account' }, 400)
    }
    const store = getStore()
    await store.setUserActive(target.id, body.active)
    if (!body.active) {
      const revoked = await store.revokeOpUserCredentials(target.id)
      await audit('account.deactivated', target.id, { userId: gate.user.id, userName: gate.user.name }, { revoked })
    } else {
      await audit('account.reactivated', target.id, { userId: gate.user.id, userName: gate.user.name }, {})
    }
    return c.json({ ok: true, active: body.active })
  })

  // DELETE /api/op/accounts/:id — the ERASURE act (the offboarding
  // runbook's delete path, docs/deployment/identity-operations.md):
  // deactivate preserves the account; DELETE removes the person from it.
  // Everything the account held is removed (the password credential, the
  // enrollment + email-change tokens, the linked identities, the
  // per-client role assignments, every live session/token/code, the
  // avatar's bytes) and the user row is ANONYMIZED in place — a
  // tombstone ('Deleted account', deleted-<id>@erased.invalid, provider
  // 'erased') so the audit chain's entity_id still resolves while no
  // surface lists, signs in, or administers the account again. The audit
  // journal itself STANDS (the scheme's audit evidence — the runbook):
  // its rows name the acts and the actors, and the erasure event joins
  // them. Irreversible — and you cannot erase your own account (the
  // lockout guard, same as deactivation).
  accounts.delete('/api/op/accounts/:id', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const target = await registryAccount(c.req.param('id'))
    if (!target) return c.json({ error: 'not found' }, 404)
    if (target.id === gate.user.id) {
      return c.json({ error: 'you cannot erase your own account' }, 400)
    }
    const erased = await getStore().eraseOpAccount(target.id)
    if (!erased) return c.json({ error: 'not found' }, 404)
    // The avatar's bytes go too — best-effort (a blob-store hiccup never
    // blocks the erasure; the failure is logged).
    const blobs = getBlobStore()
    if (blobs) {
      for (const key of avatarKeys(target.id)) {
        try { await blobs.delete(key) } catch (err) { console.error(`[op] erasure: avatar blob ${key} survived:`, (err as Error).message) }
      }
    }
    await audit('account.deleted', target.id, { userId: gate.user.id, userName: gate.user.name }, {
      email: target.email,
      erased,
    })
    return c.json({ ok: true })
  })

  // POST /api/op/accounts/:id/enrollment — a FRESH one-time setup link
  // (the first one expired, or the account needs a password reset: the
  // link sets the password either way). TODO.identity/09: the link goes
  // BY EMAIL (the reset template) when a provider is configured; the
  // `mail` block says which happened and the link always answers for
  // the handover fallback.
  accounts.post('/api/op/accounts/:id/enrollment', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const token = mintEnrollmentToken()
    const enrollment = await store.createEnrollmentToken({
      token,
      userId: user.id,
      createdBy: gate.user.email,
      ttlMs: OP_ENROLLMENT_TTL_MS,
    })
    const setupUrl = setupUrlFor(c, token)
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    const mail = await sendSetupLink(c, 'reset', { to: user.email, name: user.name, setupUrl, issuer })
    await audit('account.enrollment', user.id, { userId: gate.user.id, userName: gate.user.name }, {
      email: user.email,
      link_delivery: mail.sent ? 'email' : 'enrollment-link',
      mail_error: mail.error,
    })
    return c.json({ setupUrl, expiresAt: enrollment.expiresAt, mail: mailBlock(mail) }, 201)
  })

  // GET /api/op/enroll/:token — the setup page's context (public): the
  // account it sets up + the honest state of the link. NEVER anything
  // beyond name/email.
  accounts.get('/api/op/enroll/:token', async (c) => {
    const store = getStore()
    const row = await store.getEnrollmentToken(c.req.param('token'))
    if (!row) {
      return c.json({ error: 'unknown', error_description: 'This setup link is not valid. Ask your administrator for a new one.' }, 404)
    }
    if (row.consumedAt) {
      return c.json({ error: 'used', error_description: 'This setup link was already used. Sign in, or ask your administrator for a new one.' }, 410)
    }
    if (new Date(row.expiresAt).getTime() <= Date.now()) {
      return c.json({ error: 'expired', error_description: 'This setup link has expired (setup links live 24 hours). Ask your administrator for a fresh one.' }, 410)
    }
    const user = await store.getUserById(row.userId)
    if (!user) {
      return c.json({ error: 'unknown', error_description: 'This setup link is not valid. Ask your administrator for a new one.' }, 404)
    }
    return c.json({ name: user.name, email: user.email, expiresAt: row.expiresAt })
  })

  // POST /api/op/enroll/:token — set the password. The policy is judged
  // BEFORE the link is touched (a refused password never burns it); the
  // completion consumes it atomically (one-time means one-time).
  accounts.post('/api/op/enroll/:token', async (c) => {
    const body = await c.req.json<{ password?: string }>().catch(() => null)
    if (!body || typeof body.password !== 'string') {
      return c.json({ error: 'password is required' }, 400)
    }
    const policy = passwordPolicy(body.password)
    if (!policy.ok) {
      return c.json({ error: `The password needs ${policy.problems.join(' and ')}.` }, 400)
    }
    const store = getStore()
    const result = await store.completeEnrollment(c.req.param('token'), await hashPassword(body.password), 'enrollment')
    if (result.kind === 'expired') {
      return c.json({ error: 'This setup link has expired (setup links live 24 hours). Ask your administrator for a fresh one.' }, 410)
    }
    if (result.kind !== 'ok') {
      return c.json({ error: 'This setup link is not valid or was already used. Ask your administrator for a new one.' }, 410)
    }
    const token = await store.createSession(result.userId, clientInfo(c))
    await store.touchLastLogin(result.userId)
    setCookie(c, SESSION_COOKIE, token, sessionCookieOpts(c))
    await audit('account.enrolled', result.userId, { userId: result.userId }, {})
    return c.json(await store.getUserById(result.userId))
  })

  // ── the account self-service (TODO.identity/02 + the 06 console) ───

  // GET /api/op/account — the account console's context: the account (with
  // the primary address's verification state and the avatar), the password
  // state, the live sessions (with their sign-in context), and the pending
  // email change when one exists. The linked identities ride
  // TODO.identity/08's /api/op/account/links. NEVER credential material,
  // never session tokens.
  // TODO.identity/11: the ORGANIZATIONS block — the account's memberships
  // (every state, with the register's display names), the session's
  // active-org stamp + the effective org the claims carry, and the
  // account's own join requests (the membership-request path's state).
  accounts.get('/api/op/account', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const store = getStore()
    const sessionToken = getCookie(c, SESSION_COOKIE) ?? ''
    const [methods, sessions, pendingEmailChange, memberships, activeOrg, emails] = await Promise.all([
      store.countSignInMethods(user.id),
      store.listUserSessions(user.id, sessionToken),
      store.getPendingEmailChange(user.id),
      store.listOrgMemberships(user.id),
      store.getSessionActiveOrg(sessionToken),
      // TODO.identity-features/01: every address of the account (the
      // primary first) with its verification state — the console's
      // EMAILS section reads it.
      store.listAccountEmails(user.id),
    ])
    // The register resolves the display names; the account's own join
    // requests (by email — the row names the requester) show the ask's
    // state honestly.
    const orgs = memberships.length ? await listRegistryOrganizations(store) : []
    const byId = new Map(orgs.map(o => [o.id, o]))
    const ownRequests = (await store.listOrgJoinRequests({ scope: 'all' }))
      .filter(r => r.email === user.email)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    return c.json({
      account: {
        id: user.id,
        email: user.email,
        emailVerifiedAt: user.emailVerifiedAt ?? null,
        name: user.name,
        role: user.role,
        avatarUrl: user.avatarUrl ?? null,
      },
      passwordSet: methods.password,
      sessions,
      emails: emails.map(e => ({
        email: e.email,
        isPrimary: e.isPrimary,
        verifiedAt: e.verifiedAt,
        createdAt: e.createdAt,
      })),
      pendingEmailChange: pendingEmailChange
        ? { newEmail: pendingEmailChange.newEmail, expiresAt: pendingEmailChange.expiresAt, delivery: pendingEmailChange.deliveredBy }
        : null,
      organizations: {
        // The session's stamp (null = the primary context) and the
        // EFFECTIVE org the session's claims carry right now (the
        // context rule's answer — a disabled membership's stamp never
        // survives a read).
        activeOrg,
        effectiveOrg: user.orgId,
        memberships: memberships.map(m => ({
          orgId: m.orgId,
          orgName: byId.get(m.orgId)?.name ?? m.orgId,
          orgKind: byId.get(m.orgId)?.kind ?? null,
          roles: m.roles,
          state: m.state,
          isPrimary: m.isPrimary,
          invitedBy: m.invitedBy,
          createdAt: m.createdAt,
          disabledAt: m.disabledAt,
          disabledBy: m.disabledBy,
        })),
        requests: ownRequests.map(r => ({
          id: r.id,
          orgId: r.orgId,
          orgName: r.orgId ? byId.get(r.orgId)?.name ?? r.orgId : null,
          orgNameText: r.orgNameText,
          requestedRole: r.requestedRole,
          status: r.status,
          refusalReason: r.refusalReason,
          createdAt: r.createdAt,
          decidedAt: r.decidedAt,
        })),
      },
      // The avatar upload's availability + its limit, so the console can
      // render the feature HONESTLY: hidden where no blob store is bound
      // (a Worker without the R2 binding; BLOBS_DISABLED on node), the
      // real byte cap named where it shows.
      features: {
        avatarUploads: !!getBlobStore(),
        avatarMaxBytes: avatarMaxBytes(runtimeEnv<EnvLike>(c)),
      },
    })
  })

  // ── the avatar (the profile card's picture) ─────────────────────────
  // The upload/download/remove trio over the document-store seam
  // (server/blobs.ts), the limits in auth/op/avatars.ts: 2 MiB by default,
  // the four raster types only (SVG never — an image channel must not
  // become a script channel), and the bytes sniffed against the declared
  // Content-Type. The serving URL is the account's OWN route below, so a
  // stored avatar never depends on an outside provider's availability.

  // PUT /api/op/account/avatar — the upload (the raw body, the document
  //  store's POSTure). Replaces the current avatar (the other extensions'
  //  keys are deleted — at most one avatar blob exists per account).
  accounts.put('/api/op/account/avatar', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const blobs = getBlobStore()
    if (!blobs) {
      return c.json({
        error: 'no blob store is bound on this deployment — avatar uploads are unavailable (the account shows the linked provider’s picture, or the initials)',
        available: false,
      }, 503)
    }
    const max = avatarMaxBytes(runtimeEnv<EnvLike>(c))
    const declared = Number(c.req.header('content-length') ?? 0)
    if (declared > max) {
      // Refuse on the DECLARED length (a lying client never streams
      // into memory) — but DRAIN the body before answering: a 413
      // returned with the request stream unread wedges the dev proxy
      // (the vite '/api' relay surfaces the early answer as a 502 to
      // the browser / an EPIPE to undici instead of the honest 413 —
      // the id-06 leg-6 race, observed byte-identical on v2's own CI).
      // Discard streaming, never buffered; a client that goes away
      // mid-drain is fine.
      try {
        const body = c.req.raw.body
        if (body) for await (const _ of body) { /* discard */ }
      } catch { /* the client tearing down mid-drain still earns the 413 */ }
      return c.json({ error: `the picture exceeds the ${Math.round(max / 1024 / 1024)} MB avatar limit`, maxBytes: max }, 413)
    }
    const contentType = c.req.header('content-type')?.split(';')[0]?.trim().toLowerCase() ?? ''
    if (!AVATAR_TYPES[contentType]) {
      return c.json({ error: `the picture must be a PNG, JPEG, WebP or GIF image (received ${contentType || 'no content type'})`, allowed: Object.keys(AVATAR_TYPES) }, 415)
    }
    const data = await c.req.arrayBuffer()
    if (data.byteLength > max) {
      return c.json({ error: `the picture exceeds the ${Math.round(max / 1024 / 1024)} MB avatar limit`, maxBytes: max }, 413)
    }
    if (data.byteLength === 0) return c.json({ error: 'the upload is empty' }, 400)
    // The BYTES decide, not the label: the payload must sniff as the
    // declared type (a renamed executable with an image/* header never
    // reaches storage).
    if (sniffAvatar(data) !== contentType) {
      return c.json({ error: 'the file’s bytes do not match its declared image type — upload the picture itself' }, 415)
    }
    const key = avatarKey(user.id, contentType)
    for (const sibling of avatarKeys(user.id)) {
      if (sibling !== key) await blobs.delete(sibling)
    }
    await blobs.put(key, data, contentType)
    const avatarUrl = '/api/op/account/avatar'
    await getStore().setUserAvatar(user.id, avatarUrl)
    await audit('account.avatar', user.id, { userId: user.id, userName: user.name }, { size: data.byteLength, type: contentType })
    return c.json({ ok: true, avatarUrl, size: data.byteLength, type: contentType })
  })

  // GET /api/op/account/avatar — the session account's own avatar. The
  // <img> surfaces (the console, the header's user menu, the consent
  // page) are same-origin and session-bound, so the URL names no account
  // — it only ever serves "me". 404 when no upload exists (the initials
  // stand in); 503 when no blob store is bound (the bytes are
  // unavailable, honestly).
  accounts.get('/api/op/account/avatar', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const blobs = getBlobStore()
    if (!blobs) return c.json({ error: 'no blob store is bound on this deployment', available: false }, 503)
    for (const key of avatarKeys(user.id)) {
      const obj = await blobs.get(key)
      if (!obj) continue
      c.header('content-type', obj.contentType ?? 'application/octet-stream')
      c.header('content-length', String(obj.size))
      c.header('x-content-type-options', 'nosniff')
      c.header('cache-control', 'private, no-cache')
      return c.body(obj.data)
    }
    return c.json({ error: 'no avatar is stored for this account' }, 404)
  })

  // DELETE /api/op/account/avatar — remove the uploaded picture (the
  // linked provider's picture or the initials stand in again).
  accounts.delete('/api/op/account/avatar', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const blobs = getBlobStore()
    if (!blobs) return c.json({ error: 'no blob store is bound on this deployment', available: false }, 503)
    for (const key of avatarKeys(user.id)) await blobs.delete(key)
    await getStore().setUserAvatar(user.id, null)
    await audit('account.avatar_removed', user.id, { userId: user.id, userName: user.name }, {})
    return c.json({ ok: true })
  })


  // POST /api/op/account/profile — the display-name edit. The name is the
  // only self-service profile field; the email moves through the
  // verify-new-email ceremony below, the role stays admin-managed.
  accounts.post('/api/op/account/profile', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const body = await c.req.json<{ name?: string }>().catch(() => null)
    const name = typeof body?.name === 'string' ? body.name.trim() : ''
    if (!name) return c.json({ error: 'The display name must not be empty.' }, 400)
    if (name.length > 200) return c.json({ error: 'The display name is limited to 200 characters.' }, 400)
    if (name === user.name) return c.json({ ok: true, unchanged: true })
    await getStore().updateUserName(user.id, name)
    await audit('account.profile', user.id, { userId: user.id, userName: name }, { field: 'name' })
    return c.json({ ok: true, name })
  })

  // POST /api/op/account/email — request the email change. The address is
  // validated and checked against the account list NOW and again at
  // completion (a take-over between the two burns the link honestly). The
  // verification link travels by mail when the deployment's mailer sends
  // it (TODO.identity/09's mailer, auth/op/email-change.ts); otherwise it
  // is SHOWN to the signed-in holder, and the response says so plainly.
  accounts.post('/api/op/account/email', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const body = await c.req.json<{ email?: string }>().catch(() => null)
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : ''
    if (!email || !email.includes('@') || email.length > 254) {
      return c.json({ error: 'A valid email address is required.' }, 400)
    }
    if (email === user.email) {
      return c.json({ error: 'That is already the address on this account.' }, 400)
    }
    const store = getStore()
    if (await store.findUserByEmail(email)) {
      return c.json({ error: `Another account already uses ${email}.` }, 409)
    }
    // TODO.identity-features/01: the account's OWN additional addresses
    // hold the address too — a "change" to one of them is a PROMOTION,
    // and the completion's cross-table conflict would burn the link
    // honestly. Name the right act now. (Another account's additional
    // still completes to the honest burn — the re-check's doctrine.)
    if ((await store.listAccountEmails(user.id)).some(e => !e.isPrimary && e.email === email)) {
      return c.json({ error: `${email} is already on this account as an additional address — make it the primary from the emails section instead.` }, 409)
    }
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    const token = mintEnrollmentToken() // the enrollment doctrine: 256-bit random, the row is its proof
    const verificationUrl = `${issuer}/op/email-change?token=${encodeURIComponent(token)}`
    const delivery = await deliverEmailChangeLink(runtimeEnv<EnvLike>(c), {
      to: email,
      name: user.name,
      issuer,
      verificationUrl,
    })
    const row = await store.createEmailChangeToken({
      token,
      userId: user.id,
      newEmail: email,
      deliveredBy: delivery,
      ttlMs: OP_EMAIL_CHANGE_TTL_MS,
    })
    await audit('account.email_change_requested', user.id, { userId: user.id, userName: user.name }, { from: user.email, to: email, delivery })
    return c.json({
      delivery,
      newEmail: row.newEmail,
      expiresAt: row.expiresAt,
      // The link rides the response ONLY when it could not be mailed; a
      // mailed link never echoes back (the mailbox is its only channel).
      ...(delivery === 'shown' ? { verificationUrl } : {}),
    }, 201)
  })

  // GET /api/op/email-change/:token — the change page's context (public,
  // the enroll context's posture): the account, the from/to addresses, the
  // honest state of the link. NEVER anything beyond name + the addresses.
  accounts.get('/api/op/email-change/:token', async (c) => {
    const store = getStore()
    const row = await store.getEmailChangeToken(c.req.param('token'))
    if (!row) {
      return c.json({ error: 'unknown', error_description: 'This verification link is not valid. Start the email change again from your account page.' }, 404)
    }
    if (row.consumedAt) {
      return c.json({ error: 'used', error_description: 'This verification link was already used. Only the newest link works; start the change again if you still need it.' }, 410)
    }
    if (new Date(row.expiresAt).getTime() <= Date.now()) {
      return c.json({ error: 'expired', error_description: 'This verification link has expired (it lives 24 hours). Start the change again from your account page.' }, 410)
    }
    const user = await store.getUserById(row.userId)
    if (!user) {
      return c.json({ error: 'unknown', error_description: 'This verification link is not valid. Start the email change again from your account page.' }, 404)
    }
    return c.json({ name: user.name, email: user.email, newEmail: row.newEmail, expiresAt: row.expiresAt, kind: row.kind })
  })

  // POST /api/op/email-change/:token — complete the change. The store
  // consumes the link ATOMICALLY first (one-time means one-time), then
  // judges expiry and the address's uniqueness; a mailed link verifies the
  // new address, a shown one applies the change with the address staying
  // unverified (auth/op/email-change.ts documents why).
  // TODO.identity-features/01: a kind 'add' link verifies the ADDED
  // address instead (the account_emails row's stamp) — the audit names
  // the ceremony that ran.
  accounts.post('/api/op/email-change/:token', async (c) => {
    // The ceremony's kind rides the token row (read before the
    // completion burns it — the row persists, the consumed stamp is the
    // one-time proof).
    const row = await getStore().getEmailChangeToken(c.req.param('token'))
    const result = await getStore().completeEmailChange(c.req.param('token'))
    if (result.kind === 'expired') {
      return c.json({ error: 'expired', error_description: 'This verification link has expired (it lives 24 hours). Start the change again from your account page.' }, 410)
    }
    if (result.kind === 'conflict') {
      return c.json({ error: 'conflict', error_description: 'Another account took this address after the change was requested. The link is void; start the change again with a different address.' }, 409)
    }
    if (result.kind !== 'ok') {
      return c.json({ error: 'used', error_description: 'This verification link is not valid or was already used. Start the change again from your account page.' }, 410)
    }
    if (row?.kind === 'add') {
      await audit('account.email_verified', result.userId, { userId: result.userId }, { email: result.newEmail, verified: result.verified })
    } else {
      await audit('account.email_changed', result.userId, { userId: result.userId }, { to: result.newEmail, verified: result.verified })
    }
    return c.json({ ok: true, email: result.newEmail, verified: result.verified, kind: row?.kind ?? 'change' })
  })

  // ── multiple emails per account (TODO.identity-features/01) ────────
  // The account carries a primary + additional addresses. Every
  // additional verifies INDEPENDENTLY (the kind 'add' ceremony above);
  // the sign-in + the recovery paths answer to ANY verified one; the
  // primary switch keeps the old primary as a verified additional; the
  // primary itself is never removed from under the holder.

  /** The per-address verification send (the add + the resend share it):
   *  the link travels BY MAIL ONLY (a mailbox proof cannot ride a
   *  screen — auth/op/emails.ts documents the departure from the change
   *  flow's shown-link posture); the token mints ONLY on a sent link. */
  async function sendEmailVerification(
    c: Context,
    user: { id: string; name: string },
    email: string,
  ): Promise<EmailVerificationDelivery> {
    const issuer = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw)).issuer
    const token = mintEnrollmentToken() // the enrollment doctrine: 256-bit random, the row is its proof
    const verificationUrl = `${issuer}/op/email-change?token=${encodeURIComponent(token)}`
    const delivery = await deliverEmailVerificationLink(runtimeEnv<EnvLike>(c), {
      to: email,
      name: user.name,
      issuer,
      verificationUrl,
      hours: Math.round(OP_EMAIL_CHANGE_TTL_MS / 3_600_000),
    })
    if (delivery !== 'mailer') return 'unavailable'
    await getStore().createEmailChangeToken({
      token,
      userId: user.id,
      newEmail: email,
      deliveredBy: 'mailer',
      kind: 'add',
      ttlMs: OP_EMAIL_CHANGE_TTL_MS,
    })
    return 'mailer'
  }

  // POST /api/op/account/emails — ADD an additional address. The row
  // lands UNVERIFIED at once (the unverified state is first-class: it
  // never signs in, never receives account mail), the verification link
  // follows by mail when the deployment can send it. A re-add of the
  // account's own row is the idempotent verification re-send.
  accounts.post('/api/op/account/emails', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const body = await c.req.json<{ email?: string }>().catch(() => null)
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : ''
    if (!email || !email.includes('@') || email.length > 254) {
      return c.json({ error: 'A valid email address is required.' }, 400)
    }
    if (email === user.email) {
      return c.json({ error: 'That is already the primary address on this account.' }, 400)
    }
    const store = getStore()
    const outcome = await store.addAccountEmail(user.id, email, user.email)
    if (outcome === 'conflict') {
      return c.json({ error: `Another account already uses ${email}.` }, 409)
    }
    const delivery = await sendEmailVerification(c, user, email)
    await audit('account.email_added', user.id, { userId: user.id, userName: user.name }, {
      email,
      delivery,
      ...(outcome === 'present' ? { reAdd: true } : {}),
    })
    return c.json({ email, verified: false, delivery }, 201)
  })

  // POST /api/op/account/emails/:email/verification — resend the added
  // address's verification link (a fresh one-time link voids the
  // address's earlier ones). The no-mailer deployment answers 503
  // honestly (the self-service reset's posture).
  accounts.post('/api/op/account/emails/:email/verification', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const email = c.req.param('email').trim().toLowerCase()
    const store = getStore()
    const row = (await store.listAccountEmails(user.id)).find(e => !e.isPrimary && e.email === email)
    if (!row) return c.json({ error: 'No such additional address on this account.' }, 404)
    if (row.verifiedAt) return c.json({ error: 'That address is already verified.' }, 409)
    const delivery = await sendEmailVerification(c, user, email)
    if (delivery !== 'mailer') {
      return c.json({
        error: 'This deployment cannot send email, so the address stays unverified. Ask your administrator to prove the mailbox out of band — or configure a mailer.',
        mailAvailable: false,
      }, 503)
    }
    await audit('account.email_verification_requested', user.id, { userId: user.id, userName: user.name }, { email, delivery })
    return c.json({ email, delivery }, 201)
  })

  // POST /api/op/account/emails/primary — the PRIMARY switch: a VERIFIED
  // additional takes over as the account's address of record (the OIDC
  // `email` claim carries it from then on); the outgoing primary stays
  // a verified additional (sign-in by it keeps working; it can be
  // removed afterwards). Registered BEFORE any :email-shaped POST so
  // the literal wins.
  accounts.post('/api/op/account/emails/primary', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const body = await c.req.json<{ email?: string }>().catch(() => null)
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : ''
    if (!email) return c.json({ error: 'email is required' }, 400)
    if (email === user.email) return c.json({ ok: true, unchanged: true })
    const store = getStore()
    const result = await store.setPrimaryAccountEmail(user.id, email)
    if (result === 'unknown') {
      return c.json({ error: 'That address is not on this account — add it first.' }, 404)
    }
    if (result === 'unverified') {
      return c.json({ error: 'Only a verified address can become the primary — open its verification link first.' }, 409)
    }
    await audit('account.email_primary_changed', user.id, { userId: user.id, userName: user.name }, { from: user.email, to: email })
    return c.json({ ok: true, email })
  })

  // DELETE /api/op/account/emails/:email — remove an ADDITIONAL address.
  // The PRIMARY refuses honestly: another verified address must be
  // promoted first (an account never loses its address of record from
  // under the holder).
  accounts.delete('/api/op/account/emails/:email', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const email = c.req.param('email').trim().toLowerCase()
    const result = await getStore().removeAccountEmail(user.id, email)
    if (result === 'primary') {
      return c.json({ error: 'The primary address is never removed. Make another verified address the primary first — then this one can go.' }, 409)
    }
    if (result === 'unknown') {
      return c.json({ error: 'No such additional address on this account.' }, 404)
    }
    await audit('account.email_removed', user.id, { userId: user.id, userName: user.name }, { email })
    return c.json({ ok: true })
  })

  // POST /api/op/account/password — set/change the password. When the
  // account already holds one, the CURRENT password must verify first
  // (one full-cost comparison either way — the timing rule holds here
  // too); the policy gates the new one. BEST PRACTICE: every OTHER
  // session of the account is revoked on the change (the response names
  // the count; the console shows it).
  accounts.post('/api/op/account/password', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const body = await c.req.json<{ current?: string; next?: string }>().catch(() => null)
    if (!body || typeof body.next !== 'string') {
      return c.json({ error: 'next (the new password) is required' }, 400)
    }
    const policy = passwordPolicy(body.next)
    if (!policy.ok) {
      return c.json({ error: `The password needs ${policy.problems.join(' and ')}.` }, 400)
    }
    const store = getStore()
    const methods = await store.countSignInMethods(user.id)
    if (methods.password) {
      const cred = await store.getPasswordLogin(user.email)
      const ok = await verifyPasswordLogin(typeof body.current === 'string' ? body.current : '', cred?.hash ?? null)
      if (!ok) return c.json({ error: 'The current password does not match.' }, 403)
    }
    await store.setPasswordHash(user.id, await hashPassword(body.next), user.email)
    const revoked = await store.deleteOtherSessions(user.id, getCookie(c, SESSION_COOKIE) ?? '')
    await audit('account.password', user.id, { userId: user.id, userName: user.name }, { otherSessionsRevoked: revoked })
    return c.json({ ok: true, otherSessionsRevoked: revoked })
  })

  // DELETE /api/op/account/password — remove the password as a sign-in
  // method. THE GUARD (the 06 rule, extended by TODO.identity-sso/02):
  // an account always keeps at least one way in — removing the password
  // while no upstream identity is linked AND no passkey is registered
  // would strand the account behind an administrator's fresh setup link,
  // so the route refuses and explains. A passkey-only account is a
  // legitimate posture (the passwordless sign-in; the email reset stands
  // behind it — never a lockout).
  accounts.delete('/api/op/account/password', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const store = getStore()
    const methods = await store.countSignInMethods(user.id)
    if (!methods.password) return c.json({ error: 'No password is set on this account.' }, 404)
    if (methods.links === 0 && methods.passkeys === 0) {
      return c.json({
        error: 'The password is your only way to sign in. Link an upstream identity (GitHub, Google, …) or register a passkey first, or keep the password — an account always keeps at least one sign-in method.',
      }, 409)
    }
    await store.deletePasswordHash(user.id)
    await audit('account.password_removed', user.id, { userId: user.id, userName: user.name }, {})
    return c.json({ ok: true })
  })

  // POST /api/op/account/sessions/revoke-others — sign out everywhere
  // else (the current session stands). Registered BEFORE the :id route
  // so the literal wins.
  accounts.post('/api/op/account/sessions/revoke-others', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const revoked = await getStore().deleteOtherSessions(user.id, getCookie(c, SESSION_COOKIE) ?? '')
    await audit('account.sessions_revoked', user.id, { userId: user.id, userName: user.name }, { count: revoked })
    return c.json({ ok: true, revoked })
  })

  // POST /api/op/account/sessions/:id/revoke — end one of the account's
  // sessions (another account's session id is a no-op by construction).
  accounts.post('/api/op/account/sessions/:id/revoke', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const revoked = await getStore().deleteSessionById(user.id, c.req.param('id'))
    if (!revoked) return c.json({ error: 'no such session' }, 404)
    await audit('account.session_revoked', user.id, { userId: user.id, userName: user.name }, { session: c.req.param('id') })
    return c.json({ ok: true })
  })

  // ── the organizations (TODO.identity/11 — the multi-org model) ───────
  // The account acts AS one org at a time (the GitHub context-switch
  // pattern): the session's active-org stamp decides which membership's
  // per-org role set the claims carry. A relying party never learns the
  // other memberships.

  // POST /api/op/account/active-org — the context switch: { org_id } names
  // an ACTIVE membership of the account (the console's switcher);
  // { org_id: null } returns to the primary context. The switch rides the
  // PRESENTING session only — the account's other sessions keep their own
  // contexts.
  accounts.post('/api/op/account/active-org', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const body = await c.req.json<{ org_id?: string | null }>().catch(() => null)
    if (!body || body.org_id === undefined) {
      return c.json({ error: 'org_id is required (null returns to the primary organization)' }, 400)
    }
    const orgId = typeof body.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : null
    const store = getStore()
    if (orgId) {
      const membership = await store.getOrgMembership(user.id, orgId)
      if (!membership) {
        return c.json({ error: 'this account holds no membership in that organization' }, 404)
      }
      if (membership.state !== 'active') {
        return c.json({
          error: membership.state === 'invited'
            ? 'the invitation is not accepted yet — accept it above first'
            : 'this membership is disabled — the organization’s administrator can re-activate it',
        }, 409)
      }
    }
    const token = getCookie(c, SESSION_COOKIE) ?? ''
    const stamped = await store.setSessionActiveOrg(token, orgId)
    if (!stamped) return c.json({ error: 'the session is no longer valid — sign in again' }, 401)
    await audit('account.active_org', user.id, { userId: user.id, userName: user.name }, { org_id: orgId })
    return c.json({ ok: true, activeOrg: orgId })
  })

  // POST /api/op/account/memberships/:orgId/accept — the holder accepts an
  // org's invitation (state invited → active). Only the account's OWN
  // invited membership, never someone else's row. The ORG's own state
  // rules too (TODO.identity-features/05): a disabled org's invitations
  // wait until the identity administrator re-enables it.
  accounts.post('/api/op/account/memberships/:orgId/accept', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const store = getStore()
    const orgId = c.req.param('orgId')
    const membership = await store.getOrgMembership(user.id, orgId)
    if (!membership) return c.json({ error: 'no membership in that organization' }, 404)
    if (membership.state !== 'invited') {
      return c.json({ error: `this membership is ${membership.state} — only an invitation can be accepted` }, 409)
    }
    const org = await store.getOrgRegistryOrg(orgId)
    if (org?.state === 'disabled') {
      return c.json({ error: `organization '${orgId}' is disabled — the invitation waits until the identity administrator re-enables the organization` }, 409)
    }
    await store.setOrgMembershipState(user.id, orgId, 'active')
    await audit('account.membership_accepted', user.id, { userId: user.id, userName: user.name }, { org_id: orgId, roles: membership.roles })
    return c.json({ ok: true, orgId, state: 'active' })
  })

  // POST /api/op/account/memberships/:orgId/decline — the holder declines
  // the invitation: the row goes away (the org's admin sees the invite
  // vanish; the audit chain records the decline).
  accounts.post('/api/op/account/memberships/:orgId/decline', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const store = getStore()
    const orgId = c.req.param('orgId')
    const membership = await store.getOrgMembership(user.id, orgId)
    if (!membership) return c.json({ error: 'no membership in that organization' }, 404)
    if (membership.state !== 'invited') {
      return c.json({ error: `this membership is ${membership.state} — only an invitation can be declined` }, 409)
    }
    await store.deleteOrgMembership(user.id, orgId)
    await audit('account.membership_declined', user.id, { userId: user.id, userName: user.name }, { org_id: orgId })
    return c.json({ ok: true, orgId })
  })

  // POST /api/op/account/membership-requests — the signed-in holder asks
  // to join ANOTHER registered organization (the account console's path;
  // the public /op/join page stays the no-account intake). The request
  // lands in the org's join-request queue (TODO.identity/10's machinery —
  // the org's administrator decides); the row names the SESSION's account
  // (name + email are never self-asserted).
  accounts.post('/api/op/account/membership-requests', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const body = await c.req.json<{ org_id?: string; requested_role?: string; note?: string | null }>().catch(() => null)
    const orgId = typeof body?.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : null
    if (!body || !orgId) return c.json({ error: 'org_id is required' }, 400)
    const store = getStore()
    const org = await resolveRegistryOrg(store, orgId)
    if (!org || !org.registered) {
      return c.json({
        error: 'that organization is not an active participant on the identity service’s organization registry — only active participant orgs can be joined (PD-03 / B 18:2025 §10.2)',
      }, 400)
    }
    const role = typeof body.requested_role === 'string' && body.requested_role.trim() ? body.requested_role.trim() : ''
    if (!orgAssignableRoles(org).includes(role)) {
      return c.json({
        error: `role '${role}' is not one a ${org.kind} organization's staff holds (assignable: ${orgAssignableRoles(org).join(', ')})`,
      }, 400)
    }
    if (await store.getOrgMembership(user.id, orgId)) {
      return c.json({ error: 'this account already holds a membership in that organization' }, 409)
    }
    if (await store.findPendingOrgJoinRequestByEmail(user.email)) {
      return c.json({ error: 'a request from this account is already waiting for a decision' }, 409)
    }
    const note = typeof body.note === 'string' && body.note.trim() ? body.note.trim() : null
    const request = await store.createOrgJoinRequest({
      name: user.name,
      email: user.email,
      orgId,
      orgNameText: null,
      requestedRole: role,
      note,
    })
    await audit('account.membership_requested', user.id, { userId: user.id, userName: user.name }, { org_id: orgId, role })
    return c.json(request, 201)
  })

  // GET /api/op/account/activity — the account's OWN sign-in + security
  // events from the OP's audit chain (the account/auth event families the
  // identity routes write), newest first, bounded. Nobody else's events
  // ever appear: the filter keys on the account's id. The status probe's
  // account.sign_in_probe rows stay out by default (the honest cadence
  // is not the holder's security news; the raw chain retains them — the
  // dashboard's queryable audit log carries them).
  accounts.get('/api/op/account/activity', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const rows = await getStore().listEntities('auditEvents')
    const events: Array<{ id: string; timestamp: string; action: string; metadata: Record<string, unknown> }> = []
    for (const row of rows) {
      try {
        const e = JSON.parse(row.data) as Record<string, unknown>
        if (e.entity_id !== user.id) continue
        if (e.entity_type !== 'account' && e.entity_type !== 'auth') continue
        if (e.action === 'account.sign_in_probe') continue
        if (typeof e.id !== 'string' || typeof e.timestamp !== 'string' || typeof e.action !== 'string') continue
        events.push({
          id: e.id,
          timestamp: e.timestamp,
          action: e.action,
          metadata: (e.metadata as Record<string, unknown> | undefined) ?? {},
        })
      } catch { /* a malformed audit row never breaks the feed */ }
    }
    events.sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    return c.json(events.slice(0, 50))
  })

  return accounts
}
