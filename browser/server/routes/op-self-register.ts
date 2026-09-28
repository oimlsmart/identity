// ═══════════════════════════════════════════════════════════════════
// The Ommisa member tier's self-enrollment routes (the
// PROMPT.self-registration.md flow, rev 4):
//
//   GET  /api/op/self-register/catalog   — the bundled member-domains
//                                          projection (the pickers;
//                                          public, cached a day)
//   POST /api/op/self-register/start     — the eligibility reads (the
//                                          kill switch → Turnstile →
//                                          the pickers → the domain
//                                          resolve → the admin_queue →
//                                          the dup email) and the
//                                          attribution bounce URL.
//                                          NOTHING is written.
//   POST /api/op/self-register/verify    — the emailed token's proof
//                                          (the setup page's on-load
//                                          call): validates, creates
//                                          NOTHING, answers the
//                                          provision posture.
//   POST /api/op/self-register/complete  — the verified creation: the
//                                          account (verified by the
//                                          click), the registry roles
//                                          as the Ommisa client's
//                                          per-client assignments, the
//                                          org binding, the password,
//                                          the audit.
//
// Plus `continueSelfRegisterAttribution` — the upstream callback's
// attribute-mode continuation (op-upstream.ts): the eligibility re-runs
// FRESH at the return, the verification email goes out, the upstream
// identity is never stored, never linked.
//
// WORKER-SAFE: hono + the store seam + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import { getInstanceProfile } from '../profile'
import { resolveOpConfig, opRequestOrigin } from '../auth/op/config'
import { resolveOpSigningKey } from '../auth/op/keys'
import { turnstileEnabled, turnstileVerify } from '../auth/op/turnstile'
import { loadDomains, resolveOrg } from '../auth/op/member-domains'
import { eligibilityFor, resolveSelfRegisterConfig } from '../auth/op/self-register'
import { mintRegistrationToken, verifyRegistrationPayload } from '../auth/op/self-register-links'
import { hashPassword } from '../auth/passwords'
import { sendOpMail } from '../auth/op/mail'

type EnvLike = Record<string, string | undefined>

function selfRegisterError(c: Context, status: 400 | 403 | 404 | 429 | 503, error: string, extra?: Record<string, unknown>): Response {
  return c.json({ error, ...extra }, status)
}

/** The start leg's Turnstile: the config-gated module (OFF = passes —
 *  the dev/e2e posture; ON = the token verifies or the honest 403). */
async function turnstileGate(c: Context): Promise<Response | null> {
  const env = runtimeEnv<EnvLike>(c)
  if (!turnstileEnabled(env)) return null
  const token = c.req.header('cf-turnstile-response') ?? ''
  const ip = c.req.header('cf-connecting-ip') ?? null
  if (!token || !(await turnstileVerify(env, token, ip))) {
    return selfRegisterError(c, 403, 'the bot check did not pass — retry the check and submit again')
  }
  return null
}

export function createSelfRegisterRouter(): Hono {
  const router = new Hono()

  // The profile gate (the op-tokens posture: one build, the identity
  // module decides).
  router.use('/api/op/self-register*', async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  })

  /** The tier's config, fail-closed: the honest refusal when the
   *  deployment disabled the tier or has not configured the org
   *  binding (the owner's deliberate act — the endpoint never
   *  guesses). */
  function configOrRefuse(c: Context): { config: ReturnType<typeof resolveSelfRegisterConfig> } | { refuse: Response } {
    const config = resolveSelfRegisterConfig(runtimeEnv<EnvLike>(c))
    if (!config.enabled) {
      const status = config.reason === 'disabled' ? 403 : 503
      const message = config.reason === 'disabled'
        ? 'self-registration is closed on this deployment — request an account through the join queue, where an administrator reviews every request'
        : 'self-registration is not configured on this deployment — request an account through the join queue, where an administrator reviews every request'
      return { refuse: selfRegisterError(c, status, message) }
    }
    return { config }
  }

  // GET /api/op/self-register/catalog — the pickers' payload (the
  // bundled projection; public, cached a day — the registry moves at
  // the pipeline's cadence, never per request).
  router.get('/api/op/self-register/catalog', (c) => {
    const catalog = loadDomains()
    return c.json({
      countries: catalog.countries,
      matchingRule: catalog.matchingRule,
      generatedAt: catalog.generatedAt,
    }, 200, { 'cache-control': 'public, max-age=86400' })
  })

  // POST /api/op/self-register/start — the eligibility reads and the
  // attribution bounce. NOTHING is written: no account, no token, no
  // queue row on the happy path (the queue fallback is §4's own
  // feature — the admin-review path's request row IS its product).
  router.post('/api/op/self-register/start', async (c) => {
    const configured = configOrRefuse(c)
    if ('refuse' in configured) return configured.refuse
    const config = configured.config

    const captcha = await turnstileGate(c)
    if (captcha) return captcha

    const body = await c.req.json<{ country?: unknown; org?: unknown; name?: unknown; email?: unknown }>().catch(() => null)
    const country = typeof body?.country === 'string' ? body.country.trim() : ''
    const org = typeof body?.org === 'string' ? body.org.trim() : ''
    const name = typeof body?.name === 'string' ? body.name.trim() : ''
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : ''
    if (!country || !org || !name || !email.includes('@')) {
      return selfRegisterError(c, 400, 'your country, your organization, your name, and an email address are all required — pick from the lists and use your work address')
    }

    const verdict = eligibilityFor({ country, org, email })
    if (!verdict.ok) {
      if (verdict.queue) {
        // The queue fallback (the spec's §4): the request row is the
        // admin-review path's product — the human review IS the
        // verification for a domain the registry does not hold. The
        // account path writes nothing; this row is the feature.
        const request = await getStore().createOrgJoinRequest({
          name,
          email,
          orgId: null,
          orgNameText: org,
          requestedRole: 'user',
          note: `the self-registration flow: the domain ${email.split('@')[1]} is not in the member-domains registry`,
        })
        return c.json({ ok: false, queued: true, requestId: request.id, error: verdict.error }, 200)
      }
      const extra = verdict.mismatch ? { registeredTo: verdict.mismatch } : undefined
      return selfRegisterError(c, 403, verdict.error ?? 'this registration cannot be completed — submit your request through the join queue', extra)
    }

    // The dup-email read (a read — the law: nothing is written before
    // the verified click).
    if (await getStore().findUserByEmail(email)) {
      return selfRegisterError(c, 400, 'an account with this email address already exists — sign in instead, or ask for a password reset if you forgot it')
    }

    // The attribution bounce: the enabled upstream (google preferred —
    // phone-vetted at Google's own signup; github accepted), carrying
    // the attribute mode + the target email. The round-trip proves an
    // attributable human; one login buys one verification email.
    const providers = await getStore().listIdentityProviders()
    const attribution = providers.find(p => p.enabled && p.id === 'google')
      ?? providers.find(p => p.enabled && p.id === 'github')
    if (!attribution) {
      return selfRegisterError(c, 503, 'the registration attribution provider is not configured on this deployment — request an account through the join queue instead')
    }
    const origin = opRequestOrigin(c.req.raw)
    const bounce = `${origin}/op/upstream/${attribution.id}/signin?mode=attribute&email=${encodeURIComponent(email)}`
    return c.json({ ok: true, next: bounce, provider: attribution.displayName ?? attribution.id })
  })

  // POST /api/op/self-register/verify — the setup page's on-load call:
  // the emailed token's proof. Validates everything and creates
  // NOTHING (the setup form's own submit does the creation).
  router.post('/api/op/self-register/verify', async (c) => {
    const configured = configOrRefuse(c)
    if ('refuse' in configured) return configured.refuse
    const config = configured.config

    const body = await c.req.json<{ token?: unknown }>().catch(() => null)
    const token = typeof body?.token === 'string' ? body.token : ''
    if (!token) return selfRegisterError(c, 400, 'this registration link is malformed — start the registration again')

    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    const verified = await verifyRegistrationPayload(key.secretMaterial, token)
    if (!verified) {
      return selfRegisterError(c, 400, 'this registration link has expired or was already used — start the registration again; your email was never stored')
    }
    const hit = resolveOrg(verified.email)
    if (!hit) {
      return selfRegisterError(c, 403, 'this email domain is not in the member-domains registry — submit your request through the join queue, where an administrator reviews it')
    }
    if (await getStore().findUserByEmail(verified.email)) {
      return selfRegisterError(c, 400, 'an account with this email address already exists — sign in instead, or ask for a password reset if you forgot it')
    }
    return c.json({ ok: true, email: verified.email, name: verified.name, org: hit.org, country: hit.country, roles: hit.roles })
  })

  // POST /api/op/self-register/complete — THE creation (the only write
  // in the whole flow): the token re-verified, the eligibility re-run
  // fresh, then the account (verified by the click), the registry
  // roles, the org binding, the password, the audit.
  router.post('/api/op/self-register/complete', async (c) => {
    const configured = configOrRefuse(c)
    if ('refuse' in configured) return configured.refuse
    const config = configured.config

    const body = await c.req.json<{ token?: unknown; password?: unknown }>().catch(() => null)
    const token = typeof body?.token === 'string' ? body.token : ''
    const password = typeof body?.password === 'string' ? body.password : ''
    if (!token) return selfRegisterError(c, 400, 'this registration link is malformed — start the registration again')
    if (password.length < 12) {
      return selfRegisterError(c, 400, 'choose a password of at least 12 characters — a passphrase of a few words works well')
    }

    const env = runtimeEnv<EnvLike>(c)
    const key = await resolveOpSigningKey(env)
    const verified = await verifyRegistrationPayload(key.secretMaterial, token)
    if (!verified) {
      return selfRegisterError(c, 400, 'this registration link has expired or was already used — start the registration again; your email was never stored')
    }
    const email = verified.email
    const name = verified.name ?? email.split('@')[0]!
    const hit = resolveOrg(email)
    if (!hit) {
      return selfRegisterError(c, 403, 'this email domain is not in the member-domains registry — submit your request through the join queue, where an administrator reviews it')
    }
    const store = getStore()
    if (await store.findUserByEmail(email)) {
      return selfRegisterError(c, 400, 'an account with this email address already exists — sign in instead, or ask for a password reset if you forgot it')
    }

    // The org binding must be an active registry org (the invite's own
    // rule): the config names it, the registry validates it.
    const { isActiveRegistryOrg } = await import('../auth/org-registry')
    if (!(await isActiveRegistryOrg(store, config.orgId))) {
      return selfRegisterError(c, 503, 'self-registration is not configured correctly on this deployment — the member organization is missing from the registry; request an account through the join queue instead')
    }

    // THE creation: verified by the click, named here, bound to the
    // tier's org, carrying the registry hit's roles as the Ommisa
    // client's per-client assignments (the containment the registry
    // declares — the OP-side account stays role 'user', no
    // administration reach).
    const account = await store.createOpAccount({
      email,
      name,
      role: config.role,
      createdBy: 'self-register',
      orgId: config.orgId,
      roles: [config.role],
      emailVerified: true,
    })
    if (!account) return selfRegisterError(c, 400, 'an account with this email address already exists — sign in instead')
    await store.setUserRoles(account.id, config.role, [config.role])
    await store.setOpClientRoles(account.id, config.client, hit.roles, 'self-register')
    await store.setPasswordHash(account.id, await hashPassword(password), 'self-register')
    await store.markPrimaryEmailVerified(account.id)
    if (config.orgId) await store.updateUserRoleOrg(account.id, config.role, config.orgId)

    const catalog = loadDomains()
    await auditSelfRegister(store, account.id, email, {
      org: hit.org,
      country: hit.country,
      roles: hit.roles,
      verification: hit.verification,
      evidence: hit.evidence,
      registry_generated_at: catalog.generatedAt,
      client: config.client,
    })

    return c.json({ ok: true })
  })

  return router
}

/** The audit chain's write (the op-accounts pattern): never blocks the
 *  path. The registry vintage rides the metadata — every enrollment
 *  names the registry generation that admitted it. */
async function auditSelfRegister(
  store: ReturnType<typeof getStore>,
  userId: string,
  email: string,
  metadata: Record<string, unknown>,
): Promise<void> {
  try {
    const id = crypto.randomUUID()
    await store.putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'op',
      entity_id: userId,
      action: 'account.self_registered',
      user_id: userId,
      metadata: { email, ...metadata },
    }))
  } catch (err) {
    console.error('[op] the self-registration audit failed to persist:', (err as Error).message)
  }
}

/** The upstream callback's attribute-mode continuation (op-upstream.ts
 *  imports this): the exchange already proved an attributable human.
 *  The eligibility re-runs FRESH, the dup read guards, the
 *  verification email goes out, and the answer is the redirect path —
 *  the page that says "check your inbox" (with the honest link shown
 *  once when no mailer stands). NOTHING is written. */
export async function continueSelfRegisterAttribution(
  c: Context,
  origin: string,
  targetEmail: string | undefined,
  providerName: string,
  handle: string,
): Promise<string> {
  const config = resolveSelfRegisterConfig(runtimeEnv<EnvLike>(c))
  const done = (fragment: string): string => `/op/self-register${fragment}`
  if (!config.enabled) return done('?error=not-configured')
  const email = targetEmail?.trim().toLowerCase() ?? ''
  if (!email.includes('@')) return done('?error=expired')

  const verdict = eligibilityFor({ country: '', org: '', email })
  // The pickers' country/org rode leg 1; the click's authority is the
  // DOMAIN resolve — the country/org mismatch cannot recur here (the
  // domain IS the verdict). An unmatched domain at this late leg reads
  // as the queue path's domain (the registry moved under the flow).
  if (!verdict.ok && !verdict.queue) return done('?error=expired')

  const store = getStore()
  if (await store.findUserByEmail(email)) return done('?error=exists')

  const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
  const token = await mintRegistrationToken(key.secretMaterial, email)
  const verifyUrl = `${origin}/op/self-register?token=${encodeURIComponent(token)}`

  const mail = await sendOpMail(runtimeEnv<Record<string, string | undefined>>(c) as never, {
    to: email,
    template: 'self_register_verify',
    issuer: resolveOpConfig(runtimeEnv<EnvLike>(c), origin).issuer,
    params: { verifyUrl, org: verdict.hit?.org ?? '', hours: 24 },
  })
  console.log(`[op] self-register: the verification email for ${email} via ${providerName} (${handle}): ${mail.sent ? 'sent' : mail.posture}`)
  return done(mail.sent ? '?sent=1' : `?sent=1&link=${encodeURIComponent(verifyUrl)}`)
}

/** The attribution continuation's stateless intent carrier: leg 1 hands
 *  the target email to the upstream bounce; the callback re-derives it
 *  from the state's `e`. The applicant's NAME cannot ride the bounce
 *  URL unencoded — it rides the SIGNED LINK instead (minted at the
 *  callback from the state's `e`-paired name field). */
export async function startSelfRegisterAttribution(
  c: Context,
  providerId: string,
  email: string,
): Promise<string> {
  const origin = opRequestOrigin(c.req.raw)
  return `${origin}/op/upstream/${providerId}/signin?mode=attribute&email=${encodeURIComponent(email)}`
}
