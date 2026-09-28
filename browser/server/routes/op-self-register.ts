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
import { loadDomains, resolveOrgDomain } from '../auth/op/member-domains'
import { eligibilityFor, resolveEligibilityOrg, resolveSelfRegisterConfig } from '../auth/op/self-register'
import { isRegistryOrgKind } from '../auth/org-registry'
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
  // The token rides the JSON BODY (the register/join gate's own
  // posture — the widget's hidden input posts with the form); the
  // header stays a fallback for non-JSON callers. Hono caches the
  // parsed body, so the handler's own read below is safe.
  let bodyToken = ''
  try {
    const body = await c.req.json() as Record<string, unknown>
    if (typeof body?.['cf-turnstile-response'] === 'string') bodyToken = body['cf-turnstile-response']
  } catch { /* a bodyless call: the empty token refuses below */ }
  const token = bodyToken || c.req.header('cf-turnstile-response') || ''
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
      return { refuse: selfRegisterError(c, 403, 'self-registration is closed on this deployment — request an account through the join queue, where an administrator reviews every request') }
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

    // The attribution CHOICE: every enabled human-proof upstream
    // (google — phone-vetted at its own signup; github — the
    // developer's own) answers with its own bounce URL. The APPLICANT
    // chooses who attests them; one login buys one verification email
    // to one address. The upstream identity itself is never stored,
    // never linked — it only proves a real, attributable human.
    const providers = (await getStore().listIdentityProviders())
      .filter(p => p.enabled && (p.id === 'google' || p.id === 'github'))
      .map(p => ({
        id: p.id,
        name: p.displayName ?? p.id,
        next: `${opRequestOrigin(c.req.raw)}/op/upstream/${p.id}/signin?mode=attribute&email=${encodeURIComponent(email)}`,
      }))
    if (!providers.length) {
      return selfRegisterError(c, 503, 'the registration attribution providers are not configured on this deployment — request an account through the join queue instead')
    }
    return c.json({ ok: true, providers })
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
    const resolved = resolveOrgDomain(verified.email)
    if (!resolved) {
      return selfRegisterError(c, 403, 'this email domain is not in the member-domains registry — submit your request through the join queue, where an administrator reviews it')
    }
    if (await getStore().findUserByEmail(verified.email)) {
      return selfRegisterError(c, 400, 'an account with this email address already exists — sign in instead, or ask for a password reset if you forgot it')
    }
    return c.json({ ok: true, email: verified.email, name: verified.name, org: resolved.owner.org, country: resolved.owner.country, roles: resolved.owner.roles, orgDomain: resolved.domain })
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
    const resolved = resolveOrgDomain(verified.email)
    if (!resolved) {
      return selfRegisterError(c, 403, 'this email domain is not in the member-domains registry — submit your request through the join queue, where an administrator reviews it')
    }
    const { domain, owner } = resolved
    const name = verified.name ?? verified.email.split('@')[0]!
    const store = getStore()
    if (await store.findUserByEmail(verified.email)) {
      return selfRegisterError(c, 400, 'an account with this email address already exists — sign in instead, or ask for a password reset if you forgot it')
    }

    // THE ORG OF THE SAME DOMAIN NAME: the organization the registry
    // entry names — the row's full name comes from the registry
    // (e.g. 'National Institute of Standards and Technology (NIST)'),
    // keyed by the domain, materialized from the sourced data when
    // absent, active. Every account but the four super admins carries
    // an org (the owner's ruling).
    const orgKind = isRegistryOrgKind(owner.status) ? owner.status : 'associate'
    if (!(await store.getOrgRegistryOrg(domain))) {
      await store.createOrgRegistryOrg({
        id: domain,
        name: owner.org,
        kind: orgKind,
        country: owner.country,
        createdBy: 'self-register',
      })
      await store.setOrgRegistryOrgState(domain, 'active', 'self-register')
    }

    // THE creation: verified by the click, bound to the domain's org,
    // carrying the registry hit's roles as the Ommisa client's
    // per-client assignments (the containment the registry declares —
    // the OP-side account stays role 'user', no administration reach).
    const account = await store.createOpAccount({
      email: verified.email,
      name,
      role: 'user',
      createdBy: 'self-register',
      orgId: domain,
      roles: ['user'],
      emailVerified: true,
    })
    if (!account) return selfRegisterError(c, 400, 'an account with this email address already exists — sign in instead')
    await store.setUserRoles(account.id, 'user', ['user'])
    await store.setOpClientRoles(account.id, config.client, owner.roles, 'self-register')
    await store.setPasswordHash(account.id, await hashPassword(password), 'self-register')
    await store.markPrimaryEmailVerified(account.id)
    await store.updateUserRoleOrg(account.id, 'user', domain)

    const catalog = loadDomains()
    await auditSelfRegister(store, account.id, verified.email, {
      org: owner.org,
      org_domain: domain,
      country: owner.country,
      roles: owner.roles,
      verification: owner.verification,
      evidence: owner.evidence,
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
  assertedEmail?: string,
): Promise<string> {
  const config = resolveSelfRegisterConfig(runtimeEnv<EnvLike>(c))
  const done = (fragment: string): string => `/op/self-register${fragment}`
  console.warn(`[op] self-register attribution RETURN: provider=${providerName} handle=${handle} target=${targetEmail ?? 'NONE'} enabled=${config.enabled}`)
  if (!config.enabled) return done('?error=not-configured')
  const email = targetEmail?.trim().toLowerCase() ?? ''
  if (!email.includes('@')) return done('?error=expired')

  // The pickers' country/org rode leg 1 and were judged there; the
  // click's authority is the DOMAIN resolve alone — the registry's
  // fresh verdict at this moment (an unmatched domain reads as the
  // queue path's: the registry moved under the flow).
  const resolved = resolveEligibilityOrg(email)
  if (!resolved) return done('?error=queued')
  const orgRow = loadDomains().countries
    .find(c => c.country === resolved.owner.country)?.orgs
    .find(o => o.name === resolved.owner.org)
  if (orgRow?.admin_queue) return done('?error=queued')

  const store = getStore()
  if (await store.findUserByEmail(email)) return done('?error=exists')

  const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
  const token = await mintRegistrationToken(key.secretMaterial, email)
  const verifyUrl = `${origin}/op/self-register?token=${encodeURIComponent(token)}`

  const mail = await sendOpMail(runtimeEnv<Record<string, string | undefined>>(c) as never, {
    to: email,
    template: 'self_register_verify',
    issuer: resolveOpConfig(runtimeEnv<EnvLike>(c), origin).issuer,
    params: { verifyUrl, org: resolved.owner.org, hours: 24 },
  })
  // THE FAST PATH: the upstream itself asserts THIS address as a
  // VERIFIED email (a Workspace / M365 org account, GitHub's verified
  // primary). Nobody signs in to that provider as the address without
  // controlling its mailbox — the mail round-trip is already proven,
  // so no outbound email and the setup link hands straight back to the
  // very browser that just proved itself.
  if (assertedEmail && assertedEmail.trim().toLowerCase() === email) {
    console.warn(`[op] self-register attribution FAST PATH: ${providerName} (${handle}) asserts ${email} as verified — the mail round-trip is skipped`)
    return done(`?token=${encodeURIComponent(token)}`)
  }
  console.warn(`[op] self-register attribution OK: ${providerName} (${handle}) → ${email} — mail ${mail.sent ? 'sent' : mail.posture} → ${done('')}`)
  return done(mail.sent ? '?sent=1' : `?sent=1&link=${encodeURIComponent(verifyUrl)}`)
}

