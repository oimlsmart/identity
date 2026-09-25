// ═══════════════════════════════════════════════════════════════════
// The RFC 8628 device authorization grant's OP surface
// (TODO.ai-platform/10 — auth/op/device-grant.ts carries the flow's
// doctrines): the CLI bootstrap that ends in a personal access token,
// never an OIDC ceremony.
//
//   POST /op/device/authorization   — §3.1–3.2: the PUBLIC client (the
//                                     CLI cone — a confidential client
//                                     is refused: server-side apps have
//                                     the code flow) names its scope ask
//                                     in the PAT grammar; the answer
//                                     carries the device_code, the
//                                     user_code, the verification URIs,
//                                     the expiry, the poll interval.
//                                     Account-free by construction —
//                                     the scope set validates only as
//                                     far as the registry judges without
//                                     an account (well-formed, naming
//                                     active application-class services);
//                                     the standing judgment waits for
//                                     the approving account.
//   GET  /api/op/device             — the approval page's context (the
//                                     user_code's ceremony: the client,
//                                     the ask named honestly — service
//                                     names + action classes — the
//                                     expiry), or the sign-in bounce.
//   POST /api/op/device/decide      — the holder's decision. APPROVE
//                                     re-judges the FULL ask against the
//                                     approving account's LIVE standing
//                                     (resolvePatScopesForAccount — the
//                                     console mint's own computation; a
//                                     shortfall refuses WITHOUT deciding
//                                     — the holder may switch accounts
//                                     and retry while the code lives);
//                                     the guarded flip binds the account
//                                     + the session's active-org context
//                                     (the PAT mint's pin). DENY flips
//                                     to denied (the poll answers
//                                     access_denied). Both land on the
//                                     account's audit feed.
//
// The token endpoint's device_code leg (the poll + the one-time mint)
// lives in op.ts — /op/token is its home. Discovery advertises the
// endpoint deliberately (the contract golden re-recorded).
//
// The routes mount on EVERY instance (app.ts) but answer 404 unless the
// deployment profile carries the identity module (the op-tokens
// posture).
//
// WORKER-SAFE: hono + the store seam + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, normalizePatScopes, type OrgContextResolution } from '../store'
import { getInstanceProfile } from '../profile'
import { sessionUser } from '../session'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { seedOidcClientsFromEnv } from '../auth/op/registry'
import { deviceClassOf } from '../auth/op/device-clients'
import { serviceClassOf } from '../auth/op/service-clients'
import { resolvePatScopesForAccount } from '../auth/op/tokens'
import {
  auditDeviceGrant,
  DEVICE_AUTHORIZATION_TTL_MS,
  DEVICE_POLL_INTERVAL_SECONDS,
  hashDeviceCode,
  hashUserCode,
  mintDeviceCode,
  mintUserCode,
  normalizeUserCode,
} from '../auth/op/device-grant'

type EnvLike = Record<string, string | undefined>

/** The RFC 6749-family error answer (§3.2 + the page API share the
 *  shape: error + error_description). */
function deviceError(c: Context, status: 400 | 401 | 403 | 404 | 409 | 410, error: string, description: string): Response {
  return c.json({ error, error_description: description }, status)
}

export function createOpDeviceRouter(): Hono {
  const device = new Hono()

  // The profile gate (the op-tokens posture: one build, the identity
  // module decides).
  device.use('/op/device/authorization', async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  })
  device.use('/api/op/device*', async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  })

  // The client registry's env bootstrap rides the op.ts precedent (a
  // failed seed retries next request).
  let seeded: Promise<void> | null = null
  function ensureSeeded(c: Context): Promise<void> {
    if (!seeded) {
      seeded = (async () => {
        const ids = await seedOidcClientsFromEnv(runtimeEnv<EnvLike>(c), getStore())
        if (ids.length) console.log(`[op] client registry bootstrap seeded (device): ${ids.join(', ')}`)
      })()
      seeded.catch(() => { seeded = null })
    }
    return seeded
  }

  // POST /op/device/authorization — the §3.1 ask. The client is the
  // registered PUBLIC CLI client (a secretless application-class row —
  // a confidential client has the code flow; a machine class has
  // client_credentials).
  device.post('/op/device/authorization', async (c) => {
    await ensureSeeded(c)
    const contentType = c.req.header('content-type') ?? ''
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return deviceError(c, 400, 'invalid_request', 'the device authorization endpoint speaks application/x-www-form-urlencoded')
    }
    const form = new URLSearchParams(await c.req.raw.text())
    const store = getStore()
    const clientId = (form.get('client_id') ?? '').trim()
    if (!clientId) {
      return deviceError(c, 401, 'invalid_client', 'the device flow names its public client_id')
    }
    const client = await store.getOidcClient(clientId)
    if (!client || client.status !== 'active') {
      return deviceError(c, 401, 'invalid_client', 'unknown or disabled client')
    }
    if (deviceClassOf(client.claimsPolicy) || serviceClassOf(client.claimsPolicy)) {
      return deviceError(c, 400, 'unauthorized_client', 'the machine classes speak client_credentials — the device flow is the person cone')
    }
    if (client.secretHash) {
      return deviceError(c, 400, 'unauthorized_client', 'a confidential client has the authorization-code flow — the device flow is the public CLI cone')
    }
    // The scope ask: the PAT grammar, REQUIRED (the flow's whole product
    // is a scoped token). The account-free half of the judgment: every
    // service is a registered, active, application-class relying party —
    // the standing judgment lands at the approval, against the account.
    const rawScope = (form.get('scope') ?? '').trim()
    const scopes = rawScope ? normalizePatScopes(rawScope.split(/\s+/)) : null
    if (!scopes || !scopes.length) {
      return deviceError(c, 400, 'invalid_scope', "the scope parameter is required — the PAT grammar: '<service>:<read|write|admin>' space-joined")
    }
    for (const scope of scopes) {
      const service = await store.getOidcClient(scope.service)
      if (!service || service.status !== 'active') {
        return deviceError(c, 400, 'invalid_scope', `the service '${scope.service}' is not a registered, active relying party`)
      }
      if (deviceClassOf(service.claimsPolicy) || serviceClassOf(service.claimsPolicy)) {
        return deviceError(c, 400, 'invalid_scope', `the service '${scope.service}' is a machine-class client — never a person's token`)
      }
    }

    const config = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
    const deviceCode = mintDeviceCode()
    const userCode = mintUserCode()
    const now = Date.now()
    await store.createDeviceAuthorization({
      id: crypto.randomUUID(),
      deviceCodeHash: await hashDeviceCode(deviceCode),
      userCodeHash: await hashUserCode(userCode),
      clientId: client.clientId,
      scopes: scopes.map(s => `${s.service}:${s.action}`),
      intervalSeconds: DEVICE_POLL_INTERVAL_SECONDS,
      expiresAt: new Date(now + DEVICE_AUTHORIZATION_TTL_MS).toISOString(),
    })
    const verificationUri = `${config.issuer}/op/device`
    return c.json({
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: `${verificationUri}?code=${encodeURIComponent(userCode)}`,
      expires_in: Math.floor(DEVICE_AUTHORIZATION_TTL_MS / 1000),
      interval: DEVICE_POLL_INTERVAL_SECONDS,
    })
  })

  /** The page API's shared row resolution: the entered code → the LIVE,
   *  pending ceremony, or the honest refusal (uniform across the context
   *  read and the decision — never a state oracle beyond the page's own
   *  needs). */
  async function pendingRow(c: Context, rawCode: unknown) {
    const userCode = normalizeUserCode(rawCode)
    if (!userCode) return { row: null, userCode: null, error: deviceError(c, 400, 'invalid_request', 'the code is not in the XXXX-XXXX shape') }
    const row = await getStore().findDeviceAuthorizationByUserCodeHash(await hashUserCode(userCode))
    if (!row) return { row: null, userCode, error: deviceError(c, 404, 'unknown_code', 'no ceremony knows this code — check the terminal and try again') }
    if (new Date(row.expiresAt).getTime() <= Date.now()) {
      return { row: null, userCode, error: deviceError(c, 410, 'expired', 'this code has expired — restart the sign-in in the terminal') }
    }
    if (row.status !== 'pending') {
      return { row: null, userCode, error: deviceError(c, 409, 'decided', 'this code was already decided — the terminal has its answer') }
    }
    return { row, userCode, error: null }
  }

  // GET /api/op/device?user_code=XXXX-XXXX — the approval page's
  // context: the client, the ask (service names + action classes), the
  // account, the expiry. Session required (the sign-in bounce carries
  // the page's re-entry).
  device.get('/api/op/device', async (c) => {
    await ensureSeeded(c)
    const { row, userCode, error } = await pendingRow(c, c.req.query('user_code'))
    if (error) return error
    const user = await sessionUser(c)
    if (!user) {
      return c.json({
        error: 'authentication_required',
        login: `/?redirect=${encodeURIComponent(`/op/device?code=${userCode}`)}`,
      }, 401)
    }
    const store = getStore()
    const client = await store.getOidcClient(row!.clientId)
    const requested = normalizePatScopes(row!.scopes) ?? []
    const services = await Promise.all(requested.map(async (scope) => {
      const service = await store.getOidcClient(scope.service)
      return { service: scope.service, name: service?.name ?? scope.service, action: scope.action }
    }))
    const config = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
    const profile = getInstanceProfile()
    return c.json({
      client: client ? { id: client.clientId, name: client.name } : { id: row!.clientId, name: row!.clientId },
      scopes: services,
      account: { name: user.name, email: user.email, avatarUrl: user.avatarUrl ?? null },
      expiresAt: row!.expiresAt,
      issuer: config.issuer,
      issuerName: profile.branding.name || profile.identity.org_name,
    })
  })

  // POST /api/op/device/decide — the holder's decision. Approve
  // re-judges the FULL ask against the approving account's live
  // standing FIRST (a shortfall refuses without deciding — the ceremony
  // stays pending while the code lives); the guarded flip binds the
  // account + the session's active-org context.
  device.post('/api/op/device/decide', async (c) => {
    await ensureSeeded(c)
    const body = await c.req.json<{ user_code?: unknown; decision?: unknown }>().catch(() => null)
    if (!body || (body.decision !== 'approve' && body.decision !== 'deny')) {
      return deviceError(c, 400, 'invalid_request', 'decision must be "approve" or "deny"')
    }
    const { row, error } = await pendingRow(c, body.user_code)
    if (error) return error
    const user = await sessionUser(c)
    if (!user) return deviceError(c, 401, 'authentication_required', 'sign in to decide the authorization')
    const store = getStore()
    const client = await store.getOidcClient(row!.clientId)
    const decidedAt = new Date().toISOString()

    if (body.decision === 'deny') {
      const decided = await store.decideDeviceAuthorization(row!.id, { userId: user.id, orgContext: user.orgId ?? null, approve: false, decidedAt })
      if (!decided) return deviceError(c, 409, 'decided', 'this code was already decided')
      await auditDeviceGrant('account.device_grant_denied', user.id, { userId: user.id, userName: user.name }, {
        device_authorization: row!.id,
        client: row!.clientId,
        name: client?.name ?? row!.clientId,
        scopes: row!.scopes,
      })
      return c.json({ ok: true })
    }

    // APPROVE — the standing judgment against the FULL ask (the console
    // mint's own computation): the session's effective context IS the
    // token's ceiling. A shortfall refuses WITHOUT deciding — the holder
    // may switch accounts and retry while the code lives.
    const context: OrgContextResolution = {
      orgId: user.orgId ?? null,
      roles: user.roles?.length ? user.roles : [user.role],
      cone: user.cone ?? null,
    }
    const requested = normalizePatScopes(row!.scopes) ?? []
    const verdict = await resolvePatScopesForAccount(store, user, context, requested, runtimeEnv<EnvLike>(c))
    if (!verdict.ok) {
      return c.json({ error: 'scope_standing', error_description: verdict.error }, 403)
    }
    const decided = await store.decideDeviceAuthorization(row!.id, { userId: user.id, orgContext: context.orgId, approve: true, decidedAt })
    if (!decided) return deviceError(c, 409, 'decided', 'this code was already decided')
    await auditDeviceGrant('account.device_grant_approved', user.id, { userId: user.id, userName: user.name }, {
      device_authorization: row!.id,
      client: row!.clientId,
      name: client?.name ?? row!.clientId,
      scopes: row!.scopes,
      orgContext: context.orgId,
    })
    return c.json({ ok: true })
  })

  return device
}
