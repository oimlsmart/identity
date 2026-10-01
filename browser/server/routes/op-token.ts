// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the TOKEN module, extracted from op.ts as the
// eighth and last proof of the domain-model split (the pure refactor;
// the golden + the suite are the proof — zero behavior change).
//
// POST /op/token — the grant arms:
//   client_credentials (the machine cone: the device + service classes
//   ONLY — the self-contained machine JWT);
//   the device authorization grant's poll (RFC 8628 §3.5 — the PAT
//   mints on approval);
//   the RFC 8693 token exchange, two subject kinds (the developer
//   cone's personal access tokens + the session delegation's
//   access-token subject);
//   refresh_token (the one-time consume + the rotation, a re-presented
//   spent token kills the family);
//   authorization_code (the one-time code + PKCE + the client's
//   secret → the signed ES256 ID token, the FIRST refresh of a
//   rotation family under offline_access).
//
// The client-authentication half (presentedClientCredentials +
// authenticateClient) lives here and is EXPORTED — the protocol,
// management, and clients-admin modules take it as their seam.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, normalizeOidcScopeSet, normalizePatScopes, type AuthUserPayload, type OidcClient, type PatScope } from '../store'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import {
  ensureOpKeyRegistered,
  maySelfRegisterOpKey,
  opRandomToken,
  pkceS256,
  resolveOpSigningKey,
  signOpIdToken,
  verifyOpJwt,
  warnDevKeyRegistrationSkipped,
} from '../auth/op/keys'
import { verifyClientSecret } from '../auth/op/secrets'
import { oidcError } from '../auth/op/oidc-error'
import { authTimeOf } from '../auth/op/logout'
import { roleClaimsForContext, pictureClaimForClient, orcidClaimForClient, orgRorClaimForClient } from '../auth/op/claims'
import { claimsContextFor } from '../auth/op/memberships'
import { DEVICE_CLASS, deviceClassOf, deviceTokenClaims } from '../auth/op/device-clients'
import { SERVICE_CLASS, narrowServiceScopes, serviceClassOf, serviceTokenClaims } from '../auth/op/service-clients'
import {
  auditPat, hashPat, narrowPatScopesParam, patExchangeBeatDue, patExpiryNoticeDue,
  patIntrospectionClaims, patPlausible, patTokenClaims, resolvePatScopesForAccount,
  delegationScopesParam, delegationTokenClaims, mintPatSecret, patDisplayPrefix, resolvePatExpiry,
  DELEGATION_TOKEN_TYPE, PAT_EXCHANGE_GRANT, PAT_EXCHANGE_HEARTBEAT_MS, PAT_TOKEN_TYPE,
} from '../auth/op/tokens'
import {
  DEVICE_CODE_GRANT, deviceGrantPatName, hashDeviceCode, judgeDevicePoll,
} from '../auth/op/device-grant'
import { auditGrant } from '../auth/op/grants'
import { dpopJtiExpiry, mintDpopNonce, verifyDpopProof } from '../auth/op/dpop'
import { acrOf, sessionMeetsMaxAge } from '../auth/op/step-up'
import { sendOpSecurityMail } from '../auth/op/mail'
import type { MailEnv } from '../mailer'

/** The PRESENTED client credentials (never verified here): HTTP Basic
 *  (client_secret_basic) or the form's pair. The token endpoint reads
 *  the client id BEFORE the grant dispatch (the device class's cone is
 *  decided per client); the secret verify stays per path. */
function presentedClientCredentials(c: Context, form: URLSearchParams): { clientId: string; secret: string | null; error: Response | null } {
  let clientId = form.get('client_id') ?? ''
  let secret = form.get('client_secret')
  const basic = c.req.header('authorization')
  if (basic?.startsWith('Basic ')) {
    let decoded: string
    try {
      decoded = atob(basic.slice(6))
    } catch {
      return { clientId: '', secret: null, error: oidcError(c, 401, 'invalid_client', 'the Authorization header is not valid Basic') }
    }
    const idx = decoded.indexOf(':')
    clientId = decodeURIComponent(decoded.slice(0, idx))
    secret = decoded.slice(idx + 1)
    // The RP sends the secret percent-encoded per RFC 6749 §2.3.1.
    try { secret = decodeURIComponent(secret) } catch { /* a literal secret stands */ }
  }
  return { clientId, secret, error: null }
}

/** The token endpoint's client authentication: HTTP Basic
 *  (client_secret_basic) or the form's client_secret (post). Public
 *  clients (no registered secret) authenticate by client_id + PKCE. */
export async function authenticateClient(c: Context, form: URLSearchParams): Promise<{ client: OidcClient | null; error: Response | null }> {
  const creds = presentedClientCredentials(c, form)
  if (creds.error) return { client: null, error: creds.error }
  const { clientId, secret } = creds
  if (!clientId) {
    return { client: null, error: oidcError(c, 401, 'invalid_client', 'no client authentication (client_secret_basic or a public client_id) presented') }
  }
  const client = await getStore().getOidcClient(clientId)
  if (!client || client.status !== 'active') {
    return { client: null, error: oidcError(c, 401, 'invalid_client', 'unknown or disabled client') }
  }
  if (client.secretHash) {
    if (!secret || !(await verifyClientSecret(secret, client.secretHash))) {
      return { client: null, error: oidcError(c, 401, 'invalid_client', 'the client secret does not verify') }
    }
  }
  return { client, error: null }
}

type EnvLike = Record<string, string | undefined>

/** The request's effective OP config (env + this request's origin) —
 *  the same formula every OP route reads. */
function configFor(c: Context) {
  return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
}



  // POST /op/token — the code exchange.
/** TODO.sota/09 (RFC 9449): the token request's DPoP binding. NULL =
 *  no proof rode the request (the ordinary Bearer posture). An error
 *  answers the 400 invalid_dpop_proof; { challenge } answers the 400
 *  use_dpop_nonce (§8's STRICT posture — the fresh nonce rides the
 *  DPoP-Nonce header, the client retries with it). A fresh proof's jti
 *  burns at verification — a replayed proof refuses even if the grant
 *  would have succeeded. The success answer carries a refreshed nonce
 *  (the client keeps riding without re-challenging). */
async function dpopBindingFor(
  c: Context,
  config: { issuer: string },
): Promise<{ jkt: string; nonce: string } | { error: string } | { challenge: string } | null> {
  const proof = c.req.header('dpop')
  if (!proof) return null
  const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
  const res = await verifyDpopProof(proof, { method: 'POST', uri: `${config.issuer}/op/token`, nonceSecret: key.secretMaterial })
  if ('error' in res) return res
  if ('challenge' in res) return res
  const fresh = await getStore().rememberDpopJti(res.jti, dpopJtiExpiry(res.iat))
  if (!fresh) return { error: 'the proof\u2019s jti was already used' }
  return { jkt: res.jkt, nonce: await mintDpopNonce(key.secretMaterial) }
}

/** The binding's two uniform answers: the challenge (§8) and the
 *  refreshed-nonce success stamp. The arms call these right after
 *  dpopBindingFor. */
function dpopChallenged(c: Context, challenge: string): Response {
  c.header('dpop-nonce', challenge)
  return c.json({
    error: 'use_dpop_nonce',
    error_description: 'the proof must carry the server-issued nonce (the DPoP-Nonce response header) — retry with it',
  }, 400)
}

export function createOpTokenRouter(deps: {
  ensureSeeded: (c: Context) => Promise<void>
  audit: (
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
  ) => Promise<void>
}): Hono {
  const op = new Hono()
  const { ensureSeeded } = deps
  const audit = deps.audit

  op.post('/op/token', async (c) => {
    await ensureSeeded(c)
    const config = configFor(c)
    const store = getStore()

    /** The token endpoint's refusals land on the audit chain
     *  (TODO.identity-sso/01's token-anomaly signal): the OIDC error code
     *  and the client id WHEN one authenticated (never the code, the
     *  secret, or the verifier). The success is journaled as
     *  client.token_issued below. */
    async function refuseToken(status: 400 | 401, code: string, description: string, clientId?: string): Promise<Response> {
      await audit('client.token_refused', clientId ?? 'unauthenticated', {}, { error: code })
      return oidcError(c, status, code, description)
    }

    const contentType = c.req.header('content-type') ?? ''
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return oidcError(c, 400, 'invalid_request', 'the token endpoint speaks application/x-www-form-urlencoded')
    }
    const form = new URLSearchParams(await c.req.raw.text())
    const grantType = form.get('grant_type')

    // ── the machine cone: client_credentials, the machine classes ONLY ──
    // (auth/op/device-clients.ts + service-clients.ts). The OIDC wire the
    // RPs pin is UNCHANGED: a request naming no client, an unknown client,
    // or an APPLICATION client gets the pre-machine answer
    // (unsupported_grant_type / invalid_client exactly as before — the
    // contract gate's golden holds byte-identical). Only a registered,
    // active MACHINE client (the device class or the service class)
    // presenting its secret mints: a self-contained ES256 JWT access token
    // (the consumers validate it against the OP's JWKS — no call-back),
    // the class's claims exactly, never an ID token, never a user claim.
    if (grantType === 'client_credentials') {
      const creds = presentedClientCredentials(c, form)
      if (creds.error) {
        await audit('client.token_refused', 'unauthenticated', {}, { error: 'invalid_client' })
        return creds.error
      }
      if (!creds.clientId) {
        return refuseToken(400, 'unsupported_grant_type', 'authorization_code and refresh_token only')
      }
      const machineClient = await store.getOidcClient(creds.clientId)
      if (!machineClient || machineClient.status !== 'active') {
        await audit('client.token_refused', creds.clientId, {}, { error: 'invalid_client' })
        return oidcError(c, 401, 'invalid_client', 'unknown or disabled client')
      }
      const device = deviceClassOf(machineClient.claimsPolicy)
      const service = device ? null : serviceClassOf(machineClient.claimsPolicy)
      if (!device && !service) {
        return refuseToken(400, 'unsupported_grant_type', 'authorization_code and refresh_token only (client_credentials is the machine classes’ cone)', machineClient.clientId)
      }
      // The machine caller authenticates with its secret — the machine
      // classes are always confidential (the registry refuses a public
      // one at write), so a secret-less row here is a hand-edit: refused,
      // never guessed.
      const machineClass = device ? DEVICE_CLASS : SERVICE_CLASS
      if (!machineClient.secretHash || !creds.secret || !(await verifyClientSecret(creds.secret, machineClient.secretHash))) {
        await audit('client.token_refused', machineClient.clientId, {}, { error: 'invalid_client', class: machineClass })
        return oidcError(c, 401, 'invalid_client', 'the client secret does not verify')
      }
      // The service class's scope narrowing (RFC 6749 §4.4's scope
      // parameter): the request may name a SUBSET of the registered
      // allowlist — a scope beyond it refuses loudly (never a silent
      // drop, never a mint beyond the allowlist).
      let serviceScopes: string[] = []
      if (service) {
        const narrowed = narrowServiceScopes(service, form.get('scope'))
        if (narrowed.error) {
          return refuseToken(400, 'invalid_scope', narrowed.error, machineClient.clientId)
        }
        serviceScopes = narrowed.scopes
      }
      const machineKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      // The first-use registration rides the SAME gate as the auth-code
      // path (identity#7): a generated development key never enters the
      // keyset on a declared-issuer deployment.
      if (maySelfRegisterOpKey(machineKey, config)) {
        await ensureOpKeyRegistered(store, machineKey)
      } else {
        warnDevKeyRegistrationSkipped('/op/token', machineKey)
      }
      // The DPoP arm (TODO.sota/09, RFC 9449 §6.1): a valid proof binds
      // the SELF-CONTAINED machine JWT through the cnf claim — the
      // consumers (introspection here, the external RSes) read the
      // binding; our own 8693 verifies enforce it.
      const machineDpop = await dpopBindingFor(c, config)
      if (machineDpop && 'challenge' in machineDpop) return dpopChallenged(c, machineDpop.challenge)
      if (machineDpop && 'error' in machineDpop) {
        return refuseToken(400, 'invalid_dpop_proof', machineDpop.error, machineClient.clientId)
      }
      if (machineDpop && 'nonce' in machineDpop) c.header('dpop-nonce', machineDpop.nonce)
      const machineJkt = machineDpop && 'jkt' in machineDpop ? machineDpop.jkt : null
      const machineToken = await signOpIdToken(machineKey, device
        ? deviceTokenClaims(machineClient.clientId, device, config, machineJkt)
        : serviceTokenClaims(machineClient.clientId, service!, serviceScopes, config, machineJkt))
      // The issuance lands on the audit chain, naming the MACHINE CALLER
      // (never the token value, never the secret).
      await audit('client.token_issued', machineClient.clientId, {}, device
        ? { class: DEVICE_CLASS, device: device.id, org: device.org, instrument_model: device.instrument_model }
        : { class: SERVICE_CLASS, service: service!.id, org: service!.org, audience: service!.audience, scopes: serviceScopes })
      return c.json({
        access_token: machineToken,
        token_type: machineJkt ? 'DPoP' : 'Bearer',
        expires_in: config.accessTokenTtlMs / 1000,
        // The effective scopes ride the service class's answer (RFC 6749
        // §5.1's explicitness — the caller reads what it actually got).
        ...(service ? { scope: serviceScopes.join(' ') } : {}),
      })
    }

    // ── the device authorization grant's poll (RFC 8628 §3.5,
    // TODO.ai-platform/10 — routes/op-device.ts's ceremony): the CLI
    // polls with its device_code; on the holder's approval the leg mints
    // the personal access token through the ONE store path, so the
    // plaintext shows exactly once — in this answer (the GitHub
    // doctrine). The delivered credential IS the PAT (never an OIDC
    // answer — no ID token, no userinfo): the CLI exchanges it at the
    // RFC 8693 grant per use, exactly like a console-minted token; the
    // audit names the device grant and the client. The §3.5 error set
    // rides verbatim: authorization_pending / slow_down / access_denied /
    // expired_token; a re-presented consumed code answers invalid_grant.
    if (grantType === DEVICE_CODE_GRANT) {
      const { client: deviceClient, error: deviceClientError } = await authenticateClient(c, form)
      if (deviceClientError || !deviceClient) {
        await audit('client.token_refused', form.get('client_id')?.trim() || 'unauthenticated', {}, { error: 'invalid_client', grant: 'device_code' })
        return deviceClientError ?? oidcError(c, 401, 'invalid_client', 'the device-code poll requires client authentication')
      }
      const presentedDeviceCode = form.get('device_code') ?? ''
      const ceremony = presentedDeviceCode
        ? await store.findDeviceAuthorizationByDeviceCodeHash(await hashDeviceCode(presentedDeviceCode))
        : null
      if (!ceremony || ceremony.clientId !== deviceClient.clientId) {
        return refuseToken(400, 'invalid_grant', 'the device_code is unknown or was not issued to this client', deviceClient.clientId)
      }
      const poll = judgeDevicePoll(ceremony)
      const pollNowIso = new Date().toISOString()
      if (poll.kind === 'expired') {
        return refuseToken(400, 'expired_token', 'the device_code has expired — restart the sign-in in the terminal', deviceClient.clientId)
      }
      if (poll.kind === 'denied') {
        return refuseToken(400, 'access_denied', 'the account holder declined the authorization', deviceClient.clientId)
      }
      if (poll.kind === 'consumed') {
        return refuseToken(400, 'invalid_grant', 'the device_code was already used', deviceClient.clientId)
      }
      if (poll.kind === 'slow_down') {
        await store.stampDeviceAuthorizationPoll(ceremony.id, pollNowIso, poll.intervalSeconds)
        return refuseToken(400, 'slow_down', 'the poll interval is being exceeded — the interval grows by 5 seconds', deviceClient.clientId)
      }
      if (poll.kind === 'pending') {
        await store.stampDeviceAuthorizationPoll(ceremony.id, pollNowIso)
        return refuseToken(400, 'authorization_pending', 'the account holder has not decided yet', deviceClient.clientId)
      }
      // Approved → the ONE-TIME consume claims the row atomically (a
      // replay or a race answers invalid_grant, never a second token).
      const claimed = await store.consumeDeviceAuthorization(ceremony.id)
      if (!claimed || !claimed.userId) {
        return refuseToken(400, 'invalid_grant', 'the device_code was already used', deviceClient.clientId)
      }
      // The approving account's standing (the exchange lattice's leg: a
      // deactivated or erased account's approvals die with it).
      const approvedRow = (await store.listUsers()).find(u => u.id === claimed.userId)
      const approved = await store.getUserById(claimed.userId)
      if (!approvedRow || !approved || !approvedRow.active || approvedRow.provider === 'erased') {
        return refuseToken(400, 'invalid_grant', 'the approving account no longer stands', deviceClient.clientId)
      }
      // The pinned org context + the scope set, re-judged LIVE (the
      // exchange doctrine: what the account lost since the approval falls
      // away — the audit names the dropped; a whole-set loss refuses).
      const claimedContext = await claimsContextFor(store, approved, claimed.orgContext)
      const claimedPinned = normalizePatScopes(claimed.scopes) ?? []
      const claimedGranted: PatScope[] = []
      const claimedDropped: string[] = []
      for (const scope of claimedPinned) {
        const scopeVerdict = await resolvePatScopesForAccount(store, approved, claimedContext, [scope], runtimeEnv<EnvLike>(c))
        if (scopeVerdict.ok) {
          claimedGranted.push(scope)
        } else {
          claimedDropped.push(`${scope.service}:${scope.action}`)
        }
      }
      if (!claimedGranted.length) {
        return refuseToken(400, 'invalid_grant', 'the approving account no longer holds the approved scopes', deviceClient.clientId)
      }
      // The PAT mints NOW — the plaintext shows exactly once (this
      // answer). The one store path, the console mint's audit + mail; the
      // catalog-permission cone stays a console act (empty at mint).
      const claimedExpiry = resolvePatExpiry(undefined)
      if ('error' in claimedExpiry) {
        return refuseToken(400, 'invalid_request', claimedExpiry.error, deviceClient.clientId)
      }
      const claimedPlaintext = mintPatSecret()
      const claimedPat = await store.createPersonalAccessToken({
        id: crypto.randomUUID(),
        userId: approved.id,
        name: deviceGrantPatName(deviceClient.name),
        tokenHash: await hashPat(claimedPlaintext),
        tokenPrefix: patDisplayPrefix(claimedPlaintext),
        scopes: claimedGranted.map(s => `${s.service}:${s.action}`),
        permissions: [],
        orgContext: claimedContext.orgId,
        expiresAt: claimedExpiry.expiresAt,
      })
      await auditPat('account.pat_minted', approved.id, { userId: approved.id, userName: approved.name }, {
        pat: claimedPat.id,
        name: claimedPat.name,
        scopes: claimedPat.scopes,
        orgContext: claimedPat.orgContext,
        expiresAt: claimedPat.expiresAt,
        via: 'device_grant',
        device_authorization: claimed.id,
        client: deviceClient.clientId,
        ...(claimedDropped.length ? { dropped: claimedDropped } : {}),
      })
      await sendOpSecurityMail(runtimeEnv<MailEnv>(c), store, {
        userId: approved.id,
        template: 'pat_minted',
        issuer: config.issuer,
        params: {
          name: approved.name,
          tokenName: claimedPat.name,
          scopes: claimedPat.scopes.join(', '),
          expires: claimedPat.expiresAt.slice(0, 10),
        },
      })
      return c.json({
        access_token: claimedPlaintext,
        token_type: 'Bearer',
        expires_in: Math.max(0, Math.floor((new Date(claimedPat.expiresAt).getTime() - Date.now()) / 1000)),
        scope: claimedPat.scopes.join(' '),
      })
    }

    // ── the person-bearing exchanges: the RFC 8693 grant, two subject
    // classes (auth/op/tokens.ts). The DEVELOPER cone (TODO.identity-
    // features/08): the PAT subject — the subject_token IS the credential
    // (no client auth — the PAT names its account). The SESSION
    // DELEGATION (TODO.ai-platform/03): the OP's own access token as the
    // subject — the caller authenticates and the subject binds to the
    // client it was issued to. The device class's precedent holds for
    // both: the discovery document keeps advertising the RP contract
    // alone (the exchange grant is a register-internal cone, not an RP
    // flow — the contract golden stays byte-identical), and the exchanged
    // token is the OP's ONE token shape (a self-contained ES256 JWT the
    // RPs validate against the JWKS, no call-back).
    if (grantType === PAT_EXCHANGE_GRANT) {
      const subjectTokenType = form.get('subject_token_type') ?? ''

      // ── the session delegation (TODO.ai-platform/03 — tokens.ts's
      // delegation section): the subject is the OP's OWN opaque access
      // token, minted to the AUTHENTICATED client by the sign-in's code
      // exchange. Where the PAT cone's subject IS the credential (no
      // client auth), the opaque subject is a bearer artifact — the
      // caller authenticates, and the exchange binds the subject to the
      // client it was ISSUED to (a service exchanges only its own
      // sign-ins' tokens, never another RP's). The answer carries the
      // actor claim (act.sub — the relying party's audit names the
      // acting service, never just the account).
      if (subjectTokenType === DELEGATION_TOKEN_TYPE) {
        const { client: actor, error: actorError } = await authenticateClient(c, form)
        if (actorError || !actor) {
          await auditPat('account.delegation_exchange_refused', 'unauthenticated', {}, { error: 'invalid_client' })
          return actorError ?? oidcError(c, 401, 'invalid_client', 'the delegation exchange requires client authentication')
        }
        // The refusal is ONE answer for the whole lattice (the PAT
        // cone's enrollment doctrine); the audit chain names the leg.
        // NEVER the token value.
        const refuseDelegation = async (reason: string, userId?: string): Promise<Response> => {
          await auditPat('account.delegation_exchange_refused', userId ?? 'unauthenticated', {}, { error: 'invalid_grant', reason, client: actor.clientId })
          return oidcError(c, 400, 'invalid_grant', 'the subject token is unknown, expired, or its account no longer stands')
        }
        const presentedDelegation = form.get('subject_token') ?? ''
        const subject = presentedDelegation ? await store.getOidcAccessToken(presentedDelegation) : null
        if (!subject) return refuseDelegation('unknown')
        if (subject.clientId !== actor.clientId) return refuseDelegation('foreign_token', subject.userId)
        // The DPoP enforcement (TODO.sota/09, RFC 9449 \u00a77): this
        // endpoint CONSUMES the subject token \u2014 a bound token delegates
        // only with a possession proof from the bound key (the ath over
        // the subject). A stolen bound token refuses here.
        if (subject.dpopJkt) {
          const subjectProof = c.req.header('dpop')
          const subjectKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
          const subjectRes = subjectProof
            ? await verifyDpopProof(subjectProof, { method: 'POST', uri: `${config.issuer}/op/token`, accessToken: presentedDelegation, nonceSecret: subjectKey.secretMaterial })
            : { error: 'the subject token is DPoP-bound — a proof is required' }
          if ('challenge' in subjectRes) {
            c.header('dpop-nonce', subjectRes.challenge)
            return c.json({ error: 'use_dpop_nonce', error_description: 'the proof must carry the server-issued nonce — retry with it' }, 400)
          }
          if (!('jkt' in subjectRes) || subjectRes.jkt !== subject.dpopJkt) {
            return refuseDelegation('dpop_proof', subject.userId)
          }
        }
        // The account's standing (a deactivated or erased account's
        // sessions die with it) — the PAT cone's lattice leg.
        const subjectAccountRow = (await store.listUsers()).find(u => u.id === subject.userId)
        const subjectAccount = await store.getUserById(subject.userId)
        if (!subjectAccountRow || !subjectAccount || !subjectAccountRow.active || subjectAccountRow.provider === 'erased') {
          return refuseDelegation('account_standing', subject.userId)
        }
        // The sign-in's pinned org context, re-judged against the LIVE
        // membership (never a dead org's claims).
        const delegationContext = await claimsContextFor(store, subjectAccount, subject.contextOrg)
        // The scope is REQUIRED (the delegation names its narrowed
        // target) and re-judged per scope against the live standing —
        // the PAT cone's own machinery, verbatim.
        const delegationScope = delegationScopesParam(form.get('scope'))
        if (delegationScope.error || !delegationScope.scopes) {
          await auditPat('account.delegation_exchange_refused', subject.userId, {}, { error: 'invalid_scope', client: actor.clientId })
          return oidcError(c, 400, 'invalid_scope', delegationScope.error ?? 'the scope parameter is required')
        }
        const delegationGranted: PatScope[] = []
        const delegationRoles: Record<string, string[]> = {}
        const delegationDropped: string[] = []
        for (const scope of delegationScope.scopes) {
          const verdict = await resolvePatScopesForAccount(store, subjectAccount, delegationContext, [scope], runtimeEnv<EnvLike>(c))
          if (verdict.ok) {
            delegationGranted.push(scope)
            Object.assign(delegationRoles, verdict.serviceRoles)
          } else {
            delegationDropped.push(`${scope.service}:${scope.action}`)
          }
        }
        if (!delegationGranted.length) return refuseDelegation('scope_standing', subject.userId)
        const delegationKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
        // The first-use registration rides the SAME gate as the other
        // grants (identity#7).
        if (maySelfRegisterOpKey(delegationKey, config)) {
          await ensureOpKeyRegistered(store, delegationKey)
        } else {
          warnDevKeyRegistrationSkipped('/op/token', delegationKey)
        }
        const delegated = await signOpIdToken(delegationKey, delegationTokenClaims(subjectAccount, delegationContext, delegationGranted, delegationRoles, config, actor.clientId))
        // The exchange lands on the audit chain EVERY time (the
        // delegation's cadence is per-session — the PAT cone's throttled
        // heartbeat never applies), the dropped narrowing named.
        await auditPat('account.delegation_exchange', subject.userId, {}, {
          client: actor.clientId,
          scopes: delegationGranted.map(s => `${s.service}:${s.action}`),
          ...(delegationDropped.length ? { dropped: delegationDropped } : {}),
        })
        return c.json({
          access_token: delegated,
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: config.accessTokenTtlMs / 1000,
          scope: delegationGranted.map(s => `${s.service}:${s.action}`).join(' '),
        })
      }

      if (subjectTokenType !== PAT_TOKEN_TYPE) {
        await auditPat('account.pat_exchange_refused', 'unauthenticated', {}, { error: 'invalid_request' })
        return oidcError(c, 400, 'invalid_request', `the token-exchange grant speaks subject_token_type ${PAT_TOKEN_TYPE} or ${DELEGATION_TOKEN_TYPE} only`)
      }
      const presented = form.get('subject_token') ?? ''
      const pat = patPlausible(presented) ? await store.findPersonalAccessTokenByHash(await hashPat(presented)) : null
      // The refusal is ONE answer for the whole lattice — unknown /
      // expired / revoked / wrong-standing are deliberately
      // indistinguishable on the wire (the enrollment doctrine); the
      // audit chain names the leg. NEVER the token value.
      const refuseExchange = async (reason: string, patId?: string, userId?: string): Promise<Response> => {
        await auditPat('account.pat_exchange_refused', userId ?? 'unauthenticated', {}, { error: 'invalid_grant', reason, ...(patId ? { pat: patId } : {}) })
        return oidcError(c, 400, 'invalid_grant', 'the subject token is unknown, expired, revoked, or its account no longer stands')
      }
      if (!pat) return refuseExchange('unknown')
      if (pat.revokedAt) return refuseExchange('revoked', pat.id, pat.userId)
      if (new Date(pat.expiresAt).getTime() <= Date.now()) return refuseExchange('expired', pat.id, pat.userId)
      // The account's standing (a deactivated or erased account's tokens
      // die with it): the registry row carries the active flag.
      const accountRow = (await store.listUsers()).find(u => u.id === pat.userId)
      const account = await store.getUserById(pat.userId)
      if (!accountRow || !account || !accountRow.active || accountRow.provider === 'erased') {
        return refuseExchange('account_standing', pat.id, pat.userId)
      }
      // The pinned org context, re-judged against the LIVE membership
      // (the token endpoint's own doctrine: a membership disabled since
      // the mint falls back to the primary context, never a dead org's
      // claims).
      const context = await claimsContextFor(store, account, pat.orgContext)
      const pinned = normalizePatScopes(pat.scopes) ?? []
      // The optional per-exchange narrowing (RFC 8693's scope parameter:
      // a subset of the pinned set, never wider).
      const narrowing = narrowPatScopesParam(form.get('scope'), pinned)
      if (narrowing.error) {
        await auditPat('account.pat_exchange_refused', pat.userId, {}, { error: 'invalid_scope', pat: pat.id })
        return oidcError(c, 400, 'invalid_scope', narrowing.error)
      }
      // The standing re-judgment, per scope: what the account lost since
      // the mint falls away (the audit names the dropped scopes); a
      // token whose WHOLE set fell away refuses.
      const granted: PatScope[] = []
      const serviceRoles: Record<string, string[]> = {}
      const dropped: string[] = []
      for (const scope of narrowing.scopes ?? pinned) {
        const verdict = await resolvePatScopesForAccount(store, account, context, [scope], runtimeEnv<EnvLike>(c))
        if (verdict.ok) {
          granted.push(scope)
          Object.assign(serviceRoles, verdict.serviceRoles)
        } else {
          dropped.push(`${scope.service}:${scope.action}`)
        }
      }
      if (!granted.length) {
        return refuseExchange('scope_standing', pat.id, pat.userId)
      }
      const patKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      // The first-use registration rides the SAME gate as the other
      // grants (identity#7).
      if (maySelfRegisterOpKey(patKey, config)) {
        await ensureOpKeyRegistered(store, patKey)
      } else {
        warnDevKeyRegistrationSkipped('/op/token', patKey)
      }
      const exchanged = await signOpIdToken(patKey, patTokenClaims(pat, account, context, granted, serviceRoles, config))
      // The throttled heartbeat (never a per-request write): the use
      // stamp + the audit beat share the one-hour window.
      const nowMs = Date.now()
      const nowIso = new Date(nowMs).toISOString()
      const useStale = !pat.lastUsedAt || nowMs - new Date(pat.lastUsedAt).getTime() >= PAT_EXCHANGE_HEARTBEAT_MS
      const beatDue = patExchangeBeatDue(pat, nowMs)
      if (useStale || beatDue) {
        await store.stampPersonalAccessTokenUse(pat.id, { usedAt: nowIso, ...(beatDue ? { auditAt: nowIso } : {}) })
      }
      if (beatDue) {
        await auditPat('account.pat_exchange', pat.userId, {}, {
          pat: pat.id,
          name: pat.name,
          scopes: granted.map(s => `${s.service}:${s.action}`),
          ...(dropped.length ? { dropped } : {}),
        })
      } else if (dropped.length) {
        // A narrowing between beats still lands on the chain.
        await auditPat('account.pat_exchange_narrowed', pat.userId, {}, { pat: pat.id, name: pat.name, dropped })
      }
      // The expiry-soon notice rides the use (the lazy sweep — no
      // scheduler on this deployment shape): the in-use token's owner
      // learns while the automation still works, ONCE per token. The
      // one-shot mark lands when the send resolved (or honestly logged —
      // the console posture); a transient provider failure retries on
      // the next exchange.
      // TODO.identity-features/01: the notice fans out to the primary
      // PLUS every verified additional (sendOpSecurityMail); the
      // one-shot stamp rides the PRIMARY send's result (the address of
      // record).
      if (patExpiryNoticeDue(pat, nowMs)) {
        const mail = await sendOpSecurityMail(runtimeEnv<MailEnv>(c), store, {
          userId: account.id,
          template: 'pat_expiring',
          issuer: config.issuer,
          params: { name: account.name, tokenName: pat.name, expires: pat.expiresAt.slice(0, 10) },
        })
        if (mail.sent || mail.posture === 'console') {
          await store.stampPersonalAccessTokenUse(pat.id, { usedAt: nowIso, expiryNotifiedAt: nowIso })
        }
      }
      return c.json({
        access_token: exchanged,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        token_type: 'Bearer',
        expires_in: config.accessTokenTtlMs / 1000,
        scope: granted.map(s => `${s.service}:${s.action}`).join(' '),
      })
    }

    // ── the refresh grant (TODO.identity-sso, the wave-C token surface) ──
    // RFC 6749 §6 with ROTATION (the OAuth 2.0 Security BCP's refresh
    // doctrine, kernel 0.2.6's store): the presented token consumes
    // ATOMICALLY and its successor mints IN THE SAME FAMILY; a presented
    // CONSUMED token is the theft signal (RFC 6819 §5.2.2.3) — the store
    // already killed the whole family, the answer is invalid_grant, and
    // the audit chain carries the anomaly (TODO.identity-sso/01's
    // baseline). The refreshed ID token proves the ORIGINAL
    // authentication (the row's auth_time never advances; OIDC Core
    // §12.2), the claims re-judge the LIVE standing (a role or membership
    // revoked mid-grant disappears here), and RFC 6749 §6's scope
    // narrowing narrows BOTH the access token and the rotated refresh row
    // (else the narrowing would be illusory).
    if (grantType === 'refresh_token') {
      const { client, error } = await authenticateClient(c, form)
      if (error) {
        await audit('client.token_refused', form.get('client_id')?.trim() || 'unauthenticated', {}, { error: 'invalid_client' })
        return error
      }
      // The machine classes never refresh (client_credentials re-mints
      // instead) — refused BEFORE the one-time token is consumed, so a
      // confused deputy never burns another client's grant.
      const refreshMachineClass = deviceClassOf(client!.claimsPolicy) ? DEVICE_CLASS
        : serviceClassOf(client!.claimsPolicy) ? SERVICE_CLASS
          : null
      if (refreshMachineClass) {
        return refuseToken(400, 'unsupported_grant_type', `the ${refreshMachineClass} class speaks client_credentials only — never a refresh token`, client!.clientId)
      }
      const presentedRefresh = form.get('refresh_token') ?? ''
      const consumed = presentedRefresh ? await store.consumeOidcRefreshToken(presentedRefresh) : { kind: 'invalid' as const }
      if (consumed.kind === 'reuse') {
        // The theft signal, journaled loudly: the account, the client,
        // the family — NEVER the token value.
        await audit('client.refresh_reuse_detected', consumed.clientId, {}, { account: consumed.userId, family: consumed.familyId })
        return refuseToken(400, 'invalid_grant', 'the refresh token was already used — the rotation family stands revoked', client!.clientId)
      }
      if (consumed.kind !== 'ok') {
        return refuseToken(400, 'invalid_grant', 'the refresh token is unknown, expired, or revoked', client!.clientId)
      }
      const grant = consumed.token
      if (grant.clientId !== client!.clientId) {
        // The cross-client present: the consume already burned the token
        // (fail toward invalidation — a token that leaked across clients
        // is compromised by definition); the legitimate holder's next
        // present reads the reuse verdict and the family dies.
        return refuseToken(400, 'invalid_grant', 'the refresh token was not issued to this client', client!.clientId)
      }
      // The account's standing (the delegation cone's lattice leg): a
      // deactivated or erased account's grant dies with its sessions.
      const grantUser = await store.getUserById(grant.userId)
      const grantUserRow = (await store.listUsers()).find(u => u.id === grant.userId)
      if (!grantUser || !grantUserRow || !grantUserRow.active || grantUserRow.provider === 'erased') {
        return refuseToken(400, 'invalid_grant', 'the refresh token’s account no longer stands', client!.clientId)
      }
      // RFC 6749 §6's scope narrowing: the request may name a SUBSET of
      // the granted set — an empty ask or anything beyond refuses loudly
      // (never a silent mint past the grant). The row's spelling reads as
      // a SET and the answer goes out canonical (migration 0025's scope
      // cell contract) — the code-exchange row may carry the request's
      // verbatim order, the rotation never does.
      let effectiveScope = normalizeOidcScopeSet(grant.scope)
      const askedScope = form.get('scope')
      if (askedScope !== null) {
        const grantedSet = new Set(grant.scope.split(/\s+/).filter(Boolean))
        const asked = askedScope.split(/\s+/).filter(Boolean)
        if (!asked.length || asked.some(s => !grantedSet.has(s))) {
          return refuseToken(400, 'invalid_scope', 'the scope parameter must name a subset of the granted scopes', client!.clientId)
        }
        effectiveScope = normalizeOidcScopeSet(asked.join(' '))
      }

      // The claims the code exchange's math derives, re-judged from the
      // row's provenance (the context re-checked against the LIVE
      // membership — never a dead org's claims).
      const refreshScopes = effectiveScope.split(/\s+/).filter(Boolean)
      const refreshNowSec = Math.floor(Date.now() / 1000)
      const refreshClaims: Record<string, unknown> = {
        iss: config.issuer,
        sub: grantUser.id,
        aud: client!.clientId,
        exp: refreshNowSec + config.idTokenTtlSec,
        iat: refreshNowSec,
      }
      if (refreshScopes.includes('profile')) refreshClaims.name = grantUser.name
      if (refreshScopes.includes('email')) {
        refreshClaims.email = grantUser.email
        refreshClaims.email_verified = Boolean(grantUser.emailVerifiedAt)
      }
      const refreshAssigned = await store.getOpClientRoles(grantUser.id, client!.clientId)
      const refreshContext = await claimsContextFor(store, grantUser, grant.contextOrg)
      Object.assign(refreshClaims, roleClaimsForContext(refreshAssigned, refreshContext, client!.claimsPolicy))
      const refreshPicture = pictureClaimForClient(grantUser, client!.claimsPolicy, config.issuer)
      if (refreshPicture) refreshClaims.picture = refreshPicture
      // The authorizing authentication's provenance carries through EVERY
      // rotation: the amr as recorded, the ORIGINAL authentication
      // instant (never the refresh's moment).
      if (grant.amr?.length) refreshClaims.amr = grant.amr
      refreshClaims.acr = acrOf(grant.amr)
      if (grant.authTime) {
        const grantAuthTime = authTimeOf(grant.authTime)
        if (grantAuthTime) refreshClaims.auth_time = grantAuthTime
      }

      const refreshKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      // The first-use registration rides the SAME gate as the other
      // grants (identity#7).
      if (maySelfRegisterOpKey(refreshKey, config)) {
        await ensureOpKeyRegistered(store, refreshKey)
      } else {
        warnDevKeyRegistrationSkipped('/op/token', refreshKey)
      }
      const refreshedIdToken = await signOpIdToken(refreshKey, refreshClaims)

      // The DPoP arm (TODO.sota/09): a proof on the refresh re-binds the
      // ROTATED access token to its key (each request proves fresh).
      const refreshDpop = await dpopBindingFor(c, config)
      if (refreshDpop && 'challenge' in refreshDpop) return dpopChallenged(c, refreshDpop.challenge)
      if (refreshDpop && 'error' in refreshDpop) {
        return refuseToken(400, 'invalid_dpop_proof', refreshDpop.error, client!.clientId)
      }
      if (refreshDpop && 'nonce' in refreshDpop) c.header('dpop-nonce', refreshDpop.nonce)
      const refreshedAccess = opRandomToken()
      await store.createOidcAccessToken({
        token: refreshedAccess,
        userId: grantUser.id,
        clientId: client!.clientId,
        scope: effectiveScope,
        contextOrg: grant.contextOrg,
        amr: grant.amr,
        dpopJkt: refreshDpop && 'jkt' in refreshDpop ? refreshDpop.jkt : null,
        ttlMs: config.accessTokenTtlMs,
      })
      // The rotation: the successor inherits the family + the provenance
      // (the NARROWED scope when the request narrowed — the grant's
      // record of what still stands).
      const rotated = opRandomToken()
      await store.createOidcRefreshToken({
        token: rotated,
        userId: grantUser.id,
        clientId: client!.clientId,
        scope: effectiveScope,
        contextOrg: grant.contextOrg,
        amr: grant.amr,
        authTime: grant.authTime,
        familyId: grant.familyId,
        ttlMs: config.refreshTokenTtlMs,
      })
      // The refresh lands on the audit chain (the per-client activity +
      // the anomaly baseline), NEVER the token values.
      await audit('client.token_refreshed', client!.clientId, {}, { account: grantUser.id, scope: effectiveScope, family: grant.familyId })
      return c.json({
        access_token: refreshedAccess,
        token_type: refreshDpop && 'jkt' in refreshDpop ? 'DPoP' : 'Bearer',
        expires_in: config.accessTokenTtlMs / 1000,
        id_token: refreshedIdToken,
        refresh_token: rotated,
        scope: effectiveScope,
      })
    }

    if (grantType !== 'authorization_code') {
      return refuseToken(400, 'unsupported_grant_type', 'authorization_code and refresh_token only', form.get('client_id') ?? undefined)
    }

    const { client, error } = await authenticateClient(c, form)
    if (error) {
      await audit('client.token_refused', form.get('client_id')?.trim() || 'unauthenticated', {}, { error: 'invalid_client' })
      return error
    }

    // A machine client never redeems an authorization code (the machine
    // classes speak client_credentials only) — refused BEFORE the one-time
    // code is consumed, so a confused-deputy mixup never burns another
    // flow's code.
    const redeemMachineClass = deviceClassOf(client!.claimsPolicy) ? DEVICE_CLASS
      : serviceClassOf(client!.claimsPolicy) ? SERVICE_CLASS
        : null
    if (redeemMachineClass) {
      return refuseToken(400, 'unsupported_grant_type', `the ${redeemMachineClass} class speaks client_credentials only — never an authorization code`, client!.clientId)
    }

    // The one-time code — consumed ATOMICALLY here, so whatever fails
    // below never gives the code a second life, and a replay always
    // loses (invalid_grant).
    const codeValue = form.get('code') ?? ''
    const code = codeValue ? await store.consumeOidcCode(codeValue) : null
    if (!code) return refuseToken(400, 'invalid_grant', 'the code is unknown, expired, or already used', client!.clientId)
    if (code.clientId !== client!.clientId) {
      return refuseToken(400, 'invalid_grant', 'the code was not issued to this client', client!.clientId)
    }
    if (code.redirectUri !== (form.get('redirect_uri') ?? '')) {
      return refuseToken(400, 'invalid_grant', 'redirect_uri does not match the authorization request', client!.clientId)
    }
    const verifier = form.get('code_verifier') ?? ''
    if (!verifier || (await pkceS256(verifier)) !== code.codeChallenge) {
      return refuseToken(400, 'invalid_grant', 'the PKCE verifier does not match the challenge', client!.clientId)
    }

    // The user read and the per-client roles read are INDEPENDENT (both
    // key on the consumed code's userId) — ONE phase on every exchange
    // (TODO.restructure/14). claimsContextFor stays behind the user read:
    // it resolves the org context against the user object.
    const [user, assigned] = await Promise.all([
      store.getUserById(code.userId),
      store.getOpClientRoles(code.userId, client!.clientId),
    ])
    if (!user) return refuseToken(400, 'invalid_grant', 'the code’s account no longer exists', client!.clientId)

    // The claims the client is allowed: profile+email per the scopes;
    // roles/groups/org ONLY per the client's claims policy (a client
    // with no policy never receives role claims); the picture claim
    // follows the same per-client privilege (below). TODO.identity/03:
    // the role VALUES are the account's per-client assignment (no row =
    // the account's OP-side default set), bounded by the policy's
    // optional role allowlist — the OP never emits a role the client is
    // not configured to receive (auth/op/claims.ts). TODO.identity/11: the
    // default set is resolved under the code's stamped ORG CONTEXT (the
    // consent's active org, re-judged against the live membership — a
    // membership disabled mid-flow falls back to the primary context,
    // never a dead org's claims).
    const scopes = code.scope.split(/\s+/).filter(Boolean)
    const nowSec = Math.floor(Date.now() / 1000)
    const claims: Record<string, unknown> = {
      iss: config.issuer,
      sub: user.id,
      aud: client!.clientId,
      exp: nowSec + config.idTokenTtlSec,
      iat: nowSec,
    }
    if (code.nonce) claims.nonce = code.nonce
    if (scopes.includes('profile')) claims.name = user.name
    if (scopes.includes('email')) {
      claims.email = user.email
      // TODO.identity-sso/04 (the account lifecycle discipline): the
      // claim answers the address's CURRENT verification state (the
      // invite/setup ceremony's stamp, users.email_verified_at) — an
      // invited-not-yet-set-up or admin-re-addressed account reads
      // FALSE, so an RP never takes an unproven mailbox as vouched
      // (the platform's link-by-verified-email rule depends on it).
      claims.email_verified = Boolean(user.emailVerifiedAt)
    }
    const context = await claimsContextFor(store, user, code.contextOrg ?? null)
    Object.assign(claims, roleClaimsForContext(assigned, context, client!.claimsPolicy))
    // The picture family (auth/op/claims.ts): the public avatar route's
    // absolute URL, ONLY when the policy names the family AND the account
    // has an uploaded avatar — absent otherwise, never a broken URL.
    const picture = pictureClaimForClient(user, client!.claimsPolicy, config.issuer)
    if (picture) claims.picture = picture
    // TODO.sota/05: the linked ORCID iD per the client's policy (the
    // same privilege gate; the link's verification is ORCID's own).
    const orcid = await orcidClaimForClient(store, user.id, client!.claimsPolicy)
    if (orcid) claims.orcid = orcid
    // TODO.sota/05: the active org's ROR id per the client's policy —
    // the registry row's enrichment, resolved under the SAME context
    // the org claim carried.
    const orgRor = await orgRorClaimForClient(store, context.orgId, client!.claimsPolicy)
    if (orgRor) claims.org_ror = orgRor
    // TODO.identity-sso/02+03: the authorizing authentication's amr
    // provenance (the consenting session's, carried by the code) — the
    // RP-visible claim matches the session's truth. Absent when no
    // OP-side credential event was recorded (an upstream sign-in).
    if (code.amr?.length) claims.amr = code.amr
    claims.acr = acrOf(code.amr)
    // TODO.identity-sso (the wave-A tail): the authentication INSTANT —
    // the prompt=login freshness proof the RP verifies (an RP that asked
    // for a forced re-authentication checks auth_time ≥ the request's
    // moment). Absent when the code carries none (a pre-wave row, or a
    // session whose instant never projected).
    if (code.authTime) {
      const authTime = authTimeOf(code.authTime)
      if (authTime) claims.auth_time = authTime
    }

    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    // The first-use registration rides the SAME gate as the JWKS route
    // (identity#7): a generated development key never enters the keyset
    // on a declared-issuer deployment. Signing itself still proceeds
    // (the documented dev posture — the loud warning fired at resolve).
    if (maySelfRegisterOpKey(key, config)) {
      await ensureOpKeyRegistered(store, key)
    } else {
      warnDevKeyRegistrationSkipped('/op/token', key)
    }
    const idToken = await signOpIdToken(key, claims)

    // The DPoP arm (TODO.sota/09, RFC 9449 §5): a valid proof binds the
    // minted access token to the proof key's JKT — the response answers
    // token_type DPoP and userinfo enforces the same key thereafter.
    const dpop = await dpopBindingFor(c, config)
    if (dpop && 'challenge' in dpop) return dpopChallenged(c, dpop.challenge)
    if (dpop && 'error' in dpop) {
      return refuseToken(400, 'invalid_dpop_proof', dpop.error, client!.clientId)
    }
    if (dpop && 'nonce' in dpop) c.header('dpop-nonce', dpop.nonce)
    const accessToken = opRandomToken()
    await store.createOidcAccessToken({
      token: accessToken,
      userId: user.id,
      clientId: client!.clientId,
      scope: code.scope,
      contextOrg: code.contextOrg ?? null,
      // The same provenance rides the access token — userinfo answers
      // the amr the ID token carried.
      amr: code.amr,
      dpopJkt: dpop && 'jkt' in dpop ? dpop.jkt : null,
      ttlMs: config.accessTokenTtlMs,
    })

    // TODO.identity-sso (the wave-C token surface): the offline half of
    // the consent — a granted offline_access scope mints the FIRST
    // refresh token of its rotation family (kernel 0.2.6, migration
    // 0025). The row carries the code's full provenance (the canonical
    // scope, the context, the amr, the ORIGINAL auth_time) — every later
    // rotation re-mints the same truth.
    let refreshToken: string | null = null
    if (scopes.includes('offline_access')) {
      refreshToken = opRandomToken()
      await store.createOidcRefreshToken({
        token: refreshToken,
        userId: user.id,
        clientId: client!.clientId,
        scope: code.scope,
        contextOrg: code.contextOrg ?? null,
        amr: code.amr,
        authTime: code.authTime,
        familyId: opRandomToken(),
        ttlMs: config.refreshTokenTtlMs,
      })
    }

    // The issuance lands on the audit chain (TODO.identity-sso/01's
    // per-client activity + the anomaly baseline): the client, the
    // account, the scope. NEVER the token values.
    await audit('client.token_issued', client!.clientId, {}, { account: user.id, scope: code.scope })

    // TODO.sota/08 slice 3 (OIDC4VCI): the credential grant answers
    // the c_nonce the wallet's key proof must echo at the credential
    // endpoint (the same stateless HMAC challenge as DPoP's nonce).
    if (scopes.includes('org-membership')) {
      const dpopKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      c.header('content-type', 'application/json')
      return c.json({
        access_token: accessToken,
        token_type: dpop && 'jkt' in dpop ? 'DPoP' : 'Bearer',
        expires_in: config.accessTokenTtlMs / 1000,
        id_token: idToken,
        ...(refreshToken ? { refresh_token: refreshToken } : {}),
        c_nonce: await mintDpopNonce(dpopKey.secretMaterial),
        c_nonce_expires_in: 600,
      })
    }
    return c.json({
      access_token: accessToken,
      token_type: dpop && 'jkt' in dpop ? 'DPoP' : 'Bearer',
      expires_in: config.accessTokenTtlMs / 1000,
      id_token: idToken,
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
    })
  })



  return op
}
