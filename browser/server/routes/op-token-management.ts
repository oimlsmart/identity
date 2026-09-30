// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the TOKEN SURFACE'S MANAGEMENT HALF, extracted from
// op.ts as the seventh proof of the domain-model split (the pure
// refactor; the golden + the suite are the proof — zero behavior
// change).
//
//   GET  /op/userinfo  — the access token's claims (the same policy the
//        ID token carried).
//   POST /op/revoke    — RFC 7009: the client-bound revocation — a
//        client revokes only its OWN tokens, a refresh token's
//        revocation kills its whole family, the answer is 200 whether
//        the token existed or not.
//   POST /op/introspect — RFC 7662: the authenticated client reads a
//        token's standing — the opaque access tokens from the table,
//        the machine classes' JWTs through the signature + the named
//        client's standing (never a table read).
//
// The grant arms themselves (POST /op/token) stay in op.ts; the audit
// + client-authentication seams ride in as dependencies.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, normalizePatScopes, type PatScope } from '../store'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { verifyOpJwt } from '../auth/op/keys'
import { oidcError } from '../auth/op/oidc-error'
import { roleClaimsForContext, pictureClaimForClient, orcidClaimForClient, orgRorClaimForClient } from '../auth/op/claims'
import { claimsContextFor } from '../auth/op/memberships'
import {
  auditPat, hashPat, PAT_EXCHANGE_HEARTBEAT_MS, patExchangeBeatDue, patIntrospectionClaims, patPlausible, resolvePatScopesForAccount,
} from '../auth/op/tokens'

type EnvLike = Record<string, string | undefined>

/** The request's effective OP config (env + this request's origin) —
 *  the same formula every OP route reads. */
function configFor(c: Context) {
  return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
}

export function createOpTokenManagementRouter(deps: {
  audit: (
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
  ) => Promise<void>
  authenticateClient: (c: Context, form: URLSearchParams) => Promise<{ client: import('../store').OidcClient | null; error: Response | null }>
}): Hono {
  const op = new Hono()
  const audit = deps.audit
  const authenticateClient = deps.authenticateClient

  op.get('/op/userinfo', async (c) => {
    const header = c.req.header('authorization') ?? ''
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : ''
    if (!token) {
      return c.json({ error: 'invalid_token', error_description: 'a Bearer access token is required' }, 401)
    }
    const store = getStore()
    const access = await store.getOidcAccessToken(token)
    if (!access) {
      return c.json({ error: 'invalid_token', error_description: 'the access token is unknown or expired' }, 401)
    }
    const user = await store.getUserById(access.userId)
    if (!user) return c.json({ error: 'invalid_token', error_description: 'the token’s account no longer exists' }, 401)

    const scopes = access.scope.split(/\s+/).filter(Boolean)
    const client = await store.getOidcClient(access.clientId)
    const claims: Record<string, unknown> = { sub: user.id }
    if (scopes.includes('profile')) claims.name = user.name
    if (scopes.includes('email')) {
      claims.email = user.email
      // The same honesty the ID token carries (TODO.identity-sso/04):
      // the address's CURRENT verification state, never a blanket true.
      claims.email_verified = Boolean(user.emailVerifiedAt)
    }
    // The same shaping the ID token carried (TODO.identity/03): the
    // per-client assignment through the client's policy allowlist, under
    // the granting code's org context (TODO.identity/11).
    const assigned = await store.getOpClientRoles(user.id, access.clientId)
    const context = await claimsContextFor(store, user, access.contextOrg ?? null)
    Object.assign(claims, roleClaimsForContext(assigned, context, client?.claimsPolicy ?? null))
    const picture = pictureClaimForClient(user, client?.claimsPolicy ?? null, configFor(c).issuer)
    if (picture) claims.picture = picture
    const orcid = await orcidClaimForClient(store, user.id, client?.claimsPolicy ?? null)
    if (orcid) claims.orcid = orcid
    const orgRor = await orgRorClaimForClient(store, context.orgId, client?.claimsPolicy ?? null)
    if (orgRor) claims.org_ror = orgRor
    // TODO.identity-sso/02+03: userinfo answers the same amr the ID
    // token carried (the authorizing authentication's provenance).
    if (access.amr?.length) claims.amr = access.amr
    return c.json(claims)
  })

  // ── the token surface's management half (TODO.identity-sso, wave C) ──

  // POST /op/revoke — RFC 7009: the client-bound revocation. A client
  // revokes only its OWN tokens; a REFRESH token's revocation kills its
  // whole rotation family (the grant lineage ends — the kernel store's
  // doctrine), an access token's row deletes. The machine classes' JWTs
  // carry no rows — revoking one is the honest no-op (the token's
  // standing rides its exp and the client's status; the introspection
  // endpoint below answers it). The answer is 200 whether the token
  // existed or not (RFC 7009 §2.2's indistinguishability) — the audit
  // chain carries the truth (the kind found, never the token value).
  op.post('/op/revoke', async (c) => {
    const contentType = c.req.header('content-type') ?? ''
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return oidcError(c, 400, 'invalid_request', 'the revocation endpoint speaks application/x-www-form-urlencoded')
    }
    const form = new URLSearchParams(await c.req.raw.text())
    const { client, error } = await authenticateClient(c, form)
    if (error) {
      await audit('client.revoke_refused', form.get('client_id')?.trim() || 'unauthenticated', {}, { error: 'invalid_client' })
      return error
    }
    const token = form.get('token') ?? ''
    if (!token) {
      return oidcError(c, 400, 'invalid_request', 'the token parameter is required')
    }
    // token_type_hint is ADVISORY (RFC 7009 §2.1): the hinted half is
    // tried first, but a wrong hint never protects the token — the other
    // half still answers (the RFC's own search extension).
    const hint = form.get('token_type_hint')
    let kind: 'refresh' | 'access' | 'unknown' = 'unknown'
    const halves: Array<'refresh' | 'access'> = hint === 'access_token' ? ['access', 'refresh'] : ['refresh', 'access']
    for (const half of halves) {
      if (half === 'refresh' && await getStore().revokeOidcRefreshToken(token, client!.clientId)) { kind = 'refresh'; break }
      if (half === 'access' && await getStore().deleteOidcAccessToken(token, client!.clientId)) { kind = 'access'; break }
    }
    await audit('client.token_revoked', client!.clientId, {}, { kind })
    return new Response(null, { status: 200 })
  })

  // POST /op/introspect — RFC 7662 (identity#47/#42's RS half): the
  // caller authenticates as a client (the token endpoint's own
  // machinery); ANY active registered client may introspect (the relying
  // party and the resource server are the same registry here — the
  // answer never carries more than the token's own claims). The OPAQUE
  // access tokens answer from the table (active + the claim set); the
  // machine classes' self-contained JWTs answer through the SIGNATURE
  // against the registered keyset + the issuer + the expiry + the named
  // client's LIVE standing — never a table read (there are no rows). A
  // refresh token answers { active: false }: the refresh rows serve the
  // token endpoint's rotation, never introspection (the named scope of
  // this surface). The PAT class (TODO.openapi/03 — the platform's
  // per-request enforcement read) answers from the credential row with
  // the LIVE standing judgment (the comment at the PAT leg below).
  // Everything unknown, expired, or revoked answers the honest inactive.
  op.post('/op/introspect', async (c) => {
    const contentType = c.req.header('content-type') ?? ''
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return oidcError(c, 400, 'invalid_request', 'the introspection endpoint speaks application/x-www-form-urlencoded')
    }
    const form = new URLSearchParams(await c.req.raw.text())
    const { client, error } = await authenticateClient(c, form)
    if (error) {
      await audit('client.introspect_refused', form.get('client_id')?.trim() || 'unauthenticated', {}, { error: 'invalid_client' })
      return error
    }
    const token = form.get('token') ?? ''
    if (!token) {
      return oidcError(c, 400, 'invalid_request', 'the token parameter is required')
    }
    const store = getStore()
    const config = configFor(c)

    // The opaque half: the access-token table (the row's absence — never
    // minted, revoked, or swept — IS the inactive answer; the liveness
    // clause holds the expiry honest).
    const access = await store.getOidcAccessToken(token)
    if (access) {
      return c.json({
        active: true,
        iss: config.issuer,
        sub: access.userId,
        aud: access.clientId,
        client_id: access.clientId,
        scope: access.scope,
        token_type: 'Bearer',
        exp: Math.floor(new Date(access.expiresAt).getTime() / 1000),
        ...(access.amr?.length ? { amr: access.amr } : {}),
      })
    }

    // The machine half: the compact-JWT shape (three segments) verifies
    // against the keyset — then the standing re-judges what the table
    // never carried: the issuer's match, the expiry, and the NAMED
    // client still registered + active (a disabled machine client's
    // in-flight tokens go inactive here, the revocation story the rows
    // never had).
    if (token.split('.').length === 3) {
      const claims = await verifyOpJwt(store, token)
      if (claims) {
        const namedClientId = typeof claims.client_id === 'string' ? claims.client_id
          : typeof claims.aud === 'string' ? claims.aud : ''
        const namedClient = namedClientId ? await store.getOidcClient(namedClientId) : null
        const standing = Boolean(namedClient && namedClient.status === 'active')
          && claims.iss === config.issuer
          && typeof claims.exp === 'number' && claims.exp * 1000 > Date.now()
        if (standing) {
          return c.json({
            active: true,
            iss: claims.iss,
            sub: claims.sub,
            aud: claims.aud,
            ...(typeof claims.client_id === 'string' ? { client_id: claims.client_id } : {}),
            ...(typeof claims.scope === 'string' ? { scope: claims.scope } : {}),
            token_type: 'Bearer',
            ...(typeof claims.iat === 'number' ? { iat: claims.iat } : {}),
            exp: claims.exp,
          })
        }
      }
    }

    // The PAT half (TODO.openapi/03 — the platform contract's
    // access-token class): a RAW personal access token, which never
    // resolved above (no access-token row, not a JWT), introspects
    // ACTIVE with the LIVE judgment — the account's standing, the pinned
    // org context and every scope re-judged against the account's
    // now-truth (the exchange's exact lattice, patTokenClaims's
    // resolution), so a role lost since the mint narrows the answer and
    // a revoked / expired / standing-lost token reads inactive. This IS
    // the platform's per-request enforcement read (no RP-side cache —
    // revocation is instant here); the throttled heartbeat keeps the
    // use stamps + the audit beat from becoming per-request writes.
    // Everything unknown/revoked/expired falls to the ONE honest
    // inactive below — silent, like every other introspection miss (the
    // RFC's indistinguishable answer; the caller's hot path never
    // drafts the journal per probe). Client auth above stays the gate.
    if (patPlausible(token)) {
      const pat = await store.findPersonalAccessTokenByHash(await hashPat(token))
      if (pat && !pat.revokedAt && new Date(pat.expiresAt).getTime() > Date.now()) {
        const accountRow = (await store.listUsers()).find(u => u.id === pat.userId)
        const account = await store.getUserById(pat.userId)
        if (accountRow && account && accountRow.active && accountRow.provider !== 'erased') {
          const context = await claimsContextFor(store, account, pat.orgContext)
          const pinned = normalizePatScopes(pat.scopes) ?? []
          const granted: PatScope[] = []
          const serviceRoles: Record<string, string[]> = {}
          for (const scope of pinned) {
            const verdict = await resolvePatScopesForAccount(store, account, context, [scope], runtimeEnv<EnvLike>(c))
            if (verdict.ok) {
              granted.push(scope)
              Object.assign(serviceRoles, verdict.serviceRoles)
            }
          }
          if (granted.length) {
            const nowMs = Date.now()
            const nowIso = new Date(nowMs).toISOString()
            const useStale = !pat.lastUsedAt || nowMs - new Date(pat.lastUsedAt).getTime() >= PAT_EXCHANGE_HEARTBEAT_MS
            const beatDue = patExchangeBeatDue(pat, nowMs)
            if (useStale || beatDue) {
              await store.stampPersonalAccessTokenUse(pat.id, { usedAt: nowIso, ...(beatDue ? { auditAt: nowIso } : {}) })
            }
            if (beatDue) {
              await auditPat('account.pat_introspected', pat.userId, {}, {
                pat: pat.id,
                name: pat.name,
                client: client!.clientId,
              })
            }
            return c.json(patIntrospectionClaims(pat, account, context, granted, serviceRoles, config))
          }
        }
      }
    }
    return c.json({ active: false })
  })

  return op
}
