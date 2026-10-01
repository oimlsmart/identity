// ═══════════════════════════════════════════════════════════════════
// TODO.sota/08 — the OrgMembership credential (SD-JWT VC, slice 1):
// the issuing surface. The OP-native flow reuses the OP's own session
// (the account console's posture — an OIDC4VCI authorization-code flow
// rides the same mint as the next slice): the account asks for its
// membership credential, optionally naming a HOLDER key (the wallet's
// public JWK → cnf.jkt), and receives the combined presentation with
// every disclosure — the HOLDER selects what to reveal at presentation
// time, the verifier checks the hashes.
//
//   GET  /.well-known/openid-credential-issuer — the credential
//        issuer metadata (public; the OIDC4VCI discovery doc).
//   GET  /api/op/credentials — the account's issuable types.
//   POST /api/op/credentials/membership — the mint (session-gated):
//        { holder_jwk?: { kty: 'EC', crv: 'P-256', x, y } } →
//        { format: 'vc+sd-jwt', credential, expires_in }.
//
// The credential's truth is the SAME truth the tokens carry
// (claimsContextFor's org context + the registry row's ROR id — never
// a second source). The engine: auth/op/sd-jwt.ts.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import { sessionUser } from '../session'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { ensureOpKeyRegistered, maySelfRegisterOpKey, resolveOpSigningKey, warnDevKeyRegistrationSkipped } from '../auth/op/keys'
import { claimsContextFor } from '../auth/op/memberships'

import { combinedPresentation, mintSdJwt, buildStatusListJwt } from '../auth/op/sd-jwt'
import { jktOf } from '../auth/op/dpop'
import { isSystemAuthority } from '../vocab/roles'

type EnvLike = Record<string, string | undefined>

const CREDENTIAL_TTL_SEC = 30 * 24 * 60 * 60

function configFor(c: Context) {
  return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
}

const CONFIGURATIONS = {
  'org-membership': {
    format: 'vc+sd-jwt',
    vct: 'org-membership',
    scope: 'org-membership',
    // The selectively-disclosable set — everything a verifier may ask
    // to see, each claim independently revealable by the holder.
    claims: ['name', 'email', 'org', 'org_name', 'org_ror', 'roles', 'country'],
    cryptographic_holder_binding_required: false,
  },
} as const

export function createOpCredentialsRouter(): Hono {
  const router = new Hono()

  // The OIDC4VCI discovery document (public, deploy-stable — it
  // changes only on deploys; the edge carries the repeat load).
  router.get('/.well-known/openid-credential-issuer', (c) => {
    c.header('Cache-Control', 'public, max-age=300')
    return c.json({
      credential_issuer: configFor(c).issuer,
      credential_endpoint: `${configFor(c).issuer}/op/credential`,
      grant_types_supported: ['authorization_code'],
      credential_configurations_supported: CONFIGURATIONS,
    })
  })

  // POST /op/credential — the OIDC4VCI credential endpoint (slice 3):
  // the wallet's own authorization (the org-membership scope's access
  // token) + its key proof (openid4vci-proof+jwt over the c_nonce the
  // token answer issued) mints the HOLDER-BOUND credential — the same
  // mint, the same truth, the same status anchor, cnf.jkt = the
  // wallet's key.
  router.post('/op/credential', async (c) => {
    const header = c.req.header('authorization') ?? ''
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : ''
    if (!token) return c.json({ error: 'invalid_token', error_description: 'the credential request requires the org-membership access token' }, 401)
    const store = getStore()
    const access = await store.getOidcAccessToken(token)
    if (!access) return c.json({ error: 'invalid_token', error_description: 'the access token is unknown or expired' }, 401)
    if (!access.scope.split(/\s+/).includes('org-membership')) {
      return c.json({ error: 'insufficient_scope', error_description: 'the access token was not granted the org-membership scope' }, 403)
    }
    const raw = await store.getUserById(access.userId)
    if (!raw || !raw.orgId) {
      return c.json({ error: 'invalid_request', error_description: 'the account carries no organization membership — nothing to credential' }, 400)
    }
    const body = await c.req.json<{ format?: string; vct?: string; proof?: { proof_type?: string; jwt?: string } }>().catch(() => null)
    if (!body || body.format !== 'vc+sd-jwt' || body.vct !== 'org-membership') {
      return c.json({ error: 'invalid_request', error_description: 'format must be vc+sd-jwt and vct must be org-membership' }, 400)
    }
    if (!body.proof || body.proof.proof_type !== 'jwt' || typeof body.proof.jwt !== 'string' || !body.proof.jwt) {
      return c.json({ error: 'invalid_proof', error_description: 'the wallet key proof is required (openid4vci-proof+jwt over the issued c_nonce)' }, 400)
    }
    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    if (maySelfRegisterOpKey(key, configFor(c))) {
      await ensureOpKeyRegistered(store, key)
    } else {
      warnDevKeyRegistrationSkipped('/op/credential', key)
    }
    const { verifyWalletProof } = await import('../auth/op/sd-jwt')
    const proof = await verifyWalletProof(body.proof.jwt, { issuer: configFor(c).issuer, nonceSecret: key.secretMaterial })
    if (!proof) {
      return c.json({ error: 'invalid_proof', error_description: 'the proof does not verify (the typ, the key, the audience, or the c_nonce)' }, 400)
    }
    // The credential's truth — the SAME read the session mint performs.
    const context = await claimsContextFor(store, raw, null)
    const orgId = context.orgId ?? raw.orgId
    const orgRow = await store.getOrgRegistryOrg(orgId)
    const roles = context.roles.length ? context.roles : [raw.role]
    const statusListIdx = await store.allocateCredentialStatusIdx()
    const { mintSdJwt, combinedPresentation } = await import('../auth/op/sd-jwt')
    const minted = await mintSdJwt(key, {
      issuer: configFor(c).issuer,
      subject: raw.id,
      audience: access.clientId,
      ttlSec: CREDENTIAL_TTL_SEC,
      plain: { vct: 'org-membership' },
      disclosable: {
        name: raw.name,
        email: raw.email,
        org: orgId,
        ...(orgRow ? { org_name: orgRow.name } : {}),
        ...(orgRow?.rorId ? { org_ror: orgRow.rorId } : {}),
        ...(orgRow?.country ? { country: orgRow.country } : {}),
        ...(roles.length ? { roles } : {}),
      },
      holderJkt: proof.jkt,
      statusListUri: `${configFor(c).issuer}/op/credentials/statuslist`,
      statusListIdx,
    })
    return c.json({ format: 'vc+sd-jwt', credential: combinedPresentation(minted.sdJwt, minted.disclosures) })
  })

  // GET /op/credentials/statuslist — RFC 9157's list: the compressed
  // bitstring in a statuslist+jwt (public; a verifier caches briefly —
  // a revocation shows within the minute).
  router.get('/op/credentials/statuslist', async (c) => {
    const store = getStore()
    const read = await store.readCredentialStatus()
    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    if (maySelfRegisterOpKey(key, configFor(c))) {
      await ensureOpKeyRegistered(store, key)
    } else {
      warnDevKeyRegistrationSkipped('/op/credentials/statuslist', key)
    }
    const jwt = await buildStatusListJwt(key, {
      issuer: configFor(c).issuer,
      maxIdx: read.maxIdx,
      revoked: read.revoked,
    })
    c.header('content-type', 'application/statuslist+jwt')
    c.header('cache-control', 'public, max-age=60')
    return c.body(jwt)
  })

  // POST /api/op/credentials/statuslist/:idx/revoke — the revocation
  // act: an administrator's deliberate flip (the same system-authority
  // gate as every registry act). Idempotent-refusing: an already
  // revoked index answers 409.
  router.post('/api/op/credentials/statuslist/:idx/revoke', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    if (!isSystemAuthority(user.role)) {
      return c.json({ error: 'administrator role required' }, 403)
    }
    const idx = Number(c.req.param('idx'))
    if (!Number.isInteger(idx) || idx < 1) {
      return c.json({ error: 'the status-list index must be a positive integer' }, 400)
    }
    const flipped = await getStore().setCredentialStatusRevoked(idx, new Date().toISOString())
    if (!flipped) return c.json({ error: `the index ${idx} was never issued, or is already revoked` }, 409)
    return c.json({ ok: true, idx, revoked: true })
  })

  router.get('/api/op/credentials', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    return c.json({
      configurations: CONFIGURATIONS,
      ...(user.orgId ? { issuable: ['org-membership'] } : { issuable: [] }),
    })
  })

  router.post('/api/op/credentials/membership', async (c) => {
    const session = await sessionUser(c)
    if (!session) return c.json({ error: 'authentication required' }, 401)
    const store = getStore()
    // The RAW account row — the context rule reads the primary binding
    // (the same discipline every claims emission follows).
    const raw = await store.getUserById(session.id)
    if (!raw) return c.json({ error: 'the account no longer stands' }, 401)
    if (!raw.orgId) {
      return c.json({ error: 'the account carries no organization membership — nothing to credential' }, 409)
    }
    const body = await c.req.json<{ holder_jwk?: { kty?: string; crv?: string; x?: string; y?: string } }>().catch(() => null)
    let holderJkt: string | undefined
    if (body?.holder_jwk !== undefined) {
      const jwk = body.holder_jwk
      if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
        return c.json({ error: 'holder_jwk must be a public EC P-256 key ({ kty, crv, x, y })' }, 400)
      }
      holderJkt = await jktOf({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y })
    }

    // The credential's truth: the SAME org context the tokens carry,
    // the SAME registry row the org_ror claim reads.
    const context = await claimsContextFor(store, raw, null)
    const orgId = context.orgId ?? raw.orgId
    const orgRow = await store.getOrgRegistryOrg(orgId)
    const roles = context.roles.length ? context.roles : [raw.role]

    // The first-use registration rides the SAME gate as every other
    // minting arm (identity#7): a generated development key never
    // enters the keyset on a declared-issuer deployment.
    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    if (maySelfRegisterOpKey(key, configFor(c))) {
      await ensureOpKeyRegistered(store, key)
    } else {
      warnDevKeyRegistrationSkipped('/api/op/credentials/membership', key)
    }
    // RFC 9157: the credential is born with its revocation anchor —
    // the status list's index (the table's rowid allocator).
    const statusListIdx = await store.allocateCredentialStatusIdx()
    const minted = await mintSdJwt(key, {
      issuer: configFor(c).issuer,
      subject: raw.id,
      ttlSec: CREDENTIAL_TTL_SEC,
      plain: { vct: 'org-membership' },
      disclosable: {
        name: raw.name,
        email: raw.email,
        org: orgId,
        ...(orgRow ? { org_name: orgRow.name } : {}),
        ...(orgRow?.rorId ? { org_ror: orgRow.rorId } : {}),
        ...(orgRow?.country ? { country: orgRow.country } : {}),
        ...(roles.length ? { roles } : {}),
      },
      ...(holderJkt ? { holderJkt } : {}),
      statusListUri: `${configFor(c).issuer}/op/credentials/statuslist`,
      statusListIdx,
    })
    return c.json({
      format: 'vc+sd-jwt',
      credential: combinedPresentation(minted.sdJwt, minted.disclosures),
      expires_in: CREDENTIAL_TTL_SEC,
    })
  })

  return router
}
