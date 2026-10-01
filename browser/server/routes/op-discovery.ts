// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the METADATA module, extracted from op.ts as the
// second proof of the domain-model split (the pure refactor; the
// golden + the suite are the proof — zero behavior change).
//
// The OP's PUBLIC FACING DOCUMENTS — the two endpoints every relying
// party fetches before anything else:
//
//   GET /.well-known/openid-configuration — the discovery document.
//   Public, deploy-stable, edge-cached 5 minutes (the document changes
//   only on deploys).
//
//   GET /jwks.json — the public halves of the key history. The answer
//   is the REGISTERED TABLE, never gated on the signing secret's
//   availability; the active key's self-registration is best-effort
//   AND GATED (maySelfRegisterOpKey, auth/op/keys.ts — identity#7).
//
// The key-minting/signing paths (op.ts's token grant arms) share the
// same registration gate — they import it from auth/op/keys.ts.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import {
  ensureOpKeyRegistered,
  maySelfRegisterOpKey,
  opJwks,
  resolveOpSigningKey,
  warnDevKeyRegistrationSkipped,
} from '../auth/op/keys'
import { ACR_LEVELS } from '../auth/op/step-up'
import { opRequestOrigin, resolveOpConfig, type OpConfig } from '../auth/op/config'

type EnvLike = Record<string, string | undefined>

/** The request's effective OP config (env + this request's origin) —
 *  the same formula every OP route reads. */
function configFor(c: Context): OpConfig {
  return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
}

export function createOpDiscoveryRouter(): Hono {
  const router = new Hono()

  // GET /.well-known/openid-configuration — the discovery document. The
  // RP side (auth/oidc.ts) requires issuer/authorization_endpoint/
  // token_endpoint/jwks_uri and an exact issuer match.
  router.get('/.well-known/openid-configuration', async (c) => {
    const { issuer } = configFor(c)
    c.header('Cache-Control', 'public, max-age=300')
    return c.json({
      issuer,
      authorization_endpoint: `${issuer}/op/authorize`,
      token_endpoint: `${issuer}/op/token`,
      userinfo_endpoint: `${issuer}/op/userinfo`,
      // TODO.identity-sso (the wave-A tail): the RP-initiated logout's
      // endpoint — the kernel's RP side (buildEndSessionUrl) already
      // consumes it.
      end_session_endpoint: `${issuer}/op/endsession`,
      // TODO.identity-sso (the wave-C token surface): RFC 7009 + RFC
      // 7662 — the client-bound revocation and the token-standing read.
      revocation_endpoint: `${issuer}/op/revoke`,
      introspection_endpoint: `${issuer}/op/introspect`,
      jwks_uri: `${issuer}/jwks.json`,
      // RFC 8628 (TODO.ai-platform/10): the device authorization grant —
      // the CLI cone's user-attended bootstrap (the public client, the
      // PAT-grammar scope ask, the poll mints the personal access token).
      device_authorization_endpoint: `${issuer}/op/device/authorization`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      // offline_access (the wave-C token surface): the refresh grant's
      // ask — admitted for the application class (public and confidential
      // alike; the rotation + the reuse-kill are the compensating
      // controls), never for the machine classes.
      // org-membership (TODO.sota/08): the OIDC4VCI credential grant —
      // the wallet's authorization for the membership credential.
      scopes_supported: ['openid', 'profile', 'email', 'offline_access', 'org-membership'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      // The session management surface (TODO.modern/03): the RP's
      // session observation — the OIDC Session Management poll (the
      // iframe + the authorize answer's session_state). Front-channel
      // logout is DELIBERATELY absent (backchannel logout already
      // ships — the newer posture).
      check_session_iframe: `${issuer}/op/session/check`,
      // auth_time joins: the prompt=login freshness proof the RP verifies
      // (the wave-A tail — the code carries the session's authentication
      // instant, kernel 0.2.5).
      // The step-up ladder (TODO.modern/06): the achieved-acr
      // vocabulary — derived from the session's amr, never asserted.
      acr_values_supported: [...ACR_LEVELS],
      // RFC 9126 (TODO.modern/11): the pushed authorization request.
      pushed_authorization_request_endpoint: `${issuer}/op/par`,
      // RFC 9150 (TODO.modern/12): the JWT-secured response mode.
      response_modes_supported: ['query', 'jwt'],
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email', 'email_verified', 'picture', 'roles', 'groups', 'org', 'orcid', 'org_ror', 'amr'],
    })
  })

  // GET /jwks.json — the public halves of the key history. The answer
  // is the REGISTERED TABLE, never gated on the signing secret's
  // availability: a Worker secret mid-propagation (a fresh isolate whose
  // OP_SIGNING_KEY binding reads malformed or rejects the key material
  // while the rollout settles) must never 500 the public key set. The
  // secret matters for SIGNING, not for serving public keys. The active
  // key's self-registration stays (a fresh deployment answers its own
  // key before the first token issuance, and the rotation ceremony's
  // overlap poll rides it) but is best-effort AND GATED
  // (maySelfRegisterOpKey, identity#7): a failed resolve serves the
  // table as it stands, a genuinely empty table answers an honest empty
  // JWKS, and a generated development key registers only in the dev
  // posture — never into the production keyset.
  router.get('/jwks.json', async (c) => {
    const store = getStore()
    try {
      const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      if (maySelfRegisterOpKey(key, configFor(c))) {
        await ensureOpKeyRegistered(store, key)
      } else {
        warnDevKeyRegistrationSkipped('/jwks.json', key)
      }
    } catch (err) {
      console.warn('[op] jwks.json: the signing key is unavailable on this isolate; serving the registered table:', (err as Error).message)
    }
    // Edge-cacheable: the table changes only on the rotation ceremony,
    // whose 24 h retirement margin (1 h tokens + 1 h RP caches) sits
    // two orders above a 5-minute freshness.
    c.header('Cache-Control', 'public, max-age=300')
    return c.json(await opJwks(store))
  })

  return router
}
