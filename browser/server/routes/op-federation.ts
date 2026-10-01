// ═══════════════════════════════════════════════════════════════════
// TODO.sota/09 — OIDC Federation, slice 1: the LEAF entity
// configuration. The OP publishes its own entity statement at
// /.well-known/openid-federation — the federation member's first
// document: a signed JWT whose iss=sub= the entity identifier, whose
// jwks are the OP's public keys, and whose openid_provider metadata
// mirrors the discovery document (buildDiscoveryDocument — the ONE
// builder; the two public documents can never drift).
//
// A self-standing leaf is a valid federation member today; the trust
// chain's intermediates + the trust marks are the named next slices
// (they need the first federated member authority). WORKER-SAFE.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import { ensureOpKeyRegistered, maySelfRegisterOpKey, opJwks, resolveOpSigningKey, warnDevKeyRegistrationSkipped } from '../auth/op/keys'
import { buildDiscoveryDocument } from './op-discovery'

type EnvLike = Record<string, string | undefined>

function configFor(c: Context) {
  return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
}

function bytesToB64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function createOpFederationRouter(): Hono {
  const router = new Hono()

  // GET /.well-known/openid-federation — the self-published entity
  // configuration (the entity statement with iss === sub). The
  // statement's life is 24 h; the edge caches 5 minutes (every
  // federation member fetches it; the rotation ceremony's overlap
  // margin dwarfs the freshness).
  router.get('/.well-known/openid-federation', async (c) => {
    const config = configFor(c)
    const issuer = config.issuer
    const store = getStore()
    try {
      const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      if (maySelfRegisterOpKey(key, config)) {
        await ensureOpKeyRegistered(store, key)
      } else {
        warnDevKeyRegistrationSkipped('/.well-known/openid-federation', key)
      }
      const nowSec = Math.floor(Date.now() / 1000)
      const header = bytesToB64url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', typ: 'entity-statement+jwt', kid: key.kid })))
      const payload = bytesToB64url(new TextEncoder().encode(JSON.stringify({
        iss: issuer,
        sub: issuer,
        iat: nowSec,
        exp: nowSec + 24 * 60 * 60,
        jwks: await opJwks(store),
        metadata: {
          openid_provider: buildDiscoveryDocument(issuer),
        },
      })))
      const sig = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        key.privateKey,
        new TextEncoder().encode(`${header}.${payload}`),
      )
      c.header('content-type', 'application/entity-statement+jwt')
      c.header('cache-control', 'public, max-age=300')
      return c.body(`${header}.${payload}.${bytesToB64url(new Uint8Array(sig))}`)
    } catch (err) {
      // A signing secret mid-propagation serves an honest 503 — the
      // federation member retries; never an unsigned statement.
      console.warn('[op] openid-federation: the signing key is unavailable on this isolate:', (err as Error).message)
      return c.json({ error: 'the entity statement is temporarily unavailable' }, 503)
    }
  })

  return router
}
