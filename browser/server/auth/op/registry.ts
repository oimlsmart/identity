// ═══════════════════════════════════════════════════════════════════
// The OIDC client registry's bootstrap (TODO.identity/01) — the known
// instances seeded from the OP_CLIENT_SEED env (a JSON array), the same
// posture as the demo-account seed: idempotent upserts at boot, then the
// rows are ADMIN-MANAGED (the registry API in routes/op.ts; the full
// console UI is TODO.identity/03's).
//
// A seed entry:
//   {
//     "client_id": "oiml-smart-platform",
//     "name": "OIML SMART platform hub",
//     "secret": "…",                        // OPTIONAL — absent = a
//                                           // public client (PKCE only)
//     "redirect_uris": ["https://platform.oimlsmart.org/api/auth/callback/oidc"],
//     "claims_policy": { "claims": ["roles", "groups", "org"],
//                        "roles": ["admin", "cs_admin", "ia_officer"] }
//                                           // OPTIONAL — claims: the claims
//                                           // the ID token carries for THIS
//                                           // client (absent = profile +
//                                           // email only; role claims
//                                           // are a per-client privilege);
//                                           // roles (TODO.identity/03): the
//                                           // allowlist bounding WHICH roles
//                                           // those claims may carry (absent
//                                           // = unbounded by the policy).
//   }
//
// The plaintext seed secret is hashed (PBKDF2, secrets.ts) before it
// touches the database; the env itself rides a Worker secret when it
// carries secrets. A seeded client's UPDATE on re-seed keeps the row's
// status (a disabled client stays disabled — the seed never re-enables).
//
// WORKER-SAFE: no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'
import { hashClientSecret } from './secrets'

type EnvLike = Record<string, string | undefined>

export interface OpClientSeedEntry {
  client_id: string
  name: string
  secret?: string
  redirect_uris: string[]
  claims_policy?: { claims: string[]; roles?: string[] }
}

/** Parse + validate the seed declaration. Throws honestly on a malformed
 *  document — a misdeclared registry must fail the boot, never guess. */
export function parseOpClientSeed(raw: string): OpClientSeedEntry[] {
  const parsed = JSON.parse(raw) as unknown
  if (!Array.isArray(parsed)) throw new Error('OP_CLIENT_SEED must be a JSON array of client entries')
  return parsed.map((entry, i) => {
    const rec = entry as Record<string, unknown>
    if (typeof rec?.client_id !== 'string' || !rec.client_id) throw new Error(`OP_CLIENT_SEED[${i}]: client_id is required`)
    if (typeof rec.name !== 'string' || !rec.name) throw new Error(`OP_CLIENT_SEED[${i}]: name is required`)
    if (!Array.isArray(rec.redirect_uris) || rec.redirect_uris.some(u => typeof u !== 'string')) {
      throw new Error(`OP_CLIENT_SEED[${i}]: redirect_uris must be a list of strings`)
    }
    if (rec.secret !== undefined && typeof rec.secret !== 'string') throw new Error(`OP_CLIENT_SEED[${i}]: secret must be a string`)
    const policy = rec.claims_policy as { claims?: unknown; roles?: unknown } | undefined
    if (policy !== undefined && (!Array.isArray(policy?.claims) || policy.claims.some(c => typeof c !== 'string'))) {
      throw new Error(`OP_CLIENT_SEED[${i}]: claims_policy.claims must be a list of strings`)
    }
    // TODO.identity/03: the optional role allowlist — the closed set of
    // roles the ID token may carry for this client.
    if (policy?.roles !== undefined && (!Array.isArray(policy.roles) || policy.roles.some(r => typeof r !== 'string'))) {
      throw new Error(`OP_CLIENT_SEED[${i}]: claims_policy.roles must be a list of role ids`)
    }
    return rec as unknown as OpClientSeedEntry
  })
}

/** Upsert the seed into the registry. Answers the seeded client ids. */
export async function seedOidcClientsFromEnv(env: EnvLike, store: ServerStore): Promise<string[]> {
  const raw = env.OP_CLIENT_SEED?.trim()
  if (!raw) return []
  const seeded: string[] = []
  for (const entry of parseOpClientSeed(raw)) {
    await store.upsertOidcClient({
      clientId: entry.client_id,
      name: entry.name,
      secretHash: entry.secret ? await hashClientSecret(entry.secret) : null,
      redirectUris: entry.redirect_uris,
      claimsPolicy: entry.claims_policy
        ? { claims: entry.claims_policy.claims, ...(entry.claims_policy.roles ? { roles: entry.claims_policy.roles } : {}) }
        : null,
      createdBy: 'op-client-seed',
    })
    seeded.push(entry.client_id)
  }
  return seeded
}
