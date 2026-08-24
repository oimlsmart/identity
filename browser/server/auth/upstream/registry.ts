// ═══════════════════════════════════════════════════════════════════
// The upstream provider registry (TODO.identity/08) — the OP's sign-in
// methods as DATA: GitHub + Google + Apple + Microsoft Entra + generic
// OIDC (an NMI's internal Keycloak/ADFS plugs in with zero code). Adding
// a provider is a ROW in identity_providers, never a code fork.
//
// The model:
//
//   kind 'github' — the OAuth web flow (no discovery, no ID token): the
//     endpoints ride the GITHUB_OAUTH_BASE_URL / GITHUB_API_BASE_URL env
//     seam (auth/github.ts — github.com by default, GHES or the test
//     stub by override), the account id is the numeric profile id.
//   kind 'oidc' — issuer discovery + Authorization Code + PKCE against
//     the upstream issuer, the RP-side pieces of auth/oidc.ts reused
//     against the upstream; the account id is the ID token's `sub`.
//
// APPLE'S documented quirks key on the issuer host
// (appleid.apple.com), never on a name the admin typed:
//   - the authorize request adds response_mode=form_post (the callback
//     answers POST too — routes/op-upstream.ts);
//   - the name arrives only at the FIRST consent, in the callback's
//     `user` form field (we log it; the link row keys on `sub`);
//   - the client secret is a short-lived ES256 JWT signed with Apple's
//     private key — generated per exchange from APPLE_TEAM_ID /
//     APPLE_KEY_ID / APPLE_PRIVATE_KEY (auth/upstream/apple.ts), sent
//     client_secret_post.
//
// SECRETS ARE NEVER STORED: a row's client_secret_ref names an
// environment variable ('env:<NAME>' — the OIDC_CLIENT_SECRET_REF
// discipline); resolution happens per request against the runtime env
// (process.env on node, the Worker bindings on Cloudflare).
//
// The bootstrap seed (OP_UPSTREAM_SEED, a JSON array — the
// OP_CLIENT_SEED pattern) upserts the known providers at boot; the
// registry is admin-managed afterwards (routes/op-upstream.ts; the full
// console UI is TODO.identity/07's).
//
// WORKER-SAFE: no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { IdentityProvider, ServerStore } from '@oimlsmart/platform-server/store'

type EnvLike = Record<string, string | undefined>

/** The brand-mark keys the login/account pages map to icons (an unknown
 *  or absent key renders the generic OIDC mark — never dropped). */
export const BRAND_MARKS = ['github', 'google', 'apple', 'microsoft', 'oidc'] as const

/** Apple's issuer (the quirk set's key — auth/upstream/apple.ts). */
export const APPLE_ISSUER = 'https://appleid.apple.com'

/** TRUE when the row is "Sign in with Apple" (the quirks apply: form_post,
 *  the first-consent name, the ES256 client-secret JWT). Keyed on the
 *  issuer HOST so a trailing slash or casing never forks the behavior. */
export function isAppleProvider(provider: Pick<IdentityProvider, 'kind' | 'issuer'>): boolean {
  if (provider.kind !== 'oidc' || !provider.issuer) return false
  try {
    return new URL(provider.issuer).host === 'appleid.apple.com'
  } catch {
    return false
  }
}

/** The effective scopes: the row's override, else the kind's default
 *  (Apple needs name+email declared for the first-consent name). */
export function providerScopes(provider: IdentityProvider): string {
  if (provider.scopes?.trim()) return provider.scopes.trim()
  if (provider.kind === 'github') return 'read:user user:email'
  return isAppleProvider(provider) ? 'openid name email' : 'openid profile email'
}

/** Resolve the row's client secret from the env. Answers null for a
 *  public client (no ref). Throws honestly on a dangling reference — a
 *  misdeclared provider fails CLOSED, never signs in half-configured. */
export function resolveProviderSecret(provider: IdentityProvider, env: EnvLike): string | null {
  const ref = provider.clientSecretRef?.trim()
  if (!ref) return null
  if (!ref.startsWith('env:')) {
    throw new Error(`provider ${provider.id}: client_secret_ref must name an environment variable as 'env:<NAME>' (got ${JSON.stringify(ref)})`)
  }
  const value = env[ref.slice(4)]
  if (!value) throw new Error(`provider ${provider.id}: client_secret_ref names ${ref.slice(4)}, which is not set`)
  return value
}

// ── validation (the admin API + the env seed share it) ───────────────

export interface ProviderInput {
  id: string
  kind: IdentityProvider['kind']
  displayName: string
  brandMark?: string | null
  issuer?: string | null
  clientId: string
  clientSecretRef?: string | null
  scopes?: string | null
  enabled?: boolean
}

/** The id alphabet: the value rides URLs (`/op/upstream/:id/…`) and the
 *  identity_links row — lowercase slug, never free text. */
const ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/

/** Validate an upsert. Answers the problems (empty = valid); the route
 *  refuses with the full list, never a guess. */
export function validateProviderInput(body: Record<string, unknown>): { problems: string[]; input: ProviderInput | null } {
  const problems: string[] = []
  const id = typeof body.id === 'string' ? body.id.trim() : ''
  if (!id) problems.push('id is required')
  else if (!ID_PATTERN.test(id)) problems.push(`id ${JSON.stringify(id)} must be a lowercase slug (a-z, 0-9, dashes) — it rides URLs`)

  const kind = typeof body.kind === 'string' ? body.kind.trim() : ''
  if (kind !== 'github' && kind !== 'oidc') problems.push('kind must be "github" or "oidc"')

  const displayName = typeof body.display_name === 'string' ? body.display_name.trim() : ''
  if (!displayName) problems.push('display_name is required')

  const clientId = typeof body.client_id === 'string' ? body.client_id.trim() : ''
  if (!clientId) problems.push('client_id is required')

  let issuer: string | null = null
  const rawIssuer = typeof body.issuer === 'string' ? body.issuer.trim().replace(/\/+$/, '') : ''
  if (kind === 'oidc') {
    if (!rawIssuer) {
      problems.push('issuer is required for kind "oidc" (the discovery root)')
    } else {
      try {
        const url = new URL(rawIssuer)
        if (url.protocol !== 'https:' && url.hostname !== '127.0.0.1' && url.hostname !== 'localhost') {
          // Loopback is the test/dev posture (the stub IdP); a real
          // issuer is https, always.
          problems.push(`issuer ${JSON.stringify(rawIssuer)} must be an https URL`)
        } else issuer = rawIssuer
      } catch {
        problems.push(`issuer ${JSON.stringify(rawIssuer)} is not an absolute URL`)
      }
    }
  } else if (rawIssuer) {
    problems.push('issuer is meaningless for kind "github" (its endpoints ride the GITHUB_*_BASE_URL env seam)')
  }

  const brandMark = typeof body.brand_mark === 'string' && body.brand_mark.trim() ? body.brand_mark.trim() : null
  const clientSecretRef = typeof body.client_secret_ref === 'string' && body.client_secret_ref.trim() ? body.client_secret_ref.trim() : null
  if (clientSecretRef && !clientSecretRef.startsWith('env:')) {
    problems.push(`client_secret_ref must name an environment variable as 'env:<NAME>' (got ${JSON.stringify(clientSecretRef)}) — the secret is never stored inline`)
  }
  const scopes = typeof body.scopes === 'string' && body.scopes.trim() ? body.scopes.trim() : null
  const enabled = body.enabled === true

  if (problems.length) return { problems, input: null }
  return { problems, input: { id, kind: kind as IdentityProvider['kind'], displayName, brandMark, issuer, clientId, clientSecretRef, scopes, enabled } }
}

// ── the bootstrap seed (OP_UPSTREAM_SEED) ────────────────────────────

interface SeedEntry {
  id: string
  kind: string
  display_name: string
  brand_mark?: string
  issuer?: string
  client_id: string
  client_secret_ref?: string
  scopes?: string
  enabled?: boolean
}

/** Parse + validate the seed declaration. Throws honestly on a malformed
 *  document — a misdeclared registry must fail the boot, never guess. */
export function parseUpstreamSeed(raw: string): SeedEntry[] {
  const parsed = JSON.parse(raw) as unknown
  if (!Array.isArray(parsed)) throw new Error('OP_UPSTREAM_SEED must be a JSON array of provider entries')
  return parsed.map((entry, i) => {
    const rec = entry as Record<string, unknown>
    const { problems } = validateProviderInput({ enabled: true, ...rec })
    if (problems.length) throw new Error(`OP_UPSTREAM_SEED[${i}]: ${problems.join('; ')}`)
    return rec as unknown as SeedEntry
  })
}

/** Upsert the seed into the registry (idempotent; a row's later admin
 *  edits are overwritten by a re-seed — the seed is the deployment's
 *  declaration). Answers the seeded provider ids. */
export async function seedIdentityProvidersFromEnv(env: EnvLike, store: ServerStore): Promise<string[]> {
  const raw = env.OP_UPSTREAM_SEED?.trim()
  if (!raw) return []
  const seeded: string[] = []
  for (const entry of parseUpstreamSeed(raw)) {
    await store.upsertIdentityProvider({
      id: entry.id,
      kind: entry.kind as IdentityProvider['kind'],
      displayName: entry.display_name,
      brandMark: entry.brand_mark ?? null,
      issuer: entry.issuer ?? null,
      clientId: entry.client_id,
      clientSecretRef: entry.client_secret_ref ?? null,
      scopes: entry.scopes ?? null,
      enabled: entry.enabled ?? true,
      createdBy: 'op-upstream-seed',
    })
    seeded.push(entry.id)
  }
  return seeded
}
