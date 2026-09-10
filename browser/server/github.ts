// ═══════════════════════════════════════════════════════════════════
// GitHub OAuth — the deployment's authorized sign-in
// (docs/deployment/identity.md, "GitHub OAuth"). TWO concerns live here:
//
//  1. THE STATELESS OAUTH STATE. The old flow kept a per-process
//     `Map` jar, which a sibling Worker isolate never sees — the
//     callback then failed the state check intermittently. The state
//     parameter is now SELF-PROVING: `<nonce>.<issuedAt>.<hmac>` where
//     the hmac is HMAC-SHA256 over `nonce:issuedAt` keyed by the
//     GITHUB_CLIENT_SECRET (already a deployed secret — no new secret,
//     no D1 round trip), compared in constant time, with a 10-minute
//     TTL. It verifies identically on node and on the Worker, so the
//     in-memory path is GONE — this is the only path.
//
//  2. THE AUTHORIZED-USERS DECLARATION. Which GitHub accounts may sign
//     in, and with which initial role, is instance policy declared in
//     the ENV (the same env seam the OIDC config uses — hono/adapter
//     reads process.env on node, the Worker bindings on Cloudflare):
//
//       GITHUB_ADMIN_LOGINS   comma-separated logins (case-insensitive)
//                             → role `admin`.
//       GITHUB_ALLOWED_LOGINS comma-separated logins → the default
//                             allowed role (`cs_admin`).
//       GITHUB_ROLE_MAP       `login:role,login2:role2` — fine-grained
//                             initial roles. Roles validate against the
//                             platform vocabulary (src/auth/roles.ts);
//                             an unknown role FAILS CLOSED: the entry is
//                             dropped, the resolution logs the problem
//                             once, and the login falls through to the
//                             other rules — a role is never invented.
//       GITHUB_ALLOWED_ORG    one org slug → the sign-in checks LIVE
//                             membership (GET /user/memberships/orgs/
//                             {org} with the user's own token; state
//                             `active` counts, `pending` does not) and
//                             members get the default allowed role. The
//                             authorization request adds the `read:org`
//                             scope when this is set (private membership
//                             is invisible without it).
//
//     Precedence is the declaration order above: admin list → role map
//     → allowed list → org membership → denied. With NO allowlist env
//     declared the instance is OPEN ENROLLMENT: any GitHub account signs
//     in with role `user` (the historical behavior) and the resolution
//     logs a boot warning — fine for a personal evaluation, unsuitable
//     for a shared deployment.
//
//     The allowlist is ADMISSION CONTROL + the INITIAL role. An
//     existing account keeps its locally assigned role and org (the
//     admin refines them in the users section, TODO.federation/12) —
//     but a login struck off every list is refused at the gate,
//     whatever account it holds. Org binding is NOT derived from
//     GitHub: every GitHub sign-in provisions with org NULL (item 3 of
//     the work order — binding happens through the admin's user
//     management afterwards).
//
//  GitHub Enterprise Server: GITHUB_OAUTH_BASE_URL /
//  GITHUB_API_BASE_URL override the github.com endpoints (also the
//  in-process test seam — the stub fixture rides them).
//
//  WORKER-SAFE: WebCrypto only (crypto.subtle / getRandomValues), no
//  node built-ins — the Worker bundle carries this module.
// ═══════════════════════════════════════════════════════════════════

import { APP_ROLES } from './vocab/roles'

type EnvLike = Record<string, string | undefined>

// ── the stateless OAuth state ───────────────────────────────────────

/** The state parameter's lifetime (both OAuth flows share the value). */
export const OAUTH_STATE_TTL_MS = 10 * 60 * 1000

/** Tolerance for a future-dated `issuedAt` (clock skew between the
 *  sign-in and the callback — the signature covers the timestamp, so
 *  only the secret holder could mint one; a wildly future state is
 *  still refused honestly). */
const STATE_CLOCK_SKEW_MS = 60_000

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function hmacSha256(key: string, message: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message))
  return base64url(new Uint8Array(sig))
}

/** Constant-time string equality (Workers have no
 *  crypto.timingSafeEqual — the length check leaks only what the
 *  attacker already knows, their own input's length). */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

/** Mint the state parameter: a random nonce + issue time, self-proving
 *  under HMAC. `now` is injectable for the expiry tests. */
export async function signOAuthState(secret: string, now: number = Date.now()): Promise<string> {
  const nonce = base64url(crypto.getRandomValues(new Uint8Array(24)))
  const sig = await hmacSha256(secret, `${nonce}:${now}`)
  return `${nonce}.${now}.${sig}`
}

/** Verify a presented state parameter: well-formed, inside the TTL
 *  (± skew), and carrying the signature of `nonce:issuedAt` under the
 *  secret — all three, constant-time on the signature. */
export async function verifyOAuthState(
  secret: string,
  presented: string,
  opts?: { now?: number; ttlMs?: number },
): Promise<boolean> {
  const parts = presented.split('.')
  if (parts.length !== 3) return false
  const [nonce, issuedAtRaw, sig] = parts as [string, string, string]
  if (!nonce || !sig) return false
  const issuedAt = Number(issuedAtRaw)
  if (!Number.isFinite(issuedAt)) return false
  const now = opts?.now ?? Date.now()
  const ttl = opts?.ttlMs ?? OAUTH_STATE_TTL_MS
  if (now - issuedAt > ttl) return false
  if (issuedAt - now > STATE_CLOCK_SKEW_MS) return false
  // The signature recomputes over the PRESENTED strings (never the
  // re-parsed number) so no canonicalization gap opens.
  const expected = await hmacSha256(secret, `${nonce}:${issuedAtRaw}`)
  return timingSafeEqual(expected, sig)
}

// ── the authorized-users declaration ────────────────────────────────

/** The initial role for GITHUB_ALLOWED_LOGINS members and
 *  GITHUB_ALLOWED_ORG members (the role map refines it per login). */
export const GITHUB_DEFAULT_ALLOWED_ROLE = 'cs_admin'

export interface GitHubAuthorizationConfig {
  /** Lowercased logins → `admin`. */
  admins: ReadonlySet<string>
  /** Lowercased login → validated platform role. */
  roleMap: ReadonlyMap<string, string>
  /** Lowercased logins → the default allowed role. */
  allowed: ReadonlySet<string>
  /** The org slug whose active members may sign in (null = no org check). */
  org: string | null
  /** TRUE when no allowlist env is declared at all: any GitHub account
   *  signs in with role `user` (the historical posture — the resolution
   *  logs the open-enrollment warning once). */
  openEnrollment: boolean
  /** The declaration's validation problems (unknown roles, malformed
   *  pairs) — every problem means an entry was DROPPED (fail closed),
   *  never guessed. The route logs them once per process/isolate. */
  problems: string[]
}

function parseLoginList(raw: string | undefined): string[] {
  return (raw ?? '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
}

/** Resolve + validate the allowlist declaration from the env. Pure. */
export function resolveGitHubAuthorizationConfig(env: EnvLike): GitHubAuthorizationConfig {
  const problems: string[] = []
  const admins = new Set(parseLoginList(env.GITHUB_ADMIN_LOGINS))
  const allowed = new Set(parseLoginList(env.GITHUB_ALLOWED_LOGINS))
  const roleMap = new Map<string, string>()

  const rawMap = env.GITHUB_ROLE_MAP?.trim()
  if (rawMap) {
    for (const pair of rawMap.split(',')) {
      const entry = pair.trim()
      if (!entry) continue
      const idx = entry.indexOf(':')
      const login = idx > 0 ? entry.slice(0, idx).trim().toLowerCase() : ''
      const role = idx > 0 ? entry.slice(idx + 1).trim() : ''
      if (!login || !role) {
        problems.push(`GITHUB_ROLE_MAP entry ${JSON.stringify(entry)} is not a 'login:role' pair — the entry is ignored`)
        continue
      }
      if (!(APP_ROLES as readonly string[]).includes(role)) {
        problems.push(
          `GITHUB_ROLE_MAP entry for ${JSON.stringify(login)} names the unknown role ${JSON.stringify(role)} — `
          + `the entry is ignored (fail closed; the platform roles are ${APP_ROLES.join(', ')})`,
        )
        continue
      }
      roleMap.set(login, role)
    }
  }

  const org = env.GITHUB_ALLOWED_ORG?.trim() || null
  // Open enrollment keys on the DECLARATION, not the post-validation
  // set: a deployment that declares only a broken role map fails
  // CLOSED (every login denied), never silently open.
  const declared = !!(
    env.GITHUB_ADMIN_LOGINS?.trim()
    || env.GITHUB_ALLOWED_LOGINS?.trim()
    || rawMap
    || org
  )
  return { admins, allowed, roleMap, org, openEnrollment: !declared, problems }
}

/** Where a login stands BEFORE the live org-membership check. */
export type GitHubListResolution =
  | { kind: 'listed'; role: string; via: 'admin_logins' | 'role_map' | 'allowed_logins' }
  /** Not in any list, but GITHUB_ALLOWED_ORG is declared — the live
   *  membership check decides. */
  | { kind: 'org_check' }
  /** Open enrollment: any GitHub account, role `user`. */
  | { kind: 'open' }
  | { kind: 'denied' }

/** The pure per-login resolution: admin list → role map → allowed list
 *  → org check → denied (open enrollment short-circuits to 'open').
 *  Logins compare case-insensitively (GitHub treats them so). */
export function resolveGitHubLogin(config: GitHubAuthorizationConfig, login: string): GitHubListResolution {
  const l = login.trim().toLowerCase()
  if (config.admins.has(l)) return { kind: 'listed', role: 'admin', via: 'admin_logins' }
  const mapped = config.roleMap.get(l)
  if (mapped) return { kind: 'listed', role: mapped, via: 'role_map' }
  if (config.allowed.has(l)) return { kind: 'listed', role: GITHUB_DEFAULT_ALLOWED_ROLE, via: 'allowed_logins' }
  if (config.org) return { kind: 'org_check' }
  if (config.openEnrollment) return { kind: 'open' }
  return { kind: 'denied' }
}

// ── the GitHub endpoints (github.com, or GHES / the test stub) ──────

export interface GitHubEndpoints {
  /** The OAuth web flow base (https://github.com). */
  oauthBase: string
  /** The REST API base (https://api.github.com). */
  apiBase: string
}

/** The endpoints this instance talks to — github.com by default, the
 *  GITHUB_*_BASE_URL overrides for GitHub Enterprise Server (and the
 *  in-process tests' stub). */
export function gitHubEndpoints(env: EnvLike): GitHubEndpoints {
  const trim = (v: string | undefined) => v?.trim().replace(/\/+$/, '') || ''
  return {
    oauthBase: trim(env.GITHUB_OAUTH_BASE_URL) || 'https://github.com',
    apiBase: trim(env.GITHUB_API_BASE_URL) || 'https://api.github.com',
  }
}

/** The OAuth scope request: the base identity scopes, plus `read:org`
 *  when an org gate is declared (a private membership is invisible
 *  without it — the check would fail closed against real members). */
export function gitHubScopes(env: EnvLike): string {
  const base = 'read:user user:email'
  return env.GITHUB_ALLOWED_ORG?.trim() ? `${base} read:org` : base
}

/** The LIVE org-membership check: the user's own membership record in
 *  the declared org. `active` counts; `pending` (an invitation not yet
 *  accepted) does not. Any non-200 — not a member, an org that does not
 *  exist, a token that cannot see the membership — is NOT a member:
 *  fail closed. */
export async function checkGitHubOrgMembership(
  apiBase: string,
  org: string,
  accessToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  try {
    const res = await fetchImpl(`${apiBase}/user/memberships/orgs/${encodeURIComponent(org)}`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/vnd.github+json' },
    })
    if (!res.ok) return false
    const body = await res.json() as { state?: string }
    return body.state === 'active'
  } catch {
    return false
  }
}
