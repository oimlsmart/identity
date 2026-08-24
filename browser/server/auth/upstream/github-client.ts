// ═══════════════════════════════════════════════════════════════════
// The upstream GitHub client (TODO.identity/08) — the OP as a CLIENT of
// GitHub's OAuth web flow, the registry-row counterpart of the
// instance-level sign-in (routes/auth.ts). Reuses auth/github.ts's
// endpoint seam (GITHUB_OAUTH_BASE_URL / GITHUB_API_BASE_URL — github.com
// by default, GHES or the test stub by override) and its scope
// declaration; what lives here is only the flow's read path:
//
//   exchange the code → the access token (JSON, defensive — GitHub
//   answers some failures in plain text, the 2026-08-16 lesson), then
//   the profile + the verified primary email. The token is used for
//   those reads and DISCARDED — never stored, never exposed (the same
//   discipline as the instance flow).
//
// The upstream GitHub sign-in NEVER provisions and NEVER matches by
// email: the route resolves (provider, profile.id) against
// identity_links — the match rule.
//
// WORKER-SAFE: fetch only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { gitHubEndpoints, type GitHubEndpoints } from '@oimlsmart/platform-server/github'

export { gitHubEndpoints }
export type { GitHubEndpoints }

export interface GitHubIdentity {
  /** The numeric profile id (string) — the link row's provider_account_id. */
  id: string
  login: string
  name: string
  /** The primary VERIFIED email (or the noreply fallback — display only,
   *  never a match key). */
  email: string
  avatarUrl?: string
}

export class GitHubUpstreamError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'GitHubUpstreamError'
  }
}

/** The authorize URL (the OP's upstream sign-in/link redirect target). */
export function buildGitHubAuthorizeUrl(
  endpoints: GitHubEndpoints,
  params: { clientId: string; redirectUri: string; scopes: string; state: string },
): string {
  const url = new URL(`${endpoints.oauthBase}/login/oauth/authorize`)
  url.searchParams.set('client_id', params.clientId)
  url.searchParams.set('redirect_uri', params.redirectUri)
  url.searchParams.set('scope', params.scopes)
  url.searchParams.set('state', params.state)
  return url.toString()
}

/** Exchange the code and read the identity. Throws GitHubUpstreamError
 *  on any failure (the route maps it to the plain-language message). */
export async function fetchGitHubIdentity(
  endpoints: GitHubEndpoints,
  params: { clientId: string; clientSecret: string; code: string; redirectUri: string },
  fetchImpl: typeof fetch = fetch,
): Promise<GitHubIdentity> {
  let tokenData: { access_token?: string; error?: string }
  try {
    const tokenRes = await fetchImpl(`${endpoints.oauthBase}/login/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: params.clientId,
        client_secret: params.clientSecret,
        code: params.code,
        redirect_uri: params.redirectUri,
      }),
    })
    // GitHub answers error paths in plain text ("Request forbidden") —
    // never parse blindly.
    if (!tokenRes.ok) throw new Error(`HTTP ${tokenRes.status}`)
    tokenData = await tokenRes.json() as typeof tokenData
  } catch (err) {
    throw new GitHubUpstreamError(`the token exchange failed: ${(err as Error).message}`)
  }
  if (!tokenData.access_token) {
    throw new GitHubUpstreamError(`the token exchange carried no access_token (${tokenData.error ?? 'no error named'})`)
  }

  let profile: { id: number; name?: string; login: string; avatar_url?: string }
  let emails: { email: string; primary: boolean; verified: boolean }[]
  try {
    const [profileRes, emailsRes] = await Promise.all([
      fetchImpl(`${endpoints.apiBase}/user`, { headers: { Authorization: `Bearer ${tokenData.access_token}` } }),
      fetchImpl(`${endpoints.apiBase}/user/emails`, { headers: { Authorization: `Bearer ${tokenData.access_token}` } }),
    ])
    if (!profileRes.ok || !emailsRes.ok) throw new Error(`HTTP ${profileRes.status}/${emailsRes.status}`)
    profile = await profileRes.json() as typeof profile
    emails = await emailsRes.json() as typeof emails
  } catch (err) {
    throw new GitHubUpstreamError(`the profile read failed: ${(err as Error).message}`)
  }
  if (!profile.id || !profile.login) throw new GitHubUpstreamError('the profile answer carried no id/login')

  const email = emails?.find(e => e.primary && e.verified)?.email
    || emails?.find(e => e.verified)?.email
    || `${profile.login}@users.noreply.github.com`
  return {
    id: String(profile.id),
    login: profile.login,
    name: profile.name || profile.login,
    email,
    ...(profile.avatar_url ? { avatarUrl: profile.avatar_url } : {}),
  }
}
