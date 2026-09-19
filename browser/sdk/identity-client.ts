// ═══════════════════════════════════════════════════════════════════
// The identity SDK's posture layer (TODO.modern/07). Everything
// beneath ./gen is GENERATED from the drift-gated OpenAPI spec
// (scripts/generate-sdk.ts) — never hand-edited; this file is the
// only hand-written surface, and it is deliberately thin:
//
//   • the generated operations, re-exported (typed, spec-current);
//   • the PAT exchange helper — the machine posture: one call mints
//     a short-lived, scope-narrowed bearer (the exchange re-judges
//     the PAT's scopes against live standing);
//   • createBearerClient — rides that token on every call;
//   • the session posture needs NO helper: same-origin browser calls
//     carry the oiml-session cookie automatically (fetch's
//     same-origin default credentials).
// ═══════════════════════════════════════════════════════════════════

import { createClient, createConfig, type Client } from './gen/client'

export * from './gen/types.gen'
export * from './gen/sdk.gen'

/** A client for the official service (or a self-hosted instance —
 *  pass its issuer origin as baseUrl). */
export function createIdentityClient(opts: { baseUrl?: string } = {}): Client {
  return createClient(createConfig({ baseUrl: opts.baseUrl ?? 'https://id.oimlsmart.org' }))
}

/** The RFC 8693 exchange: a personal access token in, a short-lived
 *  scope-narrowed OP JWT out (verify it against the instance's JWKS). */
export async function patAccessToken(input: {
  baseUrl: string
  pat: string
  scope?: string
  fetchImpl?: typeof fetch
}): Promise<{ accessToken: string; tokenType: string; expiresInSeconds: number }> {
  const doFetch = input.fetchImpl ?? fetch
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token_type: 'urn:oimlsmart:params:oauth:token-type:pat',
    subject_token: input.pat,
  })
  if (input.scope) body.set('scope', input.scope)
  const res = await doFetch(`${input.baseUrl}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (!res.ok) throw new Error(`the PAT exchange was refused (${res.status})`)
  const answer = await res.json() as { access_token: string; token_type: string; expires_in: number }
  return { accessToken: answer.access_token, tokenType: answer.token_type, expiresInSeconds: answer.expires_in }
}

/** The bearer posture: the exchanged token rides every call. */
export function createBearerClient(input: { baseUrl: string; accessToken: string }): Client {
  const client = createIdentityClient(input)
  client.interceptors.request.use((request) => {
    request.headers.set('authorization', `Bearer ${input.accessToken}`)
    return request
  })
  return client
}
