// ═══════════════════════════════════════════════════════════════════
// The upstream OIDC client (TODO.identity/08) — the OP as a CLIENT of
// the upstream issuers (Google, Entra, Apple, a generic Keycloak). The
// RP-side pieces of auth/oidc.ts (discovery, PKCE, the authorization
// URL, ID-token validation) are REUSED whole; what lives here is only
// what the upstream posture adds:
//
//   - the authorize URL's EXTRA parameters (Apple's documented
//     response_mode=form_post — the callback answers POST too);
//   - the code exchange's client-authentication STYLE: Apple wants the
//     client_secret in the POST BODY (client_secret_post), the rest use
//     HTTP Basic (client_secret_basic) exactly as auth/oidc.ts's
//     exchangeCode does;
//   - the exchange accepts a PRE-GENERATED secret (Apple's short-lived
//     ES256 JWT — auth/upstream/apple.ts — in place of a stored one).
//
// Failures raise auth/oidc.ts's OidcError with its machine `reason` —
// the route maps reasons to the plain-language login-page message,
// never a stack trace (the fed-10 discipline).
//
// WORKER-SAFE: WebCrypto + fetch only.
// ═══════════════════════════════════════════════════════════════════

import {
  buildAuthorizationUrl,
  discoverIssuer,
  exchangeCode,
  generatePkce,
  OidcError,
  randomToken,
  validateIdToken,
  type OidcIdTokenClaims,
  type OidcMetadata,
  type PkcePair,
} from '@oimlsmart/platform-server/oidc'
import type { IdentityProvider } from '@oimlsmart/platform-server/store'
import { isAppleProvider, providerScopes } from './registry'

export { discoverIssuer, generatePkce, randomToken, validateIdToken, OidcError }
export type { OidcIdTokenClaims, OidcMetadata, PkcePair }

/** The upstream authorization URL: the RP-side builder, plus the
 *  provider's extras (Apple: response_mode=form_post — required when
 *  the name/email scopes are requested). */
export function buildUpstreamAuthorizationUrl(
  provider: IdentityProvider,
  metadata: OidcMetadata,
  params: {
    redirectUri: string
    state: string
    nonce: string
    codeChallenge: string
  },
): string {
  const url = new URL(buildAuthorizationUrl(metadata, {
    clientId: provider.clientId,
    redirectUri: params.redirectUri,
    scopes: providerScopes(provider),
    state: params.state,
    nonce: params.nonce,
    codeChallenge: params.codeChallenge,
  }))
  if (isAppleProvider(provider)) url.searchParams.set('response_mode', 'form_post')
  return url.toString()
}

/** The code exchange against the upstream token endpoint. Apple sends
 *  the (generated) secret client_secret_post; every other provider uses
 *  auth/oidc.ts's exchangeCode as-is (client_secret_basic when a secret
 *  is configured, public-client body auth otherwise). */
export async function exchangeUpstreamCode(
  provider: IdentityProvider,
  metadata: OidcMetadata,
  params: {
    clientSecret?: string | null
    code: string
    redirectUri: string
    codeVerifier: string
  },
  fetchImpl: typeof fetch = fetch,
): Promise<{ id_token: string }> {
  if (!isAppleProvider(provider)) {
    return exchangeCode(metadata, {
      clientId: provider.clientId,
      ...(params.clientSecret ? { clientSecret: params.clientSecret } : {}),
      code: params.code,
      redirectUri: params.redirectUri,
      codeVerifier: params.codeVerifier,
    }, fetchImpl)
  }

  // Apple's shape: the secret JWT in the POST body (client_secret_post).
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: provider.clientId,
    code_verifier: params.codeVerifier,
  })
  if (params.clientSecret) body.set('client_secret', params.clientSecret)
  let json: unknown
  try {
    const res = await fetchImpl(metadata.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    json = await res.json()
    if (!res.ok) {
      const err = (json as { error?: string; error_description?: string }) ?? {}
      throw new Error(`HTTP ${res.status} ${err.error ?? ''} ${err.error_description ?? ''}`.trim())
    }
  } catch (err) {
    throw new OidcError('exchange', `the token endpoint refused the exchange: ${(err as Error).message}`)
  }
  const token = json as { id_token?: string }
  if (typeof token?.id_token !== 'string') {
    throw new OidcError('exchange', 'the token response carries no id_token — this flow requires the openid scope')
  }
  return { id_token: token.id_token }
}
