// ═══════════════════════════════════════════════════════════════════
// "Sign in with Apple" — the client-secret JWT (TODO.identity/08).
//
// Apple's documented quirk: the token endpoint's client_secret is NOT a
// stored string but a short-lived ES256 JWT the relying party signs with
// the private key from the Apple developer portal (the .p8 download):
//
//   header  { alg: "ES256", kid: <APPLE_KEY_ID>, typ: "JWT" }
//   claims  { iss: <APPLE_TEAM_ID>, iat, exp (≤ 6 months out — we mint
//             5 minutes), aud: "https://appleid.apple.com",
//             sub: <the Services ID == the provider row's client_id> }
//
// The material arrives through the env (Worker secrets in production —
// the same seam as OP_SIGNING_KEY), NEVER the database:
//
//   APPLE_TEAM_ID     the developer account's team id;
//   APPLE_KEY_ID      the Sign-in-with-Apple key's id;
//   APPLE_PRIVATE_KEY the .p8 PKCS#8 PEM (literal newlines or the
//                     '\n'-escaped one-line form both parse).
//
// The JWT is generated PER EXCHANGE (it is cheap, and a minted-at-rest
// secret would expire). A missing/malformed declaration throws honestly
// — the route maps it to the plain-language exchange failure, never a
// half-signed request.
//
// WORKER-SAFE: WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

type EnvLike = Record<string, string | undefined>

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Decode the PKCS#8 PEM (header/footer + base64; the '\n'-escaped
 *  one-line env form is normalized first). */
function pkcs8DerFromPem(pem: string): Uint8Array {
  const normalized = pem.replace(/\\n/g, '\n')
  const body = normalized
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '')
  if (!body) throw new Error('APPLE_PRIVATE_KEY is not a PEM document')
  const bin = atob(body)
  const der = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i)
  return der
}

export interface AppleSecretConfig {
  teamId: string
  keyId: string
  privateKey: CryptoKey
}

/** Resolve + import the Apple declaration. Throws honestly on any
 *  missing/malformed piece. */
export async function resolveAppleSecretConfig(env: EnvLike): Promise<AppleSecretConfig> {
  const teamId = env.APPLE_TEAM_ID?.trim()
  const keyId = env.APPLE_KEY_ID?.trim()
  const pem = env.APPLE_PRIVATE_KEY?.trim()
  if (!teamId) throw new Error('APPLE_TEAM_ID is not set (the developer account\'s team id)')
  if (!keyId) throw new Error('APPLE_KEY_ID is not set (the Sign-in-with-Apple key id)')
  if (!pem) throw new Error('APPLE_PRIVATE_KEY is not set (the .p8 PKCS#8 PEM)')
  let privateKey: CryptoKey
  try {
    privateKey = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8DerFromPem(pem) as BufferSource,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    )
  } catch (err) {
    throw new Error(`APPLE_PRIVATE_KEY did not import as an EC P-256 PKCS#8 key: ${(err as Error).message}`)
  }
  return { teamId, keyId, privateKey }
}

/** Mint the client secret JWT. `now` is injectable for the tests; the
 *  lifetime is 5 minutes (Apple tolerates up to 6 months — short-lived
 *  is the honest posture for a per-exchange secret). */
export async function generateAppleClientSecret(
  config: AppleSecretConfig,
  clientId: string,
  now: number = Date.now(),
): Promise<string> {
  const nowSec = Math.floor(now / 1000)
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', kid: config.keyId, typ: 'JWT' })))
  const payload = base64url(new TextEncoder().encode(JSON.stringify({
    iss: config.teamId,
    iat: nowSec,
    exp: nowSec + 300,
    aud: 'https://appleid.apple.com',
    sub: clientId,
  })))
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    config.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  )
  return `${header}.${payload}.${base64url(new Uint8Array(signature))}`
}
