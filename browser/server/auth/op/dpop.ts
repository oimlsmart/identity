// ═══════════════════════════════════════════════════════════════════
// DPoP (RFC 9449, TODO.sota/09's first slice) — the proof verifier and
// the JKT derivation. WORKER-SAFE: WebCrypto only, no node built-ins.
//
// THE PROOF (§4): a compact ES256 JWS, header typ "dpop+jwt" carrying
// the PUBLIC key that signed it (jwk), payload { htm, htu, iat, jti,
// ath? }. VERIFIED (§4.3): the typ, the alg (ES256 — the house
// algorithm), the jwk a PUBLIC EC P-256 key (a private member refuses),
// htm/htu matching the request, iat inside the freshness window
// (±5 min), the signature over the embedded key, and — on a
// resource-server request — ath = base64url(SHA-256(access token)).
//
// THE JKT (§6.4): the key's thumbprint (the RFC 7638 canonical members
// {crv,kty,x,y}, SHA-256, base64url) — the value the access token's
// row binds to; the replay cache (dpop_jtis, the TTL sweep's table)
// keys the jti for the window.
// ═══════════════════════════════════════════════════════════════════

/** The proof window: an iat further than this from now refuses. Five
 *  minutes — generous clock skew tolerance for a proof whose replay
 *  protection rides the jti cache anyway. */
const DPOP_IAT_WINDOW_SEC = 300

function b64urlToBytes(v: string): Uint8Array<ArrayBuffer> {
  const b64 = v.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function bytesToB64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function sha256B64url(value: string): Promise<string> {
  return bytesToB64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))
}

export interface DpopExpectation {
  method: string
  uri: string
  /** The bound access token (a resource-server request); the proof must
   *  carry ath = its SHA-256. Absent = a token-endpoint request (no
   *  ath expected). */
  accessToken?: string
}

/** The RFC 7638 thumbprint of an EC P-256 public JWK — the JKT
 *  (RFC 9449 §6.4). Exported: the token row stores it. */
export async function jktOf(jwk: { kty: string; crv: string; x: string; y: string }): Promise<string> {
  return sha256B64url(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
}

/** Verify a DPoP proof against the request's expectation. Answers the
 *  signer's JKT + the proof's jti/iat (the replay cache's row), or the
 *  error string (RFC 9449's error taxonomy; the token endpoint answers
 *  400 invalid_dpop_proof carrying it). */
export async function verifyDpopProof(
  proof: string,
  expected: DpopExpectation,
): Promise<{ jkt: string; jti: string; iat: number } | { error: string }> {
  const parts = proof.split('.')
  if (parts.length !== 3) return { error: 'malformed proof' }
  let header: Record<string, unknown>
  let payload: Record<string, unknown>
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0]!))) as Record<string, unknown>
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1]!))) as Record<string, unknown>
  } catch {
    return { error: 'malformed proof' }
  }
  if (header.typ !== 'dpop+jwt') return { error: 'typ must be dpop+jwt' }
  if (header.alg !== 'ES256') return { error: 'alg must be ES256' }
  const jwk = header.jwk as { kty?: string; crv?: string; x?: string; y?: string; d?: string } | undefined
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    return { error: 'jwk must be a public EC P-256 key' }
  }
  if (jwk.d !== undefined) return { error: 'jwk must not carry private key material' }
  if (payload.htm !== expected.method.toUpperCase()) return { error: 'htm mismatch' }
  if (payload.htu !== expected.uri) return { error: 'htu mismatch' }
  const iat = typeof payload.iat === 'number' ? payload.iat : Number.NaN
  if (!Number.isFinite(iat) || Math.abs(Math.floor(Date.now() / 1000) - iat) > DPOP_IAT_WINDOW_SEC) {
    return { error: 'iat outside the freshness window' }
  }
  if (typeof payload.jti !== 'string' || !payload.jti) return { error: 'jti required' }
  const ath = typeof payload.ath === 'string' ? payload.ath : null
  if (expected.accessToken !== undefined) {
    if (ath !== await sha256B64url(expected.accessToken)) return { error: 'ath mismatch' }
  } else if (ath !== null) {
    return { error: 'ath not expected at the token endpoint' }
  }
  const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    b64urlToBytes(parts[2]!),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  )
  if (!ok) return { error: 'signature does not verify' }
  return { jkt: await jktOf({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }), jti: payload.jti, iat }
}

/** The proof's replay-cache expiry — the freshness window past the
 *  iat, in the stores' ISO stamp. The seam's rememberDpopJti answers
 *  FALSE when the jti already stands (the replay); the TTL sweep
 *  (dpop_jtis) reaps the spent rows. */
export function dpopJtiExpiry(iatSec: number): string {
  return new Date((iatSec + DPOP_IAT_WINDOW_SEC) * 1000).toISOString()
}
