// ─────────────────────────────────────────────────────────────────────
// The test-side DPoP proof minter: REAL ES256 keys (WebCrypto), REAL
// compact JWSs — the proofs a compliant client would send (RFC 9449
// §4). Test-only; the server's verifier never imports this.
// ─────────────────────────────────────────────────────────────────────

function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export interface MintedProof {
  proof: string
  /** The public key's JKT (RFC 9449 §6.4) — what the token binds to. */
  jkt: string
}

/** The client's key pair — minted once, REUSED across proofs (a real
 *  DPoP client signs every request with the same key; that is the
 *  whole point of the binding). */
export async function mintDpopKeys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as Promise<CryptoKeyPair>
}

/** Mint a DPoP proof. Defaults: a FRESH key, iat = now, htm/htu as
 *  given, jti random; pass `keys` to reuse a client's key; `accessToken`
 *  adds the ath binding; `iat` overrides the issued-at (the staleness
 *  probe). */
export async function mintDpopProof(input: {
  method: string
  uri: string
  accessToken?: string
  iat?: number
  keys?: CryptoKeyPair
  /** RFC 9449 §8: the server-issued challenge value. */
  nonce?: string
}): Promise<MintedProof> {
  const pair = input.keys ?? await mintDpopKeys()
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  // RFC 7638: the thumbprint's members serialize in LEXICOGRAPHIC order.
  const pub = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
  const jkt = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(pub)))))
  const payload: Record<string, unknown> = {
    htm: input.method.toUpperCase(),
    htu: input.uri,
    iat: input.iat ?? Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  }
  if (input.accessToken) {
    payload.ath = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input.accessToken))))
  }
  if (input.nonce) payload.nonce = input.nonce
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: pub }
  const unsigned = `${b64url(new TextEncoder().encode(JSON.stringify(header)))}.${b64url(new TextEncoder().encode(JSON.stringify(payload)))}`
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    pair.privateKey,
    new TextEncoder().encode(unsigned),
  )
  return { proof: `${unsigned}.${b64url(new Uint8Array(sig))}`, jkt }
}
