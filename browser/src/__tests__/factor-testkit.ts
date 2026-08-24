// ─────────────────────────────────────────────────────────────────────
// The factor ceremonies' test kit: a test-side CBOR ENCODER (the
// decoder's own surface, inverted) plus a synthetic authenticator — a
// freshly minted keypair per algorithm (ES256 / Ed25519 / RS256) whose
// attestationObject and assertion bytes are exactly what a real
// authenticator emits (fmt 'none', the attested credential data, the
// signature over authData || SHA-256(clientDataJSON)). Nothing here is a
// mock of the ceremony: the server under test parses and verifies the
// real bytes; the live-browser interop leg is the e2e virtual
// authenticator (e2e/id-14-factors.e2e.ts).
//
// Shared by id-webauthn-vectors.test.ts (the parse/verify vectors) and
// id-factors.test.ts (the route-level ceremonies).
// ─────────────────────────────────────────────────────────────────────

import { base64urlDecode, base64urlEncode, type CborValue } from '../../server/auth/op/webauthn'

/** The test-side CBOR encoder (uint/negint/bytes/text/array/map). */
export function cborEncode(value: CborValue): Uint8Array {
  const out: number[] = []
  const head = (major: number, length: number): void => {
    if (length < 24) out.push((major << 5) | length)
    else if (length < 256) out.push((major << 5) | 24, length)
    else if (length < 65536) out.push((major << 5) | 25, (length >>> 8) & 0xff, length & 0xff)
    else out.push((major << 5) | 26, (length >>> 24) & 0xff, (length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff)
  }
  const write = (v: CborValue): void => {
    if (typeof v === 'number' && v >= 0) head(0, v)
    else if (typeof v === 'number') head(1, -1 - v)
    else if (typeof v === 'string') {
      const bytes = new TextEncoder().encode(v)
      head(3, bytes.length)
      out.push(...bytes)
    } else if (v instanceof Uint8Array) {
      head(2, v.length)
      out.push(...v)
    } else if (Array.isArray(v)) {
      head(4, v.length)
      v.forEach(write)
    } else if (v instanceof Map) {
      head(5, v.size)
      for (const [k, val] of v) { write(k); write(val) }
    } else {
      throw new Error('the test encoder carries the decoder’s surface only')
    }
  }
  write(value)
  return new Uint8Array(out)
}

export interface TestAuthenticator {
  credentialId: Uint8Array
  privateKey: CryptoKey
  publicKey: CryptoKey
  alg: -7 | -8 | -257
  coseKey: Uint8Array
  counter: number
}

/** Mint a fresh authenticator: the keypair + its COSE encoding. */
export async function mintAuthenticator(alg: -7 | -8 | -257): Promise<TestAuthenticator> {
  let privateKey: CryptoKey
  let publicKey: CryptoKey
  let coseKey: Uint8Array
  if (alg === -7) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    privateKey = pair.privateKey
    publicKey = pair.publicKey
    const jwk = await crypto.subtle.exportKey('jwk', publicKey)
    coseKey = cborEncode(new Map<CborValue, CborValue>([
      [1, 2], [3, -7], [-1, 1],
      [-2, base64urlDecode(jwk.x!)], [-3, base64urlDecode(jwk.y!)],
    ]))
  } else if (alg === -8) {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
    privateKey = pair.privateKey
    publicKey = pair.publicKey
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey))
    coseKey = cborEncode(new Map<CborValue, CborValue>([[1, 1], [3, -8], [-1, 6], [-2, raw]]))
  } else {
    const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
    privateKey = pair.privateKey
    publicKey = pair.publicKey
    const jwk = await crypto.subtle.exportKey('jwk', publicKey)
    coseKey = cborEncode(new Map<CborValue, CborValue>([[1, 3], [3, -257], [-1, base64urlDecode(jwk.n!)], [-2, base64urlDecode(jwk.e!)]]))
  }
  return {
    credentialId: crypto.getRandomValues(new Uint8Array(32)),
    privateKey, publicKey, alg, coseKey, counter: 0,
  }
}

export async function rpIdHash(rpId: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)))
}

export function packAuthData(rpHash: Uint8Array, flags: number, signCount: number, attested?: { aaguid: Uint8Array; credentialId: Uint8Array; coseKey: Uint8Array }): Uint8Array {
  const out: number[] = [...rpHash, flags, (signCount >>> 24) & 0xff, (signCount >>> 16) & 0xff, (signCount >>> 8) & 0xff, signCount & 0xff]
  if (attested) {
    out.push(...attested.aaguid, (attested.credentialId.length >>> 8) & 0xff, attested.credentialId.length & 0xff, ...attested.credentialId, ...attested.coseKey)
  }
  return new Uint8Array(out)
}

/** The authenticator's registration answer (attestation 'none'). */
export async function attest(
  auth: TestAuthenticator,
  challenge: string,
  rp: { rpId: string; origin: string },
  opts?: { origin?: string; rpHash?: Uint8Array; flags?: number; type?: string },
): Promise<{ clientDataJSON: string; attestationObject: string }> {
  const clientData = JSON.stringify({
    type: opts?.type ?? 'webauthn.create',
    challenge,
    origin: opts?.origin ?? rp.origin,
  })
  const authData = packAuthData(opts?.rpHash ?? await rpIdHash(rp.rpId), opts?.flags ?? 0x41, auth.counter, {
    aaguid: new Uint8Array(16),
    credentialId: auth.credentialId,
    coseKey: auth.coseKey,
  })
  const attestationObject = cborEncode(new Map<CborValue, CborValue>([
    ['fmt', 'none'],
    ['attStmt', new Map()],
    ['authData', authData],
  ]))
  return {
    clientDataJSON: base64urlEncode(new TextEncoder().encode(clientData)),
    attestationObject: base64urlEncode(attestationObject),
  }
}

/** The authenticator's assertion answer: the signature over
 *  authData || SHA-256(clientDataJSON). `counter` overrides the
 *  authenticator's own advancing counter (the clone leg presents a
 *  regressed one honestly). */
export async function assertWith(
  auth: TestAuthenticator,
  challenge: string,
  rp: { rpId: string; origin: string },
  opts?: { origin?: string; rpHash?: Uint8Array; counter?: number; userHandle?: string },
): Promise<{ clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string }> {
  const clientData = JSON.stringify({ type: 'webauthn.get', challenge, origin: opts?.origin ?? rp.origin })
  const clientDataBytes = new TextEncoder().encode(clientData)
  const counter = opts?.counter ?? ++auth.counter
  const authData = packAuthData(opts?.rpHash ?? await rpIdHash(rp.rpId), 0x01, counter)
  const clientHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes as BufferSource))
  const signed = new Uint8Array(authData.length + clientHash.length)
  signed.set(authData, 0)
  signed.set(clientHash, authData.length)
  let signature: Uint8Array
  if (auth.alg === -7) {
    const p1363 = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, auth.privateKey, signed))
    // The authenticator emits DER; WebCrypto gave P1363 — transcode.
    const half = p1363.length / 2
    const toDer = (limb: Uint8Array): Uint8Array => {
      let v = limb
      while (v.length > 1 && v[0] === 0) v = v.slice(1)
      if (v[0]! & 0x80) v = new Uint8Array([0, ...v])
      return v
    }
    const r = toDer(p1363.slice(0, half))
    const s = toDer(p1363.slice(half))
    signature = new Uint8Array([0x30, 2 + r.length + 2 + s.length, 0x02, r.length, ...r, 0x02, s.length, ...s])
  } else if (auth.alg === -8) {
    signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, auth.privateKey, signed))
  } else {
    signature = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, auth.privateKey, signed))
  }
  return {
    clientDataJSON: base64urlEncode(clientDataBytes),
    authenticatorData: base64urlEncode(authData),
    signature: base64urlEncode(signature),
    userHandle: opts?.userHandle,
  }
}

/** The account's userHandle value (the registration options' user.id —
 *  the sub's bytes, base64url). */
export function userHandleFor(userId: string): string {
  return base64urlEncode(new TextEncoder().encode(userId))
}
