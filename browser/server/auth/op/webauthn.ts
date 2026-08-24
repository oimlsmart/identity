// ═══════════════════════════════════════════════════════════════════
// The WebAuthn verification half (TODO.identity-sso/02) — HAND-ROLLED,
// bounded, zero-dependency (the codebase doctrine: WebCrypto + the store
// seam, never a server dependency). The dependency decision, recorded:
//
//   @simplewebauthn/server was the candidate exception. What it buys is
//   the FULL attestation machine (packed/fido-u2f/android-key/apple
//   formats, x5c chain validation, the MDS trust stores). This OP
//   registers at attestation 'none' — deliberately (the assurance level
//   never reads authenticator provenance; the aaguid + transports are
//   recorded as display hints, honestly). What remains is small and
//   fixed-shape:
//
//     1. a CBOR decoder (the attestationObject is ONE map with
//        fmt/attStmt/authData; definite-length items only) — below;
//     2. the authenticator-data split (rpIdHash | flags | counter | the
//        attested credential data) — fixed offsets;
//     3. the COSE→WebCrypto key conversion for exactly three algorithms
//        (ES256, Ed25519 — both WebCrypto-native on node ≥ 22 and
//        workerd — and RS256 for the Windows Hello class);
//     4. the signature verify (ES256's DER→P1363 transcode included).
//
//   The proof: the RFC 7049 Appendix A canonical CBOR vectors, an RFC
//   8032 Ed25519 known-answer, a pinned attestationObject/assertion pair
//   captured from Chrome's real virtual authenticator, and the live
//   e2e ceremonies (id-11) — see src/__tests__/id-webauthn-vectors.test.ts.
//
// THE CHECKS (every one, every ceremony):
//   - clientDataJSON: the ceremony type, the challenge (constant-time
//     equal against the consumed one-time row's value), the EXACT origin
//     (the issuer's origin — no suffix games), tokenBinding refused;
//   - authenticatorData: the RP ID hash (SHA-256 of the exact RP ID — the
//     OP's domain), the user-present flag; the attested credential data
//     at registration (AT flag, the credential id matching the response,
//     the COSE key within the algorithm allowlist);
//   - the assertion signature over authData || SHA-256(clientDataJSON);
//   - the signature counter: the STORE's guarded advance decides — a
//     regressed counter is the clone signal (the caller fails + audits).
//
// WORKER-SAFE: WebCrypto only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

// ── base64url ────────────────────────────────────────────────────────

export function base64urlDecode(text: string): Uint8Array {
  const clean = text.replace(/-/g, '+').replace(/_/g, '/')
  const padded = clean + '='.repeat((4 - (clean.length % 4)) % 4)
  const bin = atob(padded)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function base64urlEncode(bytes: Uint8Array | ArrayBuffer): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let bin = ''
  for (const b of view) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ── the CBOR decoder (bounded: definite-length uint/negint/bytes/text/
//    array/map — everything an attestationObject + a COSE key uses;
//    tags, floats, indefinite lengths and simple values are refused) ──

export type CborValue = number | Uint8Array | string | CborValue[] | Map<CborValue, CborValue>

export class CborError extends Error {}

function cborLength(bytes: Uint8Array, offset: number, info: number): { length: number; offset: number } {
  if (info < 24) return { length: info, offset }
  if (info === 24) return { length: bytes[offset++]!, offset }
  if (info === 25) return { length: (bytes[offset]! << 8) | bytes[offset + 1]!, offset: offset + 2 }
  if (info === 26) {
    return { length: (bytes[offset]! * 2 ** 24) + (bytes[offset + 1]! << 16) + (bytes[offset + 2]! << 8) + bytes[offset + 3]!, offset: offset + 4 }
  }
  throw new CborError(`CBOR additional info ${info} is outside the bounded decoder (64-bit lengths, indefinites, floats are refused)`)
}

function cborItem(bytes: Uint8Array, offset: number): { value: CborValue; offset: number } {
  if (offset >= bytes.length) throw new CborError('CBOR truncated')
  const initial = bytes[offset++]!
  const major = initial >> 5
  const info = initial & 0x1f
  const head = cborLength(bytes, offset, info)
  offset = head.offset
  switch (major) {
    case 0: return { value: head.length, offset }
    case 1: return { value: -1 - head.length, offset }
    case 2: {
      const end = offset + head.length
      if (end > bytes.length) throw new CborError('CBOR byte string overruns the input')
      return { value: bytes.slice(offset, end), offset: end }
    }
    case 3: {
      const end = offset + head.length
      if (end > bytes.length) throw new CborError('CBOR text string overruns the input')
      return { value: new TextDecoder().decode(bytes.slice(offset, end)), offset: end }
    }
    case 4: {
      const out: CborValue[] = []
      for (let i = 0; i < head.length; i++) {
        const item = cborItem(bytes, offset)
        out.push(item.value)
        offset = item.offset
      }
      return { value: out, offset }
    }
    case 5: {
      const out = new Map<CborValue, CborValue>()
      for (let i = 0; i < head.length; i++) {
        const key = cborItem(bytes, offset)
        const val = cborItem(bytes, key.offset)
        out.set(key.value, val.value)
        offset = val.offset
      }
      return { value: out, offset }
    }
    default:
      throw new CborError(`CBOR major type ${major} is outside the bounded decoder (tags/floats/simples are refused)`)
  }
}

/** Decode ONE complete CBOR item (trailing bytes are an error — the
 *  attestationObject is exactly one item). */
export function cborDecode(bytes: Uint8Array): CborValue {
  const item = cborItem(bytes, 0)
  if (item.offset !== bytes.length) throw new CborError('CBOR trailing bytes after the first item')
  return item.value
}

// ── the COSE key → WebCrypto conversion (ES256, Ed25519, RS256) ─────

export const COSE_ALG_ES256 = -7
export const COSE_ALG_ED25519 = -8
export const COSE_ALG_RS256 = -257
export const COSE_ALGS_SUPPORTED = [COSE_ALG_ES256, COSE_ALG_ED25519, COSE_ALG_RS256] as const

export class CoseError extends Error {}

/** The attestationObject's COSE key as a WebCrypto key + the algorithm
 *  the assertion signatures ride. Fixed maps only: kty 2 (EC2/P-256),
 *  kty 1 crv 6 (OKP/Ed25519), kty 3 (RSA). Anything else is refused
 *  honestly — the allowlist above is the ceremony's whole surface. */
export async function importCoseKey(cose: CborValue): Promise<{ key: CryptoKey; alg: number }> {
  if (!(cose instanceof Map)) throw new CoseError('the credential public key is not a CBOR map')
  const kty = cose.get(1)
  const alg = cose.get(3)
  if (typeof alg !== 'number' || !(COSE_ALGS_SUPPORTED as readonly number[]).includes(alg)) {
    throw new CoseError(`COSE alg ${String(alg)} is outside the allowlist (ES256 / Ed25519 / RS256)`)
  }
  if (alg === COSE_ALG_ES256) {
    const crv = cose.get(-1); const x = cose.get(-2); const y = cose.get(-3)
    if (kty !== 2 || crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
      throw new CoseError('the ES256 credential key is not a well-formed EC2 P-256 point')
    }
    const jwk: JsonWebKey = {
      kty: 'EC', crv: 'P-256',
      x: base64urlEncode(x), y: base64urlEncode(y),
    }
    return { key: await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']), alg }
  }
  if (alg === COSE_ALG_ED25519) {
    const crv = cose.get(-1); const x = cose.get(-2)
    if (kty !== 1 || crv !== 6 || !(x instanceof Uint8Array) || x.length !== 32) {
      throw new CoseError('the Ed25519 credential key is not a well-formed OKP key')
    }
    return { key: await crypto.subtle.importKey('raw', x as BufferSource, { name: 'Ed25519' }, false, ['verify']), alg }
  }
  // RS256 (the Windows Hello interop class).
  const n = cose.get(-1); const e = cose.get(-2)
  if (kty !== 3 || !(n instanceof Uint8Array) || !(e instanceof Uint8Array) || n.length < 256) {
    throw new CoseError('the RS256 credential key is not a well-formed RSA key (2048 bits minimum)')
  }
  const jwk: JsonWebKey = { kty: 'RSA', n: base64urlEncode(n), e: base64urlEncode(e) }
  return { key: await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']), alg }
}

// ── the authenticator data ───────────────────────────────────────────

export interface AuthenticatorData {
  rpIdHash: Uint8Array
  userPresent: boolean
  userVerified: boolean
  signCount: number
  /** Present at registration only (the AT flag): the aaguid, the
   *  credential id, and the COSE key bytes. */
  attested?: { aaguid: string; credentialId: Uint8Array; coseKeyBytes: Uint8Array }
}

export class AuthDataError extends Error {}

export function parseAuthenticatorData(bytes: Uint8Array, expectAttested: boolean): AuthenticatorData {
  if (bytes.length < 37) throw new AuthDataError('authenticator data is shorter than the fixed header (37 bytes)')
  const rpIdHash = bytes.slice(0, 32)
  const flags = bytes[32]!
  const signCount =
    (bytes[33]! * 2 ** 24) + (bytes[34]! << 16) + (bytes[35]! << 8) + bytes[36]!
  const userPresent = (flags & 0x01) !== 0
  const userVerified = (flags & 0x04) !== 0
  const attested = (flags & 0x40) !== 0
  let out: AuthenticatorData = { rpIdHash, userPresent, userVerified, signCount }
  if (expectAttested) {
    if (!attested) throw new AuthDataError('the registration answer carries no attested credential data (the AT flag is clear)')
    if (bytes.length < 37 + 16 + 2) throw new AuthDataError('the attested credential data is truncated')
    const aaguid = [...bytes.slice(37, 53)].map(b => b.toString(16).padStart(2, '0')).join('')
      .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5')
    const credIdLen = (bytes[53]! << 8) | bytes[54]!
    const credStart = 55
    const credEnd = credStart + credIdLen
    if (credEnd > bytes.length) throw new AuthDataError('the credential id overruns the attested data')
    out = {
      ...out,
      attested: {
        aaguid,
        credentialId: bytes.slice(credStart, credEnd),
        // The COSE key is the remainder UP TO its own end (the CBOR item
        // boundary — extensions may follow): decode from the slice start
        // and take the bytes the one item spans.
        coseKeyBytes: (() => {
          const item = cborItem(bytes, credEnd)
          return bytes.slice(credEnd, item.offset)
        })(),
      },
    }
  }
  return out
}

// ── the ECDSA DER → P1363 transcode ──────────────────────────────────
// WebCrypto verifies IEEE P1363 (r || s, 32 bytes each for P-256); the
// authenticator signs DER. The transcode is the two INTEGER limbs,
// sign-extension stripped, zero-padded to the coordinate size.

export class DerError extends Error {}

export function derToP1363(der: Uint8Array, coordinateBytes: number): Uint8Array {
  const readInteger = (at: number): { value: Uint8Array; next: number } => {
    if (der[at] !== 0x02) throw new DerError('an ECDSA DER signature is a sequence of two INTEGERs')
    const length = der[at + 1]!
    const start = at + 2
    if (length > coordinateBytes + 1 || start + length > der.length) throw new DerError('an ECDSA limb overruns the signature')
    let value = der.slice(start, start + length)
    // The sign byte and the left zero-padding go; the limb is
    // right-aligned in the coordinate field.
    while (value.length > 1 && value[0] === 0x00) value = value.slice(1)
    if (value.length > coordinateBytes) throw new DerError('an ECDSA limb exceeds the curve’s coordinate size')
    const padded = new Uint8Array(coordinateBytes)
    padded.set(value, coordinateBytes - value.length)
    return { value: padded, next: start + length }
  }
  if (der.length < 8 || der[0] !== 0x30) throw new DerError('an ECDSA signature is a DER SEQUENCE')
  const seqLength = der[1]!
  if (seqLength + 2 !== der.length) throw new DerError('the DER SEQUENCE length does not match the signature')
  const r = readInteger(2)
  const s = readInteger(r.next)
  if (s.next !== der.length) throw new DerError('trailing bytes after the ECDSA signature')
  const out = new Uint8Array(coordinateBytes * 2)
  out.set(r.value, 0)
  out.set(s.value, coordinateBytes)
  return out
}

// ── the client data ──────────────────────────────────────────────────

export interface ClientData {
  type: string
  challenge: string
  origin: string
  crossOrigin?: boolean
  tokenBinding?: unknown
}

export class ClientDataError extends Error {}

export function parseClientData(clientDataJSON: Uint8Array): ClientData {
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(clientDataJSON)) as unknown
  } catch {
    throw new ClientDataError('clientDataJSON is not JSON')
  }
  const rec = parsed as Record<string, unknown>
  if (typeof rec?.type !== 'string' || typeof rec.challenge !== 'string' || typeof rec.origin !== 'string') {
    throw new ClientDataError('clientDataJSON lacks type/challenge/origin')
  }
  return rec as unknown as ClientData
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

// ── the ceremonies ───────────────────────────────────────────────────

export interface CeremonyChecks {
  /** The consumed one-time challenge's value (base64url). */
  challenge: string
  /** The exact expected origin (the issuer's origin). */
  origin: string
  /** The exact RP ID (the issuer's host). */
  rpId: string
}

export interface RegistrationResult {
  credentialId: string
  publicKeyCose: string
  signCount: number
  aaguid: string
  alg: number
  userVerified: boolean
}

export class CeremonyError extends Error {}

/** The registration verification (attestation 'none' — the attStmt is
 *  never evaluated; the aaguid + transports are display hints). Throws
 *  CeremonyError with the honest reason. */
export async function verifyRegistration(
  response: { clientDataJSON: string; attestationObject: string },
  credentialIdB64: string,
  checks: CeremonyChecks,
): Promise<RegistrationResult> {
  const fail = (reason: string): never => { throw new CeremonyError(reason) }
  let clientData: ClientData
  try {
    clientData = parseClientData(base64urlDecode(response.clientDataJSON))
  } catch (e) { return fail((e as Error).message) }
  if (clientData.type !== 'webauthn.create') fail(`the ceremony type is ${clientData.type}, not webauthn.create`)
  if (clientData.challenge !== checks.challenge) fail('the challenge does not match the ceremony’s one-time row')
  if (clientData.tokenBinding !== undefined) fail('token binding is not supported')
  if (clientData.origin !== checks.origin) fail('the origin does not match this service exactly')

  let attestation: CborValue
  try {
    attestation = cborDecode(base64urlDecode(response.attestationObject))
  } catch (e) { return fail(`the attestation object does not decode: ${(e as Error).message}`) }
  if (!(attestation instanceof Map)) fail('the attestation object is not a CBOR map')
  const attestationMap = attestation as Map<CborValue, CborValue>
  const fmt = attestationMap.get('fmt')
  if (fmt !== 'none') fail(`attestation fmt is ${String(fmt)} — this service registers at attestation 'none'`)
  const authDataBytes = attestationMap.get('authData')
  if (!(authDataBytes instanceof Uint8Array)) fail('the attestation object carries no authData')

  let authData: AuthenticatorData
  try {
    authData = parseAuthenticatorData(authDataBytes as Uint8Array, true)
  } catch (e) { return fail((e as Error).message) }
  const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(checks.rpId)))
  if (!timingSafeEqual(authData.rpIdHash, rpHash)) fail('the RP ID hash does not match this service')
  if (!authData.userPresent) fail('the authenticator did not mark the user present')
  const attested = authData.attested!
  if (base64urlEncode(attested.credentialId) !== credentialIdB64) {
    fail('the attested credential id does not match the response’s id')
  }
  let cose: CborValue
  try {
    cose = cborDecode(attested.coseKeyBytes)
  } catch (e) { return fail(`the credential public key does not decode: ${(e as Error).message}`) }
  let imported: { key: CryptoKey; alg: number }
  try {
    imported = await importCoseKey(cose)
  } catch (e) { return fail((e as Error).message) }
  return {
    credentialId: credentialIdB64,
    publicKeyCose: base64urlEncode(attested.coseKeyBytes),
    signCount: authData.signCount,
    aaguid: attested.aaguid,
    alg: imported.alg,
    userVerified: authData.userVerified,
  }
}

/** The assertion verification against the stored COSE key. Answers the
 *  presented counter (the STORE's guarded advance judges the clone rule)
 *  and the user-verified flag. Throws CeremonyError with the reason. */
export async function verifyAssertion(
  response: { clientDataJSON: string; authenticatorData: string; signature: string },
  storedPublicKeyCose: string,
  checks: CeremonyChecks,
): Promise<{ signCount: number; userVerified: boolean }> {
  const fail = (reason: string): never => { throw new CeremonyError(reason) }
  let clientData: ClientData
  try {
    clientData = parseClientData(base64urlDecode(response.clientDataJSON))
  } catch (e) { return fail((e as Error).message) }
  if (clientData.type !== 'webauthn.get') fail(`the ceremony type is ${clientData.type}, not webauthn.get`)
  if (clientData.challenge !== checks.challenge) fail('the challenge does not match the ceremony’s one-time row')
  if (clientData.tokenBinding !== undefined) fail('token binding is not supported')
  if (clientData.origin !== checks.origin) fail('the origin does not match this service exactly')

  const authDataBytes = base64urlDecode(response.authenticatorData)
  let authData: AuthenticatorData
  try {
    authData = parseAuthenticatorData(authDataBytes, false)
  } catch (e) { return fail((e as Error).message) }
  const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(checks.rpId)))
  if (!timingSafeEqual(authData.rpIdHash, rpHash)) fail('the RP ID hash does not match this service')
  if (!authData.userPresent) fail('the authenticator did not mark the user present')

  let imported: { key: CryptoKey; alg: number }
  try {
    imported = await importCoseKey(cborDecode(base64urlDecode(storedPublicKeyCose)))
  } catch (e) { return fail(`the stored credential key does not decode: ${(e as Error).message}`) }

  const clientHash = new Uint8Array(await crypto.subtle.digest('SHA-256', base64urlDecode(response.clientDataJSON) as BufferSource))
  const signed = new Uint8Array(authDataBytes.length + clientHash.length)
  signed.set(authDataBytes, 0)
  signed.set(clientHash, authDataBytes.length)

  const signatureRaw = base64urlDecode(response.signature)
  let signature: Uint8Array = signatureRaw
  let algorithm: { name: string; hash?: string }
  let algoName: string
  if (imported.alg === COSE_ALG_ES256) {
    try {
      signature = derToP1363(signatureRaw, 32)
    } catch (e) { return fail((e as Error).message) }
    algoName = 'ECDSA'
    algorithm = { name: 'ECDSA', hash: 'SHA-256' }
  } else if (imported.alg === COSE_ALG_ED25519) {
    algoName = 'Ed25519'
    algorithm = { name: 'Ed25519' }
  } else {
    algoName = 'RSASSA-PKCS1-v1_5'
    algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
  }
  const valid = await crypto.subtle.verify(algorithm, imported.key, signature as BufferSource, signed)
  if (!valid) fail(`the ${algoName} signature does not verify against the registered credential`)
  return { signCount: authData.signCount, userVerified: authData.userVerified }
}
