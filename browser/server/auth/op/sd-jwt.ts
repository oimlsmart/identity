// ═══════════════════════════════════════════════════════════════════
// The SD-JWT engine (RFC 9445, TODO.sota/08) — the selectively
// disclosable JWT's mint/verify core + the holder key binding (the
// KB-JWT). WORKER-SAFE: WebCrypto only, no node built-ins.
//
// THE FORMAT: the issuer signs an ordinary ES256 JWT whose payload
// carries the STRUCTURAL claims (iss/sub/iat/exp/vct/cnf) plus, for
// every selectively-disclosable claim, only `_SD` — the base64url of
// SHA-256 over the DISCLOSURE string `<b64url([salt, name, value])>`.
// The values themselves are NOWHERE in the JWT. The COMBINED
// presentation is `JWS~Disclosure~…` (the holder picks which
// disclosures ride); with holder binding a final `~KB-JWT` follows.
//
// VERIFICATION (the spec's hard rules): the JWS signature against the
// issuer's keyset; every presented disclosure's hash MUST appear in
// _SD (an unreferenced disclosure refuses); duplicate claim names
// (payload ∨ disclosures) refuse; a disclosure with a non-string name
// refuses. The KB-JWT: typ kb+jwt, ES256, the holder's PUBLIC jwk in
// its header, payload { sd_hash, nonce?, aud?, iat } — sd_hash is the
// base64url SHA-256 of the JWS string ALONE, and the jwk's JKT must
// equal the payload's cnf.jkt (RFC 9449 §6.4's thumbprint).
//
// SLICE 1's SHAPE: flat claims (no recursive/nested disclosures); no
// status list yet (the revocation story — the named next slice).
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '../../store'
import { verifyOpJwt, signOpIdToken, type OpSigningKey } from './keys'
import { jktOf } from './dpop'

/** RFC 9157's bitstring width per entry: 1 bit — boolean status. */
const STATUS_BITS = 1

async function gzipB64url(bytes: Uint8Array): Promise<string> {
  const stream = new Blob([bytes as unknown as BlobPart]).stream().pipeThrough(new CompressionStream('gzip'))
  const buf = new Uint8Array(await new Response(stream).arrayBuffer())
  return bytesToB64url(buf)
}

async function gunzipBytes(b64: string): Promise<Uint8Array> {
  const stream = new Blob([b64urlToBytes(b64) as unknown as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip'))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

function bytesToB64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlToBytes(v: string): Uint8Array<ArrayBuffer> {
  const b64 = v.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4))
  const out = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function sha256B64url(value: string): Promise<string> {
  return bytesToB64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))))
}

function randomSalt(): string {
  const bytes = new Uint8Array(new ArrayBuffer(16))
  crypto.getRandomValues(bytes)
  return bytesToB64url(bytes)
}

/** One disclosure: `<b64url(JSON [salt, name, value])>` — compact JSON,
 *  the salt ≥ 128 bits (the spec's rule). */
function mintDisclosure(name: string, value: unknown): string {
  return bytesToB64url(new TextEncoder().encode(JSON.stringify([randomSalt(), name, value])))
}

/** A test/ops affordance: mint a well-formed disclosure WITHOUT
 *  referencing the payload's _SD (the verifier's unreferenced-leg
 *  probe uses it). */
export async function mintArbitraryDisclosure(name: string, value: unknown): Promise<string> {
  return mintDisclosure(name, value)
}

export interface SdJwtMintInput {
  issuer: string
  subject: string
  audience?: string
  ttlSec: number
  /** The always-visible claims (structural + non-sensitive). */
  plain?: Record<string, unknown>
  /** The selectively-disclosable claims: their names+values NEVER ride
   *  the JWT — only their disclosures' hashes. */
  disclosable?: Record<string, unknown>
  /** The holder binding: the key's JKT rides cnf.jkt (plain — it is
   *  structural, the KB's anchor). */
  holderJkt?: string
  /** RFC 9157 (TODO.sota/08 slice 2): the status list's URI — the mint
   *  stamps status.status_list.{uri, idx} (structural, never
   *  disclosable; the revocation's anchor). */
  statusListUri?: string
  statusListIdx?: number
}

/** The nested-object marker (RFC 9445's recursive disclosures): the
 *  object's PLAIN members ride inside its disclosure; its DISCLOSABLE
 *  members hide behind the object's own _SD — revealable only after
 *  the parent itself is presented. */
export interface SdObject {
  readonly __sdObject: {
    plain: Record<string, unknown>
    disclosable: Record<string, unknown>
  }
}

export function sdObject(plain: Record<string, unknown>, disclosable: Record<string, unknown>): SdObject {
  return { __sdObject: { plain, disclosable } }
}

function isSdObject(value: unknown): value is SdObject {
  return typeof value === 'object' && value !== null && '__sdObject' in value
}

/** Build one object level: the plain members + the _SD hashes of its
 *  disclosable members (nested sdObjects recurse, their disclosures
 *  joining the flat list). */
async function buildObjectLevel(
  plain: Record<string, unknown>,
  disclosable: Record<string, unknown>,
): Promise<{ obj: Record<string, unknown>; disclosures: string[] }> {
  const obj: Record<string, unknown> = { ...plain }
  const hashes: string[] = []
  const disclosures: string[] = []
  for (const [name, value] of Object.entries(disclosable)) {
    let inner: unknown = value
    if (isSdObject(value)) {
      const built = await buildObjectLevel(value.__sdObject.plain, value.__sdObject.disclosable)
      inner = built.obj
      disclosures.push(...built.disclosures)
    }
    const disclosure = mintDisclosure(name, inner)
    hashes.push(await sha256B64url(disclosure))
    disclosures.push(disclosure)
  }
  if (hashes.length) obj._SD = hashes
  return { obj, disclosures }
}

export interface MintedSdJwt {
  sdJwt: string
  /** ALL the disclosures — issuance hands everything; the HOLDER
   *  selects at presentation. */
  disclosures: string[]
}

/** Mint the SD-JWT (the JWS alone — the combined form is the
 *  presentation's business). */
export async function mintSdJwt(key: OpSigningKey, input: SdJwtMintInput): Promise<MintedSdJwt> {
  const nowSec = Math.floor(Date.now() / 1000)
  const disclosures: string[] = []
  const sdHashes: string[] = []
  for (const [name, value] of Object.entries(input.disclosable ?? {})) {
    let inner: unknown = value
    if (isSdObject(value)) {
      const built = await buildObjectLevel(value.__sdObject.plain, value.__sdObject.disclosable)
      inner = built.obj
      disclosures.push(...built.disclosures)
    }
    const disclosure = mintDisclosure(name, inner)
    disclosures.push(disclosure)
    sdHashes.push(await sha256B64url(disclosure))
  }
  const payload: Record<string, unknown> = {
    iss: input.issuer,
    sub: input.subject,
    iat: nowSec,
    exp: nowSec + input.ttlSec,
    ...(input.audience ? { aud: input.audience } : {}),
    ...(input.plain ?? {}),
    ...(input.holderJkt ? { cnf: { jkt: input.holderJkt } } : {}),
    ...(input.statusListUri !== undefined && input.statusListIdx !== undefined
      ? { status: { status_list: { uri: input.statusListUri, idx: input.statusListIdx } } }
      : {}),
    ...(sdHashes.length ? { _sd_alg: 'sha-256', _SD: sdHashes } : {}),
  }
  const sdJwt = await signOpIdToken(key, payload)
  return { sdJwt, disclosures }
}

/** The combined presentation: `JWS~d1~…~dn`, optionally `~KB-JWT`
 *  last. The holder's selection IS the disclosure — this function
 *  never invents one. */
export function combinedPresentation(sdJwt: string, disclosures: string[], kbJwt?: string): string {
  return [sdJwt, ...disclosures, ...(kbJwt ? [kbJwt] : [])].join('~')
}

export interface SdJwtVerifyExpectation {
  issuer: string
  /** When set, the trailing KB-JWT is REQUIRED and must bind to the
   *  payload's cnf.jkt with these values (the verifier's challenge). */
  keyBinding?: { nonce?: string; aud?: string }
}

/** Verify a combined presentation end-to-end: the JWS against the OP's
 *  keyset, the disclosures' hash discipline, and (when expected) the
 *  holder's KB-JWT. Answers the MERGED claims + the holder JKT, or the
 *  error. */
export async function verifySdJwtPresentation(
  store: ServerStore,
  combined: string,
  expect: SdJwtVerifyExpectation,
): Promise<{ claims: Record<string, unknown>; holderJkt: string | null } | { error: string }> {
  const parts = combined.split('~')
  if (parts.length < 1 || !parts[0]) return { error: 'malformed presentation' }
  const sdJwt = parts[0]!
  const rest = parts.slice(1)
  let kbJwt: string | undefined
  if (rest.length && rest[rest.length - 1]!.includes('.') && rest[rest.length - 1]!.split('.').length === 3) {
    const last = rest[rest.length - 1]!
    try {
      const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(last.split('.')[0]!))) as { typ?: string }
      if (header.typ === 'kb+jwt') kbJwt = rest.pop()!
    } catch { /* not a KB — it stays a disclosure and fails below */ }
  }
  const claims = await verifyOpJwt(store, sdJwt)
  if (!claims) return { error: 'the SD-JWT signature does not verify' }
  if (claims.iss !== expect.issuer) return { error: 'the issuer does not match' }

  const seenHashes = new Set<string>()
  const merged: Record<string, unknown> = { ...claims }
  delete merged._SD
  delete merged._sd_alg

  // The disclosure pool: every presented disclosure parsed once, keyed
  // by its hash. The levels then claim their members — the top _SD
  // first, and every REVEALED object's own _SD opens a sub-level (the
  // recursion: a child is revealable only under a presented parent).
  // Leftovers at the end refuse.
  const pool = new Map<string, { name: string; value: unknown; disclosure: string }>()
  for (const disclosure of rest) {
    let parsed: unknown
    try {
      parsed = JSON.parse(new TextDecoder().decode(b64urlToBytes(disclosure)))
    } catch {
      return { error: 'a disclosure is malformed' }
    }
    if (!Array.isArray(parsed) || parsed.length !== 3 || typeof parsed[0] !== 'string' || typeof parsed[1] !== 'string') {
      return { error: 'a disclosure is malformed' }
    }
    const [, name] = parsed as [string, string, unknown]
    const hash = await sha256B64url(disclosure)
    if (pool.has(hash)) return { error: `the disclosure for ${name} was presented twice` }
    pool.set(hash, { name, value: (parsed as [string, string, unknown])[2], disclosure })
  }

  const levels: Array<{ level: Record<string, unknown>; sd: unknown[] }> = []
  if (Array.isArray(claims._SD)) levels.push({ level: merged, sd: claims._SD as unknown[] })
  let progress = true
  while (progress) {
    progress = false
    for (const [hash, entry] of [...pool]) {
      if (seenHashes.has(hash)) continue
      const level = levels.find(l => l.sd.includes(hash))
      if (!level) continue
      if (entry.name in level.level) return { error: `the claim ${entry.name} collides with its level` }
      level.level[entry.name] = entry.value
      seenHashes.add(hash)
      progress = true
      // The revealed value may itself carry _SD — a new sub-level.
      if (entry.value !== null && typeof entry.value === 'object' && !Array.isArray(entry.value as object)) {
        const obj = entry.value as Record<string, unknown>
        const nestedSd = obj._SD
        if (Array.isArray(nestedSd)) {
          delete obj._SD
          levels.push({ level: obj, sd: nestedSd })
        }
      }
    }
  }
  if (seenHashes.size < pool.size) {
    const unreferenced = [...pool.entries()].filter(([hash]) => !seenHashes.has(hash)).map(([, e]) => e.name)
    return { error: `an unreferenced disclosure (${unreferenced[0]}) refuses` }
  }

  const holderJkt = (claims.cnf as { jkt?: unknown } | undefined)?.jkt
  const cnfJkt = typeof holderJkt === 'string' ? holderJkt : null
  if (expect.keyBinding) {
    if (!kbJwt) return { error: 'the key binding JWT is required' }
    if (!cnfJkt) return { error: 'the credential carries no holder binding' }
    const ok = await verifyKeyBindingJwt(kbJwt, {
      jkt: cnfJkt,
      sdJwt,
      ...(expect.keyBinding.nonce !== undefined ? { nonce: expect.keyBinding.nonce } : {}),
      ...(expect.keyBinding.aud !== undefined ? { aud: expect.keyBinding.aud } : {}),
    })
    if (!ok) return { error: 'the key binding JWT does not verify' }
  }
  return { claims: merged, holderJkt: cnfJkt }
}

/** Mint the KB-JWT (the holder's possession proof): typ kb+jwt, ES256
 *  with the holder's key, the jwk in the header, payload
 *  { sd_hash, nonce?, aud?, iat } — sd_hash over the JWS ALONE. */
export async function mintKeyBindingJwt(
  holderKeys: CryptoKeyPair,
  input: { sdJwt: string; nonce?: string; aud?: string },
): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', holderKeys.publicKey) as { kty: string; crv: string; x: string; y: string }
  const header = { typ: 'kb+jwt', alg: 'ES256', jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }
  const payload: Record<string, unknown> = {
    iat: Math.floor(Date.now() / 1000),
    sd_hash: await sha256B64url(input.sdJwt),
    ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
    ...(input.aud !== undefined ? { aud: input.aud } : {}),
  }
  const encoder = new TextEncoder()
  const unsigned = `${bytesToB64url(encoder.encode(JSON.stringify(header)))}.${bytesToB64url(encoder.encode(JSON.stringify(payload)))}`
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, holderKeys.privateKey, encoder.encode(unsigned))
  return `${unsigned}.${bytesToB64url(new Uint8Array(sig))}`
}

/** Verify a KB-JWT against the expected binding: the signature with
 *  the EMBEDDED public key, the key's JKT === the credential's cnf,
 *  sd_hash over the JWS, and the expected nonce/aud. */
export async function verifyKeyBindingJwt(
  kbJwt: string,
  expect: { jkt: string; sdJwt: string; nonce?: string; aud?: string },
): Promise<boolean> {
  const parts = kbJwt.split('.')
  if (parts.length !== 3) return false
  try {
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0]!))) as { typ?: string; alg?: string; jwk?: { kty?: string; crv?: string; x?: string; y?: string } }
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1]!))) as { sd_hash?: unknown; nonce?: unknown; aud?: unknown }
    if (header.typ !== 'kb+jwt' || header.alg !== 'ES256') return false
    const jwk = header.jwk
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) return false
    if (await jktOf({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }) !== expect.jkt) return false
    if (payload.sd_hash !== await sha256B64url(expect.sdJwt)) return false
    if (expect.nonce !== undefined && payload.nonce !== expect.nonce) return false
    if (expect.aud !== undefined && payload.aud !== expect.aud) return false
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      b64urlToBytes(parts[2]!),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    )
  } catch {
    return false
  }
}


/** Build the status list JWT (RFC 9157): typ statuslist+jwt, ES256 by
 *  the OP's key, payload { iss, sub: 'statuslist', status_list: {
 *  bits: 1, lst: base64url(gzip(bitstring)) } } — one bit per issued
 *  index, LSB-first in its byte; a REVOKED credential's bit is 1. */
export async function buildStatusListJwt(
  key: OpSigningKey,
  input: { issuer: string; maxIdx: number; revoked: number[] },
): Promise<string> {
  const bytes = new Uint8Array(new ArrayBuffer(Math.ceil((input.maxIdx + 1) / 8)))
  for (const idx of input.revoked) {
    if (idx < 0 || idx >= bytes.length * 8) continue
    bytes[Math.floor(idx / 8)]! |= 1 << (idx % 8)
  }
  return signStatuslistJwt(key, {
    iss: input.issuer,
    sub: 'statuslist',
    status_list: { bits: STATUS_BITS, lst: await gzipB64url(bytes) },
  })
}

/** The list's own signer: the typ rides the HEADER (statuslist+jwt —
 *  the media type the verifier checks), the kid names the signing key. */
async function signStatuslistJwt(key: OpSigningKey, claims: Record<string, unknown>): Promise<string> {
  const header = bytesToB64url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', typ: 'statuslist+jwt', kid: key.kid })))
  const payload = bytesToB64url(new TextEncoder().encode(JSON.stringify(claims)))
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  )
  return `${header}.${payload}.${bytesToB64url(new Uint8Array(sig))}`
}

/** The verifier's read: the list JWT verifies as the ISSUER's own (the
 *  typ + the signature + the issuer), the lst decompresses, and the
 *  bit at idx answers — TRUE = revoked. */
export async function credentialRevoked(
  store: ServerStore,
  listJwt: string,
  idx: number,
  issuer: string,
): Promise<boolean> {
  const parts = listJwt.split('.')
  if (parts.length !== 3) return true
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0]!))) as { typ?: string }
  if (header.typ !== 'statuslist+jwt') return true
  const claims = await verifyOpJwt(store, listJwt)
  if (!claims || claims.iss !== issuer || claims.sub !== 'statuslist') return true
  const list = (claims.status_list as { bits?: unknown; lst?: unknown } | undefined)
  if (!list || list.bits !== STATUS_BITS || typeof list.lst !== 'string') return true
  const bytes = await gunzipBytes(list.lst)
  const byte = bytes[Math.floor(idx / 8)]
  return byte !== undefined && (byte & (1 << (idx % 8))) !== 0
}


/** The OIDC4VCI wallet proof (TODO.sota/08 slice 3): typ
 * openid4vci-proof+jwt, ES256 with the WALLET's key (the public jwk in
 * the header — no private material), aud = the issuer, a valid
 * server-issued c_nonce, a fresh iat. Answers the key's JKT (the
 * holder binding the mint stamps), or null. */
export async function verifyWalletProof(
  proofJwt: string,
  expect: { issuer: string; nonceSecret: string },
): Promise<{ jkt: string } | null> {
  const parts = proofJwt.split('.')
  if (parts.length !== 3) return null
  try {
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0]!))) as { typ?: string; alg?: string; jwk?: { kty?: string; crv?: string; x?: string; y?: string; d?: string } }
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1]!))) as { aud?: unknown; nonce?: unknown; iat?: unknown }
    if (header.typ !== 'openid4vci-proof+jwt' || header.alg !== 'ES256') return null
    const jwk = header.jwk
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y || jwk.d !== undefined) return null
    if (payload.aud !== expect.issuer) return null
    const iat = typeof payload.iat === 'number' ? payload.iat : Number.NaN
    if (!Number.isFinite(iat) || Math.abs(Math.floor(Date.now() / 1000) - iat) > 300) return null
    const { verifyChallengeNonce } = await import('./dpop')
    if (typeof payload.nonce !== 'string' || !(await verifyChallengeNonce(expect.nonceSecret, payload.nonce))) return null
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64urlToBytes(parts[2]!), new TextEncoder().encode(`${parts[0]}.${parts[1]}`))
    if (!ok) return null
    return { jkt: await jktOf({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }) }
  } catch {
    return null
  }
}
