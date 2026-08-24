// ─────────────────────────────────────────────────────────────────────
// The hand-rolled WebAuthn/TOTP verification's proof (TODO.identity-sso/02
// + /03 — the dependency decision's evidence): server/auth/op/webauthn.ts
// parses CBOR + COSE + DER and verifies with WebCrypto ONLY (zero
// dependency — the doctrine), and server/auth/op/totp.ts computes RFC
// 6238. This suite pins:
//
//   1. the CBOR decoder against the RFC 7049 Appendix A canonical
//      vectors;
//   2. TOTP against the RFC 6238 Appendix B vectors (the SHA-1 rows; the
//      published 8-digit values modulo 10^6 are the 6-digit answers);
//   3. the full ceremonies against freshly generated authenticator
//      material (a test-side CBOR encoder builds the attestationObject /
//      assertion bytes the authenticator WOULD emit — ES256, Ed25519,
//      and RS256), including every refusal (the RP ID hash, the origin,
//      the challenge, the counter's regression rule is the store's, the
//      clone refusals at the route level live in id-factors.test.ts);
//   4. the Ed25519 COSE conversion against an RFC 8032 known-answer pair.
//
// The live interop proof (Chrome's real authenticator through the real
// pages) is e2e/id-14-factors.e2e.ts's virtual-authenticator legs.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import {
  base64urlDecode,
  base64urlEncode,
  cborDecode,
  derToP1363,
  importCoseKey,
  parseAuthenticatorData,
  verifyAssertion,
  verifyRegistration,
  CeremonyError,
  type CborValue,
} from '../../server/auth/op/webauthn'
import { base32Decode, base32Encode, generateTotpSecret, otpauthUri, totpAtStep, verifyTotp } from '../../server/auth/op/totp'
import {
  cborEncode,
  mintAuthenticator,
  attest as kitAttest,
  assertWith as kitAssertWith,
  type TestAuthenticator,
} from './factor-testkit'

// ── the RFC 7049 Appendix A vectors ──────────────────────────────────

describe('the bounded CBOR decoder (RFC 7049 Appendix A)', () => {
  const vectors: Array<{ hex: string; value: CborValue }> = [
    { hex: '00', value: 0 },
    { hex: '17', value: 23 },
    { hex: '1818', value: 24 },
    { hex: '19ffff', value: 65535 },
    { hex: '1a000f4240', value: 1_000_000 },
    { hex: '20', value: -1 },
    { hex: '3863', value: -100 },
    { hex: '40', value: new Uint8Array() },
    { hex: '4401020304', value: new Uint8Array([1, 2, 3, 4]) },
    { hex: '60', value: '' },
    { hex: '6161', value: 'a' },
    { hex: '6449455446', value: 'IETF' },
    { hex: '80', value: [] },
    { hex: '83010203', value: [1, 2, 3] },
    { hex: 'a0', value: new Map() },
    { hex: 'a26161016162820203', value: new Map<string, CborValue>([['a', 1], ['b', [2, 3]]]) },
  ]
  for (const { hex, value } of vectors) {
    it(`decodes ${hex}`, () => {
      const bytes = new Uint8Array(hex.match(/../g)!.map(h => parseInt(h, 16)))
      const decoded = cborDecode(bytes)
      if (value instanceof Uint8Array) {
        expect([...(decoded as Uint8Array)]).toEqual([...value])
      } else if (value instanceof Map) {
        const map = decoded as Map<CborValue, CborValue>
        expect(map.size).toBe(value.size)
        for (const [k, v] of value) expect(map.get(k)).toEqual(v)
      } else {
        expect(decoded).toEqual(value)
      }
    })
  }

  it('refuses the out-of-scope constructs honestly (tags, floats, indefinites, truncation)', () => {
    const bad = ['c0', 'f97e00', '9f', '41', '0102'] // tag 0, float NaN, indefinite array, truncated bytes, trailing junk
    for (const hex of bad) {
      const bytes = new Uint8Array(hex.match(/../g)!.map(h => parseInt(h, 16)))
      expect(() => cborDecode(bytes), hex).toThrow()
    }
  })
})

// ── the RFC 6238 vectors ─────────────────────────────────────────────

describe('TOTP (RFC 6238, the Appendix B SHA-1 rows)', () => {
  // The published 8-digit HMAC-SHA-1 values; my 6-digit codes are them
  // modulo 10^6. The seed is the ASCII '12345678901234567890'.
  const seed = base32Encode(new TextEncoder().encode('12345678901234567890'))
  const rows: Array<{ timeSec: number; eightDigit: string }> = [
    { timeSec: 59, eightDigit: '94287082' },
    { timeSec: 1111111109, eightDigit: '07081804' },
    { timeSec: 1111111111, eightDigit: '14050471' },
    { timeSec: 1234567890, eightDigit: '89005924' },
    { timeSec: 2000000000, eightDigit: '69279037' },
    { timeSec: 20000000000, eightDigit: '65353130' },
  ]
  for (const row of rows) {
    it(`T = ${row.timeSec}s answers …${row.eightDigit.slice(2)}`, async () => {
      const step = Math.floor(row.timeSec / 30)
      expect(await totpAtStep(seed, step)).toBe(String(Number(row.eightDigit) % 1_000_000).padStart(6, '0'))
    })
  }

  it('verifies with the ±1 step window and refuses a wrong or malformed code', async () => {
    const nowMs = 100_000 * 1000
    const step = Math.floor(nowMs / 1000 / 30)
    const code = await totpAtStep(seed, step)
    expect(await verifyTotp(seed, code, nowMs)).toBe(true)
    // The skew window: the previous step's code verifies.
    expect(await verifyTotp(seed, await totpAtStep(seed, step - 1), nowMs)).toBe(true)
    // A code two steps away or malformed never verifies.
    const farCode = await totpAtStep(seed, step - 3)
    if (farCode !== code) expect(await verifyTotp(seed, farCode, nowMs)).toBe(false)
    expect(await verifyTotp(seed, '12345', nowMs)).toBe(false)
    expect(await verifyTotp(seed, 'not a code', nowMs)).toBe(false)
  })

  it('the base32 codec round-trips and the generated seeds decode to 20 bytes', () => {
    const secret = generateTotpSecret()
    expect(secret).toMatch(/^[A-Z2-7]{32}$/)
    expect(base32Decode(secret).length).toBe(20)
    expect(base32Encode(base32Decode(secret))).toBe(secret)
    // The canonical vector: 'Hi' base32-encodes to JBUQ (padding-free).
    expect(base32Encode(new TextEncoder().encode('Hi'))).toBe('JBUQ')
    expect([...base32Decode('JBUQ')]).toEqual([...new TextEncoder().encode('Hi')])
    // the otpauth URI carries the standard params
    const uri = otpauthUri({ issuer: 'OIML SMART Identity', accountName: 'casey@example.org', secret })
    expect(uri.startsWith('otpauth://totp/')).toBe(true)
    expect(uri).toContain('algorithm=SHA1')
    expect(uri).toContain('digits=6')
    expect(uri).toContain('period=30')
  })
})

// ── the ceremonies against fresh authenticator material ──────────────
// The synthetic authenticator + the CBOR encoder live in
// factor-testkit.ts (shared with id-factors.test.ts's route legs).

const RP_ID = 'id.test'
const ORIGIN = 'https://id.test'
const RP = { rpId: RP_ID, origin: ORIGIN }

/** The kit's builders with this suite's RP bound. */
function attest(auth: TestAuthenticator, challenge: string, opts?: { origin?: string; rpHash?: Uint8Array; flags?: number; type?: string }) {
  return kitAttest(auth, challenge, RP, opts)
}
function assertWith(auth: TestAuthenticator, challenge: string, opts?: { origin?: string; rpHash?: Uint8Array; counter?: number; userHandle?: string }) {
  return kitAssertWith(auth, challenge, RP, opts)
}
describe('the WebAuthn ceremonies (fresh authenticator material per algorithm)', () => {
  for (const [name, alg] of [['ES256', -7], ['Ed25519', -8], ['RS256', -257]] as const) {
    it(`registers + asserts with ${name}, and the checks bite`, async () => {
      const auth = await mintAuthenticator(alg)
      const challenge = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
      const checks = { challenge, origin: ORIGIN, rpId: RP_ID }

      // The registration verifies; the COSE key round-trips through the
      // stored form.
      const registration = await verifyRegistration(await attest(auth, challenge), base64urlEncode(auth.credentialId), checks)
      expect(registration.credentialId).toBe(base64urlEncode(auth.credentialId))
      expect(registration.alg).toBe(alg)
      expect(registration.aaguid).toBe('00000000-0000-0000-0000-000000000000')

      // The assertion verifies against the stored COSE key; the counter
      // advances honestly (the store's clone rule is separate).
      const assertion = await verifyAssertion(await assertWith(auth, challenge), registration.publicKeyCose, checks)
      expect(assertion.signCount).toBe(1)

      // Every refusal bites: the origin, the RP hash, the challenge, the
      // ceremony type, a tampered signature.
      await expect(verifyRegistration(await attest(auth, challenge, { origin: 'https://evil.test' }), base64urlEncode(auth.credentialId), checks))
        .rejects.toThrow(CeremonyError)
      await expect(verifyRegistration(await attest(auth, challenge, { rpHash: new Uint8Array(32) }), base64urlEncode(auth.credentialId), checks))
        .rejects.toThrow(/RP ID hash/)
      await expect(verifyRegistration(await attest(auth, 'the-wrong-challenge'), base64urlEncode(auth.credentialId), checks))
        .rejects.toThrow(/challenge/)
      await expect(verifyRegistration(await attest(auth, challenge, { type: 'webauthn.get' }), base64urlEncode(auth.credentialId), checks))
        .rejects.toThrow(/webauthn.create/)
      // A different key's signature over the same bytes never verifies.
      const evil = await mintAuthenticator(alg)
      const tampered = await assertWith(evil, challenge)
      await expect(verifyAssertion(tampered, registration.publicKeyCose, checks)).rejects.toThrow(/signature/)
    })
  }

  it('refuses an attestation format other than "none" honestly', async () => {
    const auth = await mintAuthenticator(-7)
    const challenge = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
    const built = await attest(auth, challenge)
    const raw = base64urlDecode(built.attestationObject)
    // Rewrite fmt to 'packed' through the test encoder.
    const decoded = cborDecode(raw) as Map<CborValue, CborValue>
    decoded.set('fmt', 'packed')
    const repacked = base64urlEncode(cborEncode(decoded))
    await expect(verifyRegistration({ clientDataJSON: built.clientDataJSON, attestationObject: repacked }, base64urlEncode(auth.credentialId), { challenge, origin: ORIGIN, rpId: RP_ID }))
      .rejects.toThrow(/attestation 'none'/)
  })

  it('the DER transcode round-trips (P1363 → DER → P1363) and rejects malformed DER', async () => {
    const auth = await mintAuthenticator(-7)
    const challenge = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
    const registration = await verifyRegistration(await attest(auth, challenge), base64urlEncode(auth.credentialId), { challenge, origin: ORIGIN, rpId: RP_ID })
    // assertWith's ES256 path already transcodes P1363→DER; the verifier
    // DER→P1363's it back — the round trip is the assertion's success.
    const assertion = await verifyAssertion(await assertWith(auth, challenge), registration.publicKeyCose, { challenge, origin: ORIGIN, rpId: RP_ID })
    expect(assertion.signCount).toBe(1)
    expect(() => derToP1363(new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01]), 32)).toThrow()
  })
})

describe('the Ed25519 COSE conversion (the RFC 8032 known answer)', () => {
  it('verifies the RFC 8032 test vector through importCoseKey', async () => {
    // RFC 8032 §7.1 TEST 1: the public key, the empty message, the
    // signature.
    const publicKeyRaw = new Uint8Array('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'.match(/../g)!.map(h => parseInt(h, 16)))
    const signature = new Uint8Array('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'.match(/../g)!.map(h => parseInt(h, 16)))
    const cose = new Map<CborValue, CborValue>([[1, 1], [3, -8], [-1, 6], [-2, publicKeyRaw]])
    const { key, alg } = await importCoseKey(cose)
    expect(alg).toBe(-8)
    const valid = await crypto.subtle.verify({ name: 'Ed25519' }, key, signature as BufferSource, new Uint8Array())
    expect(valid).toBe(true)
  })
})

// A tiny decode seam for the truncated/trailing refusals (the encoder's
// surface test above covers the shapes; these cover the bounds).
describe('the authenticator-data splitter', () => {
  it('refuses a truncated header honestly', () => {
    expect(() => parseAuthenticatorData(new Uint8Array(10), false)).toThrow(/37 bytes/)
  })
})
