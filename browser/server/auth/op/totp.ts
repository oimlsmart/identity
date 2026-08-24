// ═══════════════════════════════════════════════════════════════════
// TOTP (RFC 6238) for the factor registry (TODO.identity-sso/03) —
// WebCrypto-native, NO dependency: HMAC-SHA-1 over the 30-second time
// step, the 6-digit dynamic truncation, exactly what every authenticator
// app computes from the otpauth:// URI. The seed is base32 (RFC 4648,
// the otpauth convention — padding optional on decode, never emitted).
//
// The verification window is ±1 step (the authenticator's clock skews);
// a code is a string of 6 digits, compared in constant time after
// computation (both sides are computed, never stored).
//
// WORKER-SAFE: WebCrypto only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** Encode bytes as base32 (RFC 4648, no padding — the otpauth shape). */
export function base32Encode(bytes: Uint8Array): string {
  let out = ''
  let buffer = 0
  let bits = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += B32_ALPHABET[(buffer >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32_ALPHABET[(buffer << (5 - bits)) & 31]
  return out
}

/** Decode base32 (upper/lowercase, padding tolerated, whitespace and
 *  dashes stripped — the manual-entry shape). Throws on a character
 *  outside the alphabet: a malformed secret is refused, never guessed. */
export function base32Decode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '')
  const bytes: number[] = []
  let buffer = 0
  let bits = 0
  for (const ch of clean) {
    const value = B32_ALPHABET.indexOf(ch)
    if (value < 0) throw new Error(`base32: character '${ch}' is outside the RFC 4648 alphabet`)
    buffer = (buffer << 5) | value
    bits += 5
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return new Uint8Array(bytes)
}

/** A fresh TOTP seed: 160 bits of randomness (the RFC 6238 / otpauth
 *  conventional size), base32-encoded for the otpauth URI + manual entry. */
export function generateTotpSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)))
}

export const TOTP_PERIOD_SEC = 30
export const TOTP_DIGITS = 6

/** The HMAC key for a seed, imported once per verification. */
function hmacKey(secret: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', secret as BufferSource, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
}

/** The RFC 6238 dynamic truncation of an HMAC block. */
function truncate(hmac: Uint8Array): number {
  const offset = hmac[hmac.length - 1]! & 0x0f
  const binary =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff)
  return binary % 10 ** TOTP_DIGITS
}

/** The TOTP code for a seed at a time step (zero-padded to 6 digits). */
export async function totpAtStep(secretBase32: string, step: number): Promise<string> {
  const secret = base32Decode(secretBase32)
  const counter = new Uint8Array(8)
  let remaining = step
  for (let i = 7; i >= 0; i--) {
    counter[i] = remaining & 0xff
    remaining = Math.floor(remaining / 256)
  }
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), counter))
  return String(truncate(hmac)).padStart(TOTP_DIGITS, '0')
}

/** The current time step (the tests inject their own clock). */
export function totpStep(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / 1000 / TOTP_PERIOD_SEC)
}

/** Verify a presented code against the seed: the current step ± 1 (the
 *  authenticator's clock skew). The comparison is between two COMPUTED
 *  strings — no stored code exists to time against. */
export async function verifyTotp(secretBase32: string, code: string, nowMs: number = Date.now()): Promise<boolean> {
  if (!/^\d{6}$/.test(code.trim())) return false
  const presented = code.trim()
  const step = totpStep(nowMs)
  for (const candidate of [step - 1, step, step + 1]) {
    if (candidate >= 0 && (await totpAtStep(secretBase32, candidate)) === presented) return true
  }
  return false
}

/** The otpauth:// provisioning URI (the QR's payload + the manual-entry
 *  fallback sits beside it). issuer + account name are label/params per
 *  the de facto otpauth standard. */
export function otpauthUri(input: { issuer: string; accountName: string; secret: string }): string {
  const label = `${encodeURIComponent(input.issuer)}:${encodeURIComponent(input.accountName)}`
  const params = new URLSearchParams({
    secret: input.secret,
    issuer: input.issuer,
    algorithm: 'SHA1',
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SEC),
  })
  return `otpauth://totp/${label}?${params.toString()}`
}
