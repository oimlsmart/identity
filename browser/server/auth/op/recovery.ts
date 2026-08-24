// ═══════════════════════════════════════════════════════════════════
// The recovery codes (TODO.identity-sso/03) — the account-recovery
// floor: generated at the FIRST factor's enrollment, shown once, stored
// HASHED, one-time each. Regeneration replaces the account's set whole
// (the old set dies with the audit event).
//
// The shape: 10 codes of 16 base32 characters (80 bits of random each),
// displayed dashed (w3c9-k2m4-…). The store keeps SHA-256 of the
// NORMALIZED code (uppercase, dashes/spaces stripped) — 80 bits of
// entropy per code makes the unsalted hash resistant to the offline
// attack, and the one-time consume is the store's guarded UPDATE.
//
// The email reset stands behind everything (the documented doctrine):
// recovery codes are never the only path back in.
//
// WORKER-SAFE: WebCrypto only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { base32Encode } from './totp'

export const RECOVERY_CODE_COUNT = 10
const CODE_BYTES = 10 // 80 bits → 16 base32 characters

/** A fresh set of recovery codes (the plaintext answers ONCE — the
 *  response at generation, never stored). */
export function generateRecoveryCodes(): string[] {
  const codes: string[] = []
  for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
    const raw = base32Encode(crypto.getRandomValues(new Uint8Array(CODE_BYTES)))
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`.toLowerCase())
  }
  return codes
}

/** The storage form: SHA-256 hex of the normalized code. */
export async function hashRecoveryCode(code: string): Promise<string> {
  const normalized = code.trim().toUpperCase().replace(/[\s-]/g, '')
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalized))
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** The presented code's plausible shape (before any hash work): 16
 *  base32 characters, dashes/spaces tolerated. */
export function recoveryCodePlausible(code: string): boolean {
  return /^[A-Za-z2-7]{16}$/.test(code.trim().toUpperCase().replace(/[\s-]/g, ''))
}
