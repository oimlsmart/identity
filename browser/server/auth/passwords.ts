// ═══════════════════════════════════════════════════════════════════
// Password credentials for the identity provider's accounts
// (TODO.identity/02) — the OP holds its OWN account list, and a password
// account signs in with a real credential, never the demo cast's shared
// plaintext (that pattern stays with the demo instances, where it belongs).
//
// PBKDF2-HMAC-SHA256 over WebCrypto (op/secrets.ts's ONE implementation),
// so node ≥ 18 and the Cloudflare Worker execute the identical code path
// and no dependency enters the bundle. The stored value is
// self-describing (pbkdf2:<iterations>:<salt>:<digest>) — a cost change
// never strands an account. 600 000 iterations is OWASP's current
// PBKDF2-HMAC-SHA256 recommendation; the verify path's cost IS the
// brute-force wall, so it is deliberately uniform (below).
//
// THE POLICY: a password is at least 12 characters (and bounded, so an
// oversized POST cannot buy free PBKDF2 work). The strength meter is
// honest feedback, not a gate: it scores length + character variety and
// says what would improve the password — the only REFUSAL is the policy.
//
// NEVER logged: no code path here, in the routes, or in the stores logs
// a password or a hash — audit lines name the account's email/id only.
//
// WORKER-SAFE: WebCrypto only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { pbkdf2Hash, pbkdf2Verify } from './op/secrets'

/** workerd (Cloudflare Workers) caps WebCrypto PBKDF2 at 100,000
 *  iterations — above that, deriveBits throws NotSupportedError
 *  (2026-08-16: the OP's password paths 500'd on the Worker). OWASP's
 *  600k recommendation is unshippable there; 100k is the cap, so the
 *  cap is the cost factor on both runtimes (interop everywhere). */
export const PASSWORD_PBKDF2_ITERATIONS = 100_000

export const PASSWORD_MIN_LENGTH = 12
/** The PBKDF2 input bound (a request body this large is a mistake or an
 *  attempt at free work — refused honestly, never truncated). */
export const PASSWORD_MAX_LENGTH = 1024

/** Hash a password for storage (fresh random salt). */
export async function hashPassword(password: string): Promise<string> {
  return pbkdf2Hash(password, PASSWORD_PBKDF2_ITERATIONS)
}

/** Verify a presented password against the stored hash (constant-time on
 *  the digest; a malformed stored value never verifies). */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  return pbkdf2Verify(password, stored)
}

// ── the timing-safe login shape ──────────────────────────────────────
// The sign-in resolves email → credential → verify. An UNKNOWN email (or
// an account without a credential) must not answer faster than a wrong
// password — that difference is a user-enumeration oracle. The login
// therefore ALWAYS runs one full verify: against the real hash when there
// is one, against this throwaway one otherwise (the comparison still
// fails, honestly).

let dummyHash: Promise<string> | null = null

/** The stand-in hash for the no-such-credential path (a real PBKDF2 over
 *  a random throwaway — same cost, never stored, never matching). */
function dummyPasswordHash(): Promise<string> {
  if (!dummyHash) {
    let bin = ''
    for (const b of crypto.getRandomValues(new Uint8Array(24))) bin += String.fromCharCode(b)
    dummyHash = hashPassword(`not-a-password:${btoa(bin)}`)
  }
  return dummyHash
}

/** The login's verify: ONE full-cost comparison whether or not the
 *  account carries a credential. Answers false for both failure classes —
 *  the caller cannot tell them apart, and neither can a timer. */
export async function verifyPasswordLogin(password: string, stored: string | null): Promise<boolean> {
  const hash = stored ?? (await dummyPasswordHash())
  const ok = await verifyPassword(password, hash)
  return stored !== null && ok
}

// ── the policy + the honest strength meter ───────────────────────────

export interface PasswordPolicy {
  ok: boolean
  problems: string[]
}

/** The gate: length ≥ 12, length ≤ the bound. Nothing else refuses. */
export function passwordPolicy(password: string): PasswordPolicy {
  const problems: string[] = []
  if (password.length < PASSWORD_MIN_LENGTH) {
    problems.push(`at least ${PASSWORD_MIN_LENGTH} characters`)
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    problems.push(`at most ${PASSWORD_MAX_LENGTH} characters`)
  }
  return { ok: problems.length === 0, problems }
}

export interface PasswordStrength {
  /** 0 too short · 1 fair · 2 good · 3 strong — the meter's steps. */
  score: 0 | 1 | 2 | 3
  label: string
  /** What would improve THIS password (empty at the top step). */
  hint: string
}

function varietyClasses(password: string): number {
  let n = 0
  if (/[a-z]/.test(password)) n++
  if (/[A-Z]/.test(password)) n++
  if (/[0-9]/.test(password)) n++
  if (/[^a-zA-Z0-9]/.test(password)) n++
  return n
}

/** The meter: length carries the score (it is what the policy gates and
 *  what brute force fights); variety breaks ties. The hint names the
 *  cheapest honest improvement — never a invented-complexity rule. */
export function passwordStrength(password: string): PasswordStrength {
  const len = password.length
  const variety = varietyClasses(password)
  if (len < PASSWORD_MIN_LENGTH) {
    return {
      score: 0,
      label: 'Too short',
      hint: `Passwords here are at least ${PASSWORD_MIN_LENGTH} characters — ${PASSWORD_MIN_LENGTH - len} more to go.`,
    }
  }
  if (len < 16 && variety < 3) {
    return { score: 1, label: 'Fair', hint: 'Longer is stronger — a passphrase of several words beats a short jumble.' }
  }
  if (len < 20) {
    return {
      score: 2,
      label: 'Good',
      hint: variety < 3 ? 'Mix in numbers or symbols, or simply make it longer.' : 'A few more characters make it stronger still.',
    }
  }
  return { score: 3, label: 'Strong', hint: '' }
}
