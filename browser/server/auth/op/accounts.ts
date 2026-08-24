// ═══════════════════════════════════════════════════════════════════
// The OP's account model (TODO.identity/02) — the pieces of
// routes/op-accounts.ts that are not HTTP:
//
//  1. THE ENROLLMENT TOKEN. Invite-only enrollment: an admin creates the
//     account, the user receives a one-time setup link whose token is a
//     256-bit random value backed by the enrollment_tokens D1 row (the
//     same doctrine as the OIDC codes: the database IS the proof, so the
//     flow survives Worker isolates). 24 h TTL; consumed atomically at
//     completion — one-time means one-time.
//
//  2. THE BOOTSTRAP SEED (OP_ACCOUNT_SEED). A fresh OP has NO accounts
//     and no open signup, so the first administrator(s) arrive by
//     declaration: a JSON array of { email, name, role? } upserted at
//     boot; an account without a password gets a FRESH enrollment token
//     and the setup link is LOGGED once (the operator reads it from the
//     deploy log — the same posture as the federation dev key's loud
//     warning). Once the account sets its password the seed goes quiet.
//
// The linked sign-in methods (GitHub, OIDC upstreams) are
// TODO.identity/08's registry-driven flows (auth/upstream/*,
// routes/op-upstream.ts) — the account list here never depends on them.
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { opRandomToken } from './keys'
import type { ServerStore } from '@oimlsmart/platform-server/store'

type EnvLike = Record<string, string | undefined>

/** The enrollment link's lifetime (24 h — the spec's value). */
export const OP_ENROLLMENT_TTL_MS = 24 * 60 * 60 * 1000

/** The provider value an OP password account carries on the users row
 *  (the demo cast is 'demo', OAuth-provisioned rows carry their upstream;
 *  the OP's own list is 'password' — its primary credential). */
export const OP_ACCOUNT_PROVIDER = 'password'

/** Mint an enrollment token value (256-bit random; the D1 row is its
 *  proof — nothing else to sign). */
export function mintEnrollmentToken(): string {
  return opRandomToken()
}

// ── the bootstrap seed (OP_ACCOUNT_SEED) ─────────────────────────────

export interface OpAccountSeedEntry {
  email: string
  name: string
  role?: string
}

/** Parse + validate the seed declaration. Throws honestly on a malformed
 *  document — a misdeclared account list must fail the boot, never guess. */
export function parseOpAccountSeed(raw: string): OpAccountSeedEntry[] {
  const parsed = JSON.parse(raw) as unknown
  if (!Array.isArray(parsed)) throw new Error('OP_ACCOUNT_SEED must be a JSON array of { email, name, role? }')
  return parsed.map((entry, i) => {
    const rec = entry as Record<string, unknown>
    if (typeof rec?.email !== 'string' || !rec.email.includes('@')) throw new Error(`OP_ACCOUNT_SEED[${i}]: email is required`)
    if (typeof rec.name !== 'string' || !rec.name) throw new Error(`OP_ACCOUNT_SEED[${i}]: name is required`)
    if (rec.role !== undefined && typeof rec.role !== 'string') throw new Error(`OP_ACCOUNT_SEED[${i}]: role must be a string`)
    return rec as unknown as OpAccountSeedEntry
  })
}

/** Upsert the declared accounts (idempotent; an existing account is left
 *  ENTIRELY alone — the rows are admin-managed afterwards, the registry
 *  seed's posture). Every seeded account WITHOUT a password gets a fresh
 *  enrollment token whose setup link is logged once per process — the
 *  first administrator's way in on a fresh deployment (invite-only means
 *  nobody else can mint one). Answers the seeded emails. */
export async function seedOpAccountsFromEnv(
  env: EnvLike,
  store: ServerStore,
  issuer: string,
): Promise<string[]> {
  const raw = env.OP_ACCOUNT_SEED?.trim()
  if (!raw) return []
  const seeded: string[] = []
  for (const entry of parseOpAccountSeed(raw)) {
    let account: { id: string; email: string } | null = await store.findUserByEmail(entry.email.trim().toLowerCase())
    if (!account) {
      account = await store.createOpAccount({
        email: entry.email,
        name: entry.name,
        role: entry.role ?? 'admin',
        createdBy: 'op-account-seed',
      })
    }
    if (!account) continue // the UNIQUE race — the concurrent writer owns it
    seeded.push(account.email)
    const methods = await store.countSignInMethods(account.id)
    if (!methods.password) {
      const token = mintEnrollmentToken()
      await store.createEnrollmentToken({
        token,
        userId: account.id,
        createdBy: 'op-account-seed',
        ttlMs: OP_ENROLLMENT_TTL_MS,
      })
      console.warn(
        `[op] bootstrap: account ${account.email} has no password — its ONE-TIME setup link (24 h):\n`
        + `  ${issuer}/op/setup?token=${token}\n`
        + 'Set the password to silence this; a fresh link is minted at every boot until then.',
      )
    }
  }
  return seeded
}
