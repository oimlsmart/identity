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
//     A DECLARED entry — one that carries any of the persona fields
//     (orgId, roles, emailVerified, password, clientRoles) — is more
//     than an invite: the declaration is AUTHORITATIVE for exactly the
//     fields it names, converged on every boot (the demo cast's align
//     posture — the declaration is the roster's source of truth, so a
//     hand edit to a declared field does not survive a boot; drop the
//     field from the declaration to hand-manage it). A PLAIN entry
//     keeps the hands-off doctrine: create-if-absent, then the account
//     belongs to its administrators. The per-client assignments and the
//     org binding are what make the demonstration personas REAL
//     accounts with NARROW reach: their OP-side role set stays outside
//     every relying party's claim mapping, and the only roles they
//     carry are the ones the declaration assigns to the named client.
//
// The linked sign-in methods (GitHub, OIDC upstreams) are
// TODO.identity/08's registry-driven flows (auth/upstream/*,
// routes/op-upstream.ts) — the account list here never depends on them.
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { opRandomToken } from './keys'
import { hashPassword } from '../passwords'
import type { ServerStore } from '../../store'

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
  /** The org binding (users.org_id + the primary membership mirror). */
  orgId?: string
  /** The FULL OP-side role set (users.roles). */
  roles?: string[]
  /** The primary address ships pre-verified (the demonstration cast's
   *  addresses are the operator's declarations, not mailboxes to prove). */
  emailVerified?: boolean
  /** The sign-in credential, hashed on the seed. Set ONLY while the
   *  account holds no password — a rotated or admin-set credential is
   *  never clobbered by a re-deploy. */
  password?: string
  /** The per-client role assignments (op_client_roles), keyed by the
   *  client id. Upserted on every boot — the declaration's narrow reach
   *  is exactly these rows. */
  clientRoles?: Record<string, string[]>
}

/** The entry carries at least one declared (converged) field. */
export function isDeclaredSeedEntry(entry: OpAccountSeedEntry): boolean {
  return entry.orgId !== undefined || entry.roles !== undefined
    || entry.emailVerified !== undefined || entry.password !== undefined
    || entry.clientRoles !== undefined
}

/** Parse + validate the seed declaration. Throws honestly on a malformed
 *  document — a misdeclared account list must fail the boot, never guess. */
export function parseOpAccountSeed(raw: string): OpAccountSeedEntry[] {
  const parsed = JSON.parse(raw) as unknown
  if (!Array.isArray(parsed)) throw new Error('OP_ACCOUNT_SEED must be a JSON array of { email, name, role?, orgId?, roles?, emailVerified?, password?, clientRoles? }')
  return parsed.map((entry, i) => {
    const rec = entry as Record<string, unknown>
    if (typeof rec?.email !== 'string' || !rec.email.includes('@')) throw new Error(`OP_ACCOUNT_SEED[${i}]: email is required`)
    if (typeof rec.name !== 'string' || !rec.name) throw new Error(`OP_ACCOUNT_SEED[${i}]: name is required`)
    if (rec.role !== undefined && typeof rec.role !== 'string') throw new Error(`OP_ACCOUNT_SEED[${i}]: role must be a string`)
    if (rec.orgId !== undefined && (typeof rec.orgId !== 'string' || !rec.orgId)) throw new Error(`OP_ACCOUNT_SEED[${i}]: orgId must be a non-empty string`)
    if (rec.roles !== undefined && (!Array.isArray(rec.roles) || !rec.roles.every(r => typeof r === 'string' && r))) throw new Error(`OP_ACCOUNT_SEED[${i}]: roles must be an array of non-empty strings`)
    if (rec.emailVerified !== undefined && typeof rec.emailVerified !== 'boolean') throw new Error(`OP_ACCOUNT_SEED[${i}]: emailVerified must be a boolean`)
    if (rec.password !== undefined && (typeof rec.password !== 'string' || !rec.password)) throw new Error(`OP_ACCOUNT_SEED[${i}]: password must be a non-empty string`)
    if (rec.clientRoles !== undefined) {
      if (!rec.clientRoles || typeof rec.clientRoles !== 'object' || Array.isArray(rec.clientRoles)) throw new Error(`OP_ACCOUNT_SEED[${i}]: clientRoles must be an object of client id → role array`)
      for (const [clientId, roles] of Object.entries(rec.clientRoles as Record<string, unknown>)) {
        if (!Array.isArray(roles) || !roles.every(r => typeof r === 'string' && r)) throw new Error(`OP_ACCOUNT_SEED[${i}]: clientRoles.${clientId} must be an array of non-empty strings`)
      }
    }
    return rec as unknown as OpAccountSeedEntry
  })
}

/** Upsert the declared accounts (idempotent). A PLAIN entry is created
 *  when absent and left ENTIRELY alone afterwards (the registry seed's
 *  posture — the rows are admin-managed). A DECLARED entry (one carrying
 *  orgId/roles/emailVerified/password/clientRoles) converges EXACTLY its
 *  declared fields on every boot: the demonstration cast's roster is the
 *  declaration, so the cast cannot drift out from under the demo. Every
 *  seeded account WITHOUT a password (and without a declared one) gets a
 *  fresh enrollment token whose setup link is logged once per process —
 *  the first administrator's way in on a fresh deployment (invite-only
 *  means nobody else can mint one). Answers the seeded emails. */
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
      const created = await store.createOpAccount({
        email: entry.email,
        name: entry.name,
        role: entry.role ?? 'admin',
        createdBy: 'op-account-seed',
        ...(entry.orgId !== undefined ? { orgId: entry.orgId } : {}),
        ...(entry.roles !== undefined ? { roles: entry.roles } : {}),
        ...(entry.emailVerified ? { emailVerified: true } : {}),
      })
      account = created ? { id: created.id, email: created.email } : null
    }
    if (!account) continue // the UNIQUE race — the concurrent writer owns it
    seeded.push(account.email)
    if (isDeclaredSeedEntry(entry)) {
      await convergeDeclaredAccount(store, account.id, entry)
    }
    const methods = await store.countSignInMethods(account.id)
    if (!methods.password && entry.password === undefined) {
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

/** A declared entry's convergence: every field the entry names is
 *  written (idempotent), every field it omits is untouched. The writes
 *  ride the store's own seams — the role/org writes re-sync the primary
 *  membership mirror themselves (TODO.identity/11). */
async function convergeDeclaredAccount(store: ServerStore, userId: string, entry: OpAccountSeedEntry): Promise<void> {
  // The role set: the declaration's role/roles, or the account's
  // standing set when the entry declares only the other fields.
  if (entry.role !== undefined || entry.roles !== undefined) {
    const current = await store.getUserById(userId)
    const role = entry.role ?? current?.role ?? 'user'
    const roles = entry.roles ?? (entry.role !== undefined ? [entry.role] : (current?.roles?.length ? current.roles : [role]))
    await store.setUserRoles(userId, role, roles)
  }
  if (entry.orgId !== undefined) {
    const current = await store.getUserById(userId)
    await store.updateUserRoleOrg(userId, current?.role ?? 'user', entry.orgId)
    // A membership an administrator disabled (or left invited) comes
    // back with the boot — the declaration says the account acts for
    // this org.
    const membership = await store.getOrgMembership(userId, entry.orgId)
    if (membership && membership.state !== 'active') {
      await store.setOrgMembershipState(userId, entry.orgId, 'active', 'op-account-seed')
    }
  }
  if (entry.emailVerified) {
    await store.markPrimaryEmailVerified(userId)
  }
  if (entry.password !== undefined) {
    const methods = await store.countSignInMethods(userId)
    if (!methods.password) {
      // The demonstration credential — the published posture the
      // declaration carries. Hashed here; never logged, never returned.
      await store.setPasswordHash(userId, await hashPassword(entry.password), 'op-account-seed')
    }
  }
  for (const [clientId, roles] of Object.entries(entry.clientRoles ?? {})) {
    await store.setOpClientRoles(userId, clientId, roles, 'op-account-seed')
  }
}
