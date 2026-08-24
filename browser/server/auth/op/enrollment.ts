// ═══════════════════════════════════════════════════════════════════
// THE INVITE SEAM (TODO.identity/10 → TODO.identity/02) — approving a
// join request, or BIML creating an org admin, ISSUES THE INVITE.
//
// 02's enrollment machinery has landed, so this seam is the REAL
// binding now (it was written against 02's spec first — the call sites
// never changed when it landed): the account is an OP PASSWORD account
// (provider 'password', createOpAccount — never the demo provider), the
// org binding + the full role set are applied to it, and the invite is
// 02's one-time 24 h setup link (mintEnrollmentToken +
// enrollment_tokens, consumed atomically at completion). The link's
// DELIVERY is TODO.identity/09's mailer (auth/op/mail.ts): the route
// emails it when a provider is configured and shows it to the deciding
// admin ONCE for the out-of-band handover when it is not — never a
// silent drop.
//
// WORKER-SAFE: the ServerStore seam + 02's worker-safe helpers only.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore, UserAdminRow } from '@oimlsmart/platform-server/store'
import { mintEnrollmentToken, OP_ENROLLMENT_TTL_MS } from './accounts'

export interface IssuedInvite {
  /** The provisioned account (with the org binding + the role set). */
  user: UserAdminRow
  /** How the invite reaches the user: 02's one-time setup link. */
  delivery: 'enrollment-link'
  /** The one-time setup link (24 h) — EMAILED when a mail provider is
   *  configured (TODO.identity/09), else shown ONCE to the deciding
   *  admin for the out-of-band handover. The route's response carries
   *  the mail outcome either way. */
  setupUrl: string
  /** The link's expiry (ISO). */
  expiresAt: string
}

/**
 * Issue the invite: provision the OP account (email + name + role), bind
 * it to the organization and the full role set, and mint the one-time
 * setup link. Answers null when an account with the email already exists
 * (the honest conflict — the route maps it to a 409, never a silent
 * overwrite).
 */
export async function issueAccountInvite(
  store: ServerStore,
  input: {
    email: string
    name: string
    role: string
    roles?: string[]
    orgId: string | null
    /** Who issues the invite (the deciding admin's email) — journaled on
     *  the account + the enrollment row, and in the caller's audit event. */
    invitedBy: string
    /** The OP's public issuer URL (the setup link's base — the route's
     *  resolved origin). */
    issuer: string
  },
): Promise<IssuedInvite | null> {
  const account = await store.createOpAccount({
    email: input.email,
    name: input.name,
    role: input.role,
    createdBy: input.invitedBy,
  })
  if (!account) return null
  // The org binding + the full role set (createOpAccount carries
  // neither — the users row takes both here, the same writes the users
  // API's assignment paths run).
  if (input.orgId) await store.updateUserRoleOrg(account.id, input.role, input.orgId)
  if (input.roles?.length) await store.setUserRoles(account.id, input.role, input.roles)
  const user = (await store.listUsers()).find(u => u.id === account.id) ?? account

  const token = mintEnrollmentToken()
  const enrollment = await store.createEnrollmentToken({
    token,
    userId: account.id,
    createdBy: input.invitedBy,
    ttlMs: OP_ENROLLMENT_TTL_MS,
  })
  return {
    user,
    delivery: 'enrollment-link',
    setupUrl: `${input.issuer}/op/setup?token=${encodeURIComponent(token)}`,
    expiresAt: enrollment.expiresAt,
  }
}
