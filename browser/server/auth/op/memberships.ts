// ═══════════════════════════════════════════════════════════════════
// THE ORG-CONTEXT RESOLUTION (TODO.identity/11 — the multi-org
// membership model) — the I/O half every OP route shares.
//
// The account acts AS one organization at a time (the GitHub
// context-switch pattern): the session carries the active-org stamp, the
// OIDC code inherits it at the consent decision, and every claims
// emission (the token endpoint, userinfo, the consent page's preview)
// resolves the SAME way here: load the memberships the context names,
// then the KERNEL's pure resolveOrgContext decides — the session payload
// (the stores' getSessionUser) and the token claims can never drift,
// because both run the one rule.
//
// THE CONTRACT: `org` and `roles` keep their EXISTING shape — `org` is
// the ACTIVE org (the primary binding when no context is stamped), and
// `roles` is the active org's per-org role set (union the account-level
// roles of an org-free account, honestly). A relying party never learns
// the other memberships.
//
// WORKER-SAFE: the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import {
  resolveOrgContext,
  type OrgContextResolution,
  type ServerStore,
} from '@oimlsmart/platform-server/store'

/** The account-shaped input the rule reads (the RAW account row). */
export interface ContextAccount {
  id: string
  role: string
  roles?: string[] | null
  orgId: string | null
}

/**
 * The effective org context for a claims emission. `user` must be the
 * RAW account row (getUserById / listUsers) — NEVER the session payload
 * (that one is already context-shaped; its orgId is the EFFECTIVE org,
 * not necessarily the primary binding). `contextOrg` is the stamped
 * active org (the session's, or the OIDC code's; NULL = the primary
 * context). A context whose membership is missing or no longer active
 * falls back to the primary rule inside resolveOrgContext — the stale
 * context never emits a dead org's claims.
 */
export async function claimsContextFor(
  store: ServerStore,
  user: ContextAccount,
  contextOrg: string | null,
): Promise<OrgContextResolution> {
  const [active, primary] = await Promise.all([
    contextOrg ? store.getOrgMembership(user.id, contextOrg) : Promise.resolve(null),
    user.orgId ? store.getOrgMembership(user.id, user.orgId) : Promise.resolve(null),
  ])
  return resolveOrgContext(user, { activeOrg: contextOrg, active, primary })
}
