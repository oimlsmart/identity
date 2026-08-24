// ═══════════════════════════════════════════════════════════════════
// The per-client role-claim shaping (TODO.identity/03) — the ONE rule
// every reader of the client registry's claims policy shares: the token
// endpoint (/op/token), userinfo (/op/userinfo), the consent page's
// context, and the registry console's effective preview all compute the
// SAME set here.
//
// THE RULE:
//
//   1. THE CLAIM GATE (TODO.identity/01): a client whose claims policy
//      does not list 'roles'/'groups' receives NO role claim at all —
//      role claims are a per-client privilege.
//   2. THE ASSIGNMENT (03): the roles the account holds ON THIS CLIENT
//      come from the registry's per-client assignment (op_client_roles).
//      NO ROW = the account's OP-side role set is the federation-wide
//      default (the pre-03 behavior — an OP that never assigned
//      per-client roles keeps emitting the account's roles); an EMPTY
//      assignment is the explicit "no roles on this client" (the
//      instance's no-claim posture: viewer / the approval queue).
//   3. THE POLICY ALLOWLIST (03): when the client's claims policy
//      declares `roles`, the emitted set is intersected with it — the
//      OP never emits a role the client is not configured to receive.
//      ABSENT = the policy does not bound the role set (01's posture).
//
// The instance side never invents a role either: the fed-10 claim
// mapping (@oimlsmart/platform-server/vocab's rolesFromClaims + the profile's
// claimMapping rules) keeps only roles the instance's RBAC map knows.
//
// WORKER-SAFE: pure functions, no I/O, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { OidcClientClaimsPolicy } from '@oimlsmart/platform-server/store'

/** The account's OP-side role set (the federation-wide default): the
 *  full assigned set when present, else the primary role. */
export function accountRoleSet(user: { role: string; roles?: string[] | null }): string[] {
  return user.roles?.length ? [...user.roles] : [user.role]
}

/**
 * The role set the ID token may carry for a client. Pure.
 *
 *  - `assigned` — the per-client assignment (getOpClientRoles):
 *    null = no row → the account default; [] = explicitly none.
 *  - `policy` — the client's claims policy; its optional `roles`
 *    allowlist bounds the emitted set.
 *
 * Answers the roles to emit; an EMPTY answer means the role claims are
 * OMITTED (never an empty array on the wire).
 */
export function rolesForClient(
  assigned: string[] | null,
  accountRoles: readonly string[],
  policy: OidcClientClaimsPolicy | null,
): string[] {
  const base = assigned ?? accountRoles
  const allow = policy?.roles ? new Set(policy.roles) : null
  const out: string[] = []
  for (const role of base) {
    if (allow && !allow.has(role)) continue
    if (!out.includes(role)) out.push(role)
  }
  return out
}

/** The claims to attach for this client (the helper the token +
 *  userinfo + consent paths share): the claim gate decides WHICH claim
 *  keys appear; rolesForClient decides their VALUES. `org` rides the
 *  account's org binding when the policy carries it. */
export function roleClaimsForClient(
  assigned: string[] | null,
  user: { role: string; roles?: string[] | null; orgId: string | null },
  policy: OidcClientClaimsPolicy | null,
): Record<string, unknown> {
  const gate = new Set(policy?.claims ?? [])
  const out: Record<string, unknown> = {}
  const roles = rolesForClient(assigned, accountRoleSet(user), policy)
  if (roles.length) {
    if (gate.has('roles')) out.roles = roles
    if (gate.has('groups')) out.groups = roles
  }
  if (gate.has('org') && user.orgId) out.org = user.orgId
  return out
}
