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
//      role claims are a per-client privilege. The same gate covers the
//      'picture' family (below): a client the policy does not name it
//      for never receives the claim.
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
import { encodeOrgMemberCone, type OrgMemberCone } from '@oimlsmart/platform-server/store'

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

/**
 * The picture claim for this client (the 'picture' claim family): the
 * PUBLIC avatar route's absolute URL (`<issuer>/op/avatar/<account id>`)
 * — an RP renders it from a plain cross-origin <img>, so the claim names
 * the session-less serve (routes/op.ts's GET /op/avatar/:id, the
 * GitHub-avatars convention), never the session-bound own-account route.
 *
 * Answers NULL (the claim is ABSENT — a token never carries a broken
 * URL) unless BOTH hold:
 *
 *   1. the client's claims policy carries the 'picture' family (the
 *      same per-client privilege gate as the role claims), AND
 *   2. the account HAS an uploaded avatar (avatar_url set — the upload
 *      plants the marker, the removal + the erasure clear it). With no
 *      upload the RP renders its own initials fallback, exactly like the
 *      account console.
 *
 * Pure: the caller knows the issuer (the request's effective OP config).
 */
export function pictureClaimForClient(
  user: { id: string; avatarUrl?: string | null },
  policy: OidcClientClaimsPolicy | null,
  issuer: string,
): string | null {
  if (!policy?.claims?.includes('picture')) return null
  if (!user.avatarUrl) return null
  return `${issuer}/op/avatar/${user.id}`
}

/** The claims to attach for a RESOLVED org context (TODO.identity/11 —
 *  the multi-org membership model): the same rule as
 *  roleClaimsForClient, keyed on the context (the active org + its
 *  per-org role set, auth/op/memberships.ts's claimsContextFor) instead
 *  of the raw account row. The CLAIM SHAPE never changes: `org` is the
 *  active org, `roles`/`groups` carry its set — an EMPTY context set
 *  omits the role claims (never an empty array on the wire — an account
 *  whose primary membership is invited/disabled emits none).
 *
 *  TODO.identity-features/09 — the `cone` claim (the membership's data
 *  cone, the canonical spelling — 'org-wide' when the column is NULL):
 *  a per-client privilege like the role claims, emitted ONLY when the
 *  client's claims policy names 'cone' AND the context resolved an org
 *  with a membership cone. The platform enforces from its own session
 *  resolution; the claim lets a relying party learn the posture without
 *  a callback. The discovery document does NOT advertise it (the
 *  wave-A sidecar posture: the OP surface contract — the committed
 *  golden — stays byte-clean; a client that wants the cone names it in
 *  its claims policy). */
export function roleClaimsForContext(
  assigned: string[] | null,
  context: { orgId: string | null; roles: string[]; cone?: OrgMemberCone | null },
  policy: OidcClientClaimsPolicy | null,
): Record<string, unknown> {
  const gate = new Set(policy?.claims ?? [])
  const out: Record<string, unknown> = {}
  const roles = rolesForClient(assigned, context.roles, policy)
  if (roles.length) {
    if (gate.has('roles')) out.roles = roles
    if (gate.has('groups')) out.groups = roles
  }
  if (gate.has('org') && context.orgId) out.org = context.orgId
  if (gate.has('cone') && context.orgId && context.cone) {
    out.cone = encodeOrgMemberCone(context.cone) ?? 'org-wide'
  }
  return out
}
