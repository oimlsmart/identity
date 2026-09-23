// ═══════════════════════════════════════════════════════════════════
// The demo personas' GRANT-BASED ASSUMPTION (the account chooser's
// Google-Workspace "sign in as user" posture — TODO.modern/17's
// chooser wave, the 2026-09-23 "the demo has to be real" order).
//
// The demonstration personas are REAL password accounts whose
// credentials are minted random and NEVER PUBLISHED — no shared demo
// password exists. The ONLY way to act as a persona is assumption: a
// declared grant set (the OP_DEMO_ASSUME_GRANTS secret) names the REAL
// accounts — the owner/team — allowed to assume the demo personas for
// the oiml-smart-demo client. A grant-holder's chooser lists the
// declared personas; picking one mints a session AS the persona
// (amr: ['assumed'], no persona password ever presented) and journals
// the event (op_assumptions — who, whom, when, which client). An
// account without a grant never sees the personas; the declared seed
// roster (OP_ACCOUNT_SEED's clientRoles for the client) is the persona
// set — nothing the declaration does not name can ever be assumed.
//
// The declaration discipline is the bootstrap seed's: a malformed
// document fails honestly (throws), never guesses.
//
// WORKER-SAFE: pure parsing/derivation, no I/O.
// ═══════════════════════════════════════════════════════════════════

import type { OpAccountSeedEntry } from './accounts'

/** The grant declaration (the OP_DEMO_ASSUME_GRANTS secret's shape):
 *  the client whose flows the grants serve + the grantee addresses
 *  (the owner/team's REAL accounts — never the personas themselves). */
export interface OpPersonaGrants {
  clientId: string
  grantees: string[]
}

/** The seed declaration's persona projection for one client: an entry
 *  whose clientRoles name the client with at least one role. */
export interface DeclaredPersona {
  email: string
  name: string
  orgId: string | null
  roles: string[]
}

/** Parse + validate the grant declaration. Throws honestly on a
 *  malformed document — a misdeclared grant set must fail the request
 *  posture loudly at parse time, never widen it. */
export function parseOpPersonaGrants(raw: string): OpPersonaGrants {
  const parsed = JSON.parse(raw) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('OP_DEMO_ASSUME_GRANTS must be a JSON object { clientId, grantees: string[] }')
  }
  const rec = parsed as Record<string, unknown>
  if (typeof rec.clientId !== 'string' || !rec.clientId.trim()) {
    throw new Error('OP_DEMO_ASSUME_GRANTS: clientId is required')
  }
  if (!Array.isArray(rec.grantees) || !rec.grantees.every(g => typeof g === 'string' && g.includes('@'))) {
    throw new Error('OP_DEMO_ASSUME_GRANTS: grantees must be an array of addresses')
  }
  return {
    clientId: rec.clientId.trim(),
    grantees: [...new Set(rec.grantees.map(g => g.trim().toLowerCase()))],
  }
}

/** The grants as the request's env declares them (null = the feature
 *  stands closed — no declaration, no personas, ever). */
export function personaGrantsFromEnv(env: Record<string, string | undefined>): OpPersonaGrants | null {
  const raw = env.OP_DEMO_ASSUME_GRANTS?.trim()
  if (!raw) return null
  try {
    return parseOpPersonaGrants(raw)
  } catch (err) {
    console.error(`[op] ${(err as Error).message}`)
    return null
  }
}

/** The declared persona set for the client, derived from the seed
 *  declaration (the roster's source of truth — a persona is exactly an
 *  entry the declaration scopes to the client). */
export function declaredPersonasForClient(seed: OpAccountSeedEntry[], clientId: string): DeclaredPersona[] {
  return seed
    .filter(entry => (entry.clientRoles?.[clientId]?.length ?? 0) > 0)
    .map(entry => ({
      email: entry.email.trim().toLowerCase(),
      name: entry.name,
      orgId: entry.orgId ?? null,
      roles: entry.clientRoles?.[clientId] ?? [],
    }))
}

/** The grant verdict for one address (normalized; the persona set's own
 *  addresses never self-grant — the personas are the OBJECTS of the
 *  grants, never subjects). */
export function grantsAllowEmail(grants: OpPersonaGrants, email: string, personaEmails: ReadonlySet<string>): boolean {
  const normalized = email.trim().toLowerCase()
  return !personaEmails.has(normalized) && grants.grantees.includes(normalized)
}

/** The declared persona by address (the assumption guard's lookup). */
export function declaredPersonaByEmail(personas: DeclaredPersona[], email: string): DeclaredPersona | null {
  const normalized = email.trim().toLowerCase()
  return personas.find(p => p.email === normalized) ?? null
}
